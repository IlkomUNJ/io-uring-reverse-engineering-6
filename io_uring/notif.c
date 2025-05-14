#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/file.h>
#include <linux/slab.h>
#include <linux/net.h>
#include <linux/io_uring.h>

#include "io_uring.h"
#include "notif.h"
#include "rsrc.h"

/*
 * io_notif_tw_complete() - Menyelesaikan tugas notifikasi yang terkait dengan task work
 * @notif: pointer ke io_kiocb yang berisi informasi operasi I/O untuk notifikasi
 * @tw: token untuk task work
 *
 * Fungsi ini menyelesaikan task work untuk notifikasi yang terhubung dengan operasi I/O.
 * Ini memproses daftar notifikasi yang berhubungan, menangani laporan Zero-Copy jika diperlukan,
 * dan mengurangi penggunaan memori yang terhitung pada notifikasi.
 * Setelah itu, notifikasi diselesaikan dengan memanggil io_req_task_complete.
 */
static void io_notif_tw_complete(struct io_kiocb *notif, io_tw_token_t tw)
{
	struct io_notif_data *nd = io_notif_to_data(notif);

	do {
		notif = cmd_to_io_kiocb(nd);

		/* Pastikan bahwa refcount adalah 0 sebelum memproses */
		lockdep_assert(refcount_read(&nd->uarg.refcnt) == 0);

		/* Jika Zero-Copy digunakan, perbarui status laporan Zero-Copy */
		if (unlikely(nd->zc_report) && (nd->zc_copied || !nd->zc_used))
			notif->cqe.res |= IORING_NOTIF_USAGE_ZC_COPIED;

		/* Mengurangi memori yang terhitung jika diperlukan */
		if (nd->account_pages && notif->ctx->user) {
			__io_unaccount_mem(notif->ctx->user, nd->account_pages);
			nd->account_pages = 0;
		}

		nd = nd->next;
		/* Menyelesaikan task work untuk notifikasi */
		io_req_task_complete(notif, tw);
	} while (nd);
}

/*
 * io_tx_ubuf_complete() - Menyelesaikan tugas Zero-Copy (ZC) untuk transaksi buffer
 * @skb: pointer ke sk_buff yang berisi paket data
 * @uarg: pointer ke ubuf_info yang berisi informasi tentang buffer
 * @success: status keberhasilan dari transaksi
 *
 * Fungsi ini menyelesaikan proses Zero-Copy pada transaksi buffer, memperbarui status
 * terkait dan mengatur task work untuk notifikasi terkait. Jika transaksi berhasil, 
 * buffer yang digunakan akan diperbarui, dan task work ditambahkan ke notifikasi.
 */
void io_tx_ubuf_complete(struct sk_buff *skb, struct ubuf_info *uarg,
			 bool success)
{
	struct io_notif_data *nd = container_of(uarg, struct io_notif_data, uarg);
	struct io_kiocb *notif = cmd_to_io_kiocb(nd);
	unsigned tw_flags;

	/* Memperbarui status Zero-Copy jika diperlukan */
	if (nd->zc_report) {
		if (success && !nd->zc_used && skb)
			WRITE_ONCE(nd->zc_used, true);
		else if (!success && !nd->zc_copied)
			WRITE_ONCE(nd->zc_copied, true);
	}

	/* Mengurangi refcount dan memeriksa apakah ini adalah notifikasi terakhir */
	if (!refcount_dec_and_test(&uarg->refcnt))
		return;

	/* Menangani kasus di mana ada notifikasi lanjutan */
	if (nd->head != nd) {
		io_tx_ubuf_complete(skb, &nd->head->uarg, success);
		return;
	}

	/* Menentukan flag untuk task work */
	tw_flags = nd->next ? 0 : IOU_F_TWQ_LAZY_WAKE;
	notif->io_task_work.func = io_notif_tw_complete;
	/* Menambahkan task work untuk notifikasi */
	__io_req_task_work_add(notif, tw_flags);
}

/*
 * io_link_skb() - Menghubungkan sk_buff dengan ubuf_info
 * @skb: pointer ke sk_buff yang berisi paket data
 * @uarg: pointer ke ubuf_info yang berisi informasi buffer
 *
 * Fungsi ini menghubungkan sk_buff dengan ubuf_info. Ini memastikan bahwa sk_buff yang
 * diberikan tidak digunakan kembali dalam status yang tidak konsisten, dan jika perlu,
 * melakukan penanganan khusus untuk menghubungkan notifikasi ke notifikasi sebelumnya.
 *
 * Mengembalikan 0 jika berhasil, atau -EEXIST jika ada kesalahan dalam menghubungkan.
 */
static int io_link_skb(struct sk_buff *skb, struct ubuf_info *uarg)
{
	struct io_notif_data *nd, *prev_nd;
	struct io_kiocb *prev_notif, *notif;
	struct ubuf_info *prev_uarg = skb_zcopy(skb);

	nd = container_of(uarg, struct io_notif_data, uarg);
	notif = cmd_to_io_kiocb(nd);

	/* Menangani kasus di mana tidak ada buffer sebelumnya */
	if (!prev_uarg) {
		net_zcopy_get(&nd->uarg);
		skb_zcopy_init(skb, &nd->uarg);
		return 0;
	}
	/* Jika buffer sebelumnya adalah notifikasi yang sama, tidak menghubungkan */
	if (unlikely(prev_uarg == &nd->uarg))
		return 0;

	/* Tidak dapat menggabungkan dua link bersama, permintaan buffer baru */
	if (unlikely(nd->head != nd || nd->next))
		return -EEXIST;

	/* Pastikan bahwa provider Zero-Copy tidak tercampur */
	if (unlikely(prev_uarg->ops != &io_ubuf_ops))
		return -EEXIST;

	/* Menghubungkan notifikasi ke yang sebelumnya */
	prev_nd = container_of(prev_uarg, struct io_notif_data, uarg);
	prev_notif = cmd_to_io_kiocb(nd);

	/* Memastikan bahwa semua notifikasi dapat diselesaikan dalam task work yang sama */
	if (unlikely(notif->ctx != prev_notif->ctx ||
		     notif->tctx != prev_notif->tctx))
		return -EEXIST;

	nd->head = prev_nd->head;
	nd->next = prev_nd->next;
	prev_nd->next = nd;
	net_zcopy_get(&nd->head->uarg);
	return 0;
}

/*
 * io_alloc_notif() - Mengalokasikan notifikasi baru untuk io-uring
 * @ctx: pointer ke konteks io-uring
 *
 * Fungsi ini mengalokasikan notifikasi baru yang akan digunakan dalam io-uring.
 * Ini juga menginisialisasi struktur notifikasi dengan nilai default dan menghubungkannya
 * dengan task terkait.
 *
 * Mengembalikan pointer ke io_kiocb yang mewakili notifikasi, atau NULL jika gagal.
 */
struct io_kiocb *io_alloc_notif(struct io_ring_ctx *ctx)
	__must_hold(&ctx->uring_lock)
{
	struct io_kiocb *notif;
	struct io_notif_data *nd;

	/* Mengalokasikan permintaan untuk notifikasi */
	if (unlikely(!io_alloc_req(ctx, &notif)))
		return NULL;

	/* Menginisialisasi notifikasi */
	notif->opcode = IORING_OP_NOP;
	notif->flags = 0;
	notif->file = NULL;
	notif->tctx = current->io_uring;
	io_get_task_refs(1);
	notif->file_node = NULL;
	notif->buf_node = NULL;

	nd = io_notif_to_data(notif);
	nd->zc_report = false;
	nd->account_pages = 0;
	nd->next = NULL;
	nd->head = nd;

	nd->uarg.flags = IO_NOTIF_UBUF_FLAGS;
	nd->uarg.ops = &io_ubuf_ops;
	refcount_set(&nd->uarg.refcnt, 1);
	return notif;
}

