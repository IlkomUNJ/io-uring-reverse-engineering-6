// SPDX-License-Identifier: GPL-2.0
#ifndef IOU_KBUF_H
#define IOU_KBUF_H

#include <uapi/linux/io_uring.h>
#include <linux/io_uring_types.h>

// Flag untuk tipe buffer list
enum {
	IOBL_BUF_RING	= 1,	// Buffer menggunakan mekanisme ring mapping
	IOBL_INC	= 2,	// Buffer dikonsumsi sebagian, bukan langsung habis
};

// Struktur untuk daftar buffer yang disediakan oleh user
struct io_buffer_list {
	union {
		struct list_head buf_list;		// Daftar buffer klasik
		struct io_uring_buf_ring *buf_ring;	// Buffer berbasis ring
	};
	__u16 bgid;			// Buffer group ID

	// Untuk buffer berbasis ring
	__u16 buf_nr_pages;		// Jumlah halaman yang digunakan
	__u16 nr_entries;		// Jumlah entri buffer
	__u16 head;			// Indeks head pada ring buffer
	__u16 mask;			// Mask untuk ring indexing

	__u16 flags;			// Flag kontrol
	struct io_mapped_region region;	// Informasi mapping untuk buffer ring
};

// Struktur representasi buffer individu
struct io_buffer {
	struct list_head list;	// Untuk masuk ke dalam list
	__u64 addr;		// Alamat virtual user-space
	__u32 len;		// Panjang buffer
	__u16 bid;		// Buffer ID
	__u16 bgid;		// Buffer group ID
};

// Mode operasi untuk alokasi buffer
enum {
	KBUF_MODE_EXPAND	= 1, // Boleh mengalokasi iovec lebih besar
	KBUF_MODE_FREE		= 2, // Bebaskan iovec lama jika diperluas
};

// Argumen untuk seleksi buffer ke dalam iovec
struct buf_sel_arg {
	struct iovec *iovs;	// Daftar iovec untuk output
	size_t out_len;		// Total panjang output yang digunakan
	size_t max_len;		// Batas maksimum panjang
	unsigned short nr_iovs;	// Jumlah iovec yang digunakan
	unsigned short mode;	// Mode buffer (lihat enum di atas)
};

// Memilih buffer yang sesuai dari daftar buffer untuk request tertentu
void __user *io_buffer_select(struct io_kiocb *req, size_t *len,
			      unsigned int issue_flags);

// Menyeleksi beberapa buffer ke dalam iovec untuk suatu request
int io_buffers_select(struct io_kiocb *req, struct buf_sel_arg *arg,
		      unsigned int issue_flags);

// Melihat (peek) buffer yang tersedia untuk suatu request
int io_buffers_peek(struct io_kiocb *req, struct buf_sel_arg *arg);

// Menghancurkan/membersihkan semua buffer yang terdaftar dalam konteks
void io_destroy_buffers(struct io_ring_ctx *ctx);

// Mempersiapkan penghapusan buffer melalui SQE
int io_remove_buffers_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);

// Menjalankan penghapusan buffer dari kernel
int io_remove_buffers(struct io_kiocb *req, unsigned int issue_flags);

// Mempersiapkan penyediaan buffer melalui SQE
int io_provide_buffers_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);

// Menyediakan buffer baru ke dalam kernel
int io_provide_buffers(struct io_kiocb *req, unsigned int issue_flags);

// Mendaftarkan buffer ring dari user ke kernel
int io_register_pbuf_ring(struct io_ring_ctx *ctx, void __user *arg);

// Membatalkan pendaftaran buffer ring
int io_unregister_pbuf_ring(struct io_ring_ctx *ctx, void __user *arg);

// Mendapatkan status dari buffer ring
int io_register_pbuf_status(struct io_ring_ctx *ctx, void __user *arg);

// Recycle (pakai ulang) buffer klasik yang sudah dipakai
bool io_kbuf_recycle_legacy(struct io_kiocb *req, unsigned issue_flags);

// Menghapus buffer klasik tanpa recycle
void io_kbuf_drop_legacy(struct io_kiocb *req);

// Fungsi internal untuk mengembalikan buffer ke sistem setelah digunakan
unsigned int __io_put_kbufs(struct io_kiocb *req, int len, int nbufs);

// Komit buffer setelah operasi IO selesai (untuk buffer ring)
bool io_kbuf_commit(struct io_kiocb *req,
		    struct io_buffer_list *bl, int len, int nr);

// Mendapatkan informasi region dari buffer ring berdasarkan group ID
struct io_mapped_region *io_pbuf_get_region(struct io_ring_ctx *ctx,
					    unsigned int bgid);

// Recycle buffer ring: cukup clear flag tanpa mengubah indeks head
static inline bool io_kbuf_recycle_ring(struct io_kiocb *req)
{
	if (req->buf_list) {
		req->buf_index = req->buf_list->bgid;
		req->flags &= ~(REQ_F_BUFFER_RING|REQ_F_BUFFERS_COMMIT);
		return true;
	}
	return false;
}

// Menentukan apakah buffer selection perlu dilakukan berdasarkan flag
static inline bool io_do_buffer_select(struct io_kiocb *req)
{
	if (!(req->flags & REQ_F_BUFFER_SELECT))
		return false;
	return !(req->flags & (REQ_F_BUFFER_SELECTED|REQ_F_BUFFER_RING));
}

// Memilih mekanisme recycle yang sesuai berdasarkan flag dan jenis buffer
static inline bool io_kbuf_recycle(struct io_kiocb *req, unsigned issue_flags)
{
	if (req->flags & REQ_F_BL_NO_RECYCLE)
		return false;
	if (req->flags & REQ_F_BUFFER_SELECTED)
		return io_kbuf_recycle_legacy(req, issue_flags);
	if (req->flags & REQ_F_BUFFER_RING)
		return io_kbuf_recycle_ring(req);
	return false;
}

// Mengembalikan satu buffer yang telah digunakan
static inline unsigned int io_put_kbuf(struct io_kiocb *req, int len,
				       unsigned issue_flags)
{
	if (!(req->flags & (REQ_F_BUFFER_RING | REQ_F_BUFFER_SELECTED)))
		return 0;
	return __io_put_kbufs(req, len, 1);
}

// Mengembalikan beberapa buffer ke sistem setelah digunakan
static inline unsigned int io_put_kbufs(struct io_kiocb *req, int len,
					int nbufs, unsigned issue_flags)
{
	if (!(req->flags & (REQ_F_BUFFER_RING | REQ_F_BUFFER_SELECTED)))
		return 0;
	return __io_put_kbufs(req, len, nbufs);
}

#endif

