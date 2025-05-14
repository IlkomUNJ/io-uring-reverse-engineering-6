// SPDX-License-Identifier: GPL-2.0
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/namei.h>
#include <linux/io_uring.h>
#include <linux/splice.h>

#include <uapi/linux/io_uring.h>

#include "io_uring.h"
#include "splice.h"

struct io_splice {
	struct file			*file_out;
	loff_t				off_out;
	loff_t				off_in;
	u64				len;
	int				splice_fd_in;
	unsigned int			flags;
	struct io_rsrc_node		*rsrc_node;
};

/*
 * __io_splice_prep() - Persiapan untuk operasi splice
 * @req: pointer ke struktur io_kiocb yang berisi informasi I/O untuk operasi splice
 * @sqe: pointer ke struktur io_uring_sqe yang berisi perintah splice
 *
 * Fungsi ini mempersiapkan struktur io_splice dengan mengambil parameter dari
 * perintah yang diterima dalam io_uring_sqe. Ini juga memvalidasi flag yang diberikan
 * untuk memastikan hanya flag yang sah yang diterima.
 *
 * Mengembalikan 0 jika berhasil, atau nilai negatif jika terjadi kesalahan.
 */
static int __io_splice_prep(struct io_kiocb *req,
			    const struct io_uring_sqe *sqe)
{
	struct io_splice *sp = io_kiocb_to_cmd(req, struct io_splice);
	unsigned int valid_flags = SPLICE_F_FD_IN_FIXED | SPLICE_F_ALL;

	/* Menetapkan panjang data dan flag splice */
	sp->len = READ_ONCE(sqe->len);
	sp->flags = READ_ONCE(sqe->splice_flags);
	/* Memeriksa apakah flag yang diterima valid */
	if (unlikely(sp->flags & ~valid_flags))
		return -EINVAL;
	sp->splice_fd_in = READ_ONCE(sqe->splice_fd_in);
	sp->rsrc_node = NULL;
	req->flags |= REQ_F_FORCE_ASYNC;  // Menandakan bahwa operasi harus dilakukan asinkron
	return 0;
}

/*
 * io_tee_prep() - Persiapan untuk operasi tee
 * @req: pointer ke struktur io_kiocb yang berisi informasi I/O untuk operasi tee
 * @sqe: pointer ke struktur io_uring_sqe yang berisi perintah tee
 *
 * Fungsi ini memastikan bahwa parameter `splice_off_in` dan `off` adalah nol.
 * Kemudian, memanggil __io_splice_prep untuk persiapan splice lebih lanjut.
 *
 * Mengembalikan 0 jika berhasil, atau nilai negatif jika terjadi kesalahan.
 */
int io_tee_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe)
{
	if (READ_ONCE(sqe->splice_off_in) || READ_ONCE(sqe->off))
		return -EINVAL;
	return __io_splice_prep(req, sqe);
}

/*
 * io_splice_cleanup() - Pembersihan setelah operasi splice
 * @req: pointer ke struktur io_kiocb yang berisi informasi I/O untuk operasi splice
 *
 * Fungsi ini memeriksa apakah ada node sumber daya yang terpasang untuk operasi splice,
 * dan jika ada, melepaskannya untuk menghindari kebocoran sumber daya.
 */
void io_splice_cleanup(struct io_kiocb *req)
{
	struct io_splice *sp = io_kiocb_to_cmd(req, struct io_splice);

	if (sp->rsrc_node)
		io_put_rsrc_node(req->ctx, sp->rsrc_node);
}

/*
 * io_splice_get_file() - Mendapatkan file untuk operasi splice
 * @req: pointer ke struktur io_kiocb yang berisi informasi I/O untuk operasi splice
 * @issue_flags: flag yang menentukan apakah operasi dilakukan dengan non-blocking
 *
 * Fungsi ini menentukan file mana yang akan digunakan dalam operasi splice. Jika file
 * berada dalam slot tetap, ia mencari node sumber daya yang sesuai dalam tabel file
 * yang ada. Jika tidak, ia mengambil file menggunakan metode biasa.
 *
 * Mengembalikan pointer ke file yang digunakan, atau NULL jika gagal.
 */
static struct file *io_splice_get_file(struct io_kiocb *req,
				       unsigned int issue_flags)
{
	struct io_splice *sp = io_kiocb_to_cmd(req, struct io_splice);
	struct io_ring_ctx *ctx = req->ctx;
	struct io_rsrc_node *node;
	struct file *file = NULL;

	/* Jika bukan file tetap, dapatkan file biasa */
	if (!(sp->flags & SPLICE_F_FD_IN_FIXED))
		return io_file_get_normal(req, sp->splice_fd_in);

	/* Mendapatkan node sumber daya dari tabel file */
	io_ring_submit_lock(ctx, issue_flags);
	node = io_rsrc_node_lookup(&ctx->file_table.data, sp->splice_fd_in);
	if (node) {
		node->refs++;  // Menambah referensi untuk node sumber daya
		sp->rsrc_node = node;
		file = io_slot_file(node);
		req->flags |= REQ_F_NEED_CLEANUP;  // Menandakan bahwa perlu pembersihan
	}
	io_ring_submit_unlock(ctx, issue_flags);
	return file;
}

/*
 * io_tee() - Melakukan operasi tee untuk menyalin data antara dua file
 * @req: pointer ke struktur io_kiocb yang berisi informasi I/O untuk operasi tee
 * @issue_flags: flag yang menentukan apakah operasi dilakukan dengan non-blocking
 *
 * Fungsi ini mengalihkan data dari file sumber (input) ke file tujuan (output) menggunakan
 * operasi tee, yang memungkinkan data disalin tanpa memodifikasi file sumber.
 *
 * Mengembalikan status operasi (berhasil atau gagal).
 */
int io_tee(struct io_kiocb *req, unsigned int issue_flags)
{
	struct io_splice *sp = io_kiocb_to_cmd(req, struct io_splice);
	struct file *out = sp->file_out;
	unsigned int flags = sp->flags & ~SPLICE_F_FD_IN_FIXED;
	struct file *in;
	ssize_t ret = 0;

	WARN_ON_ONCE(issue_flags & IO_URING_F_NONBLOCK);

	/* Mendapatkan file input untuk operasi tee */
	in = io_splice_get_file(req, issue_flags);
	if (!in) {
		ret = -EBADF;
		goto done;
	}

	/* Melakukan operasi tee dengan panjang data yang ditentukan */
	if (sp->len)
		ret = do_tee(in, out, sp->len, flags);

	/* Melepaskan file input jika bukan file tetap */
	if (!(sp->flags & SPLICE_F_FD_IN_FIXED))
		fput(in);

done:
	/* Memastikan hasil operasi sesuai dengan panjang yang diminta */
	if (ret != sp->len)
		req_set_fail(req);
	io_req_set_res(req, ret, 0);
	return IOU_OK;
}

/*
 * io_splice_prep() - Persiapan untuk operasi splice
 * @req: pointer ke struktur io_kiocb yang berisi informasi I/O untuk operasi splice
 * @sqe: pointer ke struktur io_uring_sqe yang berisi perintah splice
 *
 * Fungsi ini mempersiapkan struktur io_splice dengan mengambil parameter dari
 * perintah yang diterima dalam io_uring_sqe dan memanggil __io_splice_prep untuk
 * persiapan lebih lanjut.
 *
 * Mengembalikan 0 jika berhasil, atau nilai negatif jika terjadi kesalahan.
 */
int io_splice_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe)
{
	struct io_splice *sp = io_kiocb_to_cmd(req, struct io_splice);

	sp->off_in = READ_ONCE(sqe->splice_off_in);
	sp->off_out = READ_ONCE(sqe->off);
	return __io_splice_prep(req, sqe);
}

/*
 * io_splice() - Melakukan operasi splice untuk menyalin data antara dua file
 * @req: pointer ke struktur io_kiocb yang berisi informasi I/O untuk operasi splice
 * @issue_flags: flag yang menentukan apakah operasi dilakukan dengan non-blocking
 *
 * Fungsi ini menyalin data antara dua file, berdasarkan parameter yang diberikan pada
 * struktur io_splice, dan menyesuaikan offset input dan output jika diperlukan.
 *
 * Mengembalikan status operasi (berhasil atau gagal).
 */
int io_splice(struct io_kiocb *req, unsigned int issue_flags)
{
	struct io_splice *sp = io_kiocb_to_cmd(req, struct io_splice);
	struct file *out = sp->file_out;
	unsigned int flags = sp->flags & ~SPLICE_F_FD_IN_FIXED;
	loff_t *poff_in, *poff_out;
	struct file *in;
	ssize_t ret = 0;

	WARN_ON_ONCE(issue_flags & IO_URING_F_NONBLOCK);

	/* Mendapatkan file input untuk operasi splice */
	in = io_splice_get_file(req, issue_flags);
	if (!in) {
		ret = -EBADF;
		goto done;
	}

	/* Menyesuaikan offset input dan output jika diperlukan */
	poff_in = (sp->off_in == -1) ? NULL : &sp->off_in;
	poff_out = (sp->off_out == -1) ? NULL : &sp->off_out;

	/* Melakukan operasi splice dengan panjang data yang ditentukan */
	if (sp->len)
		ret = do_splice(in, poff_in, out, poff_out, sp->len, flags);

	/* Melepaskan file input jika bukan file tetap */
	if (!(sp->flags & SPLICE_F_FD_IN_FIXED))
		fput(in);

done:
	/* Memastikan hasil operasi sesuai dengan panjang yang diminta */
	if (ret != sp->len)
		req_set_fail(req);
	io_req_set_res(req, ret, 0);
	return IOU_OK;
}

