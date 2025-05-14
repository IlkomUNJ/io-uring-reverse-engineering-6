// SPDX-License-Identifier: GPL-2.0
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/syscalls.h>
#include <linux/io_uring.h>

#include <uapi/linux/io_uring.h>

#include "../fs/internal.h"

#include "io_uring.h"
#include "truncate.h"

/*
 * struct io_ftrunc - Struktur data internal untuk perintah ftruncate
 * @file: File yang akan dipotong ukurannya
 * @len: Panjang (offset) akhir file baru setelah truncate
 *
 * Struktur ini digunakan untuk menyimpan informasi yang dibutuhkan
 * dalam operasi ftruncate() melalui io_uring.
 */
struct io_ftrunc {
	struct file			*file;
	loff_t				len;
};

/*
 * io_ftruncate_prep - Menyiapkan permintaan ftruncate dari sqe
 * @req: Struktur permintaan io_uring
 * @sqe: Submission Queue Entry dari userspace
 *
 * Melakukan validasi terhadap field yang tidak seharusnya digunakan
 * dalam operasi ftruncate. Jika validasi sukses, menyimpan offset
 * target (panjang baru file) ke dalam struktur internal.
 *
 * Return: 0 jika sukses, -EINVAL jika field tidak valid ditemukan.
 */
int io_ftruncate_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe)
{
	struct io_ftrunc *ft = io_kiocb_to_cmd(req, struct io_ftrunc);

	/* Validasi: hanya .off yang boleh diisi, field lain harus nol */
	if (sqe->rw_flags || sqe->addr || sqe->len || sqe->buf_index ||
	    sqe->splice_fd_in || sqe->addr3)
		return -EINVAL;

	ft->len = READ_ONCE(sqe->off);

	/* Paksa eksekusi asynchronous karena bisa melakukan blocking I/O */
	req->flags |= REQ_F_FORCE_ASYNC;
	return 0;
}

/*
 * io_ftruncate - Menjalankan operasi ftruncate
 * @req: Struktur permintaan io_uring
 * @issue_flags: Flag eksekusi (IO_URING_F_NONBLOCK, dll)
 *
 * Memanggil do_ftruncate() untuk mengubah ukuran file sesuai panjang
 * yang diberikan. Operasi ini tidak mendukung non-blocking, dan akan
 * memberikan peringatan jika dipaksa.
 *
 * Return: IOU_OK setelah menyimpan hasil operasi ke dalam req->result.
 */
int io_ftruncate(struct io_kiocb *req, unsigned int issue_flags)
{
	struct io_ftrunc *ft = io_kiocb_to_cmd(req, struct io_ftrunc);
	int ret;

	/* ftruncate tidak mendukung non-blocking, beri peringatan jika dipaksa */
	WARN_ON_ONCE(issue_flags & IO_URING_F_NONBLOCK);

	/* Lakukan truncate, mode '1' artinya gunakan file->f_pos sebagai dasar */
	ret = do_ftruncate(req->file, ft->len, 1);

	io_req_set_res(req, ret, 0);
	return IOU_OK;
}

