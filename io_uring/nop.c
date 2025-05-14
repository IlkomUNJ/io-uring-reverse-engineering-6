// SPDX-License-Identifier: GPL-2.0
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/io_uring.h>

#include <uapi/linux/io_uring.h>

#include "io_uring.h"
#include "rsrc.h"
#include "nop.h"

struct io_nop {
	/* NOTE: kiocb has the file as the first member, so don't do it here */
	struct file     *file;
	int             result;
	int		fd;
	unsigned int	flags;
};

#define NOP_FLAGS	(IORING_NOP_INJECT_RESULT | IORING_NOP_FIXED_FILE | \
			 IORING_NOP_FIXED_BUFFER | IORING_NOP_FILE)

/*
 * io_nop_prep() - Persiapkan operasi NOP (No Operation) untuk eksekusi
 * @req: pointer ke struktur io_kiocb yang berisi informasi operasi I/O
 * @sqe: pointer ke struktur io_uring_sqe yang berisi parameter dari user space
 *
 * Fungsi ini mempersiapkan struktur io_nop berdasarkan data yang diterima dari 
 * io_uring_sqe. Melakukan validasi flag yang diterima dan mengatur nilai yang 
 * terkait dengan operasi NOP, seperti hasil, file descriptor, dan buffer.
 * 
 * Mengembalikan 0 jika berhasil, atau -EINVAL jika ada kesalahan dalam parameter.
 */
int io_nop_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe)
{
	struct io_nop *nop = io_kiocb_to_cmd(req, struct io_nop);

	nop->flags = READ_ONCE(sqe->nop_flags);
	if (nop->flags & ~NOP_FLAGS)
		return -EINVAL;

	/* Tentukan hasil berdasarkan flag IORING_NOP_INJECT_RESULT */
	if (nop->flags & IORING_NOP_INJECT_RESULT)
		nop->result = READ_ONCE(sqe->len);
	else
		nop->result = 0;

	/* Tentukan file descriptor jika flag IORING_NOP_FILE diset */
	if (nop->flags & IORING_NOP_FILE)
		nop->fd = READ_ONCE(sqe->fd);
	else
		nop->fd = -1;

	/* Tentukan index buffer jika flag IORING_NOP_FIXED_BUFFER diset */
	if (nop->flags & IORING_NOP_FIXED_BUFFER)
		req->buf_index = READ_ONCE(sqe->buf_index);
	return 0;
}

/*
 * io_nop() - Eksekusi operasi NOP (No Operation)
 * @req: pointer ke struktur io_kiocb yang berisi informasi operasi I/O
 * @issue_flags: flag yang digunakan untuk pengaturan lebih lanjut selama eksekusi
 *
 * Fungsi ini mengeksekusi operasi NOP yang sudah dipersiapkan dalam 
 * io_nop_prep(). Fungsi ini menangani alokasi file descriptor dan buffer yang 
 * diperlukan jika flag IORING_NOP_FILE atau IORING_NOP_FIXED_BUFFER diset.
 *
 * Mengembalikan IOU_OK jika berhasil, atau set nilai kesalahan seperti -EBADF atau 
 * -EFAULT jika ada masalah dengan file descriptor atau buffer.
 */
int io_nop(struct io_kiocb *req, unsigned int issue_flags)
{
	struct io_nop *nop = io_kiocb_to_cmd(req, struct io_nop);
	int ret = nop->result;

	/* Tangani file descriptor jika flag IORING_NOP_FILE diset */
	if (nop->flags & IORING_NOP_FILE) {
		if (nop->flags & IORING_NOP_FIXED_FILE) {
			req->file = io_file_get_fixed(req, nop->fd, issue_flags);
			req->flags |= REQ_F_FIXED_FILE;
		} else {
			req->file = io_file_get_normal(req, nop->fd);
		}
		if (!req->file) {
			ret = -EBADF;  /* Kesalahan jika file tidak valid */
			goto done;
		}
	}

	/* Tangani buffer jika flag IORING_NOP_FIXED_BUFFER diset */
	if (nop->flags & IORING_NOP_FIXED_BUFFER) {
		if (!io_find_buf_node(req, issue_flags))
			ret = -EFAULT;  /* Kesalahan jika buffer tidak ditemukan */
	}

done:
	/* Set status gagal jika ada kesalahan */
	if (ret < 0)
		req_set_fail(req);

	/* Tentukan hasil operasi pada permintaan */
	io_req_set_res(req, nop->result, 0);
	return IOU_OK;
}

