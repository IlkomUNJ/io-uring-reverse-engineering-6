// SPDX-License-Identifier: GPL-2.0
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/file.h>
#include <linux/io_uring.h>

#include <uapi/linux/io_uring.h>

#include "../fs/internal.h"

#include "io_uring.h"
#include "statx.h"

/*
 * Struktur io_statx - Menyimpan parameter untuk operasi statx
 *
 * Digunakan untuk menyimpan informasi yang diperlukan untuk memanggil
 * syscall statx dari dalam io_uring. Struktur ini akan diisi pada tahap
 * persiapan (prep) dan digunakan saat eksekusi.
 */
struct io_statx {
	struct file			*file;		// Tidak digunakan dalam implementasi ini
	int				dfd;		// File descriptor dasar (misalnya AT_FDCWD)
	unsigned int			mask;		// Mask bit statx untuk memilih informasi file
	unsigned int			flags;		// Flag untuk kontrol tambahan (misalnya AT_SYMLINK_NOFOLLOW)
	struct filename			*filename;	// Nama file yang ditargetkan
	struct statx __user		*buffer;	// Buffer user-space untuk menyimpan hasil statx
};

/*
 * io_statx_prep - Menyiapkan request statx
 * @req: Pointer ke struktur io_kiocb untuk permintaan yang sedang diproses
 * @sqe: SQE (Submission Queue Entry) yang diterima dari userspace
 *
 * Fungsi ini membaca parameter dari SQE dan menginisialisasi struktur io_statx
 * untuk operasi statx. Ini juga melakukan validasi terhadap parameter dan
 * menangani alokasi nama file dari pointer user.
 *
 * Return: 0 jika berhasil, atau kode error negatif jika gagal.
 */
int io_statx_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe)
{
	struct io_statx *sx = io_kiocb_to_cmd(req, struct io_statx);
	const char __user *path;

	/* Validasi: statx tidak boleh menggunakan buf_index atau splice_fd_in */
	if (sqe->buf_index || sqe->splice_fd_in)
		return -EINVAL;
	/* Tidak diperbolehkan jika menggunakan fixed file descriptor */
	if (req->flags & REQ_F_FIXED_FILE)
		return -EBADF;

	/* Ambil parameter dari SQE */
	sx->dfd = READ_ONCE(sqe->fd);                       // File descriptor dasar
	sx->mask = READ_ONCE(sqe->len);                     // Mask statx
	path = u64_to_user_ptr(READ_ONCE(sqe->addr));       // Alamat nama file user-space
	sx->buffer = u64_to_user_ptr(READ_ONCE(sqe->addr2));// Buffer hasil statx
	sx->flags = READ_ONCE(sqe->statx_flags);            // Flags tambahan

	/* Salin nama file dari user */
	sx->filename = getname_uflags(path, sx->flags);
	if (IS_ERR(sx->filename)) {
		int ret = PTR_ERR(sx->filename);
		sx->filename = NULL;
		return ret;
	}

	/* Tandai bahwa request perlu dibersihkan dan diproses secara async */
	req->flags |= REQ_F_NEED_CLEANUP;
	req->flags |= REQ_F_FORCE_ASYNC;
	return 0;
}

/*
 * io_statx - Menjalankan syscall statx dalam konteks io_uring
 * @req: Pointer ke struktur io_kiocb yang berisi request statx
 * @issue_flags: Flag dari io_uring (misalnya non-blocking, yang diabaikan di sini)
 *
 * Fungsi ini memanggil syscall `do_statx()` untuk mengambil informasi file sesuai
 * parameter yang telah disiapkan sebelumnya di io_statx_prep().
 *
 * Return: IOU_OK setelah hasil dicatat dalam request.
 */
int io_statx(struct io_kiocb *req, unsigned int issue_flags)
{
	struct io_statx *sx = io_kiocb_to_cmd(req, struct io_statx);
	int ret;

	WARN_ON_ONCE(issue_flags & IO_URING_F_NONBLOCK);  // Statx tidak mendukung non-blocking

	ret = do_statx(sx->dfd, sx->filename, sx->flags, sx->mask, sx->buffer);
	io_req_set_res(req, ret, 0);  // Set hasil ke request
	return IOU_OK;
}

/*
 * io_statx_cleanup - Membersihkan sumber daya yang digunakan request statx
 * @req: Pointer ke struktur io_kiocb
 *
 * Fungsi ini dipanggil setelah operasi selesai, untuk membebaskan nama file
 * yang dialokasikan saat tahap persiapan.
 */
void io_statx_cleanup(struct io_kiocb *req)
{
	struct io_statx *sx = io_kiocb_to_cmd(req, struct io_statx);

	if (sx->filename)
		putname(sx->filename);
}

