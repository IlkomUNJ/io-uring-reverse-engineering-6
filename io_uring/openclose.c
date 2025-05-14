// SPDX-License-Identifier: GPL-2.0
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/fdtable.h>
#include <linux/fsnotify.h>
#include <linux/namei.h>
#include <linux/io_uring.h>

#include <uapi/linux/io_uring.h>

#include "../fs/internal.h"

#include "io_uring.h"
#include "rsrc.h"
#include "openclose.h"

/*
 * io_openat_force_async() - Menentukan apakah operasi open harus dipaksa menjadi asynchronous
 * @open: pointer ke struktur io_open yang berisi informasi tentang operasi open
 *
 * Fungsi ini memeriksa apakah operasi open yang diminta memiliki flag yang dapat menyebabkan
 * operasi dilakukan secara asynchronous. Flag yang dicek adalah O_TRUNC, O_CREAT, dan __O_TMPFILE.
 * Jika salah satu flag tersebut ada, fungsi ini mengembalikan true, yang menandakan bahwa operasi
 * harus dipaksa asynchronous.
 */
static bool io_openat_force_async(struct io_open *open)
{
	/* Mengecek flag O_TRUNC, O_CREAT, atau __O_TMPFILE untuk menentukan apakah perlu dipaksa asynchronous */
	return open->how.flags & (O_TRUNC | O_CREAT | __O_TMPFILE);
}

/*
 * __io_openat_prep() - Persiapan untuk operasi openat
 * @req: pointer ke struktur io_kiocb yang berisi informasi I/O untuk operasi openat
 * @sqe: pointer ke struktur io_uring_sqe yang berisi perintah openat
 *
 * Fungsi ini mempersiapkan data yang diperlukan untuk operasi openat, termasuk memeriksa
 * dan mengonfigurasi parameter seperti flag dan path file. Ini juga memeriksa batasan
 * pada operasi open, seperti pengecekan pada file slot dan ukuran buffer.
 *
 * Mengembalikan 0 jika berhasil, atau nilai negatif jika terjadi kesalahan.
 */
static int __io_openat_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe)
{
	struct io_open *open = io_kiocb_to_cmd(req, struct io_open);
	const char __user *fname;
	int ret;

	/* Memeriksa jika buffer index tidak sesuai atau fixed file flag ada */
	if (unlikely(sqe->buf_index))
		return -EINVAL;
	if (unlikely(req->flags & REQ_F_FIXED_FILE))
		return -EBADF;

	/* Menginisialisasi flag open */
	if (!(open->how.flags & O_PATH) && force_o_largefile())
		open->how.flags |= O_LARGEFILE;

	/* Membaca file descriptor dan path file */
	open->dfd = READ_ONCE(sqe->fd);
	fname = u64_to_user_ptr(READ_ONCE(sqe->addr));
	open->filename = getname(fname);
	if (IS_ERR(open->filename)) {
		ret = PTR_ERR(open->filename);
		open->filename = NULL;
		return ret;
	}

	open->file_slot = READ_ONCE(sqe->file_index);
	if (open->file_slot && (open->how.flags & O_CLOEXEC))
		return -EINVAL;

	/* Menyimpan jumlah file yang dapat dibuka */
	open->nofile = rlimit(RLIMIT_NOFILE);
	req->flags |= REQ_F_NEED_CLEANUP;
	/* Menentukan jika operasi harus dilakukan secara asynchronous */
	if (io_openat_force_async(open))
		req->flags |= REQ_F_FORCE_ASYNC;
	return 0;
}

/*
 * io_openat_prep() - Persiapan untuk operasi openat dengan opsi tambahan
 * @req: pointer ke struktur io_kiocb yang berisi informasi I/O untuk operasi openat
 * @sqe: pointer ke struktur io_uring_sqe yang berisi perintah openat
 *
 * Fungsi ini digunakan untuk menyiapkan operasi openat dengan membaca dan memproses
 * flags dan mode file yang diberikan dalam perintah io_uring_sqe.
 *
 * Mengembalikan 0 jika berhasil, atau nilai negatif jika terjadi kesalahan.
 */
int io_openat_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe)
{
	struct io_open *open = io_kiocb_to_cmd(req, struct io_open);
	u64 mode = READ_ONCE(sqe->len);
	u64 flags = READ_ONCE(sqe->open_flags);

	open->how = build_open_how(flags, mode);
	return __io_openat_prep(req, sqe);
}

/*
 * io_openat2_prep() - Persiapan untuk operasi openat2 dengan opsi tambahan
 * @req: pointer ke struktur io_kiocb yang berisi informasi I/O untuk operasi openat2
 * @sqe: pointer ke struktur io_uring_sqe yang berisi perintah openat2
 *
 * Fungsi ini menyiapkan operasi openat2 dengan menyalin parameter 'how' dari pengguna
 * dan memastikan bahwa ukuran struktur yang diterima sesuai.
 *
 * Mengembalikan 0 jika berhasil, atau nilai negatif jika terjadi kesalahan.
 */
int io_openat2_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe)
{
	struct io_open *open = io_kiocb_to_cmd(req, struct io_open);
	struct open_how __user *how;
	size_t len;
	int ret;

	how = u64_to_user_ptr(READ_ONCE(sqe->addr2));
	len = READ_ONCE(sqe->len);
	if (len < OPEN_HOW_SIZE_VER0)
		return -EINVAL;

	ret = copy_struct_from_user(&open->how, sizeof(open->how), how, len);
	if (ret)
		return ret;

	return __io_openat_prep(req, sqe);
}

/*
 * io_openat2() - Menjalankan operasi openat2 untuk membuka file
 * @req: pointer ke struktur io_kiocb yang berisi informasi I/O untuk operasi openat2
 * @issue_flags: flag yang menentukan apakah operasi harus dilakukan non-blocking
 *
 * Fungsi ini menjalankan operasi openat2, termasuk penanganan file descriptor,
 * parameter non-blocking, dan pengelolaan file yang tetap (fixed file).
 *
 * Mengembalikan status operasi (berhasil atau gagal).
 */
int io_openat2(struct io_kiocb *req, unsigned int issue_flags)
{
	struct io_open *open = io_kiocb_to_cmd(req, struct io_open);
	struct open_flags op;
	struct file *file;
	bool resolve_nonblock, nonblock_set;
	bool fixed = !!open->file_slot;
	int ret;

	/* Menyiapkan flag open */
	ret = build_open_flags(&open->how, &op);
	if (ret)
		goto err;
	nonblock_set = op.open_flag & O_NONBLOCK;
	resolve_nonblock = open->how.resolve & RESOLVE_CACHED;
	if (issue_flags & IO_URING_F_NONBLOCK) {
		WARN_ON_ONCE(io_openat_force_async(open));
		op.lookup_flags |= LOOKUP_CACHED;
		op.open_flag |= O_NONBLOCK;
	}

	/* Jika file slot tidak tetap, ambil file descriptor baru */
	if (!fixed) {
		ret = __get_unused_fd_flags(open->how.flags, open->nofile);
		if (ret < 0)
			goto err;
	}

	/* Membuka file dan menangani kesalahan */
	file = do_filp_open(open->dfd, open->filename, &op);
	if (IS_ERR(file)) {
		if (!fixed)
			put_unused_fd(ret);

		ret = PTR_ERR(file);
		if (ret == -EAGAIN && !resolve_nonblock && (issue_flags & IO_URING_F_NONBLOCK))
			return -EAGAIN;
		goto err;
	}

	/* Menyesuaikan flag O_NONBLOCK jika diperlukan */
	if ((issue_flags & IO_URING_F_NONBLOCK) && !nonblock_set)
		file->f_flags &= ~O_NONBLOCK;

	/* Menyimpan file descriptor jika tidak fixed */
	if (!fixed)
		fd_install(ret, file);
	else
		ret = io_fixed_fd_install(req, issue_flags, file, open->file_slot);

err:
	putname(open->filename);
	req->flags &= ~REQ_F_NEED_CLEANUP;
	if (ret < 0)
		req_set_fail(req);
	io_req_set_res(req, ret, 0);
	return IOU_OK;
}

/*
 * io_openat() - Menjalankan operasi openat, alias untuk io_openat2
 * @req: pointer ke struktur io_kiocb yang berisi informasi I/O untuk operasi openat
 * @issue_flags: flag yang menentukan apakah operasi harus dilakukan non-blocking
 *
 * Fungsi ini memanggil io_openat2 untuk menjalankan operasi openat.
 *
 * Mengembalikan status operasi (berhasil atau gagal).
 */
int io_openat(struct io_kiocb *req, unsigned int issue_flags)
{
	return io_openat2(req, issue_flags);
}

/*
 * io_open_cleanup() - Membersihkan sumber daya yang digunakan dalam operasi open
 * @req: pointer ke struktur io_kiocb yang berisi informasi I/O untuk operasi open
 *
 * Fungsi ini membersihkan nama file yang telah dialokasikan selama persiapan operasi open.
 */
void io_open_cleanup(struct io_kiocb *req)
{
	struct io_open *open = io_kiocb_to_cmd(req, struct io_open);

	if (open->filename)
		putname(open->filename);
}

/*
 * __io_close_fixed() - Menutup file yang terpasang dalam fixed slot
 * @ctx: pointer ke konteks io-ring
 * @issue_flags: flag yang menentukan apakah operasi harus dilakukan non-blocking
 * @offset: offset dalam konteks fixed file
 *
 * Fungsi ini menutup file yang ada di dalam fixed slot, menghapusnya dari daftar file yang terpasang.
 *
 * Mengembalikan status operasi (berhasil atau gagal).
 */
int __io_close_fixed(struct io_ring_ctx *ctx, unsigned int issue_flags,
		     unsigned int offset)
{
	int ret;

	io_ring_submit_lock(ctx, issue_flags);
	ret = io_fixed_fd_remove(ctx, offset);
	io_ring_submit_unlock(ctx, issue_flags);

	return ret;
}

/*
 * io_close_fixed() - Menutup file yang terpasang pada fixed file slot
 * @req: pointer ke struktur io_kiocb yang berisi informasi I/O untuk operasi close
 * @issue_flags: flag yang menentukan apakah operasi harus dilakukan non-blocking
 *
 * Fungsi ini memanggil __io_close_fixed untuk menutup file yang ada pada fixed file slot.
 * Operasi ini digunakan ketika file yang akan ditutup terpasang pada slot file tetap.
 *
 * Mengembalikan status operasi (berhasil atau gagal).
 */
static inline int io_close_fixed(struct io_kiocb *req, unsigned int issue_flags)
{
	struct io_close *close = io_kiocb_to_cmd(req, struct io_close);

	return __io_close_fixed(req->ctx, issue_flags, close->file_slot - 1);
}

/*
 * io_close_prep() - Persiapan untuk operasi close file
 * @req: pointer ke struktur io_kiocb yang berisi informasi I/O untuk operasi close
 * @sqe: pointer ke struktur io_uring_sqe yang berisi perintah close
 *
 * Fungsi ini memeriksa parameter yang diterima dalam struktur io_uring_sqe dan memastikan
 * bahwa parameter yang diterima valid. Jika ada ketidaksesuaian, mengembalikan -EINVAL.
 * Jika file yang dimaksud berada dalam fixed file slot atau memiliki file descriptor yang
 * tidak valid, operasi ini gagal.
 *
 * Mengembalikan 0 jika berhasil, atau nilai negatif jika terjadi kesalahan.
 */
int io_close_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe)
{
	struct io_close *close = io_kiocb_to_cmd(req, struct io_close);

	/* Memeriksa apakah ada parameter yang tidak valid */
	if (sqe->off || sqe->addr || sqe->len || sqe->rw_flags || sqe->buf_index)
		return -EINVAL;
	/* Memeriksa apakah file berada dalam fixed file slot */
	if (req->flags & REQ_F_FIXED_FILE)
		return -EBADF;

	/* Membaca file descriptor dan file slot */
	close->fd = READ_ONCE(sqe->fd);
	close->file_slot = READ_ONCE(sqe->file_index);
	if (close->file_slot && close->fd)
		return -EINVAL;

	return 0;
}

/*
 * io_close() - Menutup file melalui file descriptor atau fixed file slot
 * @req: pointer ke struktur io_kiocb yang berisi informasi I/O untuk operasi close
 * @issue_flags: flag yang menentukan apakah operasi harus dilakukan non-blocking
 *
 * Fungsi ini menutup file yang terhubung dengan file descriptor atau file slot tetap.
 * Jika file descriptor berada dalam fixed file slot, maka __io_close_fixed dipanggil.
 * Jika file tidak berada di fixed file slot, file descriptor dicari dalam struktur file
 * task dan ditutup secara aman.
 *
 * Mengembalikan status operasi (berhasil atau gagal).
 */
int io_close(struct io_kiocb *req, unsigned int issue_flags)
{
	struct files_struct *files = current->files;
	struct io_close *close = io_kiocb_to_cmd(req, struct io_close);
	struct file *file;
	int ret = -EBADF;

	/* Menangani file yang terpasang pada fixed file slot */
	if (close->file_slot) {
		ret = io_close_fixed(req, issue_flags);
		goto err;
	}

	/* Mencari file descriptor dalam struktur file task */
	spin_lock(&files->file_lock);
	file = files_lookup_fd_locked(files, close->fd);
	if (!file || io_is_uring_fops(file)) {
		spin_unlock(&files->file_lock);
		goto err;
	}

	/* Jika file memiliki metode flush, lakukan secara asinkron jika non-blocking */
	if (file->f_op->flush && (issue_flags & IO_URING_F_NONBLOCK)) {
		spin_unlock(&files->file_lock);
		return -EAGAIN;
	}

	/* Menutup file descriptor yang ditemukan */
	file = file_close_fd_locked(files, close->fd);
	spin_unlock(&files->file_lock);
	if (!file)
		goto err;

	/* Menutup file jika tidak ada flush atau sudah asinkron */
	ret = filp_close(file, current->files);

err:
	if (ret < 0)
		req_set_fail(req);
	io_req_set_res(req, ret, 0);
	return IOU_OK;
}

/*
 * io_install_fixed_fd_prep() - Persiapan untuk menginstal file descriptor tetap
 * @req: pointer ke struktur io_kiocb yang berisi informasi I/O untuk operasi instalasi file descriptor tetap
 * @sqe: pointer ke struktur io_uring_sqe yang berisi perintah instalasi
 *
 * Fungsi ini memeriksa parameter dari permintaan instalasi file descriptor tetap dan memastikan
 * bahwa file descriptor yang akan dipasang adalah file tetap dan kredensial task sesuai.
 * Jika parameter tidak valid atau tidak sesuai, fungsi mengembalikan kesalahan.
 *
 * Mengembalikan 0 jika berhasil, atau nilai negatif jika terjadi kesalahan.
 */
int io_install_fixed_fd_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe)
{
	struct io_fixed_install *ifi;
	unsigned int flags;

	/* Memeriksa kesalahan pada parameter */
	if (sqe->off || sqe->addr || sqe->len || sqe->buf_index ||
	    sqe->splice_fd_in || sqe->addr3)
		return -EINVAL;

	/* Memeriksa apakah ini adalah file tetap */
	if (!(req->flags & REQ_F_FIXED_FILE))
		return -EBADF;

	/* Memeriksa dan menetapkan flag instalasi */
	flags = READ_ONCE(sqe->install_fd_flags);
	if (flags & ~IORING_FIXED_FD_NO_CLOEXEC)
		return -EINVAL;

	/* Memastikan kredensial task digunakan saat instalasi file descriptor */
	if (req->flags & REQ_F_CREDS)
		return -EPERM;

	/* Menetapkan flag O_CLOEXEC atau menonaktifkannya jika flag IORING_FIXED_FD_NO_CLOEXEC ada */
	ifi = io_kiocb_to_cmd(req, struct io_fixed_install);
	ifi->o_flags = O_CLOEXEC;
	if (flags & IORING_FIXED_FD_NO_CLOEXEC)
		ifi->o_flags = 0;

	return 0;
}

/*
 * io_install_fixed_fd() - Menginstal file descriptor tetap
 * @req: pointer ke struktur io_kiocb yang berisi informasi I/O untuk operasi instalasi
 * @issue_flags: flag yang menentukan apakah operasi harus dilakukan non-blocking
 *
 * Fungsi ini melakukan instalasi file descriptor tetap dengan menggunakan flag yang ditentukan
 * untuk memasang file descriptor ke dalam konteks task yang sesuai.
 *
 * Mengembalikan status operasi (berhasil atau gagal).
 */
int io_install_fixed_fd(struct io_kiocb *req, unsigned int issue_flags)
{
	struct io_fixed_install *ifi;
	int ret;

	/* Mendapatkan perintah instalasi file descriptor tetap */
	ifi = io_kiocb_to_cmd(req, struct io_fixed_install);
	ret = receive_fd(req->file, NULL, ifi->o_flags);
	if (ret < 0)
		req_set_fail(req);
	io_req_set_res(req, ret, 0);
	return IOU_OK;
}

