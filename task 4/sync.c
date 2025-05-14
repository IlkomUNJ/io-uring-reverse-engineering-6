// SPDX-License-Identifier: GPL-2.0
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/namei.h>
#include <linux/io_uring.h>
#include <linux/fsnotify.h>

#include <uapi/linux/io_uring.h>

#include "io_uring.h"
#include "sync.h"

/*
 * Struktur io_sync - Menyimpan parameter untuk operasi sinkronisasi file
 *
 * Struktur ini digunakan untuk menyimpan data yang dibutuhkan oleh operasi:
 * - sync_file_range
 * - fsync
 * - fallocate
 */
struct io_sync {
	struct file			*file;	// File yang ditargetkan
	loff_t				len;	// Panjang data (digunakan di sync dan fallocate)
	loff_t				off;	// Offset dari mana operasi dimulai
	int				flags;	// Flags untuk kontrol operasi (misalnya IORING_FSYNC_DATASYNC)
	int				mode;	// Mode fallocate (misalnya FALLOC_FL_KEEP_SIZE)
};

/*
 * io_sfr_prep - Menyiapkan request sync_file_range
 * @req: Request io_kiocb dari io_uring
 * @sqe: SQE (Submission Queue Entry) dari userspace
 *
 * Mengambil offset, panjang, dan flags untuk operasi sync_file_range.
 * Operasi ini memerlukan konteks blocking, sehingga REQ_F_FORCE_ASYNC diatur.
 *
 * Return: 0 jika berhasil, -EINVAL jika parameter tidak valid.
 */
int io_sfr_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe)
{
	struct io_sync *sync = io_kiocb_to_cmd(req, struct io_sync);

	if (unlikely(sqe->addr || sqe->buf_index || sqe->splice_fd_in))
		return -EINVAL;

	sync->off = READ_ONCE(sqe->off);
	sync->len = READ_ONCE(sqe->len);
	sync->flags = READ_ONCE(sqe->sync_range_flags);
	req->flags |= REQ_F_FORCE_ASYNC;

	return 0;
}

/*
 * io_sync_file_range - Menjalankan sync_file_range pada file
 * @req: Request io_kiocb yang telah disiapkan
 * @issue_flags: Flags issue dari io_uring
 *
 * Memanggil syscall sync_file_range untuk mensinkronkan bagian tertentu dari file
 * ke media penyimpanan.
 *
 * Return: IOU_OK setelah hasil disimpan dalam request.
 */
int io_sync_file_range(struct io_kiocb *req, unsigned int issue_flags)
{
	struct io_sync *sync = io_kiocb_to_cmd(req, struct io_sync);
	int ret;

	WARN_ON_ONCE(issue_flags & IO_URING_F_NONBLOCK);

	ret = sync_file_range(req->file, sync->off, sync->len, sync->flags);
	io_req_set_res(req, ret, 0);
	return IOU_OK;
}

/*
 * io_fsync_prep - Menyiapkan request fsync
 * @req: Request io_kiocb dari io_uring
 * @sqe: Submission Queue Entry
 *
 * Mengatur flags fsync dan parameter offset/panjang. Validasi dilakukan untuk
 * memastikan flags yang digunakan valid.
 *
 * Return: 0 jika berhasil, -EINVAL jika invalid.
 */
int io_fsync_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe)
{
	struct io_sync *sync = io_kiocb_to_cmd(req, struct io_sync);

	if (unlikely(sqe->addr || sqe->buf_index || sqe->splice_fd_in))
		return -EINVAL;

	sync->flags = READ_ONCE(sqe->fsync_flags);
	if (unlikely(sync->flags & ~IORING_FSYNC_DATASYNC))
		return -EINVAL;

	sync->off = READ_ONCE(sqe->off);
	sync->len = READ_ONCE(sqe->len);
	req->flags |= REQ_F_FORCE_ASYNC;
	return 0;
}

/*
 * io_fsync - Menjalankan operasi fsync (atau datasync) pada file
 * @req: Request io_kiocb
 * @issue_flags: Flags issue dari io_uring
 *
 * Melakukan sinkronisasi file ke disk, menggunakan vfs_fsync_range().
 * Jika offset dan len disediakan, hanya rentang tersebut yang disinkronkan.
 *
 * Return: IOU_OK setelah hasil disimpan dalam request.
 */
int io_fsync(struct io_kiocb *req, unsigned int issue_flags)
{
	struct io_sync *sync = io_kiocb_to_cmd(req, struct io_sync);
	loff_t end = sync->off + sync->len;
	int ret;

	WARN_ON_ONCE(issue_flags & IO_URING_F_NONBLOCK);

	ret = vfs_fsync_range(req->file, sync->off,
			      end > 0 ? end : LLONG_MAX,
			      sync->flags & IORING_FSYNC_DATASYNC);
	io_req_set_res(req, ret, 0);
	return IOU_OK;
}

/*
 * io_fallocate_prep - Menyiapkan request fallocate
 * @req: Request io_kiocb dari io_uring
 * @sqe: Submission Queue Entry
 *
 * Mengatur parameter offset, panjang, dan mode untuk operasi fallocate.
 * Fallocate digunakan untuk mengalokasikan ruang di file.
 *
 * Return: 0 jika berhasil, -EINVAL jika parameter tidak valid.
 */
int io_fallocate_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe)
{
	struct io_sync *sync = io_kiocb_to_cmd(req, struct io_sync);

	if (sqe->buf_index || sqe->rw_flags || sqe->splice_fd_in)
		return -EINVAL;

	sync->off = READ_ONCE(sqe->off);
	sync->len = READ_ONCE(sqe->addr);
	sync->mode = READ_ONCE(sqe->len);
	req->flags |= REQ_F_FORCE_ASYNC;
	return 0;
}

/*
 * io_fallocate - Menjalankan fallocate pada file
 * @req: Request io_kiocb
 * @issue_flags: Flags issue dari io_uring
 *
 * Memanggil vfs_fallocate() untuk mengalokasikan ruang pada file sesuai offset,
 * panjang, dan mode. Jika berhasil, akan memicu notifikasi modify untuk inotify.
 *
 * Return: IOU_OK setelah hasil disimpan dalam request.
 */
int io_fallocate(struct io_kiocb *req, unsigned int issue_flags)
{
	struct io_sync *sync = io_kiocb_to_cmd(req, struct io_sync);
	int ret;

	WARN_ON_ONCE(issue_flags & IO_URING_F_NONBLOCK);

	ret = vfs_fallocate(req->file, sync->mode, sync->off, sync->len);
	if (ret >= 0)
		fsnotify_modify(req->file);
	io_req_set_res(req, ret, 0);
	return IOU_OK;
}

