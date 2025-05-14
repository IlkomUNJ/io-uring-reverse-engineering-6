// SPDX-License-Identifier: GPL-2.0
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/namei.h>
#include <linux/io_uring.h>

#include <uapi/linux/fadvise.h>
#include <uapi/linux/io_uring.h>

#include "io_uring.h"
#include "advise.h"

struct io_fadvise {
	struct file			*file;
	u64				offset;
	u64				len;
	u32				advice;
};

struct io_madvise {
	struct file			*file;
	u64				addr;
	u64				len;
	u32				advice;
};

/*
 * Menyiapkan operasi madvise untuk io_uring.
 * Fungsi ini membaca parameter dari SQE dan mengisi struktur io_madvise,
 * yang digunakan untuk memberikan saran ke pengelola memori sistem.
 * Operasi ini dipaksa untuk dieksekusi secara asynchronous.
 * Jika sistem tidak mendukung syscall advise dan MMU, operasi akan gagal.
 */
int io_madvise_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe)
{
#if defined(CONFIG_ADVISE_SYSCALLS) && defined(CONFIG_MMU)
	struct io_madvise *ma = io_kiocb_to_cmd(req, struct io_madvise);

	if (sqe->buf_index || sqe->splice_fd_in)
		return -EINVAL;

	ma->addr = READ_ONCE(sqe->addr);
	ma->len = READ_ONCE(sqe->off);
	if (!ma->len)
		ma->len = READ_ONCE(sqe->len);
	ma->advice = READ_ONCE(sqe->fadvise_advice);
	req->flags |= REQ_F_FORCE_ASYNC;
	return 0;
#else
	return -EOPNOTSUPP;
#endif
}

/*
 * Menjalankan syscall madvise untuk io_uring.
 * Fungsi ini memberikan saran manajemen memori untuk alamat dan panjang tertentu,
 * menggunakan fungsi do_madvise. Hasilnya disimpan dalam request dan diteruskan
 * sebagai hasil ke pengguna.
 */
int io_madvise(struct io_kiocb *req, unsigned int issue_flags)
{
#if defined(CONFIG_ADVISE_SYSCALLS) && defined(CONFIG_MMU)
	struct io_madvise *ma = io_kiocb_to_cmd(req, struct io_madvise);
	int ret;

	WARN_ON_ONCE(issue_flags & IO_URING_F_NONBLOCK);

	ret = do_madvise(current->mm, ma->addr, ma->len, ma->advice);
	io_req_set_res(req, ret, 0);
	return IOU_OK;
#else
	return -EOPNOTSUPP;
#endif
}

/*
 * Menentukan apakah tipe saran fadvise memerlukan eksekusi secara asynchronous.
 * Untuk saran NORMAL, RANDOM, dan SEQUENTIAL, operasi bisa berjalan sinkron.
 * Saran lain seperti DONTNEED dan WILLNEED dipaksa async karena sifatnya blocking.
 */
static bool io_fadvise_force_async(struct io_fadvise *fa)
{
	switch (fa->advice) {
	case POSIX_FADV_NORMAL:
	case POSIX_FADV_RANDOM:
	case POSIX_FADV_SEQUENTIAL:
		return false;
	default:
		return true;
	}
}

/*
 * Menyiapkan operasi fadvise untuk io_uring.
 * Membaca parameter dari SQE (offset, panjang, dan jenis saran) dan menyimpannya
 * dalam struktur io_fadvise. Menentukan apakah operasi perlu dipaksa async.
 */
int io_fadvise_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe)
{
	struct io_fadvise *fa = io_kiocb_to_cmd(req, struct io_fadvise);

	if (sqe->buf_index || sqe->splice_fd_in)
		return -EINVAL;

	fa->offset = READ_ONCE(sqe->off);
	fa->len = READ_ONCE(sqe->addr);
	if (!fa->len)
		fa->len = READ_ONCE(sqe->len);
	fa->advice = READ_ONCE(sqe->fadvise_advice);
	if (io_fadvise_force_async(fa))
		req->flags |= REQ_F_FORCE_ASYNC;
	return 0;
}

/*
 * Menjalankan operasi fadvise menggunakan fungsi vfs_fadvise.
 * Fungsi ini memberikan saran pengaksesan file berdasarkan offset dan panjang tertentu,
 * yang akan digunakan oleh kernel untuk optimasi cache dan IO.
 * Hasil operasi dicatat dalam request dan dikembalikan ke pengguna.
 */
int io_fadvise(struct io_kiocb *req, unsigned int issue_flags)
{
	struct io_fadvise *fa = io_kiocb_to_cmd(req, struct io_fadvise);
	int ret;

	WARN_ON_ONCE(issue_flags & IO_URING_F_NONBLOCK && io_fadvise_force_async(fa));

	ret = vfs_fadvise(req->file, fa->offset, fa->len, fa->advice);
	if (ret < 0)
		req_set_fail(req);
	io_req_set_res(req, ret, 0);
	return IOU_OK;
}

