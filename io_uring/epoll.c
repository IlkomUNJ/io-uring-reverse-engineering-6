// SPDX-License-Identifier: GPL-2.0
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/io_uring.h>
#include <linux/eventpoll.h>

#include <uapi/linux/io_uring.h>

#include "io_uring.h"
#include "epoll.h"

// Struktur untuk operasi epoll, berisi informasi tentang file, epfd, fd, dan event yang terkait
struct io_epoll {
	struct file			*file;
	int				epfd;
	int				op;
	int				fd;
	struct epoll_event		event;
};

// Struktur untuk operasi epoll wait, berisi informasi tentang file, maxevents, dan pointer ke events user-space
struct io_epoll_wait {
	struct file			*file;
	int				maxevents;
	struct epoll_event __user	*events;
};

// Menyiapkan struktur io_epoll untuk operasi epoll_ctl sesuai dengan informasi yang diberikan dalam SQE (Submission Queue Entry)
int io_epoll_ctl_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe)
{
	struct io_epoll *epoll = io_kiocb_to_cmd(req, struct io_epoll);

	// Memastikan bahwa parameter lainnya yang tidak relevan tidak diisi
	if (sqe->buf_index || sqe->splice_fd_in)
		return -EINVAL;

	// Membaca dan menyimpan nilai epfd, operasi, dan file descriptor dari SQE
	epoll->epfd = READ_ONCE(sqe->fd);
	epoll->op = READ_ONCE(sqe->len);
	epoll->fd = READ_ONCE(sqe->off);

	// Jika operasi epoll membutuhkan event, salin event dari user space
	if (ep_op_has_event(epoll->op)) {
		struct epoll_event __user *ev;

		ev = u64_to_user_ptr(READ_ONCE(sqe->addr));
		if (copy_from_user(&epoll->event, ev, sizeof(*ev)))
			return -EFAULT;
	}

	return 0;
}

/**
 * Melakukan operasi epoll_ctl berdasarkan informasi yang ada pada struktur io_epoll.
 * Operasi ini dilakukan dalam mode non-blocking jika diberi flag IO_URING_F_NONBLOCK.
 */
int io_epoll_ctl(struct io_kiocb *req, unsigned int issue_flags)
{
	struct io_epoll *ie = io_kiocb_to_cmd(req, struct io_epoll);
	int ret;
	bool force_nonblock = issue_flags & IO_URING_F_NONBLOCK;

	// Melakukan epoll_ctl dan menangani hasilnya jika dalam mode non-blocking
	ret = do_epoll_ctl(ie->epfd, ie->op, ie->fd, &ie->event, force_nonblock);
	if (force_nonblock && ret == -EAGAIN)
		return -EAGAIN;

	if (ret < 0)
		req_set_fail(req);  // Menandakan permintaan gagal jika return negatif
	io_req_set_res(req, ret, 0);  // Set hasil untuk permintaan
	return IOU_OK;
}

// Menyiapkan struktur io_epoll_wait untuk operasi epoll_wait berdasarkan informasi dalam SQE
int io_epoll_wait_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe)
{
	struct io_epoll_wait *iew = io_kiocb_to_cmd(req, struct io_epoll_wait);

	// Memastikan bahwa parameter lainnya yang tidak relevan tidak diisi
	if (sqe->off || sqe->rw_flags || sqe->buf_index || sqe->splice_fd_in)
		return -EINVAL;

	// Membaca jumlah event maksimal yang dapat diterima dan pointer ke events di user space
	iew->maxevents = READ_ONCE(sqe->len);
	iew->events = u64_to_user_ptr(READ_ONCE(sqe->addr));
	return 0;
}

/**
 * Melakukan epoll_wait berdasarkan informasi yang ada pada struktur io_epoll_wait.
 * Mengambil event dari file yang sudah di-synchronize dan mengembalikan hasilnya.
 */
int io_epoll_wait(struct io_kiocb *req, unsigned int issue_flags)
{
	struct io_epoll_wait *iew = io_kiocb_to_cmd(req, struct io_epoll_wait);
	int ret;

	// Mengirim event ke user space melalui epoll_sendevents
	ret = epoll_sendevents(req->file, iew->events, iew->maxevents);
	if (ret == 0)
		return -EAGAIN;  // Jika tidak ada event, return EAGAIN untuk non-blocking
	if (ret < 0)
		req_set_fail(req);  // Menandakan permintaan gagal jika return negatif

	io_req_set_res(req, ret, 0);  // Set hasil untuk permintaan
	return IOU_OK;
}

