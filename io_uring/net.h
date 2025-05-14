// SPDX-License-Identifier: GPL-2.0

#include <linux/net.h>
#include <linux/uio.h>
#include <linux/io_uring_types.h>

struct io_async_msghdr {
#if defined(CONFIG_NET)
	struct iou_vec				vec;

	struct_group(clear,
		int				namelen;
		struct iovec			fast_iov;
		__kernel_size_t			controllen;
		__kernel_size_t			payloadlen;
		struct sockaddr __user		*uaddr;
		struct msghdr			msg;
		struct sockaddr_storage		addr;
	);
#else
	struct_group(clear);
#endif
};

#if defined(CONFIG_NET)

/* Mempersiapkan operasi shutdown socket dari SQE. */
int io_shutdown_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);

/* Menjalankan syscall shutdown untuk socket. */
int io_shutdown(struct io_kiocb *req, unsigned int issue_flags);

/* Membersihkan sumber daya temporer untuk operasi sendmsg dan recvmsg. */
void io_sendmsg_recvmsg_cleanup(struct io_kiocb *req);

/* Mempersiapkan struktur data untuk operasi sendmsg. */
int io_sendmsg_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);

/* Menjalankan syscall sendmsg untuk mengirim pesan melalui socket. */
int io_sendmsg(struct io_kiocb *req, unsigned int issue_flags);

/* Menjalankan syscall send untuk mengirim data melalui socket. */
int io_send(struct io_kiocb *req, unsigned int issue_flags);

/* Mempersiapkan struktur data untuk operasi recvmsg. */
int io_recvmsg_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);

/* Menjalankan syscall recvmsg untuk menerima pesan dari socket. */
int io_recvmsg(struct io_kiocb *req, unsigned int issue_flags);

/* Menjalankan syscall recv untuk menerima data dari socket. */
int io_recv(struct io_kiocb *req, unsigned int issue_flags);

/* Menandai kegagalan untuk operasi send atau recv. */
void io_sendrecv_fail(struct io_kiocb *req);

/* Mempersiapkan operasi accept() dari SQE. */
int io_accept_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);

/* Menjalankan syscall accept untuk menerima koneksi masuk. */
int io_accept(struct io_kiocb *req, unsigned int issue_flags);

/* Mempersiapkan operasi pembuatan socket dari SQE. */
int io_socket_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);

/* Menjalankan syscall socket untuk membuat socket baru. */
int io_socket(struct io_kiocb *req, unsigned int issue_flags);

/* Mempersiapkan operasi connect dari SQE. */
int io_connect_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);

/* Menjalankan syscall connect untuk menyambungkan socket ke server. */
int io_connect(struct io_kiocb *req, unsigned int issue_flags);

/* Menjalankan pengiriman data dengan zero-copy. */
int io_send_zc(struct io_kiocb *req, unsigned int issue_flags);

/* Menjalankan pengiriman pesan berbasis sendmsg dengan zero-copy. */
int io_sendmsg_zc(struct io_kiocb *req, unsigned int issue_flags);

/* Mempersiapkan operasi send zero-copy dari SQE. */
int io_send_zc_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);

/* Membersihkan sumber daya dari operasi send zero-copy. */
void io_send_zc_cleanup(struct io_kiocb *req);

/* Mempersiapkan operasi bind dari SQE. */
int io_bind_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);

/* Menjalankan syscall bind untuk mengikat socket ke alamat tertentu. */
int io_bind(struct io_kiocb *req, unsigned int issue_flags);

/* Mempersiapkan operasi listen dari SQE. */
int io_listen_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);

/* Menjalankan syscall listen untuk mulai mendengarkan koneksi masuk. */
int io_listen(struct io_kiocb *req, unsigned int issue_flags);

/* Fungsi pembersihan entri cache pesan jaringan. */
void io_netmsg_cache_free(const void *entry);
#else
/* Dummy jika CONFIG_NET tidak didefinisikan. */
static inline void io_netmsg_cache_free(const void *entry)
{
}
#endif

