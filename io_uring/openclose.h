// SPDX-License-Identifier: GPL-2.0

// Fungsi untuk menutup file descriptor yang telah dipersiapkan sebelumnya
int __io_close_fixed(struct io_ring_ctx *ctx, unsigned int issue_flags,
		     unsigned int offset);

// Fungsi untuk menyiapkan permintaan openat
int io_openat_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);

// Fungsi untuk membuka file dengan openat
int io_openat(struct io_kiocb *req, unsigned int issue_flags);

// Fungsi untuk membersihkan setelah operasi openat selesai
void io_open_cleanup(struct io_kiocb *req);

// Fungsi untuk menyiapkan permintaan openat2
int io_openat2_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);

// Fungsi untuk membuka file dengan openat2
int io_openat2(struct io_kiocb *req, unsigned int issue_flags);

// Fungsi untuk menyiapkan permintaan close
int io_close_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);

// Fungsi untuk menutup file descriptor
int io_close(struct io_kiocb *req, unsigned int issue_flags);

// Fungsi untuk menyiapkan permintaan untuk menginstal file descriptor tetap (fixed fd)
int io_install_fixed_fd_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);

// Fungsi untuk menginstal file descriptor tetap (fixed fd)
int io_install_fixed_fd(struct io_kiocb *req, unsigned int issue_flags);

