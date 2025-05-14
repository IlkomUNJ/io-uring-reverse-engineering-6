// SPDX-License-Identifier: GPL-2.0

// Memastikan bahwa kode hanya disertakan jika CONFIG_EPOLL diaktifkan
#if defined(CONFIG_EPOLL)

// Prototipe fungsi untuk persiapan operasi epoll_ctl, yang akan dipanggil oleh io_uring
// Menyiapkan perintah epoll_ctl berdasarkan informasi dalam SQE (Submission Queue Entry)
int io_epoll_ctl_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);

// Prototipe fungsi untuk melaksanakan operasi epoll_ctl yang telah dipersiapkan
// Fungsi ini akan memproses perintah epoll_ctl dalam mode blocking atau non-blocking
int io_epoll_ctl(struct io_kiocb *req, unsigned int issue_flags);

// Prototipe fungsi untuk persiapan operasi epoll_wait, yang akan dipanggil oleh io_uring
// Menyiapkan perintah epoll_wait berdasarkan informasi dalam SQE (Submission Queue Entry)
int io_epoll_wait_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);

// Prototipe fungsi untuk melaksanakan operasi epoll_wait yang telah dipersiapkan
// Fungsi ini akan memproses perintah epoll_wait dan mengirim event yang ditemukan kembali ke user space
int io_epoll_wait(struct io_kiocb *req, unsigned int issue_flags);

#endif // CONFIG_EPOLL

