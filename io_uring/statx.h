// SPDX-License-Identifier: GPL-2.0

// Fungsi untuk mempersiapkan operasi `statx` pada I/O ring.
int io_statx_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);

// Fungsi untuk melakukan operasi `statx`, yang memungkinkan untuk mendapatkan informasi status file secara efisien.
int io_statx(struct io_kiocb *req, unsigned int issue_flags);

// Fungsi untuk membersihkan sumber daya setelah operasi `statx` selesai.
void io_statx_cleanup(struct io_kiocb *req);

