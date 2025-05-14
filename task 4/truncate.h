// SPDX-License-Identifier: GPL-2.0

// Fungsi untuk mempersiapkan operasi pemangkasan file (truncate) menggunakan io_uring.
// Fungsi ini mempersiapkan data yang diperlukan dalam permintaan I/O sebelum operasi dilakukan.
int io_ftruncate_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);

// Fungsi untuk melakukan operasi pemangkasan file (truncate) secara nyata menggunakan io_uring.
// Fungsi ini mengirimkan permintaan untuk memotong ukuran file yang ditunjuk oleh `req`.
int io_ftruncate(struct io_kiocb *req, unsigned int issue_flags);

