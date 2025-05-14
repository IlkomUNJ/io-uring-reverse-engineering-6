// SPDX-License-Identifier: GPL-2.0

// Fungsi untuk mempersiapkan operasi `sync_file_range` pada I/O ring.
int io_sfr_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);

// Fungsi untuk melakukan operasi `sync_file_range` pada file, yang melakukan sinkronisasi bagian dari file ke storage.
int io_sync_file_range(struct io_kiocb *req, unsigned int issue_flags);

// Fungsi untuk mempersiapkan operasi `fsync` pada I/O ring.
int io_fsync_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);

// Fungsi untuk melakukan operasi `fsync` pada file untuk memastikan data yang dimodifikasi disinkronkan ke disk.
int io_fsync(struct io_kiocb *req, unsigned int issue_flags);

// Fungsi untuk melakukan alokasi ruang pada file (seperti pengalokasian ruang disk).
int io_fallocate(struct io_kiocb *req, unsigned int issue_flags);

// Fungsi untuk mempersiapkan operasi `fallocate` pada I/O ring.
int io_fallocate_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);

