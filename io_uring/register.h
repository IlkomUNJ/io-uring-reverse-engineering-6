// SPDX-License-Identifier: GPL-2.0
#ifndef IORING_REGISTER_H
#define IORING_REGISTER_H

// Fungsi untuk membatalkan pendaftaran eventfd di dalam konteks io_uring.
int io_eventfd_unregister(struct io_ring_ctx *ctx);

// Fungsi untuk membatalkan pendaftaran personalitas tertentu dalam konteks io_uring berdasarkan id.
int io_unregister_personality(struct io_ring_ctx *ctx, unsigned id);

// Fungsi untuk mendapatkan file yang terdaftar dalam io_uring berdasarkan deskriptor file.
struct file *io_uring_register_get_file(unsigned int fd, bool registered);

#endif

