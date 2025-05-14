// SPDX-License-Identifier: GPL-2.0
#ifndef IORING_CANCEL_H
#define IORING_CANCEL_H

#include <linux/io_uring_types.h>

/*
 * Struktur untuk menyimpan informasi pembatalan I/O.
 * Menyimpan konteks ring I/O, data pembatalan, opcode, flag, dan sequence cancel.
 */
struct io_cancel_data {
	struct io_ring_ctx *ctx;	// Konteks untuk ring I/O
	union {
		u64 data;		// Data yang dibatalkan
		struct file *file;	// File terkait pembatalan
	};
	u8 opcode;		// Opcode untuk operasi I/O
	u32 flags;		// Flag pembatalan (misalnya, apakah membatalkan berdasarkan file, opcode, dll.)
	int seq;		// Sequence number untuk pembatalan
};

/*
 * Menyiapkan pembatalan permintaan asinkron berdasarkan Submission Queue Entry (SQE).
 * Mengisi struktur pembatalan dan memeriksa kevalidan flags.
 * Return 0 jika sukses, -EINVAL jika ada kesalahan pada SQE.
 */
int io_async_cancel_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);

/*
 * Melakukan pembatalan asinkron terhadap permintaan I/O yang sesuai dengan kriteria
 * dalam `req->cmd`. Menetapkan hasil ke dalam `req` dan mengembalikan status IOU_OK.
 */
int io_async_cancel(struct io_kiocb *req, unsigned int issue_flags);

/*
 * Mencoba membatalkan permintaan berdasarkan data pembatalan yang ada di `cd`.
 * Berbeda untuk pembatalan kerja async, poll, waitid, futex, atau timeout.
 * Mengembalikan 0 jika berhasil, atau kode error jika tidak ditemukan.
 */
int io_try_cancel(struct io_uring_task *tctx, struct io_cancel_data *cd,
		  unsigned int issue_flags);

/*
 * Menangani pembatalan sinkron dari ruang pengguna.
 * Memproses `io_uring_sync_cancel_reg` dan menunggu hasil pembatalan atau timeout.
 * Mengembalikan 0 jika berhasil membatalkan request, atau error jika gagal.
 */
int io_sync_cancel(struct io_ring_ctx *ctx, void __user *arg);

/*
 * Memeriksa apakah permintaan I/O (`req`) cocok dengan kriteria pembatalan (`cd`).
 * Memeriksa apakah file, opcode, data pengguna, atau sequence yang cocok untuk pembatalan.
 * Mengembalikan true jika cocok, false jika tidak.
 */
bool io_cancel_req_match(struct io_kiocb *req, struct io_cancel_data *cd);

/*
 * Menghapus semua permintaan I/O yang cocok dengan kriteria dari list hash `list`
 * menggunakan callback `cancel`. Digunakan untuk pembatalan menyeluruh.
 * Mengembalikan true jika ada permintaan yang dibatalkan, atau false jika tidak ada.
 */
bool io_cancel_remove_all(struct io_ring_ctx *ctx, struct io_uring_task *tctx,
			  struct hlist_head *list, bool cancel_all,
			  bool (*cancel)(struct io_kiocb *));

/*
 * Mencoba membatalkan permintaan dalam list `list` yang sesuai dengan kriteria pembatalan
 * yang diberikan dalam `cd`. Bisa membatalkan satu atau beberapa permintaan tergantung flag
 * `IORING_ASYNC_CANCEL_ALL`.
 * Mengembalikan jumlah request yang dibatalkan atau -ENOENT jika tidak ada yang dibatalkan.
 */
int io_cancel_remove(struct io_ring_ctx *ctx, struct io_cancel_data *cd,
		     unsigned int issue_flags, struct hlist_head *list,
		     bool (*cancel)(struct io_kiocb *));

/*
 * Membandingkan sequence cancel permintaan I/O dengan sequence yang diberikan.
 * Jika sequence sudah diset, akan memeriksa apakah cocok. Jika cocok, return true.
 * Jika belum diset, akan menyet sequence dan return false.
 */
static inline bool io_cancel_match_sequence(struct io_kiocb *req, int sequence);
{
	if (req->cancel_seq_set && sequence == req->work.cancel_seq)
		return true;

	req->cancel_seq_set = true;
	req->work.cancel_seq = sequence;
	return false;
}

#endif
