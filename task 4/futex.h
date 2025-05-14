// SPDX-License-Identifier: GPL-2.0

#include "cancel.h"

// Mempersiapkan permintaan futex untuk operasi tertentu
// Fungsi ini akan dipanggil saat persiapan awal untuk operasi futex dimulai
int io_futex_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);

// Mempersiapkan permintaan futex vector untuk operasi tertentu
// Fungsi ini akan dipanggil saat persiapan awal untuk operasi futex vector dimulai
int io_futexv_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);

// Menunggu futex untuk diproses, biasanya digunakan untuk operasi tunggu pada futex
// Fungsi ini akan dipanggil untuk memblokir eksekusi hingga kondisi tertentu terpenuhi pada futex
int io_futex_wait(struct io_kiocb *req, unsigned int issue_flags);

// Menunggu futex vector untuk diproses, biasanya digunakan untuk operasi tunggu pada beberapa futex sekaligus
// Fungsi ini akan dipanggil untuk memblokir eksekusi hingga kondisi tertentu terpenuhi pada futex vector
int io_futexv_wait(struct io_kiocb *req, unsigned int issue_flags);

// Membangunkan satu futex yang sedang menunggu, untuk melanjutkan eksekusi
// Fungsi ini digunakan untuk membangunkan satu futex yang sebelumnya dalam keadaan tunggu
int io_futex_wake(struct io_kiocb *req, unsigned int issue_flags);

#if defined(CONFIG_FUTEX)

// Fungsi untuk membatalkan permintaan futex yang telah dimulai
// Fungsi ini akan dipanggil untuk membatalkan permintaan futex jika terjadi kesalahan atau pembatalan
int io_futex_cancel(struct io_ring_ctx *ctx, struct io_cancel_data *cd,
		    unsigned int issue_flags);

// Fungsi untuk menghapus semua futex yang terkait dengan task tertentu
// Fungsi ini digunakan untuk membersihkan semua permintaan futex yang ada dalam konteks
bool io_futex_remove_all(struct io_ring_ctx *ctx, struct io_uring_task *tctx,
			 bool cancel_all);

// Menginisialisasi cache untuk futex dalam konteks IO ring
// Fungsi ini dipanggil untuk mengalokasikan cache yang digunakan untuk operasi futex
bool io_futex_cache_init(struct io_ring_ctx *ctx);

// Membebaskan cache yang digunakan untuk futex dalam konteks IO ring
// Fungsi ini dipanggil untuk membersihkan cache setelah operasi futex selesai
void io_futex_cache_free(struct io_ring_ctx *ctx);

#else

// Definisi inline kosong jika CONFIG_FUTEX tidak diaktifkan
// Fungsi-fungsi berikut tidak akan dipanggil jika fitur futex tidak diaktifkan dalam kernel
static inline int io_futex_cancel(struct io_ring_ctx *ctx,
				  struct io_cancel_data *cd,
				  unsigned int issue_flags)
{
	return 0;
}

// Fungsi ini tidak akan melakukan apa-apa jika fitur futex tidak diaktifkan
static inline bool io_futex_remove_all(struct io_ring_ctx *ctx,
				       struct io_uring_task *tctx, bool cancel_all)
{
	return false;
}

// Fungsi ini tidak akan melakukan apa-apa jika fitur futex tidak diaktifkan
static inline bool io_futex_cache_init(struct io_ring_ctx *ctx)
{
	return false;
}

// Fungsi ini tidak akan melakukan apa-apa jika fitur futex tidak diaktifkan
static inline void io_futex_cache_free(struct io_ring_ctx *ctx)
{
}
#endif

