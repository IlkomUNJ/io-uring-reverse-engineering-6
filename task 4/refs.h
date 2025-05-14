#ifndef IOU_REQ_REF_H
#define IOU_REQ_REF_H

#include <linux/atomic.h>
#include <linux/io_uring_types.h>

/*
 * Implementasi pengelolaan referensi untuk permintaan I/O (io_kiocb) menggunakan
 * atomic operations. Teknik ini diambil dari implementasi referensi halaman pada
 * manajemen memori di Linux (commit f958d7b528b1). Tujuannya adalah untuk mengelola
 * referensi pada objek I/O secara thread-safe, dengan memastikan bahwa referensi yang
 * dihitung tidak menyebabkan overflow atau kesalahan lainnya.
 */

// Makro untuk memeriksa apakah nilai referensi mendekati overflow atau sudah nol
#define req_ref_zero_or_close_to_overflow(req)	\
	((unsigned int) atomic_read(&(req->refs)) + 127u <= 127u)

// Fungsi untuk meningkatkan referensi permintaan I/O jika masih ada referensi yang tersisa
static inline bool req_ref_inc_not_zero(struct io_kiocb *req)
{
	WARN_ON_ONCE(!(req->flags & REQ_F_REFCOUNT));  // Memastikan bahwa permintaan memiliki referensi
	return atomic_inc_not_zero(&req->refs);  // Meningkatkan referensi hanya jika lebih dari nol
}

// Fungsi untuk menurunkan referensi permintaan I/O dan memeriksa apakah referensi mencapai nol
static inline bool req_ref_put_and_test_atomic(struct io_kiocb *req)
{
	WARN_ON_ONCE(!(data_race(req->flags) & REQ_F_REFCOUNT));  // Memastikan permintaan memiliki referensi
	WARN_ON_ONCE(req_ref_zero_or_close_to_overflow(req));  // Memastikan referensi tidak mendekati overflow
	return atomic_dec_and_test(&req->refs);  // Menurunkan referensi dan memeriksa apakah sudah nol
}

// Fungsi untuk menurunkan referensi permintaan I/O dan memeriksa apakah referensi mencapai nol
static inline bool req_ref_put_and_test(struct io_kiocb *req)
{
	if (likely(!(req->flags & REQ_F_REFCOUNT)))  // Jika tidak menggunakan referensi
		return true;  // Langsung kembali true karena tidak ada referensi

	WARN_ON_ONCE(req_ref_zero_or_close_to_overflow(req));  // Memastikan referensi tidak mendekati overflow
	return atomic_dec_and_test(&req->refs);  // Menurunkan referensi dan memeriksa apakah sudah nol
}

// Fungsi untuk mendapatkan referensi permintaan I/O
static inline void req_ref_get(struct io_kiocb *req)
{
	WARN_ON_ONCE(!(req->flags & REQ_F_REFCOUNT));  // Memastikan bahwa permintaan memiliki referensi
	WARN_ON_ONCE(req_ref_zero_or_close_to_overflow(req));  // Memastikan referensi tidak mendekati overflow
	atomic_inc(&req->refs);  // Meningkatkan referensi
}

// Fungsi untuk mengurangi referensi permintaan I/O
static inline void req_ref_put(struct io_kiocb *req)
{
	WARN_ON_ONCE(!(req->flags & REQ_F_REFCOUNT));  // Memastikan permintaan memiliki referensi
	WARN_ON_ONCE(req_ref_zero_or_close_to_overflow(req));  // Memastikan referensi tidak mendekati overflow
	atomic_dec(&req->refs);  // Menurunkan referensi
}

// Fungsi untuk mengatur jumlah referensi permintaan I/O
static inline void __io_req_set_refcount(struct io_kiocb *req, int nr)
{
	if (!(req->flags & REQ_F_REFCOUNT)) {  // Jika permintaan belum memiliki referensi
		req->flags |= REQ_F_REFCOUNT;  // Menandai bahwa permintaan memiliki referensi
		atomic_set(&req->refs, nr);  // Menetapkan jumlah referensi awal
	}
}

// Fungsi untuk mengatur jumlah referensi permintaan I/O menjadi 1
static inline void io_req_set_refcount(struct io_kiocb *req)
{
	__io_req_set_refcount(req, 1);  // Set jumlah referensi menjadi 1
}

#endif

