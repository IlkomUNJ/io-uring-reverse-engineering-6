// SPDX-License-Identifier: GPL-2.0

#include <linux/io_uring_types.h>
#include <linux/pagemap.h>

// Struktur untuk menyimpan state metadata
struct io_meta_state {
	u32			seed;          // Seed untuk operasi
	struct iov_iter_state	iter_meta;    // Metadata untuk iterasi I/O
};

// Struktur untuk operasi I/O asinkron (read/write)
struct io_async_rw {
	struct iou_vec			vec;          // Vector I/O
	size_t				bytes_done;   // Jumlah byte yang telah selesai diproses

	// Grup untuk membersihkan struktur
	struct_group(clear,
		struct iov_iter			iter;          // Iterator untuk operasi I/O
		struct iov_iter_state		iter_state;    // State iterator
		struct iovec			fast_iov;      // Iovec cepat
		/*
		 * wpq digunakan untuk buffered I/O, sedangkan meta fields digunakan untuk direct I/O
		 */
		union {
			struct wait_page_queue		wpq;        // Queue untuk buffered I/O
			struct {
				struct uio_meta			meta;       // Metadata untuk I/O
				struct io_meta_state		meta_state; // State metadata
			};
		};
	);
};

// Fungsi untuk mempersiapkan operasi read dengan fixed buffer
int io_prep_read_fixed(struct io_kiocb *req, const struct io_uring_sqe *sqe);

// Fungsi untuk mempersiapkan operasi write dengan fixed buffer
int io_prep_write_fixed(struct io_kiocb *req, const struct io_uring_sqe *sqe);

// Fungsi untuk mempersiapkan operasi readv dengan fixed buffer
int io_prep_readv_fixed(struct io_kiocb *req, const struct io_uring_sqe *sqe);

// Fungsi untuk mempersiapkan operasi writev dengan fixed buffer
int io_prep_writev_fixed(struct io_kiocb *req, const struct io_uring_sqe *sqe);

// Fungsi untuk mempersiapkan operasi readv
int io_prep_readv(struct io_kiocb *req, const struct io_uring_sqe *sqe);

// Fungsi untuk mempersiapkan operasi writev
int io_prep_writev(struct io_kiocb *req, const struct io_uring_sqe *sqe);

// Fungsi untuk mempersiapkan operasi read
int io_prep_read(struct io_kiocb *req, const struct io_uring_sqe *sqe);

// Fungsi untuk mempersiapkan operasi write
int io_prep_write(struct io_kiocb *req, const struct io_uring_sqe *sqe);

// Fungsi untuk melakukan operasi read
int io_read(struct io_kiocb *req, unsigned int issue_flags);

// Fungsi untuk melakukan operasi write
int io_write(struct io_kiocb *req, unsigned int issue_flags);

// Fungsi untuk melakukan operasi read dengan fixed buffer
int io_read_fixed(struct io_kiocb *req, unsigned int issue_flags);

// Fungsi untuk melakukan operasi write dengan fixed buffer
int io_write_fixed(struct io_kiocb *req, unsigned int issue_flags);

// Fungsi untuk membersihkan operasi readv/writev
void io_readv_writev_cleanup(struct io_kiocb *req);

// Fungsi untuk menangani kegagalan operasi read/write
void io_rw_fail(struct io_kiocb *req);

// Fungsi untuk menyelesaikan operasi read/write
void io_req_rw_complete(struct io_kiocb *req, io_tw_token_t tw);

// Fungsi untuk mempersiapkan operasi read mshot
int io_read_mshot_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);

// Fungsi untuk melakukan operasi read mshot
int io_read_mshot(struct io_kiocb *req, unsigned int issue_flags);

// Fungsi untuk membersihkan cache untuk operasi read/write
void io_rw_cache_free(const void *entry);

