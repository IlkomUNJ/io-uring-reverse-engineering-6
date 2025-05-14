// SPDX-License-Identifier: GPL-2.0
#ifndef IOU_RSRC_H
#define IOU_RSRC_H

#include <linux/io_uring_types.h>
#include <linux/lockdep.h>

#define IO_VEC_CACHE_SOFT_CAP		256

enum {
	IORING_RSRC_FILE		= 0,  // Jenis sumber daya: file
	IORING_RSRC_BUFFER		= 1,  // Jenis sumber daya: buffer
};

// Struktur untuk node sumber daya dalam io_uring
struct io_rsrc_node {
	unsigned char			type;  // Jenis sumber daya (file atau buffer)
	int				refs;  // Jumlah referensi pada sumber daya

	u64 tag;  // Tag unik untuk node sumber daya
	union {
		unsigned long file_ptr;  // Pointer ke file jika sumber daya adalah file
		struct io_mapped_ubuf *buf;  // Pointer ke buffer jika sumber daya adalah buffer
	};
};

// Enumerator untuk menentukan arah transfer data dalam buffer
enum {
	IO_IMU_DEST	= 1 << ITER_DEST,  // Arah: tujuan
	IO_IMU_SOURCE	= 1 << ITER_SOURCE,  // Arah: sumber
};

// Struktur untuk buffer yang dipetakan
struct io_mapped_ubuf {
	u64		ubuf;  // Pointer ke buffer
	unsigned int	len;  // Panjang buffer
	unsigned int	nr_bvecs;  // Jumlah bio_vec yang terkait
	unsigned int    folio_shift;  // Perpindahan halaman
	refcount_t	refs;  // Refcount untuk buffer
	unsigned long	acct_pages;  // Menghitung jumlah halaman yang dipetakan
	void		(*release)(void *);  // Fungsi untuk melepaskan buffer
	void		*priv;  // Data pribadi untuk buffer
	bool		is_kbuf;  // Menunjukkan apakah buffer adalah buffer kernel
	u8		dir;  // Arah transfer data (sumber atau tujuan)
	struct bio_vec	bvec[] __counted_by(nr_bvecs);  // Array bvec untuk buffer
};

// Struktur untuk data folio yang terkait dengan buffer memori yang dipetakan
struct io_imu_folio_data {
	/* Head folio bisa termasuk sebagian dalam buffer tetap */
	unsigned int	nr_pages_head;  // Jumlah halaman dalam bagian head
	/* Folio non-head/tail harus sepenuhnya tercakup */
	unsigned int	nr_pages_mid;  // Jumlah halaman di bagian tengah folio
	unsigned int	folio_shift;  // Perpindahan halaman
	unsigned int	nr_folios;  // Jumlah folio yang terlibat
};

// Fungsi untuk menginisialisasi cache sumber daya dalam konteks I/O
bool io_rsrc_cache_init(struct io_ring_ctx *ctx);
// Fungsi untuk membebaskan cache sumber daya dalam konteks I/O
void io_rsrc_cache_free(struct io_ring_ctx *ctx);
// Fungsi untuk mengalokasikan node sumber daya dalam konteks I/O
struct io_rsrc_node *io_rsrc_node_alloc(struct io_ring_ctx *ctx, int type);
// Fungsi untuk membebaskan node sumber daya dalam konteks I/O
void io_free_rsrc_node(struct io_ring_ctx *ctx, struct io_rsrc_node *node);
// Fungsi untuk membebaskan data sumber daya
void io_rsrc_data_free(struct io_ring_ctx *ctx, struct io_rsrc_data *data);
// Fungsi untuk mengalokasikan data sumber daya
int io_rsrc_data_alloc(struct io_rsrc_data *data, unsigned nr);

// Fungsi untuk mencari node buffer dalam permintaan I/O
struct io_rsrc_node *io_find_buf_node(struct io_kiocb *req,
				      unsigned issue_flags);
// Fungsi untuk mengimpor buffer yang terdaftar dalam operasi I/O
int io_import_reg_buf(struct io_kiocb *req, struct iov_iter *iter,
			u64 buf_addr, size_t len, int ddir,
			unsigned issue_flags);
// Fungsi untuk mengimpor vektor I/O yang terdaftar dalam operasi I/O
int io_import_reg_vec(int ddir, struct iov_iter *iter,
			struct io_kiocb *req, struct iou_vec *vec,
			unsigned nr_iovs, unsigned issue_flags);
// Fungsi untuk mempersiapkan vektor I/O yang terdaftar dalam permintaan I/O
int io_prep_reg_iovec(struct io_kiocb *req, struct iou_vec *iv,
			const struct iovec __user *uvec, size_t uvec_segs);

// Fungsi untuk mendaftar file dalam konteks I/O
int io_register_clone_buffers(struct io_ring_ctx *ctx, void __user *arg);
// Fungsi untuk membatalkan pendaftaran buffer dalam konteks I/O
int io_sqe_buffers_unregister(struct io_ring_ctx *ctx);
// Fungsi untuk mendaftarkan buffer dalam konteks I/O
int io_sqe_buffers_register(struct io_ring_ctx *ctx, void __user *arg,
			    unsigned int nr_args, u64 __user *tags);
// Fungsi untuk mendaftar file dalam konteks I/O
int io_sqe_files_unregister(struct io_ring_ctx *ctx);
// Fungsi untuk mendaftarkan file dalam konteks I/O
int io_sqe_files_register(struct io_ring_ctx *ctx, void __user *arg,
			  unsigned nr_args, u64 __user *tags);

// Fungsi untuk memperbarui daftar file dalam permintaan I/O
int io_register_files_update(struct io_ring_ctx *ctx, void __user *arg,
			     unsigned nr_args);
// Fungsi untuk memperbarui data sumber daya dalam konteks I/O
int io_register_rsrc_update(struct io_ring_ctx *ctx, void __user *arg,
			    unsigned size, unsigned type);
// Fungsi untuk mendaftarkan sumber daya dalam konteks I/O
int io_register_rsrc(struct io_ring_ctx *ctx, void __user *arg,
			unsigned int size, unsigned int type);
// Fungsi untuk memvalidasi buffer I/O
int io_buffer_validate(struct iovec *iov);

// Fungsi untuk memeriksa apakah beberapa halaman memori dapat digabungkan
bool io_check_coalesce_buffer(struct page **page_array, int nr_pages,
			      struct io_imu_folio_data *data);

// Fungsi untuk mencari node sumber daya dalam data sumber daya
static inline struct io_rsrc_node *io_rsrc_node_lookup(struct io_rsrc_data *data,
						       int index)
{
	if (index < data->nr)
		return data->nodes[array_index_nospec(index, data->nr)];
	return NULL;
}

// Fungsi untuk membebaskan node sumber daya
static inline void io_put_rsrc_node(struct io_ring_ctx *ctx, struct io_rsrc_node *node)
{
	lockdep_assert_held(&ctx->uring_lock);
	if (!--node->refs)
		io_free_rsrc_node(ctx, node);
}

// Fungsi untuk mereset node sumber daya dalam data sumber daya
static inline bool io_reset_rsrc_node(struct io_ring_ctx *ctx,
				      struct io_rsrc_data *data, int index)
{
	struct io_rsrc_node *node = data->nodes[index];

	if (!node)
		return false;
	io_put_rsrc_node(ctx, node);
	data->nodes[index] = NULL;
	return true;
}

// Fungsi untuk membebaskan node sumber daya yang terkait dengan permintaan I/O
static inline void io_req_put_rsrc_nodes(struct io_kiocb *req)
{
	if (req->file_node) {
		io_put_rsrc_node(req->ctx, req->file_node);
		req->file_node = NULL;
	}
	if (req->flags & REQ_F_BUF_NODE) {
		io_put_rsrc_node(req->ctx, req->buf_node);
		req->buf_node = NULL;
	}
}

// Fungsi untuk menetapkan node sumber daya atau buffer ke permintaan I/O
static inline void io_req_assign_rsrc_node(struct io_rsrc_node **dst_node,
					   struct io_rsrc_node *node)
{
	node->refs++;
	*dst_node = node;
}

// Fungsi untuk menetapkan node buffer ke permintaan I/O
static inline void io_req_assign_buf_node(struct io_kiocb *req,
					  struct io_rsrc_node *node)
{
	io_req_assign_rsrc_node(&req->buf_node, node);
	req->flags |= REQ_F_BUF_NODE;
}

// Fungsi untuk memperbarui file dalam permintaan I/O
int io_files_update(struct io_kiocb *req, unsigned int issue_flags);
// Fungsi untuk mempersiapkan pembaruan file dalam permintaan I/O
int io_files_update_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);

// Fungsi untuk mengelola akuntansi memori untuk pengguna
int __io_account_mem(struct user_struct *user, unsigned long nr_pages);

// Fungsi untuk membebaskan akun memori yang digunakan oleh pengguna
static inline void __io_unaccount_mem(struct user_struct *user,
				      unsigned long nr_pages)
{
	atomic_long_sub(nr_pages, &user->locked_vm);
}

// Fungsi untuk membebaskan vektor I/O
void io_vec_free(struct iou_vec *iv);
// Fungsi untuk mengalokasikan kembali vektor I/O
int io_vec_realloc(struct iou_vec *iv, unsigned nr_entries);

// Fungsi untuk mereset vektor I/O dengan data baru
static inline void io_vec_reset_iovec(struct iou_vec *iv,
				      struct iovec *iovec, unsigned nr)
{
	io_vec_free(iv);
	iv->iovec = iovec;
	iv->nr = nr;
}

// Fungsi untuk mengalokasikan vektor I/O untuk KASAN (Kernel Address Sanitizer)
static inline void io_alloc_cache_vec_kasan(struct iou_vec *iv)
{
	if (IS_ENABLED(CONFIG_KASAN))
		io_vec_free(iv);
}

#endif

