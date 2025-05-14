// SPDX-License-Identifier: GPL-2.0

// Struktur yang digunakan untuk menyimpan informasi terkait konteks I/O pada task.
struct io_tctx_node {
	struct list_head	ctx_node;        // Node daftar untuk menyimpan konteks dalam daftar.
	struct task_struct	*task;          // Pointer ke task_struct yang terkait dengan task.
	struct io_ring_ctx	*ctx;           // Pointer ke konteks I/O ring yang terkait dengan task.
};

// Fungsi untuk mengalokasikan konteks I/O ring untuk task tertentu.
int io_uring_alloc_task_context(struct task_struct *task,
				struct io_ring_ctx *ctx);

// Fungsi untuk menghapus node konteks I/O dari daftar berdasarkan indeks.
void io_uring_del_tctx_node(unsigned long index);

// Fungsi untuk menambahkan node konteks I/O ke dalam daftar.
int __io_uring_add_tctx_node(struct io_ring_ctx *ctx);

// Fungsi untuk menambahkan node konteks I/O ke dalam daftar saat pengajuan I/O dilakukan.
int __io_uring_add_tctx_node_from_submit(struct io_ring_ctx *ctx);

// Fungsi untuk membersihkan konteks I/O yang terkait dengan task tertentu.
void io_uring_clean_tctx(struct io_uring_task *tctx);

// Fungsi untuk membatalkan pendaftaran ringfd terkait dengan I/O ring.
void io_uring_unreg_ringfd(void);

// Fungsi untuk mendaftarkan ringfd untuk I/O ring yang terkait dengan konteks tertentu.
int io_ringfd_register(struct io_ring_ctx *ctx, void __user *__arg,
		       unsigned nr_args);

// Fungsi untuk membatalkan pendaftaran ringfd dari I/O ring yang terkait dengan konteks tertentu.
int io_ringfd_unregister(struct io_ring_ctx *ctx, void __user *__arg,
			 unsigned nr_args);

// Fungsi inline untuk menambahkan node konteks I/O ke dalam daftar.
// Fungsi ini hanya akan menambahkan node jika konteks I/O yang terakhir terkait dengan task saat ini tidak sama dengan `ctx`.
static inline int io_uring_add_tctx_node(struct io_ring_ctx *ctx)
{
	struct io_uring_task *tctx = current->io_uring;

	// Jika tctx ada dan ctx adalah konteks I/O yang terakhir terkait, tidak perlu menambah node.
	if (likely(tctx && tctx->last == ctx))
		return 0;

	// Jika tidak, tambahkan node konteks I/O ke daftar.
	return __io_uring_add_tctx_node_from_submit(ctx);
}

