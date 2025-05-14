// SPDX-License-Identifier: GPL-2.0

// Struktur data untuk memanajemen thread yang melakukan offload pekerjaan pada I/O submit queue (SQ).
struct io_sq_data {
	refcount_t		refs;             // Referensi hitungan untuk objek ini, untuk manajemen memori.
	atomic_t		park_pending;     // Penanda apakah thread parkir (idle) atau tidak.
	struct mutex		lock;             // Mutex untuk mengamankan akses ke data yang dibagikan.

	/* ctx's that are using this sqd */
	struct list_head	ctx_list;         // Daftar konteks yang menggunakan submit queue data ini.

	struct task_struct	*thread;        // Pointer ke thread yang mengelola submit queue.
	struct wait_queue_head	wait;          // Antrian tunggu untuk menunggu event pada queue.

	unsigned		sq_thread_idle;   // Penanda apakah thread sedang idle.
	int			sq_cpu;           // CPU yang digunakan oleh thread untuk memproses submit queue.
	pid_t			task_pid;         // PID dari task yang menjalankan thread ini.
	pid_t			task_tgid;        // PID grup dari task.

	u64			work_time;        // Waktu total yang dihabiskan untuk pekerjaan oleh thread.
	unsigned long		state;            // Status dari thread atau submit queue.
	struct completion	exited;          // Penyelesaian tugas, untuk mengindikasikan thread selesai.
};

// Fungsi untuk membuat dan mengonfigurasi offload submit queue untuk I/O ring.
int io_sq_offload_create(struct io_ring_ctx *ctx, struct io_uring_params *p);

// Fungsi untuk menyelesaikan dan menghentikan thread submit queue.
void io_sq_thread_finish(struct io_ring_ctx *ctx);

// Fungsi untuk menghentikan thread submit queue secara paksa.
void io_sq_thread_stop(struct io_sq_data *sqd);

// Fungsi untuk memarkir thread submit queue (membuatnya idle sementara).
void io_sq_thread_park(struct io_sq_data *sqd);

// Fungsi untuk membangunkan thread submit queue yang terparkir.
void io_sq_thread_unpark(struct io_sq_data *sqd);

// Fungsi untuk melepaskan sumber daya yang terkait dengan submit queue data.
void io_put_sq_data(struct io_sq_data *sqd);

// Fungsi untuk menunggu submit queue polling.
void io_sqpoll_wait_sq(struct io_ring_ctx *ctx);

// Fungsi untuk mengatur afinitas CPU untuk polling submit queue.
int io_sqpoll_wq_cpu_affinity(struct io_ring_ctx *ctx, cpumask_var_t mask);

