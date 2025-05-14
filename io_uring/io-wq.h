#ifndef INTERNAL_IO_WQ_H
#define INTERNAL_IO_WQ_H

#include <linux/refcount.h>
#include <linux/io_uring_types.h>

struct io_wq; // Deklarasi struktur io_wq

// Enumerasi untuk status pekerjaan dalam io_wq
enum {
	IO_WQ_WORK_CANCEL	= 1,	// Menandakan pekerjaan dibatalkan
	IO_WQ_WORK_HASHED	= 2,	// Menandakan pekerjaan telah dihash
	IO_WQ_WORK_UNBOUND	= 4,	// Menandakan pekerjaan tidak terikat
	IO_WQ_WORK_CONCURRENT	= 16,	// Menandakan pekerjaan dapat berjalan secara bersamaan

	IO_WQ_HASH_SHIFT	= 24,	// Digunakan untuk menentukan hash key
};

// Enumerasi untuk status pembatalan pekerjaan
enum io_wq_cancel {
	IO_WQ_CANCEL_OK,	// Pekerjaan dibatalkan sebelum dimulai
	IO_WQ_CANCEL_RUNNING,	// Pekerjaan sedang berjalan dan dibatalkan
	IO_WQ_CANCEL_NOTFOUND,	// Pekerjaan tidak ditemukan
};

// Tipe fungsi untuk membebaskan pekerjaan
typedef struct io_wq_work *(free_work_fn)(struct io_wq_work *);
// Tipe fungsi untuk melakukan pekerjaan
typedef void (io_wq_work_fn)(struct io_wq_work *);

// Struktur untuk menyimpan informasi terkait hash pada io_wq
struct io_wq_hash {
	refcount_t refs;		// Referensi count untuk hash
	unsigned long map;		// Peta hash
	struct wait_queue_head wait;	// Antrian tunggu untuk pekerjaan
};

// Fungsi untuk mengurangi referensi dan membebaskan memori jika referensinya mencapai nol
static inline void io_wq_put_hash(struct io_wq_hash *hash)
{
	if (refcount_dec_and_test(&hash->refs))	// Jika referensi menjadi nol
		kfree(hash);	// Bebaskan memori untuk hash
}

// Struktur data untuk io_wq
struct io_wq_data {
	struct io_wq_hash *hash;		// Pointer ke hash yang terkait
	struct task_struct *task;		// Tugas yang terkait dengan io_wq
	io_wq_work_fn *do_work;		// Fungsi untuk menjalankan pekerjaan
	free_work_fn *free_work;		// Fungsi untuk membebaskan pekerjaan
};

// Fungsi untuk membuat io_wq baru
struct io_wq *io_wq_create(unsigned bounded, struct io_wq_data *data);
// Fungsi untuk memulai proses keluar dari io_wq
void io_wq_exit_start(struct io_wq *wq);
// Fungsi untuk memproses keluar dan membebaskan io_wq
void io_wq_put_and_exit(struct io_wq *wq);

// Fungsi untuk menambahkan pekerjaan ke dalam io_wq
void io_wq_enqueue(struct io_wq *wq, struct io_wq_work *work);
// Fungsi untuk memberikan hash pada pekerjaan
void io_wq_hash_work(struct io_wq_work *work, void *val);

// Fungsi untuk mengatur afinitas CPU untuk task tertentu
int io_wq_cpu_affinity(struct io_uring_task *tctx, cpumask_var_t mask);
// Fungsi untuk mengatur jumlah maksimal pekerja pada io_wq
int io_wq_max_workers(struct io_wq *wq, int *new_count);
// Fungsi untuk memeriksa apakah pekerja telah berhenti
bool io_wq_worker_stopped(void);

// Fungsi inline untuk memeriksa apakah pekerjaan telah dihash
static inline bool __io_wq_is_hashed(unsigned int work_flags)
{
	return work_flags & IO_WQ_WORK_HASHED;	// Periksa apakah flag pekerjaan menunjukkan pekerjaan telah dihash
}

// Fungsi inline untuk memeriksa apakah pekerjaan tertentu telah dihash
static inline bool io_wq_is_hashed(struct io_wq_work *work)
{
	return __io_wq_is_hashed(atomic_read(&work->flags));	// Ambil flag dari pekerjaan dan periksa apakah telah dihash
}

// Tipe fungsi untuk membatalkan pekerjaan
typedef bool (work_cancel_fn)(struct io_wq_work *, void *);

// Fungsi untuk membatalkan pekerjaan berdasarkan callback
enum io_wq_cancel io_wq_cancel_cb(struct io_wq *wq, work_cancel_fn *cancel,
					void *data, bool cancel_all);

#if defined(CONFIG_IO_WQ)
// Fungsi yang dipanggil ketika pekerja tidur
extern void io_wq_worker_sleeping(struct task_struct *);
// Fungsi yang dipanggil ketika pekerja sedang berjalan
extern void io_wq_worker_running(struct task_struct *);
#else
// Versi dummy dari fungsi pekerja tidur jika tidak ada konfigurasi IO_WQ
static inline void io_wq_worker_sleeping(struct task_struct *tsk)
{
}
// Versi dummy dari fungsi pekerja berjalan jika tidak ada konfigurasi IO_WQ
static inline void io_wq_worker_running(struct task_struct *tsk)
{
}
#endif

// Fungsi inline untuk memeriksa apakah thread saat ini adalah pekerja
static inline bool io_wq_current_is_worker(void)
{
	return in_task() && (current->flags & PF_IO_WORKER) &&	// Periksa apakah thread saat ini adalah pekerja
		current->worker_private;	// Periksa apakah pekerja memiliki data privat
}

#endif

