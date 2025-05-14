// SPDX-License-Identifier: GPL-2.0

#include "io_uring.h"
#include "napi.h"

#ifdef CONFIG_NET_RX_BUSY_POLL

/* Timeout for cleanout of stale entries. */
#define NAPI_TIMEOUT		(60 * SEC_CONVERSION)

// Struktur untuk entri NAPI
struct io_napi_entry {
    unsigned int napi_id; // ID untuk NAPI
    struct list_head list; // Daftar link untuk entry ini

    unsigned long timeout; // Waktu kedaluwarsa untuk NAPI
    struct hlist_node node; // Node untuk list berbasis hash

    struct rcu_head rcu; // Untuk manajemen RCU (Read-Copy-Update)
};

// Fungsi untuk mencari entri NAPI berdasarkan napi_id dalam hash list
static struct io_napi_entry *io_napi_hash_find(struct hlist_head *hash_list,
                                               unsigned int napi_id)
{
    struct io_napi_entry *e;

    // Iterasi melalui list dan cari entri yang cocok dengan napi_id
    hlist_for_each_entry_rcu(e, hash_list, node) {
        if (e->napi_id != napi_id)
            continue;
        return e;
    }

    return NULL;
}

// Mengkonversi waktu dalam bentuk long ke ktime_t (napi dengan unit mikrodetik)
static inline ktime_t net_to_ktime(unsigned long t)
{
    // Konversi waktu NAPI dalam mikrodetik ke ktime_t
    return ns_to_ktime(t << 10);
}

// Fungsi untuk menambahkan napi_id ke dalam struktur io_ring_ctx
int __io_napi_add_id(struct io_ring_ctx *ctx, unsigned int napi_id)
{
    struct hlist_head *hash_list;
    struct io_napi_entry *e;

    // Validasi napi_id, jika tidak valid return error
    if (!napi_id_valid(napi_id))
        return -EINVAL;

    hash_list = &ctx->napi_ht[hash_min(napi_id, HASH_BITS(ctx->napi_ht))];

    scoped_guard(rcu) {
        // Mencari napi_id yang sudah ada di dalam hash list
        e = io_napi_hash_find(hash_list, napi_id);
        if (e) {
            // Jika sudah ada, perbarui timeout dan return error sudah ada
            WRITE_ONCE(e->timeout, jiffies + NAPI_TIMEOUT);
            return -EEXIST;
        }
    }

    // Alokasikan memori untuk entri NAPI baru
    e = kmalloc(sizeof(*e), GFP_NOWAIT);
    if (!e)
        return -ENOMEM;

    e->napi_id = napi_id;
    e->timeout = jiffies + NAPI_TIMEOUT;

    // Memeriksa apakah sudah ada entri dengan napi_id yang sama dalam hash list
    spin_lock(&ctx->napi_lock);
    if (unlikely(io_napi_hash_find(hash_list, napi_id))) {
        spin_unlock(&ctx->napi_lock);
        kfree(e);
        return -EEXIST;
    }

    // Menambahkan entri ke hash list dan daftar NAPI
    hlist_add_tail_rcu(&e->node, hash_list);
    list_add_tail_rcu(&e->list, &ctx->napi_list);
    spin_unlock(&ctx->napi_lock);
    return 0;
}

// Fungsi untuk menghapus napi_id dari struktur io_ring_ctx
static int __io_napi_del_id(struct io_ring_ctx *ctx, unsigned int napi_id)
{
    struct hlist_head *hash_list;
    struct io_napi_entry *e;

    // Validasi napi_id, jika tidak valid return error
    if (!napi_id_valid(napi_id))
        return -EINVAL;

    hash_list = &ctx->napi_ht[hash_min(napi_id, HASH_BITS(ctx->napi_ht))];
    guard(spinlock)(&ctx->napi_lock);
    e = io_napi_hash_find(hash_list, napi_id);
    if (!e)
        return -ENOENT;

    // Hapus entri dari daftar dan hash list
    list_del_rcu(&e->list);
    hash_del_rcu(&e->node);
    kfree_rcu(e, rcu);
    return 0;
}

// Fungsi untuk menghapus entri NAPI yang sudah kadaluarsa
static void __io_napi_remove_stale(struct io_ring_ctx *ctx)
{
    struct io_napi_entry *e;

    guard(spinlock)(&ctx->napi_lock);
    // Iterasi melalui daftar NAPI untuk menghapus entri yang kadaluarsa
    list_for_each_entry(e, &ctx->napi_list, list) {
        if (time_after(jiffies, READ_ONCE(e->timeout))) {
            list_del_rcu(&e->list);
            hash_del_rcu(&e->node);
            kfree_rcu(e, rcu);
        }
    }
}

// Fungsi inline untuk menghapus entri NAPI kadaluarsa jika perlu
static inline void io_napi_remove_stale(struct io_ring_ctx *ctx, bool is_stale)
{
    if (is_stale)
        __io_napi_remove_stale(ctx);
}

// Fungsi untuk memeriksa apakah loop busy poll harus dihentikan berdasarkan waktu
static inline bool io_napi_busy_loop_timeout(ktime_t start_time,
                                             ktime_t bp)
{
    if (bp) {
        ktime_t end_time = ktime_add(start_time, bp);
        ktime_t now = net_to_ktime(busy_loop_current_time());

        // Jika waktu sekarang melebihi waktu akhir loop, return true
        return ktime_after(now, end_time);
    }

    return true;
}

// Fungsi untuk menentukan apakah loop busy poll harus berakhir
static bool io_napi_busy_loop_should_end(void *data,
                                         unsigned long start_time)
{
    struct io_wait_queue *iowq = data;

    // Jika ada signal pending atau ada pekerjaan yang harus dilakukan, return true
    if (signal_pending(current))
        return true;
    if (io_should_wake(iowq) || io_has_work(iowq->ctx))
        return true;
    if (io_napi_busy_loop_timeout(net_to_ktime(start_time),
                                  iowq->napi_busy_poll_dt))
        return true;

    return false;
}

// Fungsi untuk melakukan busy poll dalam mode tracking statis
static bool static_tracking_do_busy_loop(struct io_ring_ctx *ctx,
                                         bool (*loop_end)(void *, unsigned long),
                                         void *loop_end_arg)
{
    struct io_napi_entry *e;

    // Iterasi melalui daftar NAPI dan lakukan busy loop
    list_for_each_entry_rcu(e, &ctx->napi_list, list)
        napi_busy_loop_rcu(e->napi_id, loop_end, loop_end_arg,
                           ctx->napi_prefer_busy_poll, BUSY_POLL_BUDGET);
    return false;
}

// Fungsi untuk melakukan busy poll dalam mode tracking dinamis
static bool
dynamic_tracking_do_busy_loop(struct io_ring_ctx *ctx,
                              bool (*loop_end)(void *, unsigned long),
                              void *loop_end_arg)
{
    struct io_napi_entry *e;
    bool is_stale = false;

    // Iterasi melalui daftar NAPI dan lakukan busy loop
    list_for_each_entry_rcu(e, &ctx->napi_list, list) {
        napi_busy_loop_rcu(e->napi_id, loop_end, loop_end_arg,
                           ctx->napi_prefer_busy_poll, BUSY_POLL_BUDGET);

        // Periksa apakah entri sudah kadaluarsa
        if (time_after(jiffies, READ_ONCE(e->timeout)))
            is_stale = true;
    }

    return is_stale;
}

// Fungsi untuk melakukan busy loop tergantung pada mode tracking NAPI
static inline bool
__io_napi_do_busy_loop(struct io_ring_ctx *ctx,
                       bool (*loop_end)(void *, unsigned long),
                       void *loop_end_arg)
{
    if (READ_ONCE(ctx->napi_track_mode) == IO_URING_NAPI_TRACKING_STATIC)
        return static_tracking_do_busy_loop(ctx, loop_end, loop_end_arg);
    return dynamic_tracking_do_busy_loop(ctx, loop_end, loop_end_arg);
}

// Fungsi untuk menjalankan busy poll dalam kondisi blocking
static void io_napi_blocking_busy_loop(struct io_ring_ctx *ctx,
                                       struct io_wait_queue *iowq)
{
    unsigned long start_time = busy_loop_current_time();
    bool (*loop_end)(void *, unsigned long) = NULL;
    void *loop_end_arg = NULL;
    bool is_stale = false;

    // Jika hanya ada satu entri, gunakan fungsi pengecekan berbeda untuk loop berakhir
    if (list_is_singular(&ctx->napi_list)) {
        loop_end = io_napi_busy_loop_should_end;
        loop_end_arg = iowq;
    }

    scoped_guard(rcu) {
        do {
            is_stale = __io_napi_do_busy_loop(ctx, loop_end,
                                              loop_end_arg);
        } while (!io_napi_busy_loop_should_end(iowq, start_time) &&
                 !loop_end_arg);
    }

    // Hapus entri NAPI yang sudah kadaluarsa setelah busy loop
    io_napi_remove_stale(ctx, is_stale);
}

// Fungsi untuk menginisialisasi pengaturan NAPI dalam io-uring
void io_napi_init(struct io_ring_ctx *ctx)
{
    u64 sys_dt = READ_ONCE(sysctl_net_busy_poll) * NSEC_PER_USEC;

    // Inisialisasi daftar dan kunci spinlock untuk NAPI
    INIT_LIST_HEAD(&ctx->napi_list);
    spin_lock_init(&ctx->napi_lock);
    ctx->napi_prefer_busy_poll = false;
    ctx->napi_busy_poll_dt = ns_to_ktime(sys_dt);
    ctx->napi_track_mode = IO_URING_NAPI_TRACKING_INACTIVE;
}

// Fungsi untuk membebaskan sumber daya NAPI dari io-uring
void io_napi_free(struct io_ring_ctx *ctx)
{
    struct io_napi_entry *e;

    guard(spinlock)(&ctx->napi_lock);
    list_for_each_entry(e, &ctx->napi_list, list) {
        hash_del_rcu(&e->node);
        kfree_rcu(e, rcu);
    }
    INIT_LIST_HEAD_RCPU(&ctx->napi_list);
}


/*
 * io_napi_register_napi() - Mendaftarkan napi dalam konteks io-uring
 * @ctx: pointer ke struktur konteks io-uring
 * @napi: pointer ke struktur io_uring_napi yang berisi parameter konfigurasi napi
 *
 * Fungsi ini digunakan untuk mendaftarkan napi baru ke dalam konteks io-uring. 
 * Mengecek jenis tracking napi dan mengatur pengaturan polling, seperti waktu 
 * polling dan preferensi polling.
 * 
 * Mengembalikan 0 jika berhasil, atau -EINVAL jika ada kesalahan pada parameter.
 */
static int io_napi_register_napi(struct io_ring_ctx *ctx,
				 struct io_uring_napi *napi)
{
	switch (napi->op_param) {
	case IO_URING_NAPI_TRACKING_DYNAMIC:
	case IO_URING_NAPI_TRACKING_STATIC:
		break;
	default:
		return -EINVAL;
	}
	/* Bersihkan daftar napi untuk pengaturan baru */
	io_napi_free(ctx);
	WRITE_ONCE(ctx->napi_track_mode, napi->op_param);
	WRITE_ONCE(ctx->napi_busy_poll_dt, napi->busy_poll_to * NSEC_PER_USEC);
	WRITE_ONCE(ctx->napi_prefer_busy_poll, !!napi->prefer_busy_poll);
	return 0;
}

/*
 * io_register_napi() - Mendaftarkan napi dalam konteks io-uring
 * @ctx: pointer ke struktur konteks io-uring
 * @arg: pointer ke struktur io_uring_napi yang berisi parameter registrasi
 *
 * Fungsi ini menerima struktur dari user-space untuk mendaftarkan napi ke dalam 
 * konteks io-uring. Fungsi ini juga akan mengembalikan nilai saat ini ke 
 * user-space untuk dikonfirmasi.
 *
 * Mengembalikan 0 jika berhasil atau nilai kesalahan seperti -EINVAL, -EFAULT.
 */
int io_register_napi(struct io_ring_ctx *ctx, void __user *arg)
{
	const struct io_uring_napi curr = {
		.busy_poll_to 	  = ktime_to_us(ctx->napi_busy_poll_dt),
		.prefer_busy_poll = ctx->napi_prefer_busy_poll,
		.op_param	  = ctx->napi_track_mode
	};
	struct io_uring_napi napi;

	if (ctx->flags & IORING_SETUP_IOPOLL)
		return -EINVAL;
	if (copy_from_user(&napi, arg, sizeof(napi)))
		return -EFAULT;
	if (napi.pad[0] || napi.pad[1] || napi.resv)
		return -EINVAL;

	if (copy_to_user(arg, &curr, sizeof(curr)))
		return -EFAULT;

	switch (napi.opcode) {
	case IO_URING_NAPI_REGISTER_OP:
		return io_napi_register_napi(ctx, &napi);
	case IO_URING_NAPI_STATIC_ADD_ID:
		if (curr.op_param != IO_URING_NAPI_TRACKING_STATIC)
			return -EINVAL;
		return __io_napi_add_id(ctx, napi.op_param);
	case IO_URING_NAPI_STATIC_DEL_ID:
		if (curr.op_param != IO_URING_NAPI_TRACKING_STATIC)
			return -EINVAL;
		return __io_napi_del_id(ctx, napi.op_param);
	default:
		return -EINVAL;
	}
}

/*
 * io_unregister_napi() - Menghapus pendaftaran napi dari io-uring
 * @ctx: pointer ke struktur konteks io-uring
 * @arg: pointer ke struktur io_uring_napi yang berisi parameter penghapusan
 *
 * Fungsi ini digunakan untuk menghapus pendaftaran napi dari konteks io-uring. 
 * Jika argumen diberikan, fungsi ini juga akan mengirimkan pengaturan polling 
 * saat ini ke user-space.
 * 
 * Mengembalikan 0 jika berhasil, atau -EFAULT jika terjadi kesalahan dalam 
 * menyalin data.
 */
int io_unregister_napi(struct io_ring_ctx *ctx, void __user *arg)
{
	const struct io_uring_napi curr = {
		.busy_poll_to 	  = ktime_to_us(ctx->napi_busy_poll_dt),
		.prefer_busy_poll = ctx->napi_prefer_busy_poll
	};

	if (arg && copy_to_user(arg, &curr, sizeof(curr)))
		return -EFAULT;

	WRITE_ONCE(ctx->napi_busy_poll_dt, 0);
	WRITE_ONCE(ctx->napi_prefer_busy_poll, false);
	WRITE_ONCE(ctx->napi_track_mode, IO_URING_NAPI_TRACKING_INACTIVE);
	return 0;
}

/*
 * __io_napi_busy_loop() - Eksekusi loop polling sibuk untuk napi
 * @ctx: pointer ke struktur konteks io-uring
 * @iowq: pointer ke struktur io wait queue
 *
 * Fungsi ini mengeksekusi loop polling sibuk berdasarkan pengaturan waktu polling 
 * yang diberikan. Jika timeout telah tercapai, loop berhenti dan melanjutkan 
 * dengan eksekusi lainnya.
 */
void __io_napi_busy_loop(struct io_ring_ctx *ctx, struct io_wait_queue *iowq)
{
	if (ctx->flags & IORING_SETUP_SQPOLL)
		return;

	iowq->napi_busy_poll_dt = READ_ONCE(ctx->napi_busy_poll_dt);
	if (iowq->timeout != KTIME_MAX) {
		ktime_t dt = ktime_sub(iowq->timeout, io_get_time(ctx));

		iowq->napi_busy_poll_dt = min_t(u64, iowq->napi_busy_poll_dt, dt);
	}

	iowq->napi_prefer_busy_poll = READ_ONCE(ctx->napi_prefer_busy_poll);
	io_napi_blocking_busy_loop(ctx, iowq);
}

/*
 * io_napi_sqpoll_busy_poll() - Loop polling sibuk untuk sqpoll
 * @ctx: pointer ke struktur konteks io-uring
 *
 * Fungsi ini menjalankan loop polling sibuk untuk sqpoll dengan memeriksa apakah
 * ada entri NAPI yang harus diproses. Jika ada, loop polling dilanjutkan sampai 
 * kondisi tertentu tercapai.
 *
 * Mengembalikan 1 jika polling aktif atau 0 jika tidak ada pekerjaan yang harus 
 * diproses.
 */
int io_napi_sqpoll_busy_poll(struct io_ring_ctx *ctx)
{
	bool is_stale = false;

	if (!READ_ONCE(ctx->napi_busy_poll_dt))
		return 0;
	if (list_empty_careful(&ctx->napi_list))
		return 0;

	scoped_guard(rcu) {
		is_stale = __io_napi_do_busy_loop(ctx, NULL, NULL);
	}

	io_napi_remove_stale(ctx, is_stale);
	return 1;
}

#endif
