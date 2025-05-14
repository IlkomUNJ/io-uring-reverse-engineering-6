// Forward declaration dari struct io_ring_ctx
struct io_ring_ctx;

// Fungsi untuk mendaftarkan eventfd dengan io_uring
// ctx: konteks io_ring yang akan digunakan
// arg: alamat pengguna yang berisi file descriptor eventfd
// eventfd_async: apakah eventfd ini digunakan dalam mode asynchronous
// Mengembalikan 0 jika berhasil, atau error code jika gagal
int io_eventfd_register(struct io_ring_ctx *ctx, void __user *arg,
			unsigned int eventfd_async);

// Fungsi untuk membatalkan pendaftaran eventfd dalam io_uring
// ctx: konteks io_ring yang terkait
// Mengembalikan 0 jika berhasil membatalkan pendaftaran, atau -ENXIO jika tidak ada eventfd terdaftar
int io_eventfd_unregister(struct io_ring_ctx *ctx);

// Fungsi untuk flush (menyebarkan) sinyal pada eventfd
// ctx: konteks io_ring yang terkait
// Memicu pengiriman sinyal pada eventfd hanya jika ada perubahan yang perlu diberitahukan
void io_eventfd_flush_signal(struct io_ring_ctx *ctx);

// Fungsi untuk memicu sinyal pada eventfd
// ctx: konteks io_ring yang terkait
// Mengirimkan sinyal ke eventfd jika ada perubahan yang perlu diberitahukan
void io_eventfd_signal(struct io_ring_ctx *ctx);

