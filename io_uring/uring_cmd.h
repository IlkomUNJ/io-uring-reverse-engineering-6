// SPDX-License-Identifier: GPL-2.0

// Mengimpor file header yang berkaitan dengan perintah I/O dan tipe terkait dalam io_uring.
#include <linux/io_uring/cmd.h>
#include <linux/io_uring_types.h>

// Struktur untuk menangani perintah I/O asinkron menggunakan io_uring.
// Menyimpan data terkait perintah, vektor I/O, dan dua elemen SQE (submission queue entry).
struct io_async_cmd {
	struct io_uring_cmd_data data;   // Data terkait perintah I/O yang akan dieksekusi.
	struct iou_vec vec;              // Vektor I/O yang digunakan untuk pengambilan data.
	struct io_uring_sqe sqes[2];     // Dua elemen SQE untuk perintah I/O asinkron.
};

// Fungsi untuk menjalankan perintah I/O menggunakan io_uring.
// Fungsi utama yang mengirimkan perintah I/O ke io_uring.
int io_uring_cmd(struct io_kiocb *req, unsigned int issue_flags);

// Fungsi untuk mempersiapkan perintah I/O yang akan dikirim ke io_uring.
// Mempersiapkan entri dalam queue submission untuk perintah I/O.
int io_uring_cmd_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);

// Fungsi untuk membersihkan sumber daya yang digunakan oleh perintah I/O setelah selesai.
// Digunakan untuk membersihkan objek atau struktur yang tidak lagi diperlukan.
void io_uring_cmd_cleanup(struct io_kiocb *req);

// Fungsi untuk mencoba membatalkan perintah I/O yang sedang berlangsung di io_uring.
// Membatalkan perintah I/O dalam kasus di mana operasi perlu dihentikan sebelum selesai.
bool io_uring_try_cancel_uring_cmd(struct io_ring_ctx *ctx,
				   struct io_uring_task *tctx, bool cancel_all);

// Fungsi untuk membebaskan cache yang digunakan untuk entri I/O tertentu.
// Cache ini digunakan untuk meningkatkan efisiensi pengelolaan I/O di io_uring.
void io_cmd_cache_free(const void *entry);

// Fungsi untuk mengimpor vektor I/O dari pengguna dan mempersiapkannya untuk digunakan dalam perintah I/O.
// Mengonversi vektor I/O yang diberikan oleh pengguna menjadi struktur yang dapat diproses oleh io_uring.
int io_uring_cmd_import_fixed_vec(struct io_uring_cmd *ioucmd,
				  const struct iovec __user *uvec,
				  size_t uvec_segs,
				  int ddir, struct iov_iter *iter,
				  unsigned issue_flags);

