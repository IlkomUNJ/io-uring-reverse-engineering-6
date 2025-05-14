// SPDX-License-Identifier: GPL-2.0

/*
 * Menyiapkan operasi madvise untuk io_uring.
 * Fungsi ini membaca parameter dari SQE dan mengisi struktur io_madvise,
 * yang digunakan untuk memberikan saran ke pengelola memori sistem.
 * Operasi ini dipaksa untuk dieksekusi secara asynchronous.
 * Jika sistem tidak mendukung syscall advise dan MMU, operasi akan gagal.
 */
int io_madvise_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);

/*
 * Menjalankan syscall madvise untuk io_uring.
 * Fungsi ini memberikan saran manajemen memori untuk alamat dan panjang tertentu,
 * menggunakan fungsi do_madvise. Hasilnya disimpan dalam request dan diteruskan
 * sebagai hasil ke pengguna.
 */
int io_madvise(struct io_kiocb *req, unsigned int issue_flags);

/*
 * Menyiapkan operasi fadvise untuk io_uring.
 * Membaca parameter dari SQE (offset, panjang, dan jenis saran) dan menyimpannya
 * dalam struktur io_fadvise. Menentukan apakah operasi perlu dipaksa async.
 */
int io_fadvise_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);

/*
 * Menjalankan operasi fadvise menggunakan fungsi vfs_fadvise.
 * Fungsi ini memberikan saran pengaksesan file berdasarkan offset dan panjang tertentu,
 * yang akan digunakan oleh kernel untuk optimasi cache dan IO.
 * Hasil operasi dicatat dalam request dan dikembalikan ke pengguna.
 */
int io_fadvise(struct io_kiocb *req, unsigned int issue_flags);

