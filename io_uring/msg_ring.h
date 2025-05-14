// SPDX-License-Identifier: GPL-2.0

/*
 * io_uring_sync_msg_ring() - Melakukan sinkronisasi pesan antar ring
 * @sqe: pointer ke io_uring_sqe yang berisi informasi pesan
 *
 * Fungsi ini menangani pengiriman pesan sinkron antar dua ring berbeda
 * dengan memanfaatkan SQE yang dikirimkan ke ring target.
 */
int io_uring_sync_msg_ring(struct io_uring_sqe *sqe);

/*
 * io_msg_ring_prep() - Mempersiapkan permintaan msg_ring
 * @req: permintaan I/O yang sedang diproses
 * @sqe: pointer ke io_uring_sqe yang menyimpan parameter pengguna
 *
 * Mengekstrak dan memverifikasi parameter dari SQE sebelum operasi
 * msg_ring dapat dijalankan.
 */
int io_msg_ring_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);

/*
 * io_msg_ring() - Menjalankan operasi msg_ring
 * @req: permintaan I/O yang sudah dipersiapkan
 * @issue_flags: flag eksekusi tambahan
 *
 * Menangani pengiriman pesan (SQE) dari satu ring ke ring io_uring lainnya.
 */
int io_msg_ring(struct io_kiocb *req, unsigned int issue_flags);

/*
 * io_msg_ring_cleanup() - Membersihkan resource terkait msg_ring
 * @req: permintaan I/O yang telah dijalankan
 *
 * Digunakan untuk membebaskan alokasi atau membersihkan status setelah
 * operasi msg_ring selesai.
 */
void io_msg_ring_cleanup(struct io_kiocb *req);

