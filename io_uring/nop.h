// SPDX-License-Identifier: GPL-2.0

/**
 * io_nop_prep - Mempersiapkan operasi NOP (No Operation) untuk io_uring
 * @req: Struktur io_kiocb yang mewakili permintaan I/O.
 * @sqe: Entry dari submission queue yang berisi detail permintaan pengguna.
 *
 * Fungsi ini tidak melakukan persiapan khusus karena operasi NOP tidak memiliki parameter
 * atau efek samping. Fungsi ini hanya mengembalikan 0 untuk menyatakan bahwa persiapan sukses.
 *
 * Return: Selalu 0.
 */
int io_nop_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);

/**
 * io_nop - Menjalankan operasi NOP dalam io_uring
 * @req: Struktur io_kiocb yang mewakili permintaan I/O.
 * @issue_flags: Bendera yang menentukan cara penanganan permintaan.
 *
 * Fungsi ini menyelesaikan permintaan NOP tanpa melakukan aksi nyata. Tujuannya biasanya
 * untuk pengujian atau sebagai placeholder dalam batch operasi I/O. Hasil permintaan
 * disetel ke 0 untuk menandakan keberhasilan.
 *
 * Return: IOU_OK (nilai yang menunjukkan penyelesaian sukses).
 */
int io_nop(struct io_kiocb *req, unsigned int issue_flags);

