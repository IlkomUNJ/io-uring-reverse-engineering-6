// SPDX-License-Identifier: GPL-2.0

// Fungsi untuk menyiapkan operasi io_tee, yang mengkopi data dari satu file descriptor ke file descriptor lainnya.
int io_tee_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);

// Fungsi untuk mengeksekusi operasi io_tee, yang mengkopi data di antara dua file descriptor.
int io_tee(struct io_kiocb *req, unsigned int issue_flags);

// Fungsi untuk membersihkan sumber daya terkait operasi splice.
void io_splice_cleanup(struct io_kiocb *req);

// Fungsi untuk menyiapkan operasi io_splice, yang menghubungkan dua file descriptor untuk transfer data langsung tanpa melalui buffer.
int io_splice_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);

// Fungsi untuk mengeksekusi operasi io_splice, yang memindahkan data antara dua file descriptor.
int io_splice(struct io_kiocb *req, unsigned int issue_flags);

