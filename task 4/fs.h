// SPDX-License-Identifier: GPL-2.0

// Fungsi untuk menyiapkan operasi renameat pada io_kiocb (IO Control Block)
int io_renameat_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);

// Fungsi untuk melaksanakan operasi renameat pada io_kiocb (IO Control Block)
// Melakukan operasi penggantian nama file atau direktori.
int io_renameat(struct io_kiocb *req, unsigned int issue_flags);

// Fungsi untuk membersihkan sumber daya yang digunakan setelah operasi renameat selesai
void io_renameat_cleanup(struct io_kiocb *req);

// Fungsi untuk menyiapkan operasi unlinkat pada io_kiocb (IO Control Block)
// Menghapus file atau direktori pada lokasi yang diberikan oleh sqe.
int io_unlinkat_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);

// Fungsi untuk melaksanakan operasi unlinkat pada io_kiocb (IO Control Block)
// Menghapus file atau direktori berdasarkan path yang diberikan.
int io_unlinkat(struct io_kiocb *req, unsigned int issue_flags);

// Fungsi untuk membersihkan sumber daya yang digunakan setelah operasi unlinkat selesai
void io_unlinkat_cleanup(struct io_kiocb *req);

// Fungsi untuk menyiapkan operasi mkdirat pada io_kiocb (IO Control Block)
// Membuat direktori baru pada path yang diberikan dengan mode yang ditentukan.
int io_mkdirat_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);

// Fungsi untuk melaksanakan operasi mkdirat pada io_kiocb (IO Control Block)
// Membuat direktori baru pada path yang diberikan dengan mode yang ditentukan.
int io_mkdirat(struct io_kiocb *req, unsigned int issue_flags);

// Fungsi untuk membersihkan sumber daya yang digunakan setelah operasi mkdirat selesai
void io_mkdirat_cleanup(struct io_kiocb *req);

// Fungsi untuk menyiapkan operasi symlinkat pada io_kiocb (IO Control Block)
// Membuat symbolic link pada file atau direktori.
int io_symlinkat_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);

// Fungsi untuk melaksanakan operasi symlinkat pada io_kiocb (IO Control Block)
// Membuat symbolic link pada file atau direktori di lokasi yang diberikan.
int io_symlinkat(struct io_kiocb *req, unsigned int issue_flags);

// Fungsi untuk menyiapkan operasi linkat pada io_kiocb (IO Control Block)
// Membuat hard link dari file yang ada.
int io_linkat_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);

// Fungsi untuk melaksanakan operasi linkat pada io_kiocb (IO Control Block)
// Membuat hard link pada file yang ada.
int io_linkat(struct io_kiocb *req, unsigned int issue_flags);

// Fungsi untuk membersihkan sumber daya yang digunakan setelah operasi linkat selesai
void io_link_cleanup(struct io_kiocb *req);

