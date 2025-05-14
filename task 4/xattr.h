// SPDX-License-Identifier: GPL-2.0

// Fungsi ini bertugas untuk membersihkan sumber daya yang dialokasikan untuk operasi xattr.
// Biasanya digunakan setelah operasi terkait xattr selesai diproses.
void io_xattr_cleanup(struct io_kiocb *req);

// Fungsi ini mempersiapkan permintaan untuk operasi setxattr yang terkait dengan file descriptor.
// Biasanya dipanggil sebelum operasi dilakukan pada file melalui io_uring.
int io_fsetxattr_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);

// Fungsi ini melakukan operasi setxattr pada file yang diwakili oleh file descriptor.
// Fungsi ini menjalankan operasi yang dipersiapkan sebelumnya dengan io_fsetxattr_prep.
int io_fsetxattr(struct io_kiocb *req, unsigned int issue_flags);

// Fungsi ini mempersiapkan permintaan untuk operasi setxattr yang tidak terkait dengan file descriptor.
// Biasanya dipanggil sebelum operasi dilakukan pada objek atau file lainnya.
int io_setxattr_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);

// Fungsi ini melakukan operasi setxattr pada objek atau file yang tidak menggunakan file descriptor.
// Fungsi ini menjalankan operasi yang dipersiapkan sebelumnya dengan io_setxattr_prep.
int io_setxattr(struct io_kiocb *req, unsigned int issue_flags);

// Fungsi ini mempersiapkan permintaan untuk operasi getxattr yang terkait dengan file descriptor.
// Dipanggil sebelum melakukan operasi getxattr pada file yang diberikan.
int io_fgetxattr_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);

// Fungsi ini melakukan operasi getxattr pada file yang diwakili oleh file descriptor.
// Fungsi ini menjalankan operasi yang dipersiapkan sebelumnya dengan io_fgetxattr_prep.
int io_fgetxattr(struct io_kiocb *req, unsigned int issue_flags);

// Fungsi ini mempersiapkan permintaan untuk operasi getxattr yang tidak terkait dengan file descriptor.
// Dipanggil sebelum melakukan operasi getxattr pada objek atau file lainnya.
int io_getxattr_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);

// Fungsi ini melakukan operasi getxattr pada objek atau file yang tidak menggunakan file descriptor.
// Fungsi ini menjalankan operasi yang dipersiapkan sebelumnya dengan io_getxattr_prep.
int io_getxattr(struct io_kiocb *req, unsigned int issue_flags);

