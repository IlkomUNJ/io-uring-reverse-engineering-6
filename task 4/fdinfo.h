// SPDX-License-Identifier: GPL-2.0

/*
 * Menampilkan informasi terkait file descriptor (fd) yang digunakan oleh io_uring.
 * Fungsi ini bertugas untuk menampilkan data status terkait file descriptor 
 * yang digunakan dalam konteks io_uring, seperti status antrian dan buffer 
 * yang terdaftar dalam io_uring.
 * Fungsi ini memanfaatkan objek `seq_file` untuk menampilkan informasi 
 * dalam format teks secara terstruktur.
 */
void io_uring_show_fdinfo(struct seq_file *m, struct file *f);

