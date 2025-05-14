// SPDX-License-Identifier: GPL-2.0
#ifndef IOU_OP_DEF_H
#define IOU_OP_DEF_H

/*
 * Struktur yang mendefinisikan properti dan fungsi yang terkait dengan operasi I/O
 */
struct io_issue_def {
	/* Menandakan apakah permintaan ini memerlukan file yang terpasang */
	unsigned		needs_file : 1;

	/* Menandakan apakah operasi ini perlu plug blok I/O */
	unsigned		plug : 1;

	/* Menandakan apakah operasi ini mendukung prioritas I/O (ioprio) */
	unsigned		ioprio : 1;

	/* Menandakan apakah operasi ini mendukung polling I/O (iopoll) */
	unsigned		iopoll : 1;

	/* Menandakan apakah operasi ini mendukung seleksi buffer */
	unsigned		buffer_select : 1;

	/* Menandakan apakah harus dilakukan hash untuk file reguler */
	unsigned		hash_reg_file : 1;

	/* Menandakan apakah harus dilakukan unbound wq untuk file non-reguler */
	unsigned		unbound_nonreg_file : 1;

	/* Menandakan apakah operasi ini mendukung polling "wait" (pollin) */
	unsigned		pollin : 1;
	unsigned		pollout : 1;

	/* Menandakan apakah operasi ini eksklusif dalam polling */
	unsigned		poll_exclusive : 1;

	/* Menandakan apakah operasi ini harus melewati proses audit */
	unsigned		audit_skip : 1;

	/* Menandakan apakah operasi ini harus dimasukkan ke dalam daftar polling */
	unsigned		iopoll_queue : 1;

	/* Menandakan apakah operasi ini bersifat vektoral (vectored), dan jika ya, handler perlu tahu */
	unsigned		vectored : 1;

	/* Ukuran data asinkron yang diperlukan, jika ada */
	unsigned short		async_size;

	/* Fungsi untuk menjalankan operasi I/O */
	int (*issue)(struct io_kiocb *, unsigned int);

	/* Fungsi untuk mempersiapkan operasi I/O */
	int (*prep)(struct io_kiocb *, const struct io_uring_sqe *);
};

/*
 * Struktur untuk mendefinisikan operasi cold I/O
 */
struct io_cold_def {
	const char		*name;		// Nama operasi cold

	/* Fungsi untuk membersihkan operasi cold setelah selesai */
	void (*cleanup)(struct io_kiocb *);

	/* Fungsi untuk menangani kegagalan operasi cold */
	void (*fail)(struct io_kiocb *);
};

/*
 * Array yang mendefinisikan operasi I/O yang tersedia
 */
extern const struct io_issue_def io_issue_defs[];

/*
 * Array yang mendefinisikan operasi cold I/O yang tersedia
 */
extern const struct io_cold_def io_cold_defs[];

/*
 * Fungsi untuk memeriksa apakah operasi I/O tertentu didukung oleh io_uring
 */
bool io_uring_op_supported(u8 opcode);

/*
 * Fungsi untuk menginisialisasi tabel operasi io_uring
 */
void io_uring_optable_init(void);

#endif

