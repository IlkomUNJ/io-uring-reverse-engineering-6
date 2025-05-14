// SPDX-License-Identifier: GPL-2.0
#ifndef IOU_FILE_TABLE_H
#define IOU_FILE_TABLE_H

#include <linux/file.h>
#include <linux/io_uring_types.h>
#include "rsrc.h"

// Fungsi untuk mengalokasikan tabel file
bool io_alloc_file_tables(struct io_ring_ctx *ctx, struct io_file_table *table, unsigned nr_files);

// Fungsi untuk membebaskan tabel file
void io_free_file_tables(struct io_ring_ctx *ctx, struct io_file_table *table);

// Fungsi untuk memasang file tetap (fixed file) ke dalam io_uring
int io_fixed_fd_install(struct io_kiocb *req, unsigned int issue_flags,
			struct file *file, unsigned int file_slot);

// Fungsi untuk instalasi file tetap yang lebih rendah (tanpa lock)
int __io_fixed_fd_install(struct io_ring_ctx *ctx, struct file *file,
				unsigned int file_slot);

// Fungsi untuk menghapus file tetap dari io_uring
int io_fixed_fd_remove(struct io_ring_ctx *ctx, unsigned int offset);

// Fungsi untuk mendaftarkan rentang alokasi file
int io_register_file_alloc_range(struct io_ring_ctx *ctx,
				 struct io_uring_file_index_range __user *arg);

// Fungsi untuk mendapatkan flag dari file dalam konteks io_uring
io_req_flags_t io_file_get_flags(struct file *file);

// Fungsi untuk membersihkan bit tertentu dalam bitmap
static inline void io_file_bitmap_clear(struct io_file_table *table, int bit)
{
	WARN_ON_ONCE(!test_bit(bit, table->bitmap));  // Cek apakah bit sudah di-set
	__clear_bit(bit, table->bitmap);  // Hapus bit
	table->alloc_hint = bit;  // Set hint ke bit yang baru dibersihkan
}

// Fungsi untuk menyetel bit tertentu dalam bitmap
static inline void io_file_bitmap_set(struct io_file_table *table, int bit)
{
	WARN_ON_ONCE(test_bit(bit, table->bitmap));  // Cek apakah bit sudah dibersihkan
	__set_bit(bit, table->bitmap);  // Set bit
	table->alloc_hint = bit + 1;  // Set hint ke bit berikutnya
}

// Definisi flag untuk file
#define FFS_NOWAIT		0x1UL  // Flag untuk operasi tanpa menunggu
#define FFS_ISREG		0x2UL  // Flag untuk file reguler
#define FFS_MASK		~(FFS_NOWAIT|FFS_ISREG)  // Mask untuk menghilangkan bit ini

// Fungsi untuk mendapatkan flag slot dalam node sumber daya
static inline unsigned int io_slot_flags(struct io_rsrc_node *node)
{
	// Kembalikan flag slot dengan menggeser bit
	return (node->file_ptr & ~FFS_MASK) << REQ_F_SUPPORT_NOWAIT_BIT;
}

// Fungsi untuk mendapatkan pointer ke file dalam slot
static inline struct file *io_slot_file(struct io_rsrc_node *node)
{
	// Kembalikan file berdasarkan pointer dalam node
	return (struct file *)(node->file_ptr & FFS_MASK);
}

// Fungsi untuk menyetel file tetap (fixed file) dalam node
static inline void io_fixed_file_set(struct io_rsrc_node *node,
				     struct file *file)
{
	// Set file pointer dalam node, dengan menyertakan flag file
	node->file_ptr = (unsigned long)file |
		(io_file_get_flags(file) >> REQ_F_SUPPORT_NOWAIT_BIT);
}

// Fungsi untuk mengatur rentang alokasi file dalam konteks io_uring
static inline void io_file_table_set_alloc_range(struct io_ring_ctx *ctx,
						 unsigned off, unsigned len)
{
	// Set rentang alokasi file dan update hint alokasi
	ctx->file_alloc_start = off;
	ctx->file_alloc_end = off + len;
	ctx->file_table.alloc_hint = ctx->file_alloc_start;
}

#endif  // IOU_FILE_TABLE_H

