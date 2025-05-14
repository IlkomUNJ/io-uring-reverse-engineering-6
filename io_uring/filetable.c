// SPDX-License-Identifier: GPL-2.0
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/file.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/nospec.h>
#include <linux/io_uring.h>

#include <uapi/linux/io_uring.h>

#include "io_uring.h"
#include "rsrc.h"
#include "filetable.h"

// Fungsi untuk mendapatkan slot file yang tersedia dalam bitmap
static int io_file_bitmap_get(struct io_ring_ctx *ctx)
{
	struct io_file_table *table = &ctx->file_table;
	unsigned long nr = ctx->file_alloc_end;
	int ret;

	if (!table->bitmap)
		return -ENFILE;  // Tidak ada bitmap, tidak bisa mengalokasikan file

	// Mencari bit yang belum terpakai di dalam bitmap
	do {
		ret = find_next_zero_bit(table->bitmap, nr, table->alloc_hint);
		if (ret != nr)
			return ret;  // Slot ditemukan, kembalikan indeksnya

		// Jika sudah mencapai batas alokasi, coba mulai dari awal lagi
		if (table->alloc_hint == ctx->file_alloc_start)
			break;
		nr = table->alloc_hint;
		table->alloc_hint = ctx->file_alloc_start;
	} while (1);

	return -ENFILE;  // Tidak ada slot yang tersedia
}

// Fungsi untuk mengalokasikan tabel file
bool io_alloc_file_tables(struct io_ring_ctx *ctx, struct io_file_table *table,
			  unsigned nr_files)
{
	// Alokasi data tabel file
	if (io_rsrc_data_alloc(&table->data, nr_files))
		return false;
	table->bitmap = bitmap_zalloc(nr_files, GFP_KERNEL_ACCOUNT);  // Alokasi bitmap
	if (table->bitmap)
		return true;  // Sukses alokasi

	// Jika gagal, bebaskan alokasi yang telah dilakukan
	io_rsrc_data_free(ctx, &table->data);
	return false;
}

// Fungsi untuk membebaskan tabel file
void io_free_file_tables(struct io_ring_ctx *ctx, struct io_file_table *table)
{
	io_rsrc_data_free(ctx, &table->data);  // Bebaskan data tabel
	bitmap_free(table->bitmap);  // Bebaskan bitmap
	table->bitmap = NULL;  // Set bitmap ke NULL
}

// Fungsi untuk memasang file ke dalam slot tetap (fixed slot)
static int io_install_fixed_file(struct io_ring_ctx *ctx, struct file *file,
				 u32 slot_index)
	__must_hold(&req->ctx->uring_lock)
{
	struct io_rsrc_node *node;

	// Cek apakah file adalah file uring, jika ya, tidak bisa dipasang
	if (io_is_uring_fops(file))
		return -EBADF;
	if (!ctx->file_table.data.nr)
		return -ENXIO;  // Tidak ada file yang terdaftar
	if (slot_index >= ctx->file_table.data.nr)
		return -EINVAL;  // Index slot tidak valid

	// Alokasikan node sumber daya untuk file
	node = io_rsrc_node_alloc(ctx, IORING_RSRC_FILE);
	if (!node)
		return -ENOMEM;

	// Reset node dan pasang file ke slot yang diminta
	if (!io_reset_rsrc_node(ctx, &ctx->file_table.data, slot_index))
		io_file_bitmap_set(&ctx->file_table, slot_index);

	// Pasang node ke slot yang dipilih
	ctx->file_table.data.nodes[slot_index] = node;
	io_fixed_file_set(node, file);
	return 0;
}

// Fungsi untuk menginstal file tetap (fixed file) ke dalam io_uring
int __io_fixed_fd_install(struct io_ring_ctx *ctx, struct file *file,
			  unsigned int file_slot)
{
	bool alloc_slot = file_slot == IORING_FILE_INDEX_ALLOC;
	int ret;

	// Jika slot harus dialokasikan
	if (alloc_slot) {
		ret = io_file_bitmap_get(ctx);  // Dapatkan slot yang tersedia
		if (unlikely(ret < 0))
			return ret;
		file_slot = ret;
	} else {
		file_slot--;  // Kurangi 1 untuk mendapatkan index yang benar
	}

	// Pasang file ke slot
	ret = io_install_fixed_file(ctx, file, file_slot);
	if (!ret && alloc_slot)
		ret = file_slot;  // Kembalikan slot yang dialokasikan
	return ret;
}

/*
 * Catatan: Ketika io_fixed_fd_install() mengembalikan nilai error, itu
 * akan memastikan fput() dipanggil sesuai dengan yang diharapkan.
 */
int io_fixed_fd_install(struct io_kiocb *req, unsigned int issue_flags,
			struct file *file, unsigned int file_slot)
{
	struct io_ring_ctx *ctx = req->ctx;
	int ret;

	// Lock io_uring untuk memastikan konsistensi data
	io_ring_submit_lock(ctx, issue_flags);
	ret = __io_fixed_fd_install(ctx, file, file_slot);
	io_ring_submit_unlock(ctx, issue_flags);

	// Jika terjadi kesalahan, pastikan file dibebaskan
	if (unlikely(ret < 0))
		fput(file);
	return ret;
}

// Fungsi untuk menghapus file tetap (fixed file) dari io_uring
int io_fixed_fd_remove(struct io_ring_ctx *ctx, unsigned int offset)
{
	struct io_rsrc_node *node;

	// Cek apakah file table kosong atau offset tidak valid
	if (unlikely(!ctx->file_table.data.nr))
		return -ENXIO;
	if (offset >= ctx->file_table.data.nr)
		return -EINVAL;

	// Cari node yang terkait dengan file yang akan dihapus
	node = io_rsrc_node_lookup(&ctx->file_table.data, offset);
	if (!node)
		return -EBADF;  // Tidak ditemukan file yang sesuai
	io_reset_rsrc_node(ctx, &ctx->file_table.data, offset);
	io_file_bitmap_clear(&ctx->file_table, offset);  // Bersihkan bit dari bitmap
	return 0;
}

// Fungsi untuk mendaftarkan rentang alokasi file
int io_register_file_alloc_range(struct io_ring_ctx *ctx,
				 struct io_uring_file_index_range __user *arg)
{
	struct io_uring_file_index_range range;
	u32 end;

	// Salin data rentang alokasi file dari user space
	if (copy_from_user(&range, arg, sizeof(range)))
		return -EFAULT;
	if (check_add_overflow(range.off, range.len, &end))
		return -EOVERFLOW;
	if (range.resv || end > ctx->file_table.data.nr)
		return -EINVAL;  // Cek validitas rentang

	// Set rentang alokasi file
	io_file_table_set_alloc_range(ctx, range.off, range.len);
	return 0;
}

