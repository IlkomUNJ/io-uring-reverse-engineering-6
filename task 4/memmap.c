// SPDX-License-Identifier: GPL-2.0
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/errno.h>
#include <linux/mm.h>
#include <linux/mman.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/io_uring.h>
#include <linux/io_uring_types.h>
#include <asm/shmparam.h>

#include "memmap.h"
#include "kbuf.h"
#include "rsrc.h"

static void *io_mem_alloc_compound(struct page **pages, int nr_pages,
				   size_t size, gfp_t gfp)
{
	// Menentukan order (tingkat alokasi) berdasarkan ukuran memori yang diminta
	order = get_order(size);
	// Jika order melebihi batas maksimum, kembalikan error
	if (order > MAX_PAGE_ORDER)
		return ERR_PTR(-ENOMEM);
	else if (order)
		gfp |= __GFP_COMP;  // Menggunakan flag __GFP_COMP jika order > 0

	// Mencoba mengalokasikan halaman (pages) dengan menggunakan alloc_pages
	page = alloc_pages(gfp, order);
	if (!page)
		return ERR_PTR(-ENOMEM);  // Jika alokasi gagal, kembalikan error

	// Menyimpan alamat setiap halaman yang dialokasikan ke dalam array pages
	for (i = 0; i < nr_pages; i++)
		pages[i] = page + i;

	// Mengembalikan alamat halaman pertama
	return page_address(page);
}

struct page **io_pin_pages(unsigned long uaddr, unsigned long len, int *npages)
{
	// Memeriksa apakah alamat dan panjang yang diberikan valid (overflow)
	if (check_add_overflow(uaddr, len, &end))
		return ERR_PTR(-EOVERFLOW);
	if (check_add_overflow(end, PAGE_SIZE - 1, &end))
		return ERR_PTR(-EOVERFLOW);

	// Menentukan jumlah halaman berdasarkan alamat dan panjang yang diberikan
	end = end >> PAGE_SHIFT;
	start = uaddr >> PAGE_SHIFT;
	nr_pages = end - start;
	if (WARN_ON_ONCE(!nr_pages))
		return ERR_PTR(-EINVAL);  // Jika tidak ada halaman, kembalikan error

	// Mengalokasikan array untuk menyimpan halaman-halaman yang dipin
	pages = kvmalloc_array(nr_pages, sizeof(struct page *), GFP_KERNEL);
	if (!pages)
		return ERR_PTR(-ENOMEM);  // Jika gagal mengalokasikan, kembalikan error

	// Memasukkan halaman-halaman ke dalam array pages menggunakan pin_user_pages_fast
	ret = pin_user_pages_fast(uaddr, nr_pages, FOLL_WRITE | FOLL_LONGTERM, pages);
	if (ret == nr_pages) {
		*npages = nr_pages;  // Jika berhasil mem-pin semua halaman
		return pages;
	}

	// Jika hanya sebagian yang berhasil dipin, atau tidak ada yang berhasil
	if (ret >= 0) {
		if (ret)
			unpin_user_pages(pages, ret);  // Melepaskan halaman yang dipin
		ret = -EFAULT;  // Menandakan kesalahan
	}
	kvfree(pages);  // Membebaskan memori jika gagal
	return ERR_PTR(ret);
}

void io_free_region(struct io_ring_ctx *ctx, struct io_mapped_region *mr)
{
	// Jika pages ada, melepaskan semua halaman yang dipin
	if (mr->pages) {
		long nr_refs = mr->nr_pages;

		// Jika hanya satu referensi, set nr_refs menjadi 1
		if (mr->flags & IO_REGION_F_SINGLE_REF)
			nr_refs = 1;

		// Jika memory disediakan oleh pengguna, unpin halaman
		if (mr->flags & IO_REGION_F_USER_PROVIDED)
			unpin_user_pages(mr->pages, nr_refs);
		else
			release_pages(mr->pages, nr_refs);  // Jika tidak, melepaskan halaman

		kvfree(mr->pages);  // Membebaskan memori untuk halaman
	}

	// Jika region vmap'ed, meng-unmap memory
	if ((mr->flags & IO_REGION_F_VMAP) && mr->ptr)
		vunmap(mr->ptr);

	// Jika ada halaman yang dipin, mengurangi akun memori
	if (mr->nr_pages && ctx->user)
		__io_unaccount_mem(ctx->user, mr->nr_pages);

	// Mengosongkan struktur mr
	memset(mr, 0, sizeof(*mr));
}

static int io_region_init_ptr(struct io_mapped_region *mr)
{
	struct io_imu_folio_data ifd;
	void *ptr;

	// Mengecek apakah halaman dapat di-coalesce
	if (io_check_coalesce_buffer(mr->pages, mr->nr_pages, &ifd)) {
		if (ifd.nr_folios == 1) {
			mr->ptr = page_address(mr->pages[0]);  // Menggunakan alamat halaman pertama jika hanya ada satu folio
			return 0;
		}
	}
	// Jika tidak, melakukan vmap untuk memetakan halaman ke alamat kernel
	ptr = vmap(mr->pages, mr->nr_pages, VM_MAP, PAGE_KERNEL);
	if (!ptr)
		return -ENOMEM;  // Mengembalikan error jika vmap gagal

	// Menyimpan pointer yang di-mapped ke struktur mr
	mr->ptr = ptr;
	mr->flags |= IO_REGION_F_VMAP;  // Menandakan bahwa region telah vmap'ed
	return 0;
}

static int io_region_pin_pages(struct io_ring_ctx *ctx,
				struct io_mapped_region *mr,
				struct io_uring_region_desc *reg)
{
	unsigned long size = mr->nr_pages << PAGE_SHIFT;
	struct page **pages;
	int nr_pages;

	// Mem-pin halaman pengguna berdasarkan alamat dan ukuran
	pages = io_pin_pages(reg->user_addr, size, &nr_pages);
	if (IS_ERR(pages))
		return PTR_ERR(pages);  // Mengembalikan error jika gagal mem-pin halaman

	// Memeriksa apakah jumlah halaman yang dipin sesuai dengan yang diinginkan
	if (WARN_ON_ONCE(nr_pages != mr->nr_pages))
		return -EFAULT;

	// Menyimpan halaman yang dipin ke dalam struktur mr
	mr->pages = pages;
	mr->flags |= IO_REGION_F_USER_PROVIDED;
	return 0;
}

static int io_region_allocate_pages(struct io_ring_ctx *ctx,
				    struct io_mapped_region *mr,
				    struct io_uring_region_desc *reg,
				    unsigned long mmap_offset)
{
	gfp_t gfp = GFP_KERNEL_ACCOUNT | __GFP_ZERO | __GFP_NOWARN;
	unsigned long size = mr->nr_pages << PAGE_SHIFT;
	unsigned long nr_allocated;
	struct page **pages;
	void *p;

	// Mengalokasikan array halaman
	pages = kvmalloc_array(mr->nr_pages, sizeof(*pages), gfp);
	if (!pages)
		return -ENOMEM;  // Mengembalikan error jika gagal mengalokasikan array

	// Mencoba mengalokasikan memori compound untuk halaman-halaman
	p = io_mem_alloc_compound(pages, mr->nr_pages, size, gfp);
	if (!IS_ERR(p)) {
		mr->flags |= IO_REGION_F_SINGLE_REF;  // Menandakan hanya ada satu referensi
		goto done;
	}

	// Jika alokasi compound gagal, menggunakan alokasi halaman secara bulk
	nr_allocated = alloc_pages_bulk_node(gfp, NUMA_NO_NODE, mr->nr_pages, pages);
	if (nr_allocated != mr->nr_pages) {
		if (nr_allocated)
			release_pages(pages, nr_allocated);  // Membebaskan halaman yang berhasil dialokasikan
		kvfree(pages);  // Membebaskan array halaman
		return -ENOMEM;
	}
done:
	// Menyimpan informasi mmap_offset
	reg->mmap_offset = mmap_offset;
	mr->pages = pages;
	return 0;
}

int io_create_region(struct io_ring_ctx *ctx, struct io_mapped_region *mr,
		     struct io_uring_region_desc *reg,
		     unsigned long mmap_offset)
{
	int nr_pages, ret;
	u64 end;

	// Memeriksa apakah region sudah ada
	if (WARN_ON_ONCE(mr->pages || mr->ptr || mr->nr_pages))
		return -EFAULT;

	// Memeriksa apakah ada nilai yang tidak valid pada __resv
	if (memchr_inv(&reg->__resv, 0, sizeof(reg->__resv)))
		return -EINVAL;

	// Memeriksa apakah flags valid
	if (reg->flags & ~IORING_MEM_REGION_TYPE_USER)
		return -EINVAL;

	// Memeriksa apakah user_addr sudah diatur dengan benar
	if ((reg->flags & IORING_MEM_REGION_TYPE_USER) != !!reg->user_addr)
		return -EFAULT;

	// Memeriksa apakah ukuran dan offset valid
	if (!reg->size || reg->mmap_offset || reg->id)
		return -EINVAL;
	if ((reg->size >> PAGE_SHIFT) > INT_MAX)
		return -E2BIG;
	if ((reg->user_addr | reg->size) & ~PAGE_MASK)
		return -EINVAL;
	if (check_add_overflow(reg->user_addr, reg->size, &end))
		return -EOVERFLOW;

	// Menentukan jumlah halaman
	nr_pages = reg->size >> PAGE_SHIFT;
	if (ctx->user) {
		// Menghitung akun memori
		ret = __io_account_mem(ctx->user, nr_pages);
		if (ret)
			return ret;
	}
	mr->nr_pages = nr_pages;

	// Mem-pin halaman atau alokasikan halaman tergantung pada tipe region
	if (reg->flags & IORING_MEM_REGION_TYPE_USER)
		ret = io_region_pin_pages(ctx, mr, reg);
	else
		ret = io_region_allocate_pages(ctx, mr, reg, mmap_offset);
	if (ret)
		goto out_free;

	// Menginisialisasi pointer untuk region
	ret = io_region_init_ptr(mr);
	if (ret)
		goto out_free;
	return 0;

out_free:
	// Membebaskan region jika ada kesalahan
	io_free_region(ctx, mr);
	return ret;
}

int io_create_region_mmap_safe(struct io_ring_ctx *ctx, struct io_mapped_region *mr,
				struct io_uring_region_desc *reg,
				unsigned long mmap_offset)
{
	struct io_mapped_region tmp_mr;
	int ret;

	// Menyalin struktur mr ke tmp_mr untuk keamanan
	memcpy(&tmp_mr, mr, sizeof(tmp_mr));
	ret = io_create_region(ctx, &tmp_mr, reg, mmap_offset);
	if (ret)
		return ret;

	// Mengunci mmap_lock dan menyalin tmp_mr kembali ke mr
	guard(mutex)(&ctx->mmap_lock);
	memcpy(mr, &tmp_mr, sizeof(tmp_mr));
	return 0;
}

/* 
 * io_mmap_get_region - Menentukan dan mengembalikan region yang sesuai
 * berdasarkan offset halaman yang diberikan.
 */
static struct io_mapped_region *io_mmap_get_region(struct io_ring_ctx *ctx,
						   loff_t pgoff)
{
	loff_t offset = pgoff << PAGE_SHIFT;
	unsigned int bgid;

	switch (offset & IORING_OFF_MMAP_MASK) {
	case IORING_OFF_SQ_RING:
	case IORING_OFF_CQ_RING:
		return &ctx->ring_region;
	case IORING_OFF_SQES:
		return &ctx->sq_region;
	case IORING_OFF_PBUF_RING:
		bgid = (offset & ~IORING_OFF_MMAP_MASK) >> IORING_OFF_PBUF_SHIFT;
		return io_pbuf_get_region(ctx, bgid);
	case IORING_MAP_OFF_PARAM_REGION:
		return &ctx->param_region;
	case IORING_MAP_OFF_ZCRX_REGION:
		return &ctx->zcrx_region;
	}
	return NULL;
}

/* 
 * io_region_validate_mmap - Memvalidasi region yang dipetakan untuk mmap.
 * Fungsi ini memeriksa apakah region sudah benar diatur dan tidak dalam keadaan
 * yang salah untuk mmap.
 */
static void *io_region_validate_mmap(struct io_ring_ctx *ctx,
				     struct io_mapped_region *mr)
{
	lockdep_assert_held(&ctx->mmap_lock);

	if (!io_region_is_set(mr))
		return ERR_PTR(-EINVAL);
	if (mr->flags & IO_REGION_F_USER_PROVIDED)
		return ERR_PTR(-EINVAL);

	return io_region_get_ptr(mr);
}

/* 
 * io_uring_validate_mmap_request - Memvalidasi permintaan mmap dengan memeriksa
 * region yang sesuai berdasarkan offset halaman yang diberikan.
 */
static void *io_uring_validate_mmap_request(struct file *file, loff_t pgoff,
					    size_t sz)
{
	struct io_ring_ctx *ctx = file->private_data;
	struct io_mapped_region *region;

	region = io_mmap_get_region(ctx, pgoff);
	if (!region)
		return ERR_PTR(-EINVAL);
	return io_region_validate_mmap(ctx, region);
}

#ifdef CONFIG_MMU

/* 
 * io_region_mmap - Melakukan pemetaan region ke dalam area memori virtual
 * yang ditentukan oleh vma.
 */
static int io_region_mmap(struct io_ring_ctx *ctx,
			  struct io_mapped_region *mr,
			  struct vm_area_struct *vma,
			  unsigned max_pages)
{
	unsigned long nr_pages = min(mr->nr_pages, max_pages);

	vm_flags_set(vma, VM_DONTEXPAND);
	return vm_insert_pages(vma, vma->vm_start, mr->pages, &nr_pages);
}

/* 
 * io_uring_mmap - Memproses permintaan mmap untuk io_uring. Fungsi ini akan
 * memvalidasi permintaan dan melakukan pemetaan region yang sesuai.
 */
__cold int io_uring_mmap(struct file *file, struct vm_area_struct *vma)
{
	struct io_ring_ctx *ctx = file->private_data;
	size_t sz = vma->vm_end - vma->vm_start;
	long offset = vma->vm_pgoff << PAGE_SHIFT;
	unsigned int page_limit = UINT_MAX;
	struct io_mapped_region *region;
	void *ptr;

	guard(mutex)(&ctx->mmap_lock);

	ptr = io_uring_validate_mmap_request(file, vma->vm_pgoff, sz);
	if (IS_ERR(ptr))
		return PTR_ERR(ptr);

	switch (offset & IORING_OFF_MMAP_MASK) {
	case IORING_OFF_SQ_RING:
	case IORING_OFF_CQ_RING:
		page_limit = (sz + PAGE_SIZE - 1) >> PAGE_SHIFT;
		break;
	}

	region = io_mmap_get_region(ctx, vma->vm_pgoff);
	return io_region_mmap(ctx, region, vma, page_limit);
}

/* 
 * io_uring_get_unmapped_area - Menghitung area memori yang belum dipetakan untuk mmap.
 * Fungsi ini digunakan untuk mendapatkan area yang dapat dipetakan oleh mmap.
 */
unsigned long io_uring_get_unmapped_area(struct file *filp, unsigned long addr,
					 unsigned long len, unsigned long pgoff,
					 unsigned long flags)
{
	struct io_ring_ctx *ctx = filp->private_data;
	void *ptr;

	/*
	 * Tidak mengizinkan pemetaan ke alamat yang diberikan oleh pengguna untuk menghindari
	 * pelanggaran aturan aliasing.
	 */
	if (addr)
		return -EINVAL;

	guard(mutex)(&ctx->mmap_lock);

	ptr = io_uring_validate_mmap_request(filp, pgoff, len);
	if (IS_ERR(ptr))
		return -ENOMEM;

	/*
	 * Beberapa arsitektur memiliki persyaratan aliasing cache yang kuat.
	 * Untuk arsitektur seperti itu, kita perlu pemetaan yang koheren yang mengaliasi
	 * memori kernel *dan* memori pengguna.
	 */
	filp = NULL;
	flags |= MAP_SHARED;
	pgoff = 0;	/* sudah diterjemahkan ke ptr di atas */
#ifdef SHM_COLOUR
	addr = (uintptr_t) ptr;
	pgoff = addr >> PAGE_SHIFT;
#else
	addr = 0UL;
#endif
	return mm_get_unmapped_area(current->mm, filp, addr, len, pgoff, flags);
}

#else /* !CONFIG_MMU */

/* 
 * io_uring_mmap - Fungsi mmap untuk sistem tanpa MMU. Melakukan pemetaan
 * sederhana untuk sistem tanpa MMU.
 */
int io_uring_mmap(struct file *file, struct vm_area_struct *vma)
{
	return is_nommu_shared_mapping(vma->vm_flags) ? 0 : -EINVAL;
}

/* 
 * io_uring_nommu_mmap_capabilities - Mendapatkan kemampuan mmap untuk sistem tanpa MMU.
 */
unsigned int io_uring_nommu_mmap_capabilities(struct file *file)
{
	return NOMMU_MAP_DIRECT | NOMMU_MAP_READ | NOMMU_MAP_WRITE;
}

/* 
 * io_uring_get_unmapped_area - Fungsi ini menangani perhitungan area yang belum dipetakan
 * untuk mmap pada sistem tanpa MMU.
 */
unsigned long io_uring_get_unmapped_area(struct file *file, unsigned long addr,
					 unsigned long len, unsigned long pgoff,
					 unsigned long flags)
{
	struct io_ring_ctx *ctx = file->private_data;
	void *ptr;

	guard(mutex)(&ctx->mmap_lock);

	ptr = io_uring_validate_mmap_request(file, pgoff, len);
	if (IS_ERR(ptr))
		return PTR_ERR(ptr);

	return (unsigned long) ptr;
}
#endif /* CONFIG_MMU */

