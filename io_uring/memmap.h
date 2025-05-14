#ifndef IO_URING_MEMMAP_H
#define IO_URING_MEMMAP_H

#define IORING_MAP_OFF_PARAM_REGION		0x20000000ULL
#define IORING_MAP_OFF_ZCRX_REGION		0x30000000ULL

/*
 * io_pin_pages() - Melakukan pinning halaman memori user untuk digunakan di kernel
 * @ubuf: alamat awal buffer user
 * @len: panjang buffer
 * @npages: pointer untuk menyimpan jumlah halaman yang berhasil dipin
 *
 * Mengunci halaman user space untuk akses kernel langsung, dan mengembalikan
 * array struct page yang menunjukkan halaman tersebut.
 */
struct page **io_pin_pages(unsigned long ubuf, unsigned long len, int *npages);

#ifndef CONFIG_MMU
/*
 * io_uring_nommu_mmap_capabilities() - Mendapatkan kemampuan mmap untuk sistem tanpa MMU
 * @file: file yang terkait dengan io_uring
 *
 * Mengembalikan kemampuan mmap yang didukung oleh io_uring pada sistem tanpa MMU.
 */
unsigned int io_uring_nommu_mmap_capabilities(struct file *file);
#endif

/*
 * io_uring_get_unmapped_area() - Mendapatkan area unmapped dari virtual memory
 * @file: file yang dimapping
 * @addr: alamat virtual yang diminta
 * @len: panjang area
 * @pgoff: offset halaman
 * @flags: flag mmap
 *
 * Mengembalikan alamat virtual yang belum digunakan untuk mmap.
 */
unsigned long io_uring_get_unmapped_area(struct file *file, unsigned long addr,
					 unsigned long len, unsigned long pgoff,
					 unsigned long flags);

/*
 * io_uring_mmap() - Handler mmap untuk io_uring
 * @file: file io_uring
 * @vma: struct vm_area_struct dari mapping
 *
 * Mengatur mapping dari file io_uring ke address space pengguna.
 */
int io_uring_mmap(struct file *file, struct vm_area_struct *vma);

/*
 * io_free_region() - Membebaskan region mmap
 * @ctx: konteks io_ring
 * @mr: region yang akan dibebaskan
 *
 * Digunakan untuk melepas halaman yang telah dipin dan membebaskan sumber daya.
 */
void io_free_region(struct io_ring_ctx *ctx, struct io_mapped_region *mr);

/*
 * io_create_region() - Membuat region mmap baru
 * @ctx: konteks io_ring
 * @mr: objek region mmap yang akan diisi
 * @reg: deskripsi region dari pengguna
 * @mmap_offset: offset mmap yang diminta
 *
 * Mengatur region baru berdasarkan parameter pengguna dan mengalokasikan
 * halaman yang diperlukan.
 */
int io_create_region(struct io_ring_ctx *ctx, struct io_mapped_region *mr,
		     struct io_uring_region_desc *reg,
		     unsigned long mmap_offset);

/*
 * io_create_region_mmap_safe() - Membuat region mmap baru secara aman
 * @ctx: konteks io_ring
 * @mr: objek region mmap
 * @reg: deskripsi region pengguna
 * @mmap_offset: offset mmap
 *
 * Versi aman dari io_create_region, biasanya digunakan saat mmap sudah aktif.
 */
int io_create_region_mmap_safe(struct io_ring_ctx *ctx,
				struct io_mapped_region *mr,
				struct io_uring_region_desc *reg,
				unsigned long mmap_offset);

/*
 * io_region_get_ptr() - Mengambil pointer ke data region
 * @mr: region mmap
 *
 * Mengembalikan pointer langsung ke data region.
 */
static inline void *io_region_get_ptr(struct io_mapped_region *mr)
{
	return mr->ptr;
}

/*
 * io_region_is_set() - Mengecek apakah region telah diinisialisasi
 * @mr: region mmap
 *
 * Mengembalikan true jika region memiliki halaman yang sudah dialokasikan.
 */
static inline bool io_region_is_set(struct io_mapped_region *mr)
{
	return !!mr->nr_pages;
}

#endif

