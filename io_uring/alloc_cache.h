#ifndef IOU_ALLOC_CACHE_H
#define IOU_ALLOC_CACHE_H

#include <linux/io_uring_types.h>

/*
 * Batas maksimum jumlah entri yang disimpan dalam cache alokasi.
 */
#define IO_ALLOC_CACHE_MAX	128

/*
 * Membebaskan semua entri dalam cache dan men-dealokasi array penyimpanan entri.
 * Setiap entri dibebaskan dengan fungsi free() yang diberikan pemanggil.
 */
void io_alloc_cache_free(struct io_alloc_cache *cache,
			 void (*free)(const void *));

/*
 * Menginisialisasi cache alokasi dengan kapasitas maksimal, ukuran elemen,
 * dan jumlah byte awal yang harus dibersihkan saat alokasi.
 * Mengembalikan false jika berhasil, true jika gagal mengalokasi memori.
 */
bool io_alloc_cache_init(struct io_alloc_cache *cache,
			 unsigned max_nr, unsigned int size,
			 unsigned int init_bytes);

/*
 * Mengalokasikan elemen baru dari heap sesuai dengan konfigurasi cache.
 * Jika init_clear diatur, maka awal memori akan dibersihkan dengan nol.
 */
void *io_cache_alloc_new(struct io_alloc_cache *cache, gfp_t gfp);

/*
 * Menyimpan kembali objek ke dalam cache jika masih ada ruang.
 * Objek akan diracuni terlebih dahulu jika KASAN aktif.
 * Mengembalikan true jika berhasil dimasukkan ke cache, false jika cache penuh.
 */
static inline bool io_alloc_cache_put(struct io_alloc_cache *cache,
				      void *entry)
{
	if (cache->nr_cached < cache->max_cached) {
		if (!kasan_mempool_poison_object(entry))
			return false;
		cache->entries[cache->nr_cached++] = entry;
		return true;
	}
	return false;
}

/*
 * Mengambil satu objek dari cache alokasi jika tersedia.
 * Jika KASAN aktif, objek akan di-unpoison dan dibersihkan sesuai konfigurasi.
 * Mengembalikan pointer objek atau NULL jika cache kosong.
 */
static inline void *io_alloc_cache_get(struct io_alloc_cache *cache)
{
	if (cache->nr_cached) {
		void *entry = cache->entries[--cache->nr_cached];

		/*
		 * Jika KASAN aktif, selalu bersihkan byte awal yang perlu diinisialisasi,
		 * karena bisa saja tumpang tindih dengan penyimpanan KASAN.
		 */
#if defined(CONFIG_KASAN)
		kasan_mempool_unpoison_object(entry, cache->elem_size);
		if (cache->init_clear)
			memset(entry, 0, cache->init_clear);
#endif
		return entry;
	}

	return NULL;
}

/*
 * Mengambil objek dari cache jika tersedia, jika tidak tersedia maka
 * dialokasikan objek baru menggunakan fungsi io_cache_alloc_new().
 */
static inline void *io_cache_alloc(struct io_alloc_cache *cache, gfp_t gfp)
{
	void *obj;

	obj = io_alloc_cache_get(cache);
	if (obj)
		return obj;
	return io_cache_alloc_new(cache, gfp);
}

/*
 * Mengembalikan objek ke cache, jika cache penuh maka objek langsung dibebaskan.
 */
static inline void io_cache_free(struct io_alloc_cache *cache, void *obj)
{
	if (!io_alloc_cache_put(cache, obj))
		kfree(obj);
}

#endif

