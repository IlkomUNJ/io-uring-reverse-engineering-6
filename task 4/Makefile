# SPDX-License-Identifier: GPL-2.0
#
# Makefile untuk kompilasi modul io_uring

# Jika konfigurasi GCOV profiling untuk io_uring diaktifkan, aktifkan GCOV
ifdef CONFIG_GCOV_PROFILE_URING
GCOV_PROFILE := y
endif

# Kompilasi file io_uring.o dan dependensinya jika CONFIG_IO_URING diaktifkan
obj-$(CONFIG_IO_URING) += io_uring.o opdef.o kbuf.o rsrc.o notif.o \
                          tctx.o filetable.o rw.o net.o poll.o \
                          eventfd.o uring_cmd.o openclose.o \
                          sqpoll.o xattr.o nop.o fs.o splice.o \
                          sync.o msg_ring.o advise.o openclose.o \
                          statx.o timeout.o fdinfo.o cancel.o \
                          waitid.o register.o truncate.o \
                          memmap.o alloc_cache.o

# Kompilasi zcrx.o jika fitur IO_URING_ZCRX diaktifkan
obj-$(CONFIG_IO_URING_ZCRX) += zcrx.o

# Kompilasi io-wq.o jika CONFIG_IO_WQ diaktifkan (workqueue internal io_uring)
obj-$(CONFIG_IO_WQ) += io-wq.o

# Kompilasi futex.o jika dukungan futex diaktifkan (sinkronisasi user space)
obj-$(CONFIG_FUTEX) += futex.o

# Kompilasi epoll.o jika dukungan epoll diaktifkan (I/O multiplexing)
obj-$(CONFIG_EPOLL) += epoll.o

# Kompilasi napi.o jika dukungan busy-polling jaringan diaktifkan
obj-$(CONFIG_NET_RX_BUSY_POLL) += napi.o

