# Task 3: Data Structure Investigation
The objective of this task is to document all internal data structures defined in io_uring. 

Structure name | Defined in | Attributes | Caller Functions Source | source caller | usage
---------------|------------|------------|-------------------------|---------------|-------------------
io_ev_fd       | io_uring/eventfd.c | eventfd_ctx, uint, uint, refcount_t, atomic_t, rcu_head | io_eventfd_free | io_uring/eventfd.c | local variable
| | | | io_eventfd_put | io_uring/eventfd.c | function parameter
| | | | io_eventfd_do_signal | io_uring/eventfd.c | local variable, function parameter
| | | | __io_eventfd_signal | io_uring/eventfd.c | function parameter
| | | | io_eventfd_grab | io_uring/eventfd.c | return value, local variable
| | | | io_eventfd_signal | io_uring/eventfd.c | local variable 
| | | | io_eventfd_flush_signal | io_uring/eventfd.c | local variable
| | | | io_eventfd_register | io_uring/eventfd.c | local variable
| | | | io_eventfd_unregister | io_uring/eventfd.c | function parameter

If the following row value in a column is missing, assume the value is the same with the previous row in the same column. 
Continue until all data structures documented properly.

| Structure name | Defined in           | Attributes                                               | Caller Functions Source | source caller         | usage                            |
|----------------|----------------------|----------------------------------------------------------|--------------------------|------------------------|----------------------------------|
| io_ev_fd       | io_uring/eventfd.c   | eventfd_ctx, uint, uint, refcount_t, atomic_t, rcu_head | io_eventfd_free          | io_uring/eventfd.c     | local variable                   |
|                |                      |                                                          | io_eventfd_put           | io_uring/eventfd.c     | function parameter               |
|                |                      |                                                          | io_eventfd_do_signal     | io_uring/eventfd.c     | local variable, function parameter |
|                |                      |                                                          | __io_eventfd_signal      | io_uring/eventfd.c     | function parameter               |
|                |                      |                                                          | io_eventfd_grab          | io_uring/eventfd.c     | return value, local variable     |
|                |                      |                                                          | io_eventfd_signal        | io_uring/eventfd.c     | local variable                   |
|                |                      |                                                          | io_eventfd_flush_signal  | io_uring/eventfd.c     | local variable                   |
|                |                      |                                                          | io_eventfd_register      | io_uring/eventfd.c     | local variable                   |
|                |                      |                                                          | io_eventfd_unregister    | io_uring/eventfd.c     | function parameter               |
| io_fadvise     | io_uring/advise.c    | file, offset, len, advice                               | io_fadvise_force_async   | io_uring/advise.c      | function parameter               |
|                |                      |                                                          | io_fadvise_prep          | io_uring/advise.c      | local variable                   |
|                |                      |                                                          | io_fadvise               | io_uring/advise.c      | local variable                   |
| io_madvise     | io_uring/advise.c    | file, addr, len, advice                                 | io_madvise_prep          | io_uring/advise.c      | local variable                   |
|                |                      |                                                          | io_madvise               | io_uring/advise.c      | local variable                   |
| io_cancel        | io_uring/cancel.c    | file, addr, flags, fd, opcode                            | io_async_cancel_prep       | io_uring/cancel.c      | local variable                   |
|                  |                      |                                                          | io_async_cancel            | io_uring/cancel.c      | local variable                   |
| io_cancel_data   | io_uring/cancel.h    | ctx, union(data, file*), opcode, flags, seq             | io_cancel_req_match        | io_uring/cancel.h      | parameter                        |
|                  |                      |                                                          | io_async_cancel_one        | io_uring/cancel.h      | parameter                        |
|                  |                      |                                                          | io_try_cancel              | io_uring/cancel.h      | parameter                        |
|                  |                      |                                                          | __io_async_cancel          | io_uring/cancel.h      | local variable                   |
|                  |                      |                                                          | io_async_cancel            | io_uring/cancel.h      | local variable                   |
|                  |                      |                                                          | __io_sync_cancel           | io_uring/cancel.h      | parameter                        |
|                  |                      |                                                          | io_sync_cancel             | io_uring/cancel.h      | local variable                   |
| io_epoll       | io_uring/epoll.c   | file, epfd, op, fd, event                                       | io_epoll_ctl_prep        | io_uring/epoll.c      | local variable     |
|                |                    |                                                                  | io_epoll_ctl             | io_uring/epoll.c      | local variable     |
| io_rename      | io_uring/fs.c      | file, old_dfd, new_dfd, oldpath, newpath, flags                | io_renameat_prep         | io_uring/fs.c         | local variable     |
|                |                    |                                                                  | io_renameat              | io_uring/fs.c         | local variable     |
|                |                    |                                                                  | io_renameat_cleanup      | io_uring/fs.c         | local variable     |
| io_unlink      | io_uring/fs.c      | file, dfd, flags, filename                                     | io_unlinkat_prep         | io_uring/fs.c         | local variable     |
|                |                    |                                                                  | io_unlinkat              | io_uring/fs.c         | local variable     |
|                |                    |                                                                  | io_unlinkat_cleanup      | io_uring/fs.c         | local variable     |
| io_mkdir       | io_uring/fs.c      | file, dfd, mode, filename                                      | io_mkdirat_prep          | io_uring/fs.c         | local variable     |
|                |                    |                                                                  | io_mkdirat               | io_uring/fs.c         | local variable     |
|                |                    |                                                                  | io_mkdirat_cleanup       | io_uring/fs.c         | local variable     |
| io_link        | io_uring/fs.c      | file, old_dfd, new_dfd, filename, filename, flags             | io_symlinkat_prep        | io_uring/fs.c         | local variable     |
|                |                    |                                                                  | io_symlinkat             | io_uring/fs.c         | local variable     |
|                |                    |                                                                  | io_linkat_prep           | io_uring/fs.c         | local variable     |
|                |                    |                                                                  | io_linkat                | io_uring/fs.c         | local variable     |
|                |                    |                                                                  | io_link_cleanup          | io_uring/fs.c         | local variable     |
| io_futex         | io_uring/futex.c    | file, uaddr/uwaitv, futex_val, futex_mask, futexv_owned, futex_flags, futex_nr, futexv_unqueued | io_futex_prep             | io_uring/futex.c       | local variable                   |
|                  |                     |                                                                                            | io_futexv_prep            | io_uring/futex.c       | local variable                   |
|                  |                     |                                                                                            | io_futexv_wait            | io_uring/futex.c       | local variable                   |
|                  |                     |                                                                                            | io_futex_wait             | io_uring/futex.c       | local variable                   |
|                  |                     |                                                                                            | io_futex_wake             | io_uring/futex.c       | local variable                   |
|                  |                     |                                                                                            | __io_futex_cancel         | io_uring/futex.c       | local variable                   |
|                  |                     |                                                                                            | io_futexv_complete        | io_uring/futex.c       | local variable                   |
|                  |                     |                                                                                            | io_futexv_claim           | io_uring/futex.c       | parameter                        |
|                  |                     |                                                                                            | io_futex_wakev_fn         | io_uring/futex.c       | local variable                   |
| io_futex_data    | io_uring/futex.c    | futex_q, io_kiocb                                                                          | io_futex_wait             | io_uring/futex.c       | local variable                   |
|                  |                     |                                                                                            | __io_futex_cancel         | io_uring/futex.c       | local variable                   |
|                  |                     |                                                                                            | io_futex_complete         | io_uring/futex.c       | local variable                   |
|                  |                     |                                                                                            | io_alloc_ifd              | io_uring/futex.c       | return value                     |
|                  |                     |                                                                                            | io_futex_wake_fn          | io_uring/futex.c       | container_of                     |
| io_defer_entry   | io_uring/io_uring.c    | list_head, io_kiocb, u32                                 | io_queue_deferred          | io_uring/io_uring.c      | local variable     |
|                  |                        |                                                           | io_drain_req               | io_uring/io_uring.c      | local variable     |
|                  |                        |                                                           | io_cancel_defer_files      | io_uring/io_uring.c      | local variable     |
| io_wait_queue    | io_uring/io_uring.h    | wait_queue_entry_wq, io_ring_ctx, cq_tail, nr_timeouts, timeout | io_wake_function      | io_uring/io_uring.c      | local variable     |
|                  |                        |                                                           | io_cqring_wait_schedule     | io_uring/io_uring.c      | local variable     |
|                  |                        |                                                           | io_cqing_wait               | io_uring/io_uring.c      | local variable     |
| io_msg           | io_uring/io_msg.c      | file, src_file, tw, user_data, len, cmd, src_fd, dst_fd / cqe_flags, flags | io_msg_ring_prep  | io_uring/io_msg.c        | local variable     |
|                  |                        |                                                           | io_msg_tw_fd_complete       | io_uring/io_msg.c        | container_of       |
| io_napi_entry    | io_uring/io_napi.c     | napi_id, list, timeout, node, rcu                        | __io_napi_add              | io_uring/io_napi.c       | local variable     |
|                  |                        |                                                           | __io_napi_remove_stale      | io_uring/io_napi.c       | local variable     |
|                  |                        |                                                           | __io_napi_do_busy_loop      | io_uring/io_napi.c       | local variable     |
| io_nop             | io_uring/nop.c       | file, result                                            | io_nop_prep              | io_uring/nop.c         | local variable     |
|                    |                      |                                                         | io_nop                   | io_uring/nop.c         | local variable     |
| io_notif_data      | io_uring/notif.h     | file, uarg, next, head, account_pages, zc_report, zc_used, zc_copied | io_notif_to_data  | io_uring/notif.h       | local variable     |
|                    |                      |                                                         | io_notif_flush           | io_uring/notif.h       | local variable     |
|                    |                      |                                                         | io_notif_account_mem     | io_uring/notif.h       | local variable     |
| io_issue_def       | io_uring/opdef.h     | needs_file, plug, hash_reg_file, unbound_nonreg_file, pollin, pollout, poll_exclusive, buffer_select, audit_skip, ioprio, iopoll, iopoll_queue, vectored, async_size, issue, prep |                          |                        |                    |
| io_open          | io_uring/openclose.c | file, dfd, file_slot, filename, how, nofile              | __io_openat_prep           | io_uring/openclose.c    | local variable             |
|                  |                      |                                                          | io_openat_prep             | io_uring/openclose.c    | local variable             |
|                  |                      |                                                          | io_openat2_prep            | io_uring/openclose.c    | local variable             |
|                  |                      |                                                          | io_openat                  | io_uring/openclose.c    | local variable             |
|                  |                      |                                                          | io_open_cleanup            | io_uring/openclose.c    | local variable             |
| io_close         | io_uring/openclose.c | file, fd, file_slot                                      | io_close_prep              | io_uring/openclose.c    | local variable             |
|                  |                      |                                                          | io_close                   | io_uring/openclose.c    | via req (converted cmd)    |
| io_fixed_install | io_uring/openclose.c | file, o_flags                                            | io_install_fixed_fd_prep   | io_uring/openclose.c    | local variable             |
|                  |                      |                                                          | io_install_fixed_fd        | io_uring/openclose.c    | local variable             |
| io_poll_update   | io_uring/poll.c      | file, old_user_data, new_user_data                                    | io_poll_update             | io_uring/poll.c       | local variable     |
| io_poll_table    | io_uring/poll.c      | poll_table_struct, io_kiocb, nr_entries, error, owning                | io_poll_table              | io_uring/poll.c       | local variable     |
| io_poll          | io_uring/poll.h      | file, wait_queue_head, _poll_t events, retries, wait_queue_entry     | io_poll                   | io_uring/poll.h       | local variable     |
| async_poll       | io_uring/poll.h      | io_poll poll, io_poll *double_poll                                    | async_poll                | io_uring/poll.h       | local variable     |
| io_rsrc_update   | io_uring/rsrc.c      | file, arg, nr_args, offset                                            | io_rsrc_update            | io_uring/rsrc.c       | local variable     |
| io_rsrc_put      | io_uring/rsrc.h      | tag, union (*rsrc, file, io_mapped_ubuf)                             | io_rsrc_put               | io_uring/rsrc.h       | local variable     |
| io_rsrc_data     | io_uring/rsrc.h      | **tags, unint, rsrc_type, quiesce                                    | io_rsrc_data              | io_uring/rsrc.h       | local variable     |
| io_rsrc_node     | io_uring/rsrc.h      | io_ring_ctx, refs, empty, type, list_head, io_rsrc_put               | io_rsrc_node              | io_uring/rsrc.h       | local variable     |
| io_mapped_ubuf   | io_uring/rsrc.h      | ubuf, ubuf_end, nr_bvecs, acct_pages, bio_vec                        | io_mapped_ubuf            | io_uring/rsrc.h       | local variable     |
| io_rw            | io_uring/rw.c        | kiocb, addr, len, flags                                              | io_rw                     | io_uring/rw.c         | local variable     |
| io_async_rw      | io_uring/rw.h        | bytes_cone, iov_iter, iov_iter_state, iovec, iovec, free_iov_nr, wait_page_queue | io_async_rw          | io_uring/rw.h         | local variable     |
| io_splice       | io_uring/splice.c   | file, off_out, off_in, len, splice_fd_in, flags                   | io_splice                | io_uring/splice.c     | local variable     |
| io_sq_data      | io_uring/sqpoll.c   | Refs, park_pending, muex, list_head, task_struct, wait_queue_head, sq_thread_idle, sq_cpu, task_pid, task_tgid, work_time, tate, completion | io_sq_data         | io_uring/sqpoll.c    | local variable     |
| io_statx        | io_uring/statx.c    | file, dfd, mask, flags, filename, stats_user                      | io_statx                 | io_uring/statx.c      | local variable     |
| io_sync         | io_uring/sync.c     | file, len, off, flags, mode                                       | io_sync                  | io_uring/sync.c       | local variable     |
| io_tctx_node    | io_uring/tctx.h     | list_head, task_struct, io_ring_ctx                               | io_tctx_node             | io_uring/tctx.h       | local variable     |
| io_timeout      | io_uring/timeout.c  | file, off, target_seq, repeats, list head, io_kiocb, io_kiocb    | io_timeout               | io_uring/timeout.c    | local variable     |
| io_timeout_rem  | io_uring/timeout.c  | file, addr, timespec64, flags, ltimeout                           | io_timeout_rem           | io_uring/timeout.c    | local variable     |
| io_timeout_data | io_uring/timeout.h  | io_kiocb, hrtimer, timspace64, hrtimer_mode, flags               | io_timeout_data          | io_uring/timeout.h    | local variable     |
| io_ftrunc       | io_uring/truncate.c | file, len                                                        | io_ftrunc                | io_uring/truncate.c   | local variable     |
| uring_cache     | io_uring/uring_cmd.h| io_uring_sqe                                                   | uring_cache              | io_uring/uring_cmd.h  | local variable     |
| io_waitid        | io_uring/waitid.c    | File, which, upid, options, refs, wait_queue_head, siginfo__user, waitidio_info | io_waitid            | io_uring/waitid.c    | local variable     |
| io_waitid_async  | io_uring/waitid.h    | io_kiocb, wait_opts                                | io_waitid_async          | io_uring/waitid.h    | local variable     |
| io_xattr         | io_uring/xattr.c     | file, xattr_ctx, filename                          | io_xattr                 | io_uring/xattr.c     | local variable     |