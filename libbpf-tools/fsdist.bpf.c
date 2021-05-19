// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Copyright (c) 2021 Hengqi Chen
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "bits.bpf.h"
#include "fsdist.h"

#define MAX_ENTRIES	10240

const volatile pid_t target_pid = 0;
const volatile bool in_ms = false;

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, __u32);
	__type(value, __u64);
} starts SEC(".maps");

struct hist hists[MAX_OP] = {};

static int probe_entry()
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 pid = pid_tgid >> 32;
	__u32 tid = (__u32)pid_tgid;
	__u64 ts;

	if (target_pid && target_pid != pid)
		return 0;

	ts = bpf_ktime_get_ns();
	bpf_map_update_elem(&starts, &tid, &ts, BPF_ANY);
	return 0;
}

static int probe_return(enum fs_file_op op)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 pid = pid_tgid >> 32;
	__u32 tid = (__u32)pid_tgid;
	__u64 ts = bpf_ktime_get_ns();
	__u64 *tsp, slot;
	__s64 delta;

	tsp = bpf_map_lookup_elem(&starts, &tid);
	if (!tsp)
		return 0;

	if (op >= MAX_OP)
		goto cleanup;

	delta = (__s64)(ts - *tsp);
	if (delta < 0)
		goto cleanup;

	if (in_ms)
		delta /= 1000000;
	else
		delta /= 1000;

	slot = log2l(delta);
	if (slot >= MAX_SLOTS)
		slot = MAX_SLOTS - 1;
	__sync_fetch_and_add(&hists[op].slots[slot], 1);

cleanup:
	bpf_map_delete_elem(&starts, &tid);
	return 0;
}

// btrfs

SEC("kprobe/btrfs_file_read_iter")
int BPF_KPROBE(btrfs_file_read_entry)
{
	return probe_entry();
}

SEC("kretprobe/btrfs_file_read_iter")
int BPF_KRETPROBE(btrfs_file_read_return)
{
	return probe_return(READ);
}

SEC("kprobe/btrfs_file_write_iter")
int BPF_KPROBE(btrfs_file_write_entry)
{
	return probe_entry();
}

SEC("kretprobe/btrfs_file_write_iter")
int BPF_KRETPROBE(btrfs_file_write_return)
{
	return probe_return(WRITE);
}

SEC("kprobe/btrfs_file_open")
int BPF_KPROBE(btrfs_file_open_entry)
{
	return probe_entry();
}

SEC("kretprobe/btrfs_file_open")
int BPF_KRETPROBE(btrfs_file_open_return)
{
	return probe_return(OPEN);
}

SEC("kprobe/btrfs_sync_file")
int BPF_KPROBE(btrfs_file_sync_entry)
{
	return probe_entry();
}

SEC("kretprobe/btrfs_sync_file")
int BPF_KRETPROBE(btrfs_file_sync_return)
{
	return probe_return(FSYNC);
}

SEC("fentry/btrfs_file_read_iter")
int BPF_PROG(btrfs_file_read_fentry)
{
	return probe_entry();
}

SEC("fexit/btrfs_file_read_iter")
int BPF_PROG(btrfs_file_read_fexit)
{
	return probe_return(READ);
}

SEC("fentry/btrfs_file_write_iter")
int BPF_PROG(btrfs_file_write_fentry)
{
	return probe_entry();
}

SEC("fexit/btrfs_file_write_iter")
int BPF_PROG(btrfs_file_write_fexit)
{
	return probe_return(WRITE);
}

SEC("fentry/btrfs_file_open")
int BPF_PROG(btrfs_file_open_fentry)
{
	return probe_entry();
}

SEC("fexit/btrfs_file_open")
int BPF_PROG(btrfs_file_open_fexit)
{
	return probe_return(OPEN);
}

SEC("fentry/btrfs_sync_file")
int BPF_PROG(btrfs_file_sync_fentry)
{
	return probe_entry();
}

SEC("fexit/btrfs_sync_file")
int BPF_PROG(btrfs_file_sync_fexit)
{
	return probe_return(FSYNC);
}

// ext4fs

SEC("kprobe/ext4_file_read_iter")
int BPF_KPROBE(ext4_file_read_entry)
{
	return probe_entry();
}

SEC("kretprobe/ext4_file_read_iter")
int BPF_KRETPROBE(ext4_file_read_return)
{
	return probe_return(READ);
}

SEC("kprobe/ext4_file_write_iter")
int BPF_KPROBE(ext4_file_write_entry)
{
	return probe_entry();
}

SEC("kretprobe/ext4_file_write_iter")
int BPF_KRETPROBE(ext4_file_write_return)
{
	return probe_return(WRITE);
}

SEC("kprobe/ext4_file_open")
int BPF_KPROBE(ext4_file_open_entry)
{
	return probe_entry();
}

SEC("kretprobe/ext4_file_open")
int BPF_KRETPROBE(ext4_file_open_return)
{
	return probe_return(OPEN);
}

SEC("kprobe/ext4_sync_file")
int BPF_KPROBE(ext4_file_sync_entry)
{
	return probe_entry();
}

SEC("kretprobe/ext4_sync_file")
int BPF_KRETPROBE(ext4_file_sync_return)
{
	return probe_return(FSYNC);
}

SEC("kprobe/ext4_file_getattr")
int BPF_KPROBE(ext4_file_getattr_entry)
{
	return probe_entry();
}

SEC("kretprobe/ext4_file_getattr")
int BPF_KRETPROBE(ext4_file_getattr_return)
{
	return probe_return(GETATTR);
}

SEC("fentry/ext4_file_read_iter")
int BPF_PROG(ext4_file_read_fentry)
{
	return probe_entry();
}

SEC("fexit/ext4_file_read_iter")
int BPF_PROG(ext4_file_read_fexit)
{
	return probe_return(READ);
}

SEC("fentry/ext4_file_write_iter")
int BPF_PROG(ext4_file_write_fentry)
{
	return probe_entry();
}

SEC("fexit/ext4_file_write_iter")
int BPF_PROG(ext4_file_write_fexit)
{
	return probe_return(WRITE);
}

SEC("fentry/ext4_file_open")
int BPF_PROG(ext4_file_open_fentry)
{
	return probe_entry();
}

SEC("fexit/ext4_file_open")
int BPF_PROG(ext4_file_open_fexit)
{
	return probe_return(OPEN);
}

SEC("fentry/ext4_sync_file")
int BPF_PROG(ext4_file_sync_fentry)
{
	return probe_entry();
}

SEC("fexit/ext4_sync_file")
int BPF_PROG(ext4_file_sync_fexit)
{
	return probe_return(FSYNC);
}

SEC("fentry/ext4_file_getattr")
int BPF_PROG(ext4_file_getattr_fentry)
{
	return probe_entry();
}

SEC("fexit/ext4_file_getattr")
int BPF_PROG(ext4_file_getattr_fexit)
{
	return probe_return(GETATTR);
}

// nfs

SEC("kprobe/nfs_file_read")
int BPF_KPROBE(nfs_file_read_entry)
{
	return probe_entry();
}

SEC("kretprobe/nfs_file_read")
int BPF_KRETPROBE(nfs_file_read_return)
{
	return probe_return(READ);
}

SEC("kprobe/nfs_file_write")
int BPF_KPROBE(nfs_file_write_entry)
{
	return probe_entry();
}

SEC("kretprobe/nfs_file_write")
int BPF_KRETPROBE(nfs_file_write_return)
{
	return probe_return(WRITE);
}

SEC("kprobe/nfs_file_open")
int BPF_KPROBE(nfs_file_open_entry)
{
	return probe_entry();
}

SEC("kretprobe/nfs_file_open")
int BPF_KRETPROBE(nfs_file_open_return)
{
	return probe_return(OPEN);
}

SEC("kprobe/nfs_file_fsync")
int BPF_KPROBE(nfs_file_sync_entry)
{
	return probe_entry();
}

SEC("kretprobe/nfs_file_fsync")
int BPF_KRETPROBE(nfs_file_sync_return)
{
	return probe_return(FSYNC);
}

SEC("kprobe/nfs_getattr")
int BPF_KPROBE(nfs_getattr_entry)
{
	return probe_entry();
}

SEC("kretprobe/nfs_getattr")
int BPF_KRETPROBE(nfs_getattr_return)
{
	return probe_return(GETATTR);
}

SEC("fentry/nfs_file_read")
int BPF_PROG(nfs_file_read_fentry)
{
	return probe_entry();
}

SEC("fexit/nfs_file_read")
int BPF_PROG(nfs_file_read_fexit)
{
	return probe_return(READ);
}

SEC("fentry/nfs_file_write")
int BPF_PROG(nfs_file_write_fentry)
{
	return probe_entry();
}

SEC("fexit/nfs_file_write")
int BPF_PROG(nfs_file_write_fexit)
{
	return probe_return(WRITE);
}

SEC("fentry/nfs_file_open")
int BPF_PROG(nfs_file_open_fentry)
{
	return probe_entry();
}

SEC("fexit/nfs_file_open")
int BPF_PROG(nfs_file_open_fexit)
{
	return probe_return(OPEN);
}

SEC("fentry/nfs_file_fsync")
int BPF_PROG(nfs_file_sync_fentry)
{
	return probe_entry();
}

SEC("fexit/nfs_file_fsync")
int BPF_PROG(nfs_file_sync_fexit)
{
	return probe_return(FSYNC);
}

SEC("fentry/nfs_getattr")
int BPF_PROG(nfs_getattr_fentry)
{
	return probe_entry();
}

SEC("fexit/nfs_getattr")
int BPF_PROG(nfs_getattr_fexit)
{
	return probe_return(GETATTR);
}

// xfs

SEC("kprobe/xfs_file_read_iter")
int BPF_KPROBE(xfs_file_read_entry)
{
	return probe_entry();
}

SEC("kretprobe/xfs_file_read_iter")
int BPF_KRETPROBE(xfs_file_read_return)
{
	return probe_return(READ);
}

SEC("kprobe/xfs_file_write_iter")
int BPF_KPROBE(xfs_file_write_entry)
{
	return probe_entry();
}

SEC("kretprobe/xfs_file_write_iter")
int BPF_KRETPROBE(xfs_file_write_return)
{
	return probe_return(WRITE);
}

SEC("kprobe/xfs_file_open")
int BPF_KPROBE(xfs_file_open_entry)
{
	return probe_entry();
}

SEC("kretprobe/xfs_file_open")
int BPF_KRETPROBE(xfs_file_open_return)
{
	return probe_return(OPEN);
}

SEC("kprobe/xfs_file_fsync")
int BPF_KPROBE(xfs_file_sync_entry)
{
	return probe_entry();
}

SEC("kretprobe/xfs_file_fsync")
int BPF_KRETPROBE(xfs_file_sync_return)
{
	return probe_return(FSYNC);
}

SEC("fentry/xfs_file_read_iter")
int BPF_PROG(xfs_file_read_fentry)
{
	return probe_entry();
}

SEC("fexit/xfs_file_read_iter")
int BPF_PROG(xfs_file_read_fexit)
{
	return probe_return(READ);
}

SEC("fentry/xfs_file_write_iter")
int BPF_PROG(xfs_file_write_fentry)
{
	return probe_entry();
}

SEC("fexit/xfs_file_write_iter")
int BPF_PROG(xfs_file_write_fexit)
{
	return probe_return(WRITE);
}

SEC("fentry/xfs_file_open")
int BPF_PROG(xfs_file_open_fentry)
{
	return probe_entry();
}

SEC("fexit/xfs_file_open")
int BPF_PROG(xfs_file_open_fexit)
{
	return probe_return(OPEN);
}

SEC("fentry/xfs_file_fsync")
int BPF_PROG(xfs_file_sync_fentry)
{
	return probe_entry();
}

SEC("fexit/xfs_file_fsync")
int BPF_PROG(xfs_file_sync_fexit)
{
	return probe_return(FSYNC);
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
