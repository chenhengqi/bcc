/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2021 Hengqi Chen */
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "mountsnoop.h"

#define MAX_ENTRIES 10240

const volatile pid_t target_pid = 0;

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, __u32);
	__type(value, struct arg);
} args SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, struct event);
} heap SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(__u32));
} events SEC(".maps");

static int probe_entry(const char *src, const char *dest, const char *fs,
		       __u64 flags, const char *data, enum op op)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 pid = pid_tgid >> 32;
	__u32 tid = (__u32)pid_tgid;
	struct arg arg = {};

	if (target_pid && target_pid != pid)
		return 0;

	arg.ts = bpf_ktime_get_ns();
	arg.flags = flags;
	arg.src = src;
	arg.dest = dest;
	arg.fs = fs;
	arg.data= data;
	arg.op = op;
	bpf_map_update_elem(&args, &tid, &arg, BPF_ANY);
	return 0;
};

static int probe_exit(void *ctx, int ret)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 pid = pid_tgid >> 32;
	__u32 tid = (__u32)pid_tgid;
	struct arg *argp;
	struct event *eventp;
	struct task_struct *task;
	int zero = 0;

	argp = bpf_map_lookup_elem(&args, &tid);
	if (!argp)
		return 0;

	eventp = bpf_map_lookup_elem(&heap, &zero);
	if (!eventp)
		return 0;

	task = (struct task_struct *)bpf_get_current_task();
	eventp->delta = bpf_ktime_get_ns() - argp->ts;
	eventp->flags = argp->flags;
	eventp->pid = pid;
	eventp->tid = tid;
	eventp->mnt_ns = BPF_CORE_READ(task, nsproxy, mnt_ns, ns.inum);
	eventp->ret = ret;
	eventp->op = argp->op;
	bpf_get_current_comm(&eventp->comm, sizeof(eventp->comm));
	if (argp->src)
		bpf_probe_read_user_str(eventp->src, sizeof(eventp->src), argp->src);
	else
		eventp->src[0] = '\0';
	if (argp->dest)
		bpf_probe_read_user_str(eventp->dest, sizeof(eventp->dest), argp->dest);
	else
		eventp->dest[0] = '\0';
	if (argp->fs)
		bpf_probe_read_user_str(eventp->fs, sizeof(eventp->fs), argp->fs);
	else
		eventp->fs[0] = '\0';
	if (argp->data)
		bpf_probe_read_user_str(eventp->data, sizeof(eventp->data), argp->data);
	else
		eventp->data[0] = '\0';
	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, eventp, sizeof(*eventp));

	bpf_map_delete_elem(&args, &tid);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_mount")
int mount_entry(struct trace_event_raw_sys_enter *ctx)
{
	const char *src = (const char *)ctx->args[0];
	const char *dest = (const char *)ctx->args[1];
	const char *fs = (const char *)ctx->args[2];
	__u64 flags = (__u64)ctx->args[3];
	const char *data = (const char *)ctx->args[4];

	return probe_entry(src, dest, fs, flags, data, MOUNT);
}

SEC("tracepoint/syscalls/sys_exit_mount")
int mount_exit(struct trace_event_raw_sys_exit *ctx)
{
	return probe_exit(ctx, (int)ctx->ret);
}

SEC("tracepoint/syscalls/sys_enter_umount")
int umount_entry(struct trace_event_raw_sys_enter *ctx)
{
	const char *dest = (const char *)ctx->args[0];
	__u64 flags = (__u64)ctx->args[1];

	return probe_entry(NULL, dest, NULL, flags, NULL, UMOUNT);
}

SEC("tracepoint/syscalls/sys_exit_umount")
int umount_exit(struct trace_event_raw_sys_exit *ctx)
{
	return probe_exit(ctx, (int)ctx->ret);
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, int);
	__type(value, int);
} map1 SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, int);
	__type(value, int);
} map2 SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, int);
	__type(value, int);
} map3 SEC(".maps");

// TARGET
// struct {
// 	__uint(type,BPF_MAP_TYPE_PERF_EVENT_ARRAY);
// 	__uint(max_entries, MAX_ENTRIES);
// 	__type(key, int);
// 	__type(value, int);
// } map4 SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, int);
	__type(value, int);
} map5 SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, int);
	__type(value, int);
} map6 SEC(".maps");

// TARGET
// struct {
// 	__uint(type, BPF_MAP_TYPE_STACK_TRACE);
// 	__uint(max_entries, MAX_ENTRIES);
// 	__type(key, int);
// 	__type(value, int);
// } map7 SEC(".maps");

// TARGET
// struct {
// 	__uint(type, BPF_MAP_TYPE_CGROUP_ARRAY);
// 	__uint(max_entries, MAX_ENTRIES);
// 	__type(key, int);
// 	__type(value, int);
// } map8 SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, int);
	__type(value, int);
} map9 SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_PERCPU_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, int);
	__type(value, int);
} map10 SEC(".maps");

// TARGET
// struct {
// 	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
// 	__uint(max_entries, MAX_ENTRIES);
// 	__type(key, int);
// 	__type(value, int);
// } map11 SEC(".maps");

// TARGET
// struct {
// 	__uint(type, BPF_MAP_TYPE_ARRAY_OF_MAPS);
// 	__uint(max_entries, MAX_ENTRIES);
// 	__type(key, int);
// 	__type(value, int);
// } map12 SEC(".maps");

// TARGET
// struct {
// 	__uint(type, BPF_MAP_TYPE_HASH_OF_MAPS);
// 	__uint(max_entries, MAX_ENTRIES);
// 	__type(key, int);
// 	__type(value, int);
// } map13 SEC(".maps");

// TARGET
// struct {
// 	__uint(type, BPF_MAP_TYPE_DEVMAP);
// 	__uint(max_entries, MAX_ENTRIES);
// 	__type(key, int);
// 	__type(value, int);
// } map14 SEC(".maps");

// TARGET
// struct {
// 	__uint(type, BPF_MAP_TYPE_SOCKMAP);
// 	__uint(max_entries, MAX_ENTRIES);
// 	__type(key, int);
// 	__type(value, int);
// } map15 SEC(".maps");

// TARGET
// struct {
// 	__uint(type, BPF_MAP_TYPE_CPUMAP);
// 	__uint(max_entries, MAX_ENTRIES);
// 	__type(key, int);
// 	__type(value, int);
// } map16 SEC(".maps");

// TARGET
// struct {
// 	__uint(type, BPF_MAP_TYPE_XSKMAP);
// 	__uint(max_entries, MAX_ENTRIES);
// 	__type(key, int);
// 	__type(value, int);
// } map17 SEC(".maps");

// TARGET
// struct {
// 	__uint(type, BPF_MAP_TYPE_SOCKHASH);
// 	__uint(max_entries, MAX_ENTRIES);
// 	__type(key, int);
// 	__type(value, int);
// } map18 SEC(".maps");

// TARGET
// struct {
// 	__uint(type, BPF_MAP_TYPE_CGROUP_STORAGE);
// 	__uint(max_entries, MAX_ENTRIES);
// 	__type(key, int);
// 	__type(value, int);
// } map19 SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_REUSEPORT_SOCKARRAY);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, int);
	__type(value, int);
} map20 SEC(".maps");

// TARGET
// struct {
// 	__uint(type, BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE);
// 	__uint(max_entries, MAX_ENTRIES);
// 	__type(key, int);
// 	__type(value, int);
// } map21 SEC(".maps");

// TARGET
// struct {
// 	__uint(type, BPF_MAP_TYPE_QUEUE);
// 	__uint(max_entries, MAX_ENTRIES);
// 	__type(key, int);
// 	__type(value, int);
// } map22 SEC(".maps");

// TARGET
// struct {
// 	__uint(type, BPF_MAP_TYPE_STACK);
// 	__uint(max_entries, MAX_ENTRIES);
// 	__type(key, int);
// 	__type(value, int);
// } map23 SEC(".maps");

// TARGET
// struct {
// 	__uint(type, BPF_MAP_TYPE_SK_STORAGE);
// 	__uint(max_entries, MAX_ENTRIES);
// 	__type(key, int);
// 	__type(value, int);
// } map24 SEC(".maps");

// TARGET
// struct {
// 	__uint(type, BPF_MAP_TYPE_DEVMAP_HASH);
// 	__uint(max_entries, MAX_ENTRIES);
// 	__type(key, int);
// 	__type(value, int);
// } map25 SEC(".maps");

// TARGET
// struct {
// 	__uint(type, BPF_MAP_TYPE_STRUCT_OPS);
// 	__uint(max_entries, MAX_ENTRIES);
// 	__type(key, int);
// 	__type(value, int);
// } map26 SEC(".maps");

// TARGET
// struct {
// 	__uint(type, BPF_MAP_TYPE_RINGBUF);
// 	__uint(max_entries, MAX_ENTRIES);
// 	__type(key, int);
// 	__type(value, int);
// } map27 SEC(".maps");

// TARGET
// struct {
// 	__uint(type, BPF_MAP_TYPE_INODE_STORAGE);
// 	__uint(max_entries, MAX_ENTRIES);
// 	__type(key, int);
// 	__type(value, int);
// } map28 SEC(".maps");

// TARGET
// struct {
// 	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
// 	__uint(max_entries, MAX_ENTRIES);
// 	__type(key, int);
// 	__type(value, int);
// } map29 SEC(".maps");
