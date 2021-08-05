/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2021 Hengqi Chen */
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include "maps.bpf.h"
#include "bpflog.h"

#define MAX_ENTRIES	10240

static const int zero = 0;
const char container_comm[16] = "runc:[2:INIT]";

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, __u32);
	__type(value, int);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} processes SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, __u32);
	__type(value, struct value);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} writes SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, struct log);
} heap SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(__u32));
} logs SEC(".maps");

static bool strequal(const char *a, const char *b)
{
	int i;

	for (int i = 0; i < 16; i++) {
		if (a[i] != b[i])
			return false;
	}
	return true;
}

SEC("tracepoint/syscalls/sys_enter_execve")
int trace_exec(struct trace_event_raw_sys_enter *ctx)
{
	struct task_struct *task;
	char comm[16] = {};
	__u32 ppid, pid;
	int *val;

	bpf_get_current_comm(comm, sizeof(comm));
	if (strequal(comm, container_comm)) {
		pid = bpf_get_current_pid_tgid() >> 32;
		bpf_map_update_elem(&processes, &pid, &zero, BPF_ANY);
		return 0;
	}

	task = (struct task_struct *)bpf_get_current_task();
	ppid = BPF_CORE_READ(task, real_parent, tgid);
	val = bpf_map_lookup_elem(&processes, &ppid);
	if (val) {
		pid = bpf_get_current_pid_tgid() >> 32;
		bpf_map_update_elem(&processes, &pid, &zero, BPF_ANY);
	}

	return 0;
}

SEC("tracepoint/sched/sched_process_exit")
int trace_exit(struct trace_event_raw_sys_enter *ctx)
{
	char comm[16] = {};
	__u32 pid;


	bpf_get_current_comm(comm, sizeof(comm));
	if (strequal(comm, container_comm))
		return 0;

	pid = bpf_get_current_pid_tgid() >> 32;
	bpf_map_delete_elem(&processes, &pid);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_write")
int trace_write(struct trace_event_raw_sys_enter *ctx)
{
	int fd = (int)ctx->args[0], *val;
	struct value args;
	__u64 pid_tgid;
	__u32 pid, tid;

	if (fd != 1 && fd != 2)
		return 0;

	pid_tgid = bpf_get_current_pid_tgid();
	pid = pid_tgid >> 32;
	tid = (__u32)pid_tgid;
	val = bpf_map_lookup_elem(&processes, &pid);
	if (!val)
		return 0;

	args.data = (const char *)ctx->args[1];
	args.len = (size_t)ctx->args[2];
	bpf_map_update_elem(&writes, &tid, &args, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_exit_write")
int trace_write_end(struct trace_event_raw_sys_exit *ctx)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 pid = pid_tgid >> 32;
	__u32 tid = (__u32)pid_tgid;
	struct value *args;
	struct log *log;

	args = bpf_map_lookup_elem(&writes, &tid);
	if (!args)
		return 0;

	log = bpf_map_lookup_elem(&heap, &zero);
	if (!log)
		return 0;

	log->pid = pid;
	log->len = args->len;
	log->ts = bpf_ktime_get_ns();
	bpf_probe_read_user(log->content, sizeof(log->content), args->data);
	bpf_get_current_comm(log->comm, sizeof(log->comm));
	bpf_perf_event_output(ctx, &logs, BPF_F_CURRENT_CPU, log, sizeof(*log));
	bpf_map_delete_elem(&writes, &tid);
	return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
