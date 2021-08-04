/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2021 Hengqi Chen */
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include "maps.bpf.h"
#include "bpflog.h"

#define MAX_ENTRIES	1024

static const int zero = 0;
const char container_comm[16] = "runc:[2:INIT]";

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, __u64);
	__type(value, int);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} cgroup_ids SEC(".maps");

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
	char comm[16] = {};
	__u64 cgroup_id;
	int *ref_count;

	bpf_get_current_comm(comm, sizeof(comm));
	if (strequal(comm, container_comm)) {
		cgroup_id = bpf_get_current_cgroup_id();
		ref_count = bpf_map_lookup_or_try_init(&cgroup_ids, &cgroup_id, &zero);
		if (ref_count)
			__sync_fetch_and_add(ref_count, 1);
	}
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_write")
int trace_write(struct trace_event_raw_sys_enter *ctx)
{
	__u64 cgroup_id;
	struct log *log;
	int *ref_count;
	int fd = (int)ctx->args[0];

	if (fd != 1 && fd != 2)
		return 0;

	cgroup_id = bpf_get_current_cgroup_id();
	ref_count = bpf_map_lookup_elem(&cgroup_ids, &cgroup_id);
	if (!ref_count)
		return 0;

	log = bpf_map_lookup_elem(&heap, &zero);
	if (!log)
		return 0;

	bpf_probe_read_user(log->content, sizeof(log->content), (const char *)ctx->args[1]);
	log->len = (size_t)ctx->args[2];
	log->cgroup_id = cgroup_id;
	log->pid = bpf_get_current_pid_tgid() >> 32;
	bpf_get_current_comm(log->comm, sizeof(log->comm));
	bpf_perf_event_output(ctx, &logs, BPF_F_CURRENT_CPU, log, sizeof(*log));
	return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
