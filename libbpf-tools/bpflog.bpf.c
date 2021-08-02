/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2021 Hengqi Chen */
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "maps.bpf.h"
#include "bpflog.h"

#define MAX_ENTRIES	10240

const char container_comm[16] = "containerd-shim";

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, __u64);
	__type(value, int);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} cgroup_ids SEC(".maps");

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
int tracepoint__syscalls__sys_enter_execve(struct trace_event_raw_sys_enter *ctx)
{
	static int zero = 0;
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

SEC("tracepoint/sched/sys_enter_execve")
int tracepoint__syscalls__sys_enter_execve(struct trace_event_raw_sys_enter *ctx)
{
	static int zero = 0;
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

char LICENSE[] SEC("license") = "Dual BSD/GPL";
