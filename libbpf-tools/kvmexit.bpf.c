/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2021 Hengqi Chen */
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "kvmexit.h"

SEC("tracepoint/kvm/kvm_exit")
int BPF_PROG(kvm_exit)
{
	return probe_entry(ctx, (const char *)ctx->args[0]);
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
