// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2021 Hengqi Chen
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>
#include "bindsnoop.h"

#define MAX_ENTRIES 10240
#define MAX_PORTS 1024

const volatile pid_t target_pid = 0;
const volatile int target_uid = -1;
const volatile bool ignore_error = true;
const volatile int ports[MAX_PORTS] = {};
const volatile int port_count = 0;
const volatile bool count_only = false;

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, __u32);
	__type(value, struct socket *);
} sockets SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, struct ipv4_flow_key_t);
	__type(value, __u64);
} ipv4_bind_count SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(__u32));
} ipv4_bind_events SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, struct ipv6_flow_key_t);
	__type(value, __u64);
} ipv6_bind_count SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(__u32));
} ipv6_bind_events SEC(".maps");

static void count(struct sock *sock, __u16 port, short ver)
{
	struct ipv4_flow_key_t ipv4_flow_key;
	struct ipv6_flow_key_t ipv6_flow_key;
	__u64 *count, one = 1;

	if (ver == 4) {
		ipv4_flow_key.saddr = sock->__sk_common.skc_rcv_saddr;
		ipv4_flow_key.sport = port;
		count = bpf_map_lookup_elem(&ipv4_bind_count, &ipv4_flow_key);
		if (!count) {
			bpf_map_update_elem(&ipv4_bind_count, &ipv4_flow_key, &one, BPF_ANY);
		} else {
			*count += 1;
		}
	} else {
		bpf_probe_read_kernel(&ipv6_flow_key.saddr, sizeof(ipv6_flow_key.saddr),
					sock->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
		ipv6_flow_key.sport = port;
		count = bpf_map_lookup_elem(&ipv6_bind_count, &ipv6_flow_key);
		if (!count) {
			bpf_map_update_elem(&ipv6_bind_count, &ipv6_flow_key, &one, BPF_ANY);
		} else {
			*count += 1;
		}
	}
}

static int probe_entry(struct pt_regs *ctx, struct socket *socket)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 pid = pid_tgid >> 32;
	__u32 tid = pid_tgid;
	__u32 uid;

	if (target_pid && target_pid != pid) {
		return 0;
	}

	uid = bpf_get_current_uid_gid();
	if (target_uid != -1 && target_uid != uid) {
		return 0;
	}

	// TODO: add container filter

	bpf_map_update_elem(&sockets, &tid, &socket, BPF_ANY);
	return 0;
};

static int probe_return(struct pt_regs *ctx, short ver)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 pid = pid_tgid >> 32;
	__u32 tid = pid_tgid;
	struct socket **socketp, *socket;
	struct inet_sock *inet_sock;
	struct sock *sock;
	int ret, i;
	__u16 sport = 0;
	bool matched = false;
	union bind_options opts = {};
	__u8 protocol;
	struct ipv4_bind_data_t ipv4_data;
	struct ipv6_bind_data_t ipv6_data;

	socketp = bpf_map_lookup_elem(&sockets, &tid);
	if (!socketp) {
		return 0;
	}

	ret = PT_REGS_RC(ctx);
	if (ret != 0 && ignore_error) {
		bpf_map_delete_elem(&sockets, &tid);
		return 0;
	}

	socket = *socketp;
	sock = socket->sk;
	inet_sock = (struct inet_sock *)sock;
	sport = bpf_ntohs(inet_sock->inet_sport);
	for (i = 0; i < port_count; i++) {
		if (ports[i] == sport) {
			matched = true;
			break;
		}
	}
	if (!matched) {
		bpf_map_delete_elem(&sockets, &tid);
		return 0;
	}

	if (count_only) {
		count(sock, sport, ver);
		bpf_map_delete_elem(&sockets, &tid);
		return 0;
	}

	opts.fields.freebind             = inet_sock->freebind;
	opts.fields.transparent          = inet_sock->transparent;
	opts.fields.bind_address_no_port = inet_sock->bind_address_no_port;
	opts.fields.reuseaddress         = sock->__sk_common.skc_reuse;
	opts.fields.reuseport            = sock->__sk_common.skc_reuseport;
	protocol = sock->sk_protocol;
	if (ver == 4) {
		ipv4_data.ts_us = bpf_ktime_get_ns() / 1000;
		ipv4_data.pid = pid;
		ipv4_data.uid = bpf_get_current_uid_gid();
		bpf_probe_read_kernel(&ipv4_data.saddr, sizeof(ipv4_data.saddr),
							&inet_sock->inet_saddr);
		ipv4_data.sport = sport;
		ipv4_data.bound_dev_if = sock->__sk_common.skc_bound_dev_if;
		ipv4_data.return_code = ret;
		ipv4_data.socket_options = opts.data;
		ipv4_data.protocol = protocol;
		bpf_get_current_comm(&ipv4_data.task, sizeof(ipv4_data.task));
		bpf_perf_event_output(ctx, &ipv4_bind_events, BPF_F_CURRENT_CPU,
							&ipv4_data, sizeof(ipv4_data));
	} else {
		ipv6_data.ts_us = bpf_ktime_get_ns() / 1000;
		ipv6_data.pid = pid;
		ipv6_data.uid = bpf_get_current_uid_gid();
		bpf_probe_read_kernel(&ipv6_data.saddr, sizeof(ipv6_data.saddr),
				sock->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
		ipv6_data.sport = sport;
		ipv6_data.bound_dev_if = sock->__sk_common.skc_bound_dev_if;
		ipv6_data.return_code = ret;
		ipv6_data.socket_options = opts.data;
		ipv6_data.protocol = protocol;
		bpf_get_current_comm(&ipv6_data.task, sizeof(ipv6_data.task));
		bpf_perf_event_output(ctx, &ipv6_bind_events, BPF_F_CURRENT_CPU,
							&ipv6_data, sizeof(ipv6_data));
	}
	bpf_map_delete_elem(&sockets, &tid);
	return 0;
}

SEC("kprobe/inet_bind")
int BPF_KPROBE(handle_ipv4_bind_entry, struct socket *socket)
{
	return probe_entry(ctx, socket);
}

SEC("kretprobe/inet_bind")
int BPF_KRETPROBE(handle_ipv4_bind_return)
{
	return probe_return(ctx, 4);
}

SEC("kprobe/inet6_bind")
int BPF_KPROBE(handle_ipv6_bind_entry, struct socket *socket)
{
	return probe_entry(ctx, socket);
}

SEC("kretprobe/inet6_bind")
int BPF_KRETPROBE(handle_ipv6_bind_return)
{
	return probe_return(ctx, 6);
}

char LICENSE[] SEC("license") = "GPL";
