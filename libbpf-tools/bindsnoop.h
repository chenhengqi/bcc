/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef __BINDSNOOP_H
#define __BINDSNOOP_H

#define TASK_COMM_LEN	16

struct ipv4_bind_data {
	__u64 ts_us;
	__u32 pid;
	__u32 uid;
	__u32 saddr;
	__u32 bound_dev_if;
	int return_code;
	__u16 sport;
	__u8 socket_options;
	__u8 protocol;
	char task[TASK_COMM_LEN];
};

struct ipv4_flow_key {
	__u32 saddr;
	__u16 sport;
};

struct ipv6_bind_data {
	unsigned __int128 saddr;
	__u64 ts_us;
	__u32 pid;
	__u32 uid;
	__u32 bound_dev_if;
	int return_code;
	__u16 sport;
	__u8 socket_options;
	__u8 protocol;
	char task[TASK_COMM_LEN];
};

struct ipv6_flow_key {
	unsigned __int128 saddr;
	__u16 sport;
};

union bind_options {
	__u8 data;
	struct {
		__u8 freebind : 1;
		__u8 transparent : 1;
		__u8 bind_address_no_port : 1;
		__u8 reuseaddress : 1;
		__u8 reuseport : 1;
	} fields;
};

#endif /* __BINDSNOOP_H */
