/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef __BPFLOG_H
#define __BPFLOG_H

#define LINE_LIMIT	8192
#define TASK_COMM_LEN	16
struct log {
	__u64 cgroup_id;
	__u64 len;
	__u32 pid;
	char comm[TASK_COMM_LEN];
	char content[LINE_LIMIT];
};

#endif /* __BPFLOG_H */
