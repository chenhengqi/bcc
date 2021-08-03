/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef __BPFLOG_H
#define __BPFLOG_H

#define LINE_LIMIT	8192

struct log {
	size_t len;
	char content[LINE_LIMIT];
};

#endif /* __BPFLOG_H */
