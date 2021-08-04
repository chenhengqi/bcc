/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */

/*
 * bpflog  Capture container logs.
 *
 * Copyright (c) 2021 Hengqi Chen
 *
 * 01-Aug-2021   Hengqi Chen   Created this.
 */
#include <argp.h>
#include <errno.h>
#include <signal.h>
#include <time.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "bpflog.h"
#include "bpflog.skel.h"
#include "trace_helpers.h"
#include "uprobe_helpers.h"

#define PERF_BUFFER_PAGES	1024
#define PERF_POLL_TIMEOUT_MS	100
#define warn(...) fprintf(stderr, __VA_ARGS__)

static volatile sig_atomic_t exiting = 0;

const char *argp_program_version = "bpflog 0.1";
const char *argp_program_bug_address =
	"https://github.com/iovisor/bcc/tree/master/libbpf-tools";
const char argp_program_doc[] =
"Show latency for getaddrinfo/gethostbyname[2] calls.\n"
"\n"
"USAGE: bpflog [-h] [-p PID] [-l LIBC]\n"
"\n"
"EXAMPLES:\n"
"    bpflog             # time getaddrinfo/gethostbyname[2] calls\n"
"    bpflog -p 1216     # only trace PID 1216\n";

static const struct argp_option opts[] = {
	{ "pid", 'p', "PID", 0, "Process ID to trace" },
	{ "libc", 'l', "LIBC", 0, "Specify which libc.so to use" },
	{ NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help" },
	{},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	long pid;

	switch (key) {
	case 'p':
		errno = 0;
		pid = strtol(arg, NULL, 10);
		if (errno || pid <= 0) {
			warn("Invalid PID: %s\n", arg);
			argp_usage(state);
		}
		break;
	case 'h':
		argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}
	return 0;
}

static void sig_int(int signo)
{
	exiting = 1;
}

static void handle_event(void *ctx, int cpu, void *data, __u32 data_sz)
{
	struct log *log = data;
	struct tm *tm;
	char ts[16], buf[LINE_LIMIT];
	time_t t;

	time(&t);
	tm = localtime(&t);
	strftime(ts, sizeof(ts), "%H:%M:%S", tm);
	printf("%d %s\n", log->pid, log->comm);
	if (log->len < 12) {
		printf("%-4lld ", log->len);
		for (int i = 0; i < log->len; i++) {
			printf("%x ", log->content[i]);
		}
		printf("\n");
	} else {
		memcpy(buf, log->content, log->len);
		printf("%-4lld %s", log->len, log->content);
	}
}

static void handle_lost_events(void *ctx, int cpu, __u64 lost_cnt)
{
	warn("lost %llu events on CPU #%d\n", lost_cnt, cpu);
}

int main(int argc, char **argv)
{
	static const struct argp argp = {
		.options = opts,
		.parser = parse_arg,
		.doc = argp_program_doc,
	};
	struct perf_buffer_opts pb_opts;
	struct perf_buffer *pb = NULL;
	struct bpflog_bpf *obj;
	int err;

	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

	err = bump_memlock_rlimit();
	if (err) {
		warn("failed to increase rlimit: %d\n", err);
		return 1;
	}

	obj = bpflog_bpf__open();
	if (!obj) {
		warn("failed to open BPF object\n");
		return 1;
	}

	err = bpflog_bpf__load(obj);
	if (err) {
		warn("failed to load BPF object: %d\n", err);
		goto cleanup;
	}

	err = bpflog_bpf__attach(obj);
	if (err) {
		warn("failed to attach BPF object: %d\n", err);
		goto cleanup;
	}

	pb_opts.sample_cb = handle_event;
	pb_opts.lost_cb = handle_lost_events;
	pb = perf_buffer__new(bpf_map__fd(obj->maps.logs), PERF_BUFFER_PAGES,
			&pb_opts);
	err = libbpf_get_error(pb);
	if (err) {
		warn("failed to open perf buffer: %d\n", err);
		goto cleanup;
	}

	if (signal(SIGINT, sig_int) == SIG_ERR) {
		warn("can't set signal handler: %s\n", strerror(-errno));
		goto cleanup;
	}

	while (1) {
		if ((err = perf_buffer__poll(pb, PERF_POLL_TIMEOUT_MS)) < 0)
			break;
		if (exiting)
			goto cleanup;
		sleep(1);
	}
	warn("error polling perf buffer: %d\n", err);

cleanup:
	perf_buffer__free(pb);
	bpflog_bpf__destroy(obj);

	return err != 0;
}
