// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Copyright (c) 2021 Hengqi Chen
//
// Based on bindsnoop(8) from BCC by Pavel Dubovitsky.
// 11-May-2021   Hengqi Chen   Created this.
#include <argp.h>
#include <errno.h>
#include <signal.h>
#include <string.h>
#include <time.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "bindsnoop.h"
#include "bindsnoop.skel.h"
#include "trace_helpers.h"

#define PERF_BUFFER_PAGES	16
#define PERF_POLL_TIMEOUT_MS	100
#define warn(...) fprintf(stderr, __VA_ARGS__)

static volatile sig_atomic_t exiting = 0;

static bool emit_timestamp = false;
static bool count_only = false;
static bool ignore_errors = true;
static pid_t target_pid = 0;
static char *target_ports = NULL;

const char *argp_program_version = "bindsnoop 0.1";
const char *argp_program_bug_address =
	"https://github.com/iovisor/bcc/tree/master/libbpf-tools";
const char argp_program_doc[] =
"Trace bind syscalls.\n"
"\n"
"USAGE: bindsnoop [-h] [-t] [-c] [-x] [-p PID] [-P ports]\n"
"\n"
"EXAMPLES:\n"
"    bindsnoop             # trace all bind syscall\n"
"    bindsnoop -t          # include timestamps\n"
"    bindsnoop -c          # count bind per source ip\n"
"    bindsnoop -x          # include errors on output\n"
"    bindsnoop -p 1216     # only trace PID 1216\n"
"    bindsnoop -P 80,81    # only trace port 80 and 81\n";

static const struct argp_option opts[] = {
	{ "timestamp", 't', NULL, 0, "Include timestamp on output" },
	{ "count", 'c', NULL, 0, "Count binds per source ip and port" },
	{ "failed", 'x', NULL, 0, "Include errors on output." },
	{ "pid", 'p', "PID", 0, "Process ID to trace" },
	{ "ports", 'P', "PORTS", 0, "Comma-separated list of ports to trace." },
	{ NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help" },
	{},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	long pid, port_num;
	char *port;

	switch (key) {
	case 'p':
		errno = 0;
		pid = strtol(arg, NULL, 10);
		if (errno || pid <= 0) {
			warn("Invalid PID: %s\n", arg);
			argp_usage(state);
		}
		target_pid = pid;
		break;
	case 'P':
		if (!arg) {
			warn("No ports specified\n");
			argp_usage(state);
		}
		target_ports = strdup(arg);
		port = strtok(arg, ",");
		while (port) {
			port_num = strtol(port, NULL, 10);
			if (errno || port_num <= 0 || port_num > 65536) {
				warn("Invalid ports: %s\n", arg);
				argp_usage(state);
			}
			port = strtok(NULL, ",");
		}
		break;
	case 'x':
		ignore_errors = false;
		break;
	case 'c':
		count_only = true;
	case 't':
		emit_timestamp = true;
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
	struct bindsnoop_bpf *obj;
	int err, port_map_fd;
	char *port;
	short port_num;

	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

	err = bump_memlock_rlimit();
	if (err) {
		warn("failed to increase rlimit: %d\n", err);
		return 1;
	}

	obj = bindsnoop_bpf__open();
	if (!obj) {
		warn("failed to open BPF object\n");
		return 1;
	}

	obj->rodata->target_pid = target_pid;
	obj->rodata->ignore_errors = ignore_errors;
	obj->rodata->filter_by_port = target_ports != NULL;
	obj->rodata->count_only = count_only;

	port_map_fd = bpf_map__fd(obj->maps.ports);
	port = strtok(target_ports, ",");
	while (port) {
		port_num = strtol(port, NULL, 10);
		bpf_map_update_elem(port_map_fd, &port_num, &port_num, BPF_ANY);
		port = strtok(NULL, ",");
	}

	err = bindsnoop_bpf__load(obj);
	if (err) {
		warn("failed to load BPF object: %d\n", err);
		goto cleanup;
	}

	err = bindsnoop_bpf__attach(obj);
	if (err) {
		warn("failed to attach BPF programs: %d\n", err);
		goto cleanup;
	}

	if (count_only) {
		// TODO: print count
	}

	// TODO: print events
	pb_opts.sample_cb = handle_event;
	pb_opts.lost_cb = handle_lost_events;
	pb = perf_buffer__new(bpf_map__fd(obj->maps.ipv4_bind_events), PERF_BUFFER_PAGES,
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

	if (emit_timestamp) {
		printf("%-11s", "TIME");
	}
	printf("%-10s %-20s %-4s %-4s %-s\n",
			"PID", "COMM", "RET", "ERR", "PATH");

	while (1) {
		if ((err = perf_buffer__poll(pb, PERF_POLL_TIMEOUT_MS)) < 0)
			break;
		if (exiting)
			goto cleanup;
	}
	warn("error polling perf buffer: %d\n", err);

cleanup:
	bindsnoop_bpf__destroy(obj);

	return err != 0;
}
