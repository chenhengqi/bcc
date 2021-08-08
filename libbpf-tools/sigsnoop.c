/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */

/*
 * sigsnoop	Trace standard and real-time signals.
 *
 * Copyright (c) 2021 Hengqi Chen
 *
 * 08-Aug-2021   Hengqi Chen   Created this.
 */
#include <argp.h>
#include <libgen.h>
#include <errno.h>
#include <signal.h>
#include <string.h>
#include <time.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "sigsnoop.h"
#include "sigsnoop.skel.h"
#include "trace_helpers.h"

#define PERF_BUFFER_PAGES	16
#define PERF_POLL_TIMEOUT_MS	100
#define warn(...) fprintf(stderr, __VA_ARGS__)

static volatile sig_atomic_t exiting = 0;

static pid_t target_pid = 0;
static int target_signal = 0;
static bool failed_only = false;
static bool kill_only = false;
static bool signal_name = false;

static const char *sig_name[] = {
	[0] = "N/A",
	[1] = "SIGHUP",
	[2] = "SIGINT",
	[3] = "SIGQUIT",
	[4] = "SIGILL",
	[5] = "SIGTRAP",
	[6] = "SIGABRT",
	[6] = "SIGIOT",
	[7] = "SIGBUS",
	[8] = "SIGFPE",
	[9] = "SIGKILL",
	[10] = "SIGUSR1",
	[11] = "SIGSEGV",
	[12] = "SIGUSR2",
	[13] = "SIGPIPE",
	[14] = "SIGALRM",
	[15] = "SIGTERM",
	[16] = "SIGSTKFLT",
	[17] = "SIGCHLD",
	[18] = "SIGCONT",
	[19] = "SIGSTOP",
	[20] = "SIGTSTP",
	[21] = "SIGTTIN",
	[22] = "SIGTTOU",
	[23] = "SIGURG",
	[24] = "SIGXCPU",
	[25] = "SIGXFSZ",
	[26] = "SIGVTALRM",
	[27] = "SIGPROF",
	[28] = "SIGWINCH",
	[29] = "SIGIO",
	[30] = "SIGPWR",
	[31] = "SIGSYS",
};

const char *argp_program_version = "sigsnoop 0.1";
const char *argp_program_bug_address =
	"https://github.com/iovisor/bcc/tree/master/libbpf-tools";
const char argp_program_doc[] =
"Trace standard and real-time signals.\n"
"\n"
"USAGE: sigsnoop [-h] [-x] [-k] [-n] [-p PID] [-s SIGNAL]\n"
"\n"
"EXAMPLES:\n"
"    sigsnoop             # trace signals system-wide\n"
"    sigsnoop -k          # trace signals issued by kill syscall only\n"
"    sigsnoop -x          # trace failed signals only\n"
"    sigsnoop -p 1216     # only trace PID 1216\n"
"    sigsnoop -s 9        # only trace signal 9\n";

static const struct argp_option opts[] = {
	{ "failed", 'x', NULL, 0, "Trace failed signals only." },
	{ "kill", 'k', NULL, 0, "Trace signals issued by kill syscall only." },
	{ "pid", 'p', "PID", 0, "Process ID to trace" },
	{ "signal", 's', "SIGNAL", 0, "Signal to trace." },
	{ "name", 'n', NULL, 0, "Output signal name instead of signal number." },
	{ NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help" },
	{},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	long pid, sig;

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
	case 's':
		errno = 0;
		sig = strtol(arg, NULL, 10);
		if (errno || sig <= 0) {
			warn("Invalid SIGNAL: %s\n", arg);
			argp_usage(state);
		}
		target_signal = sig;
		break;
	case 'n':
		signal_name = true;
		break;
	case 'x':
		failed_only = true;
		break;
	case 'k':
		kill_only = true;
		break;
	case 'h':
		argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}
	return 0;
}

static void alias_parse(char *prog)
{
	char *name = basename(prog);

	if (!strcmp(name, "killsnoop")) {
		kill_only = true;
	}
}

static void sig_int(int signo)
{
	exiting = 1;
}

static void handle_event(void *ctx, int cpu, void *data, __u32 data_sz)
{
	struct event *e = data;
	time_t t;
	struct tm *tm;
	char ts[32];

	time(&t);
	tm = localtime(&t);
	strftime(ts, sizeof(ts), "%H:%M:%S", tm);
	if (signal_name)
		printf("%-8s %-7d %-16s %-9s %-7d %-6d\n",
		       ts, e->pid, e->comm, sig_name[e->sig], e->tpid, e->ret);
	else
		printf("%-8s %-7d %-16s %-9d %-7d %-6d\n",
		       ts, e->pid, e->comm, e->sig, e->tpid, e->ret);
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
	struct sigsnoop_bpf *obj;
	int err;

	alias_parse(argv[0]);
	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

	err = bump_memlock_rlimit();
	if (err) {
		warn("failed to increase rlimit: %d\n", err);
		return 1;
	}

	obj = sigsnoop_bpf__open();
	if (!obj) {
		warn("failed to open BPF object\n");
		return 1;
	}

	obj->rodata->target_pid = target_pid;
	obj->rodata->target_signal = target_signal;
	obj->rodata->failed_only = failed_only;

	if (kill_only) {
		bpf_program__set_autoload(obj->progs.sig_trace, false);
	} else {
		bpf_program__set_autoload(obj->progs.kill_entry, false);
		bpf_program__set_autoload(obj->progs.kill_exit, false);
		bpf_program__set_autoload(obj->progs.tkill_entry, false);
		bpf_program__set_autoload(obj->progs.tkill_exit, false);
		bpf_program__set_autoload(obj->progs.tgkill_entry, false);
		bpf_program__set_autoload(obj->progs.tgkill_exit, false);
	}

	err = sigsnoop_bpf__load(obj);
	if (err) {
		warn("failed to load BPF object: %d\n", err);
		goto cleanup;
	}

	err = sigsnoop_bpf__attach(obj);
	if (err) {
		warn("failed to attach BPF programs: %d\n", err);
		goto cleanup;
	}

	pb_opts.sample_cb = handle_event;
	pb_opts.lost_cb = handle_lost_events;
	pb = perf_buffer__new(bpf_map__fd(obj->maps.events), PERF_BUFFER_PAGES, &pb_opts);
	err = libbpf_get_error(pb);
	if (err) {
		warn("failed to open perf buffer: %d\n", err);
		goto cleanup;
	}

	if (signal(SIGINT, sig_int) == SIG_ERR) {
		warn("can't set signal handler: %s\n", strerror(-errno));
		goto cleanup;
	}

	printf("%-8s %-7s %-16s %-9s %-7s %-6s\n",
	       "TIME", "PID", "COMM", "SIG", "TPID", "RESULT");

	while (1) {
		err = perf_buffer__poll(pb, PERF_POLL_TIMEOUT_MS);
		if (err == -EINTR) {
 			err = 0;
 			goto cleanup;
 		}

		if (err < 0)
			break;
		if (exiting)
			goto cleanup;
	}
	warn("error polling perf buffer: %d\n", err);

cleanup:
	perf_buffer__free(pb);
	sigsnoop_bpf__destroy(obj);

	return err != 0;
}
