
/*
 * Copyright (c) 2018, 2019 The University of Queensland
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <sys/types.h>
#include <sys/event.h>
#include <sys/time.h>
#include <sys/ioctl.h>

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <err.h>
#include <time.h>
#include <poll.h>

#include "/sys/dev/acct.h"

#ifndef nitems
#define nitems(_a) (sizeof((_a)) / sizeof((_a)[0]))
#endif

#define DEV_ACCT "/dev/acct"

__dead static void
usage(void)
{
	extern char *__progname;

	fprintf(stderr, "usage: %s [-knptvw] [/dev/acct]\n", __progname);
	exit(1);
}

static uint8_t buffer[65536];
static int verbose = 0;
static unsigned int tries = 1;

static void handle_fork(void *msg);
static void handle_exec(void *msg);
static void handle_exit(void *msg);

struct acct_msg_type {
	const char *name;
	unsigned short len;
	void (*print)(void *);
};

static const struct acct_msg_type acct_msg_types[] = {
	[ACCT_MSG_FORK] = { "fork", sizeof(struct acct_fork), handle_fork },
	[ACCT_MSG_EXEC] = { "exec", sizeof(struct acct_exec), handle_exec },
	[ACCT_MSG_EXIT] = { "exit", sizeof(struct acct_exit), handle_exit },
};

static void
print_etime(const struct acct_common *comm)
{
	printf(" at +%lld", comm->ac_etime.tv_sec);
	if (verbose > 1)
		printf(".%09ld", comm->ac_etime.tv_nsec);
}

static void
handle_fork(void *msg)
{
	struct acct_fork *fork = msg;
	struct acct_common *comm = &fork->ac_common;

	printf("fork: %5d (%s) forked %5d", comm->ac_pid, comm->ac_comm,
	    fork->ac_cpid);
	if (verbose)
		print_etime(comm);
	printf("\n");
}

static void
handle_exec(void *msg)
{
	struct acct_exec *exec = msg;
	struct acct_common *comm = &exec->ac_common;

	printf("exec: %5d (%s)", comm->ac_pid, comm->ac_comm);
	if (verbose)
		print_etime(comm);
	printf("\n");
}

static void
handle_exit(void *msg)
{
	struct acct_exit *exit = msg;
	struct acct_common *comm = &exit->ac_common;

	printf("exit: %5d (%s)", comm->ac_pid, comm->ac_comm);
	if (verbose)
		print_etime(comm);

	printf(" user time %lld", exit->ac_utime.tv_sec);
	if (verbose)
		printf(".%09ld", exit->ac_utime.tv_nsec);
	printf(" system time %lld", exit->ac_stime.tv_sec);
	if (verbose)
		printf(".%09ld", exit->ac_stime.tv_nsec);
	printf(" memory %llu", exit->ac_mem);
	printf(" io %llu", exit->ac_io);

	printf("\n");
}

static void
acct_read(int fd, unsigned int *seqp)
{
	ssize_t rv;
	struct acct_common *comm;
	const struct acct_msg_type *type;
	unsigned int seq;

	rv = read(fd, buffer, sizeof(buffer));
	switch (rv) {
	case -1:
		switch (errno) {
		case EINTR:
		case EAGAIN:
			warn("read");
			return;
		default:
			break;
		}
		err(1, "read");
		/* NOTREACHED */
	default:
		break;
	}

	if (rv < (ssize_t)sizeof(*comm))
		errx(1, "short read: %zu < %zu", rv, sizeof(*comm));

	comm = (struct acct_common *)buffer;
	if (comm->ac_len != rv)
		errx(1, "inconsistent len: %zd < %u", rv, comm->ac_len);
	if (comm->ac_type >= nitems(acct_msg_types))
		errx(1, "invalid type: %u\n", comm->ac_type);

	type = &acct_msg_types[comm->ac_type];
	if (comm->ac_len < type->len) {
		errx(1, "short %s message: %u < %u", type->name, comm->ac_len,
		    type->len);
	}

	seq = *seqp;
	if (seq != comm->ac_seq) {
		warnx("%s message: unexpected seq number %u != %u", type->name,
		    comm->ac_seq, seq);
	}
        if (comm->ac_seq == 0x40000000)
                *seqp = 0x01;
        else
	        *seqp = comm->ac_seq << 1;

	(*type->print)(comm);
}

static void
acct_loop(int fd, unsigned int *seqp)
{
	for (;;) {
		acct_read(fd, seqp);
	}
}

static void
acct_tries(int fd, unsigned int *seqp)
{
	unsigned int i;

	for (i = 1; i <= tries; i++) {
		if (verbose)
			printf("- read try %u/%u\n", i, tries);
		acct_read(fd, seqp);
	}
}

static void
acct_poll(int fd, unsigned int *seqp)
{
	struct pollfd pfd[1];
	int rv;

	for (;;) {
		pfd[0].fd = fd;
		pfd[0].events = POLLIN;
		pfd[0].revents = 0;

		rv = poll(pfd, 1, INFTIM);
		if (verbose)
			printf("- poll returned (%d)\n", rv);
		switch (rv) {
		case 1:
			if (pfd[0].revents & POLLIN)
				acct_tries(fd, seqp);
			else
				warn("unexpected revents %x", pfd[0].revents);
			break;
		case 0:
			break;
		case -1:
			err(1, "poll");
			/* NOTREACHED */
		default:
			errx(1, "poll returned %d", rv);
			/* NOTREACHED */
		}
	}
}

static void
acct_kq(int fd, unsigned int *seqp)
{
	struct kevent kev[1];
	int kq;
	int rv;

	kq = kqueue();
	if (kq == -1)
		err(1, "kqueue");

	EV_SET(&kev[0], fd, EVFILT_READ, EV_ADD, 0, 0, 0);

	rv = kevent(kq, kev, 1, NULL, 0, NULL);
	if (rv == -1)
		err(1, "kevent set");

	for (;;) {
		rv = kevent(kq, NULL, 0, kev, 1, NULL);
		if (verbose)
			printf("- kevent returned (%d)\n", rv);

		switch (rv) {
		case 1:
			if (verbose)
				printf("- kevent data %lld\n", kev[0].data);
			acct_tries(fd, seqp);
			break;
		case 0:
			break;
		case -1:
			err(1, "kevent");
			/* NOTREACHED */
		default:
			exit(1);
		}
	}
}

int
main(int argc, char *argv[])
{
	const char *dev_acct = DEV_ACCT;
	int fd;
	unsigned int seq = 0x01;
	int oflags = 0;
	void (*loop)(int, unsigned int *) = acct_loop;
	int ch;
	int fionbio = 0;

	while ((ch = getopt(argc, argv, "iknNptvw")) != -1) {
		switch (ch) {
		case 'i':
			fionbio = 1;
			break;
		case 'k':
			loop = acct_kq;
			break;
		case 'n':
			oflags |= O_NONBLOCK;
			break;
		case 'p':
			loop = acct_poll;
			break;
		case 't':
			tries++;
			break;
		case 'v':
			verbose++;
			break;
		case 'w':
			oflags |= O_RDWR;
			break;
		default:
			usage();
		}
	}

	argc -= optind;
	argv += optind;

	switch (argc) {
	case 1:
		dev_acct = argv[0];
		/* FALLTHROUGH */
	case 0:
		break;
	default:
		usage();
	}

	fd = open(dev_acct, O_RDONLY | oflags);
	if (fd == -1) {
		err(1, "%s%s%s", dev_acct,
		    (oflags & O_RDWR) ? " O_RDWR" : " O_RDONLY",
		    (oflags & O_NONBLOCK) ? " O_NONBLOCK" : "");
	}

	if (fionbio) {
		int on = 1;
		if (ioctl(fd, FIONBIO, &on) == -1)
			err(1, "FIONBIO");
	}

	(*loop)(fd, &seq);
}
