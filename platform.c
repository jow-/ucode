/*
 * Copyright (C) 2023 Jo-Philipp Wich <jo@mein.io>
 *
 * Permission to use, copy, modify, and/or distribute this software for any
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

#include <errno.h>

#include "ucode/platform.h"

const char *uc_system_signal_names[UC_SYSTEM_SIGNAL_COUNT] = {
#if defined(SIGINT)
	[SIGINT] = "INT",
#endif
#if defined(SIGILL)
	[SIGILL] = "ILL",
#endif
#if defined(SIGABRT)
	[SIGABRT] = "ABRT",
#endif
#if defined(SIGFPE)
	[SIGFPE] = "FPE",
#endif
#if defined(SIGSEGV)
	[SIGSEGV] = "SEGV",
#endif
#if defined(SIGTERM)
	[SIGTERM] = "TERM",
#endif
#if defined(SIGHUP)
	[SIGHUP] = "HUP",
#endif
#if defined(SIGQUIT)
	[SIGQUIT] = "QUIT",
#endif
#if defined(SIGTRAP)
	[SIGTRAP] = "TRAP",
#endif
#if defined(SIGKILL)
	[SIGKILL] = "KILL",
#endif
#if defined(SIGPIPE)
	[SIGPIPE] = "PIPE",
#endif
#if defined(SIGALRM)
	[SIGALRM] = "ALRM",
#endif
#if defined(SIGSTKFLT)
	[SIGSTKFLT] = "STKFLT",
#endif
#if defined(SIGPWR)
	[SIGPWR] = "PWR",
#endif
#if defined(SIGBUS)
	[SIGBUS] = "BUS",
#endif
#if defined(SIGSYS)
	[SIGSYS] = "SYS",
#endif
#if defined(SIGURG)
	[SIGURG] = "URG",
#endif
#if defined(SIGSTOP)
	[SIGSTOP] = "STOP",
#endif
#if defined(SIGTSTP)
	[SIGTSTP] = "TSTP",
#endif
#if defined(SIGCONT)
	[SIGCONT] = "CONT",
#endif
#if defined(SIGCHLD)
	[SIGCHLD] = "CHLD",
#endif
#if defined(SIGTTIN)
	[SIGTTIN] = "TTIN",
#endif
#if defined(SIGTTOU)
	[SIGTTOU] = "TTOU",
#endif
#if defined(SIGPOLL)
	[SIGPOLL] = "POLL",
#endif
#if defined(SIGXFSZ)
	[SIGXFSZ] = "XFSZ",
#endif
#if defined(SIGXCPU)
	[SIGXCPU] = "XCPU",
#endif
#if defined(SIGVTALRM)
	[SIGVTALRM] = "VTALRM",
#endif
#if defined(SIGPROF)
	[SIGPROF] = "PROF",
#endif
#if defined(SIGUSR1)
	[SIGUSR1] = "USR1",
#endif
#if defined(SIGUSR2)
	[SIGUSR2] = "USR2",
#endif
};


#ifdef __APPLE__
int
pipe2(int pipefd[2], int flags)
{
	if (pipe(pipefd) != 0)
		return -1;

	if (flags & O_CLOEXEC) {
		if (fcntl(pipefd[0], F_SETFD, FD_CLOEXEC) != 0 ||
		    fcntl(pipefd[1], F_SETFD, FD_CLOEXEC) != 0) {
			close(pipefd[0]);
			close(pipefd[1]);

			return -1;
		}

		flags &= ~O_CLOEXEC;
	}

	if (fcntl(pipefd[0], F_SETFL, flags) != 0 ||
	    fcntl(pipefd[1], F_SETFL, flags) != 0) {
		close(pipefd[0]);
		close(pipefd[1]);

		return -1;
	}

	return 0;
}

/*
 * sigtimedwait() implementation based on
 * https://comp.unix.programmer.narkive.com/rEDH0sPT/sigtimedwait-implementation
 * and
 * https://github.com/wahern/lunix/blob/master/src/unix.c
 */
static void
sigtimedwait_consume_signal(int signo)
{
}

int
sigtimedwait(const sigset_t *set, siginfo_t *info, const struct timespec *timeout)
{
	struct timespec elapsed = { 0, 0 }, sleep, rem;
	sigset_t pending, unblock, omask;
	struct sigaction sa, osa;
	int signo;
	bool lt;

	while (true) {
		sigemptyset(&pending);
		sigpending(&pending);

		for (signo = 1; signo < NSIG; signo++) {
			if (!sigismember(set, signo) || !sigismember(&pending, signo))
				continue;

			sa.sa_handler = sigtimedwait_consume_signal;
			sa.sa_flags = 0;
			sigfillset(&sa.sa_mask);

			sigaction(signo, &sa, &osa);

			sigemptyset(&unblock);
			sigaddset(&unblock, signo);
			sigprocmask(SIG_UNBLOCK, &unblock, &omask);
			sigprocmask(SIG_SETMASK, &omask, NULL);

			sigaction(signo, &osa, NULL);

			if (info) {
				memset(info, 0, sizeof(*info));
				info->si_signo = signo;
			}

			return signo;
		}

		sleep.tv_sec = 0;
		sleep.tv_nsec = 200000000L; /* 2/10th second */
		rem = sleep;

		if (nanosleep(&sleep, &rem) == 0) {
			elapsed.tv_sec += sleep.tv_sec;
			elapsed.tv_nsec += sleep.tv_nsec;

			if (elapsed.tv_nsec > 1000000000) {
				elapsed.tv_sec++;
				elapsed.tv_nsec -= 1000000000;
			}
		}
		else if (errno == EINTR) {
			sleep.tv_sec -= rem.tv_sec;
			sleep.tv_nsec -= rem.tv_nsec;

			if (sleep.tv_nsec < 0) {
				sleep.tv_sec--;
				sleep.tv_nsec += 1000000000;
			}

			elapsed.tv_sec += sleep.tv_sec;
			elapsed.tv_nsec += sleep.tv_nsec;

			if (elapsed.tv_nsec > 1000000000) {
				elapsed.tv_sec++;
				elapsed.tv_nsec -= 1000000000;
			}
		}
		else {
			return errno;
		}

		lt = timeout
			? ((elapsed.tv_sec == timeout->tv_sec)
				? (elapsed.tv_nsec < timeout->tv_nsec)
				: (elapsed.tv_sec < timeout->tv_sec))
			: true;

		if (!lt)
			break;
	}

	errno = EAGAIN;

	return -1;
}
#endif
