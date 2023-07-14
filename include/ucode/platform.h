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

#ifndef UCODE_PLATFORM_H
#define UCODE_PLATFORM_H

#include <signal.h>
#include <fcntl.h>
#include <time.h>

#include "ucode/util.h"

#ifdef NSIG
# define UC_SYSTEM_SIGNAL_COUNT NSIG
#else
# define UC_SYSTEM_SIGNAL_COUNT (_SIGMAX + 1)
#endif

extern const char *uc_system_signal_names[];

#if defined(__linux__)
# include <endian.h>
# include <sys/sysmacros.h>
#elif defined(__APPLE__)
# include <unistd.h>
# include <crt_externs.h>
# include <machine/endian.h>
# include <libkern/OSByteOrder.h>

# define htobe16(x) OSSwapHostToBigInt16(x)
# define htole16(x) OSSwapHostToLittleInt16(x)
# define be16toh(x) OSSwapBigToHostInt16(x)
# define le16toh(x) OSSwapLittleToHostInt16(x)

# define htobe32(x) OSSwapHostToBigInt32(x)
# define htole32(x) OSSwapHostToLittleInt32(x)
# define be32toh(x) OSSwapBigToHostInt32(x)
# define le32toh(x) OSSwapLittleToHostInt32(x)

# define htobe64(x) OSSwapHostToBigInt64(x)
# define htole64(x) OSSwapHostToLittleInt64(x)
# define be64toh(x) OSSwapBigToHostInt64(x)
# define le64toh(x) OSSwapLittleToHostInt64(x)

# define environ (*_NSGetEnviron())

__hidden int pipe2(int[2], int);
__hidden int sigtimedwait(const sigset_t *, siginfo_t *, const struct timespec *);

static inline int
execvpe(const char *program, char **argv, char **envp)
{
	char **saved = environ;
	int rc;

	environ = envp;
	rc = execvp(program, argv);
	environ = saved;

	return rc;
}
#else
# error Unsupported platform
#endif

#endif /* UCODE_PLATFORM_H */
