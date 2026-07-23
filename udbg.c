/*
 * udbg - ucode remote debugger client
 *
 * Copyright (C) 2026 Jo-Philipp Wich <jo@mein.io>
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ANY IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <sys/select.h>
#include <sys/wait.h>
#include <termios.h>
#include <ctype.h>

#define SOCKET_PATH_ARG 1
#define MAX_LINE 4096
#define DEFAULT_SOCKET_DIR "/tmp"
#define MAX_WAIT_TIME 30

static int connected = 1;
static struct termios orig_termios;

static void
disable_raw_mode(void)
{
	tcsetattr(STDIN_FILENO, TCSAFLUSH, &orig_termios);
}

static void
enable_raw_mode(void)
{
	struct termios raw;

	if (!isatty(STDIN_FILENO))
		return;

	tcgetattr(STDIN_FILENO, &orig_termios);
	atexit(disable_raw_mode);

	raw = orig_termios;
	raw.c_lflag &= ~(ECHO | ICANON);
	raw.c_cc[VMIN] = 1;
	raw.c_cc[VTIME] = 0;
	tcsetattr(STDIN_FILENO, TCSAFLUSH, &raw);
}

static int
connect_socket(const char *path)
{
	struct sockaddr_un addr;
	int fd;

	fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (fd < 0)
		return -1;

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	strncpy(addr.sun_path, path, sizeof(addr.sun_path) - 1);

	if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		close(fd);
		return -1;
	}

	return fd;
}

static void
send_command(int fd, const char *cmd)
{
	write(fd, cmd, strlen(cmd));
	write(fd, "\n", 1);
}

static char *
get_socket_path_for_pid(pid_t pid)
{
	static char path[256];
	snprintf(path, sizeof(path), "%s/ucode-debug-%d.sock", DEFAULT_SOCKET_DIR, pid);
	return path;
}

static int
wait_for_socket(const char *path, int timeout_sec)
{
	int elapsed = 0;
	struct stat st;

	while (elapsed < timeout_sec) {
		if (stat(path, &st) == 0 && (st.st_mode & S_IFMT) == S_IFSOCK)
			return 0;

		sleep(1);
		elapsed++;
	}

	return -1;
}

static void
print_usage(const char *prog)
{
	fprintf(stderr, "Usage: %s <pid>\n", prog);
	fprintf(stderr, "\n");
	fprintf(stderr, "Remote debugger client for ucode.\n");
	fprintf(stderr, "\n");
	fprintf(stderr, "Attach to a running ucode process and start an interactive\n");
	fprintf(stderr, "debugging session. The target process must have been started\n");
	fprintf(stderr, "with the -X flag to enable debugger infrastructure.\n");
	fprintf(stderr, "\n");
	fprintf(stderr, "This works like 'gdb -p' - send SIGUSR1 to the target process\n");
	fprintf(stderr, "to trigger the debugger, then connect to the created socket.\n");
	fprintf(stderr, "\n");
	fprintf(stderr, "Example:\n");
	fprintf(stderr, "  # Start ucode script with debugger support:\n");
	fprintf(stderr, "  ucode -X script.uc &\n");
	fprintf(stderr, "\n");
	fprintf(stderr, "  # Attach debugger in another terminal:\n");
	fprintf(stderr, "  udbg <pid>\n");
	fprintf(stderr, "\n");
	fprintf(stderr, "  # Or use debug.attach() in script:\n");
	fprintf(stderr, "  import * as debug from 'debug';\n");
	fprintf(stderr, "  debug.attach(() => { /* code to debug */ });\n");
}

int
main(int argc, char **argv)
{
	int fd;
	fd_set readfds;
	char buf[MAX_LINE];
	char line[MAX_LINE];
	int line_len = 0;
	pid_t pid;
	char *socket_path;

	if (argc < 2) {
		print_usage(argv[0]);
		return 1;
	}

	if (strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0) {
		print_usage(argv[0]);
		return 0;
	}

	pid = atoi(argv[1]);
	if (pid <= 0) {
		fprintf(stderr, "Invalid PID: %s\n", argv[1]);
		return 1;
	}

	socket_path = get_socket_path_for_pid(pid);

	/* Send SIGUSR1 to trigger socket creation */
	if (kill(pid, SIGUSR1) < 0) {
		fprintf(stderr, "Failed to send SIGUSR1 to process %d: %s\n", pid, strerror(errno));
		return 1;
	}

	fprintf(stderr, "Sent SIGUSR1 to process %d, waiting for debugger socket...\n", pid);

	/* Wait for socket to appear */
	if (wait_for_socket(socket_path, MAX_WAIT_TIME) < 0) {
		fprintf(stderr, "Timeout waiting for debugger socket at %s\n", socket_path);
		return 1;
	}

	fprintf(stderr, "Debugger socket ready, connecting...\n");

	fd = connect_socket(socket_path);
	if (fd < 0) {
		fprintf(stderr, "Failed to connect to %s: %s\n", socket_path, strerror(errno));
		return 1;
	}

	fprintf(stderr, "Connected to ucode debugger\n");
	fprintf(stderr, "Type 'help' for available commands\n\n");

	enable_raw_mode();

	while (connected) {
		FD_ZERO(&readfds);
		FD_SET(STDIN_FILENO, &readfds);
		FD_SET(fd, &readfds);

		if (select(fd + 1, &readfds, NULL, NULL, NULL) < 0)
			break;

		if (FD_ISSET(STDIN_FILENO, &readfds)) {
			char ch;
			int n = read(STDIN_FILENO, &ch, 1);
			if (n <= 0)
				break;

			if (ch == '\n' || ch == '\r') {
				/* Send command */
				line[line_len] = '\0';
				send_command(fd, line);
				line_len = 0;
				fprintf(stderr, "\n");
			} else if (ch == 3) {
				/* Ctrl-C */
				send_command(fd, "continue");
				fprintf(stderr, "^C\n");
			} else if (ch == 4) {
				/* Ctrl-D */
				send_command(fd, "quit");
				connected = 0;
				break;
			} else if (ch == 127 || ch == 8) {
				/* Backspace */
				if (line_len > 0) {
					line_len--;
					write(STDERR_FILENO, "\b \b", 3);
				}
			} else if (isprint((unsigned char)ch)) {
				if (line_len < MAX_LINE - 1) {
					line[line_len++] = ch;
					write(STDERR_FILENO, &ch, 1);
				}
			}
		}

		if (FD_ISSET(fd, &readfds)) {
			int n = read(fd, buf, sizeof(buf) - 1);
			if (n <= 0) {
				fprintf(stderr, "\nConnection closed\n");
				connected = 0;
				break;
			}

			buf[n] = '\0';
			fwrite(buf, 1, n, stderr);
		}
	}

	close(fd);
	disable_raw_mode();

	return 0;
}
