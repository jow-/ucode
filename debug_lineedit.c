/*
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
#include <ctype.h>
#include <termios.h>
#include <fcntl.h>

#include "debug_lineedit.h"

#define EDITBUF_SIZE 4096
#define HISTORY_SIZE 100

/* -- raw terminal mode ----------------------------------------------------- */

static struct termios orig_termios;
static int orig_flags = -1;
static bool raw_active = false;

static void
raw_mode_disable(void)
{
	if (!raw_active)
		return;

	tcsetattr(STDIN_FILENO, TCSAFLUSH, &orig_termios);

	if (orig_flags != -1)
		fcntl(STDIN_FILENO, F_SETFL, orig_flags);

	raw_active = false;
}

void
lineedit_init(void)
{
	struct termios raw;

	if (raw_active || !isatty(STDIN_FILENO))
		return;

	if (tcgetattr(STDIN_FILENO, &orig_termios) != 0)
		return;

	raw = orig_termios;

	/* ISIG is deliberately cleared too: Ctrl-C is handled below as "cancel
	 * the current line" (matching the original), not as SIGINT - this
	 * client has no separate signal-based break-into-debugger path of its
	 * own to preserve that for.
	 *
	 * VMIN/VTIME are deliberately left alone: with ICANON off, setting
	 * VMIN=0/VTIME=0 makes every read() with nothing available return 0
	 * immediately - indistinguishable from real EOF, which getc_nb() below
	 * needs to detect. O_NONBLOCK (via fcntl, right below) already gives
	 * the same "don't block" behavior while keeping that distinction: a
	 * non-blocking read() returns -1/EAGAIN for "nothing yet" and only 0
	 * for an actual EOF. */
	raw.c_lflag &= (tcflag_t)~(ICANON | ECHO | ISIG);

	if (tcsetattr(STDIN_FILENO, TCSAFLUSH, &raw) != 0)
		return;

	orig_flags = fcntl(STDIN_FILENO, F_GETFL);

	/* Non-blocking so a read() for the tail of an escape sequence can never
	 * stall the process if, in some rare split-input scenario (e.g. a slow
	 * network terminal), the rest hasn't arrived yet - see read_key(). */
	if (orig_flags != -1)
		fcntl(STDIN_FILENO, F_SETFL, orig_flags | O_NONBLOCK);

	raw_active = true;
	atexit(raw_mode_disable);
}

bool
lineedit_active(void)
{
	return raw_active;
}

void
lineedit_suspend(void)
{
	raw_mode_disable();
}

void
lineedit_resume(void)
{
	lineedit_init();
}

/* -- non-blocking key decoding, ported from term_getc()/term_getc_raw()
 * (formerly lib/debug.c) ---------------------------------------------------- */

enum {
	LE_NODATA = -1, /* nothing available right now - stop reading */
	LE_EOF    = -2, /* stdin hit real EOF (terminal hung up) */

	KEY_HOME = 0x110000,
	KEY_END,
	KEY_DEL,
	KEY_ARROW_UP,
	KEY_ARROW_DOWN,
	KEY_ARROW_LEFT,
	KEY_ARROW_RIGHT,
	KEY_CTRL_LEFT,
	KEY_CTRL_RIGHT,
};

static int
getc_nb(void)
{
	unsigned char c;
	ssize_t n = read(STDIN_FILENO, &c, 1);

	if (n == 1)
		return c;

	if (n == 0)
		return LE_EOF;

	return LE_NODATA;
}

/* Decode one keypress, including multi-byte escape sequences for arrow/
 * home/end/delete keys. If a sequence is only partially available, it
 * degrades to a bare ESC (0x1b) rather than blocking or losing the bytes
 * already read - see the header comment on why that's an acceptable
 * simplification here. */
static int
read_key(void)
{
	int c = getc_nb();
	int seq[3];

	if (c != 0x1b)
		return c;

	if ((seq[0] = getc_nb()) < 0) return 0x1b;
	if ((seq[1] = getc_nb()) < 0) return 0x1b;

	if (seq[0] == '[') {
		if (seq[1] >= '0' && seq[1] <= '9') {
			if ((seq[2] = getc_nb()) < 0) return 0x1b;

			if (seq[2] == '~') {
				switch (seq[1]) {
				case '1': case '7': return KEY_HOME;
				case '3': return KEY_DEL;
				case '4': case '8': return KEY_END;
				}
			}
			else if (seq[2] == ';') {
				int mod = getc_nb();
				int fin = (mod < 0) ? LE_NODATA : getc_nb();

				if (mod == '5') {
					switch (fin) {
					case 'C': return KEY_CTRL_RIGHT;
					case 'D': return KEY_CTRL_LEFT;
					}
				}
			}

			return LE_NODATA; /* unrecognized sequence, swallow it */
		}

		switch (seq[1]) {
		case 'A': return KEY_ARROW_UP;
		case 'B': return KEY_ARROW_DOWN;
		case 'C': return KEY_ARROW_RIGHT;
		case 'D': return KEY_ARROW_LEFT;
		case 'H': return KEY_HOME;
		case 'F': return KEY_END;
		}
	}
	else if (seq[0] == 'O') {
		switch (seq[1]) {
		case 'H': return KEY_HOME;
		case 'F': return KEY_END;
		}
	}

	return LE_NODATA;
}

/* -- line buffer + cursor --------------------------------------------------- */

static char linebuf[EDITBUF_SIZE];
static size_t linelen = 0, cursor = 0;
static char cur_prompt[64];

static void
buf_insert(const char *s, size_t n)
{
	if (linelen + n >= sizeof(linebuf))
		n = sizeof(linebuf) - 1 - linelen;

	if (!n)
		return;

	memmove(linebuf + cursor + n, linebuf + cursor, linelen - cursor);
	memcpy(linebuf + cursor, s, n);
	linelen += n;
	cursor += n;
}

static void
buf_delete(size_t from, size_t to)
{
	if (to > linelen)
		to = linelen;

	if (from >= to)
		return;

	memmove(linebuf + from, linebuf + to, linelen - to);
	linelen -= (to - from);

	if (cursor > from)
		cursor = (cursor >= to) ? cursor - (to - from) : from;
}

static size_t
word_left(size_t pos)
{
	while (pos > 0 && isspace((unsigned char)linebuf[pos - 1])) pos--;
	while (pos > 0 && !isspace((unsigned char)linebuf[pos - 1])) pos--;

	return pos;
}

static size_t
word_right(size_t pos)
{
	while (pos < linelen && isspace((unsigned char)linebuf[pos])) pos++;
	while (pos < linelen && !isspace((unsigned char)linebuf[pos])) pos++;

	return pos;
}

static void
redraw(void)
{
	printf("\r\033[K%s%.*s", cur_prompt, (int)linelen, linebuf);

	if (cursor < linelen)
		printf("\033[%zuD", linelen - cursor);

	fflush(stdout);
}

/* -- history, ported from termstate.history/HISTORY_SIZE (formerly
 * lib/debug.c) -------------------------------------------------------------- */

static char *history[HISTORY_SIZE];
static size_t history_count = 0;
static size_t history_browse = 0; /* == history_count: editing the live line */
static char history_saved[EDITBUF_SIZE];

static void
history_push(const char *line)
{
	if (!*line)
		return;

	if (history_count > 0 && !strcmp(history[history_count - 1], line))
		return;

	if (history_count >= HISTORY_SIZE) {
		free(history[0]);
		memmove(&history[0], &history[1], (HISTORY_SIZE - 1) * sizeof(history[0]));
		history_count--;
	}

	history[history_count++] = strdup(line);
}

/* -- Tab completion, ported from term_line_tabcomplete() (formerly
 * lib/debug.c), restricted to command-name completion only -----------------
 * (the original also completed breakpoint specs/function names/file paths
 * depending on argument position - that needs live data from the server
 * and is future work, not something this port takes on). */

static const lineedit_completion_t *completions = NULL;
static size_t ncompletions = 0;

void
lineedit_set_completions(const lineedit_completion_t *c, size_t n)
{
	completions = c;
	ncompletions = n;
}

static void
try_complete(void)
{
	const char *matches[64];
	size_t nmatch = 0, maxlen = 0, wend = 0, i;

	while (wend < linelen && !isspace((unsigned char)linebuf[wend]))
		wend++;

	/* only complete the command word itself, not its arguments */
	if (!completions || cursor != wend || wend == 0)
		return;

	for (i = 0; i < ncompletions; i++) {
		const char *c;

		for (c = completions[i].names; *c; c += strlen(c) + 1) {
			size_t len = strlen(c);

			if (len >= wend && !strncmp(c, linebuf, wend)) {
				if (nmatch < sizeof(matches) / sizeof(matches[0]))
					matches[nmatch++] = c;

				if (len > maxlen)
					maxlen = len;
			}
		}
	}

	if (nmatch == 0)
		return;

	if (nmatch == 1) {
		buf_delete(0, wend);
		cursor = 0;
		buf_insert(matches[0], strlen(matches[0]));
		buf_insert(" ", 1);
	}
	else {
		printf("\n");

		for (i = 0; i < nmatch; i++)
			printf("%-*s  ", (int)maxlen, matches[i]);

		printf("\n");
	}
}

/* -- prompt + feed ----------------------------------------------------------- */

void
lineedit_begin(const char *prompt)
{
	snprintf(cur_prompt, sizeof(cur_prompt), "%s", prompt);
	linelen = cursor = 0;
	history_browse = history_count;

	if (raw_active) {
		redraw();
	}
	else {
		fputs(prompt, stdout);
		fflush(stdout);
	}
}

bool
lineedit_feed(char *out, size_t outsz, bool *eof)
{
	int key;

	*eof = false;

	/* Non-interactive input (piped/scripted, or stdin isn't a tty): no
	 * editing possible or needed, just read one line the plain way. */
	if (!raw_active) {
		if (!fgets(out, (int)outsz, stdin)) {
			*eof = true;
			return false;
		}

		out[strcspn(out, "\n")] = '\0';

		return true;
	}

	while ((key = read_key()) != LE_NODATA) {
		if (key == LE_EOF) {
			*eof = true;
			return false;
		}

		switch (key) {
		case '\r': case '\n':
			printf("\n");
			snprintf(out, outsz, "%.*s", (int)linelen, linebuf);
			history_push(out);

			return true;

		case 3: /* Ctrl-C: cancel the line in place, like the original */
			linelen = cursor = 0;
			history_browse = history_count;
			break;

		case 127: case 8: /* backspace */
			if (cursor > 0)
				buf_delete(cursor - 1, cursor);

			break;

		case KEY_DEL:
			buf_delete(cursor, cursor + 1);
			break;

		case KEY_HOME:
			cursor = 0;
			break;

		case KEY_END:
			cursor = linelen;
			break;

		case KEY_ARROW_LEFT:
			if (cursor > 0)
				cursor--;

			break;

		case KEY_ARROW_RIGHT:
			if (cursor < linelen)
				cursor++;

			break;

		case KEY_CTRL_LEFT:
			cursor = word_left(cursor);
			break;

		case KEY_CTRL_RIGHT:
			cursor = word_right(cursor);
			break;

		case KEY_ARROW_UP:
			if (history_browse > 0) {
				if (history_browse == history_count) {
					linebuf[linelen] = '\0';
					snprintf(history_saved, sizeof(history_saved), "%s", linebuf);
				}

				history_browse--;
				snprintf(linebuf, sizeof(linebuf), "%s", history[history_browse]);
				linelen = cursor = strlen(linebuf);
			}

			break;

		case KEY_ARROW_DOWN:
			if (history_browse < history_count) {
				history_browse++;

				if (history_browse == history_count)
					snprintf(linebuf, sizeof(linebuf), "%s", history_saved);
				else
					snprintf(linebuf, sizeof(linebuf), "%s", history[history_browse]);

				linelen = cursor = strlen(linebuf);
			}

			break;

		case 23: /* Ctrl-W */
			buf_delete(word_left(cursor), cursor);
			break;

		case 9: /* Tab */
			try_complete();
			break;

		default:
			if (key >= ' ' && key < 127) {
				char c = (char)key;

				buf_insert(&c, 1);
			}

			break;
		}

		redraw();
	}

	return false;
}
