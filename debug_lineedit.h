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
 *
 * ---
 *
 * Interactive line editing, history and command-name completion for udbg's
 * "dbg > " prompt, ported from the pre-protocol interactive debugger's
 * hand-rolled terminal line editor (formerly lib/debug.c's termline_t/
 * term_getc()/term_getline()/term_line_tabcomplete()) - no external
 * readline/editline dependency, matching the original's choice not to take
 * on one either.
 *
 * The one architectural change the port needed: the original owned a
 * dedicated, blocking input loop (it was a synchronous, in-process
 * debugger), whereas udbg is driven by a single select() loop that also has
 * to watch the server socket for async EVENTs - so every function here is
 * non-blocking and consumes only bytes already available, meant to be
 * called each time select()/poll() reports STDIN_FILENO readable.
 */

#ifndef _DEBUG_LINEEDIT_H
#define _DEBUG_LINEEDIT_H

#include <stddef.h>
#include <stdbool.h>

/* One command-name completion candidate set for Tab, e.g. a CLI's own
 * verb/alias table - `names` is a NUL-separated list of aliases (primary
 * name first), itself NUL-terminated, the same shape already used for
 * udbg's own help table. Only ever matched against the line's first
 * (unterminated-by-space) word - this module has no notion of per-argument
 * completion (function names, file paths, ...). */
typedef struct {
	const char *names;
} lineedit_completion_t;

/* Try to put STDIN_FILENO into raw, non-blocking mode for interactive
 * editing. No-op if stdin isn't a terminal (piped/scripted input, the
 * common case when testing) - callers must check lineedit_active() and
 * fall back to plain fgets()-based reads in that case, since nothing below
 * does anything useful without raw mode. Registers an atexit() handler to
 * restore the original terminal settings; safe to call more than once. */
void lineedit_init(void);

/* True if lineedit_init() actually engaged raw mode. */
bool lineedit_active(void);

/* Temporarily restore the original (cooked, blocking) terminal mode - for a
 * one-off plain fgets()-based prompt elsewhere (e.g. a yes/no confirmation)
 * that needs normal line buffering and echo. Pair with lineedit_resume(). */
void lineedit_suspend(void);

/* Re-engage raw mode after lineedit_suspend(), if it was active before. */
void lineedit_resume(void);

/* Install the Tab completion candidate table. Optional - skip the call to
 * disable completion entirely. `completions` must outlive any subsequent
 * lineedit_feed() call. */
void lineedit_set_completions(const lineedit_completion_t *completions, size_t n);

/* Print `prompt` and start a fresh, empty line - call this whenever the
 * caller (re)enters a state where it wants to accept a new command, i.e.
 * the one place that used to just printf() the prompt directly. */
void lineedit_begin(const char *prompt);

/* Consume whatever is currently available on STDIN_FILENO. Never blocks.
 * Returns true exactly once a line has been submitted (Enter), copied
 * NUL-terminated into `out` (truncated to fit `outsz`); *eof is set to true
 * if the terminal hung up (read() saw EOF) rather than a line being ready.
 * Redraws the prompt/line itself as needed - callers only need to react to
 * a completed line or *eof, not to intermediate keystrokes. */
bool lineedit_feed(char *out, size_t outsz, bool *eof);

#endif
