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
 * ucode/utpl syntax highlighting and ANSI source rendering, ported from the
 * pre-protocol interactive debugger (formerly lib/debug.c's
 * highlight_rules[]/compile_patterns()/print_source_location()) so it can
 * be reused by any client speaking the line-based debug protocol - or
 * anything else that wants to print ucode source with the same styling.
 *
 * This module is intentionally standalone: no ucode headers, no protocol
 * knowledge, just POSIX regex + stdio. A caller supplies already-split
 * source lines and, optionally, a single line/column range to shade as the
 * "current statement" - the multi-range/ellipsis-gap layout the original
 * server-side renderer supported for very large statements is not ported,
 * since every client of the debug protocol only ever receives one
 * contiguous range at a time (see SOURCE_RANGE in lib/debug_proto.h).
 */

#ifndef _DEBUG_HIGHLIGHT_H
#define _DEBUG_HIGHLIGHT_H

#include <stdio.h>
#include <stddef.h>
#include <stdbool.h>

/* A statement span to shade, in 1-based line numbers and 0-based byte
 * columns within those lines (matching the debug protocol's "col" fields).
 * Set from_line to 0 for "no highlight". */
typedef struct {
	size_t from_line, from_col;
	size_t to_line, to_col;
} debug_highlight_span_t;

/* Compile the highlight regexes once; safe to call repeatedly. Returns
 * false (and prints a diagnostic to stderr) on a regex compile error, in
 * which case debug_highlight_print_source() below still works, just
 * without coloring. */
bool debug_highlight_init(void);

/* Print source lines [from, to] (1-based, inclusive, clamped to
 * [1, nlines]) from the `nlines`-element `lines` array (as produced by
 * splitting raw source text on '\n', with no trailing newlines) to `out`,
 * applying ucode/utpl syntax highlighting and, if `hl` is non-NULL, shading
 * the statement range it describes. Every printed line is prefixed with
 * `left_pad` blank columns plus a right-aligned line number gutter.
 * `columns` is the terminal width to wrap/pad to (pass 0 for "don't know",
 * which disables truncation and trailing-space padding). */
void debug_highlight_print_source(FILE *out, char **lines, size_t nlines,
                                   size_t from, size_t to,
                                   const debug_highlight_span_t *hl,
                                   size_t left_pad, size_t columns);

#endif
