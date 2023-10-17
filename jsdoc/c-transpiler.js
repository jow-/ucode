/*
 * c-transpiler.js - transpile C to JS while retaining line numbers.
 *
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

'use strict';

function isCommentStart(source, offset) {
	if (source[offset++] != '\n')
		return false;

	while (source[offset] == ' ' || source[offset] == '\t')
		offset++;

	return (
		source[offset++] == '/' &&
		source[offset++] == '*' &&
		source[offset++] == '*'
	);
}

exports.handlers = {
  beforeParse: function(e) {
	if (!e.filename.match(/\.(c|h)$/))
		return;

	let chunks = [ { start: 0, end: -1, comment: false } ];
	let chunk = chunks[0];
	let i = 0;

	for (i = 0; i < e.source.length; i++) {
		if (!chunk.comment && isCommentStart(e.source, i)) {
			chunk.end = i;
			chunk = { start: i, end: -1, comment: true };
			chunks.push(chunk);
			i += 3;
		}
		else if (chunk.comment && e.source[i] == '*' && e.source[i+1] == '/') {
			chunk.end = i + 1;
			chunk = { start: i + 1, end: -1, comment: false };
			chunks.push(chunk);
			i += 1;
		}
	}

	chunk.end = i;

	let source = '';

	for (chunk of chunks) {
		if (chunk.comment)
			source += e.source.substring(chunk.start, chunk.end);
		else
			source += e.source.substring(chunk.start, chunk.end).replace(/(^|\n)/g, '$1//');
	}

	e.source = source;
  }
};
