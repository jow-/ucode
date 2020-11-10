/*
 * Copyright (C) 2020 Jo-Philipp Wich <jo@mein.io>
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

#include <stdio.h>

#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <regex.h>
#include <math.h>
#include <errno.h>

#include "ast.h"
#include "lib.h"
#include "lexer.h"
#include "parser.h"


struct token {
	int type;
	const char *pat;
	int plen;
	union {
		uint32_t (*parse)(struct ut_state *s);
		double d;
		bool b;
	};
};

#define dec(o) \
	((o) - '0')

#define hex(x) \
	(((x) >= 'a') ? (10 + (x) - 'a') : \
		(((x) >= 'A') ? (10 + (x) - 'A') : dec(x)))

static uint32_t parse_comment(struct ut_state *);
static uint32_t parse_string(struct ut_state *);
static uint32_t parse_regexp(struct ut_state *);
static uint32_t parse_number(struct ut_state *);
static uint32_t parse_label(struct ut_state *);

static const struct token tokens[] = {
	{ 0,			" ",     1 },
	{ 0,			"\t",    1 },
	{ 0,			"\r",    1 },
	{ 0,			"\n",    1 },
	{ T_ASLEFT,		"<<=",   3 },
	{ T_ASRIGHT,	">>=",   3 },
	{ T_LEXP,		"{{-",   3 },
	{ T_REXP,		"-}}",   3 },
	{ T_LSTM,		"{%+",   3 },
	{ T_LSTM,		"{%-",   3 },
	{ T_RSTM,		"-%}",   3 },
	{ T_EQS,		"===",   3 },
	{ T_NES,		"!==",   3 },
	{ T_ELLIP,		"...",   3 },
	{ T_AND,		"&&",    2 },
	{ T_ASADD,		"+=",    2 },
	{ T_ASBAND,		"&=",    2 },
	{ T_ASBOR,		"|=",    2 },
	{ T_ASBXOR,		"^=",    2 },
	//{ T_ASDIV,		"/=",    2 },
	{ T_ASMOD,		"%=",    2 },
	{ T_ASMUL,		"*=",    2 },
	{ T_ASSUB,		"-=",    2 },
	{ T_DEC,		"--",    2 },
	{ T_INC,		"++",    2 },
	{ T_EQ,			"==",    2 },
	{ T_NE,			"!=",    2 },
	{ T_LE,			"<=",    2 },
	{ T_GE,			">=",    2 },
	{ T_LSHIFT,		"<<",    2 },
	{ T_RSHIFT,		">>",    2 },
	{ 0,			"//",    2, { .parse = parse_comment } },
	{ 0,			"/*",    2, { .parse = parse_comment } },
	{ T_OR,			"||",    2 },
	{ T_LEXP,		"{{",    2 },
	{ T_REXP,		"}}",    2 },
	{ T_LSTM,		"{%",    2 },
	{ T_RSTM,		"%}",    2 },
	{ T_ARROW,		"=>",    2 },
	{ T_ADD,		"+",     1 },
	{ T_ASSIGN,		"=",     1 },
	{ T_BAND,		"&",     1 },
	{ T_BOR,		"|",     1 },
	{ T_LBRACK,		"[",     1 },
	{ T_RBRACK,		"]",     1 },
	{ T_BXOR,		"^",     1 },
	{ T_LBRACE,		"{",     1 },
	{ T_RBRACE,		"}",     1 },
	{ T_COLON,		":",     1 },
	{ T_COMMA,		",",     1 },
	{ T_COMPL,		"~",     1 },
	//{ T_DIV,		"/",     1 },
	{ T_GT,			">",     1 },
	{ T_NOT,		"!",     1 },
	{ T_LT,			"<",     1 },
	{ T_MOD,		"%",     1 },
	{ T_MUL,		"*",     1 },
	{ T_LPAREN,		"(",     1 },
	{ T_RPAREN,		")",     1 },
	{ T_QMARK,		"?",     1 },
	{ T_SCOL,		";",     1 },
	{ T_SUB,		"-",     1 },
	{ T_DOT,		".",     1 },
	{ T_STRING,		"'",	 1, { .parse = parse_string } },
	{ T_STRING,		"\"",	 1, { .parse = parse_string } },
	{ T_REGEXP,		"/",     1, { .parse = parse_regexp } },
	{ T_LABEL,		"_",     1, { .parse = parse_label  } },
	{ T_LABEL,		"az",    0, { .parse = parse_label  } },
	{ T_LABEL,		"AZ",    0, { .parse = parse_label  } },
	{ T_NUMBER,		"09",    0, { .parse = parse_number } },
};

static const struct token reserved_words[] = {
	{ T_ENDFUNC,	"endfunction", 11 },
	{ T_DOUBLE,		"Infinity", 8, { .d = INFINITY } },
	{ T_CONTINUE,	"continue", 8 },
	{ T_ENDWHILE,	"endwhile", 8 },
	{ T_FUNC,		"function", 8 },
	{ T_DEFAULT,	"default", 7 },
	{ T_RETURN,		"return", 6 },
	{ T_ENDFOR,		"endfor", 6 },
	{ T_SWITCH,		"switch", 6 },
	{ T_LOCAL,		"local", 5 },
	{ T_ENDIF,		"endif", 5 },
	{ T_WHILE,		"while", 5 },
	{ T_BREAK,		"break", 5 },
	{ T_CATCH,		"catch", 5 },
	{ T_BOOL,		"false", 5, { .b = false } },
	{ T_BOOL,		"true",  4, { .b = true } },
	{ T_ELIF,		"elif",  4 },
	{ T_ELSE,		"else",  4 },
	{ T_THIS,		"this",  4 },
	{ T_NULL,		"null",  4 },
	{ T_CASE,		"case",  4 },
	{ T_DOUBLE,		"NaN",   3, { .d = NAN } },
	{ T_TRY,		"try",   3 },
	{ T_FOR,		"for",   3 },
	{ T_LOCAL,		"let",   3 },
	{ T_IF,			"if",    2 },
	{ T_IN,			"in",    2 },
};


/*
 * Stores the given codepoint as a utf8 multibyte sequence into the given
 * output buffer and substracts the required amount of bytes from  the given
 * length pointer.
 *
 * Returns false if the multibyte sequence would not fit into the buffer,
 * otherwise true.
 */

bool
utf8enc(char **out, int *rem, int code)
{
	if (code >= 0 && code <= 0x7F) {
		if (*rem < 1)
			return false;

		*(*out)++ = code; (*rem)--;

		return true;
	}
	else if (code > 0 && code <= 0x7FF) {
		if (*rem < 2)
			return false;

		*(*out)++ = ((code >>  6) & 0x1F) | 0xC0; (*rem)--;
		*(*out)++ = ( code        & 0x3F) | 0x80; (*rem)--;

		return true;
	}
	else if (code > 0 && code <= 0xFFFF) {
		if (*rem < 3)
			return false;

		*(*out)++ = ((code >> 12) & 0x0F) | 0xE0; (*rem)--;
		*(*out)++ = ((code >>  6) & 0x3F) | 0x80; (*rem)--;
		*(*out)++ = ( code        & 0x3F) | 0x80; (*rem)--;

		return true;
	}
	else if (code > 0 && code <= 0x10FFFF) {
		if (*rem < 4)
			return false;

		*(*out)++ = ((code >> 18) & 0x07) | 0xF0; (*rem)--;
		*(*out)++ = ((code >> 12) & 0x3F) | 0x80; (*rem)--;
		*(*out)++ = ((code >>  6) & 0x3F) | 0x80; (*rem)--;
		*(*out)++ = ( code        & 0x3F) | 0x80; (*rem)--;

		return true;
	}

	return true;
}

/* length of the longest token in our lookup table */
#define UT_LEX_MAX_TOKEN_LEN 3

static uint32_t emit_op(struct ut_state *s, uint32_t pos, int type, struct json_object *val)
{
	uint32_t off = ut_new_op(s, type, val, UINT32_MAX);
	struct ut_op *op = ut_get_op(s, off);

	op->off = pos;

	/* Follow JSLint logic and treat a slash after any of the
	 * `(,=:[!&|?{};` characters as the beginning of a regex
	 * literal... */
	switch (type) {
	case T_LPAREN:
	case T_COMMA:

	case T_ASADD:
	case T_ASBAND:
	case T_ASBOR:
	case T_ASBXOR:
	case T_ASDIV:
	case T_ASLEFT:
	case T_ASMOD:
	case T_ASMUL:
	case T_ASRIGHT:
	case T_ASSIGN:
	case T_ASSUB:
	case T_EQ:
	case T_EQS:
	case T_GE:
	case T_LE:
	case T_NE:
	case T_NES:

	case T_COLON:
	case T_LBRACK:
	case T_NOT:

	case T_AND:
	case T_BAND:

	case T_OR:
	case T_BOR:

	case T_QMARK:

	case T_LBRACE:
	case T_RBRACE:

	case T_LSTM:
	case T_LEXP:

	case T_SCOL:
		s->lex.expect_div = false;
		break;

	default:
		s->lex.expect_div = true;
	}

	return off;
}

static void lookbehind_append(struct ut_state *s, const char *data, size_t len)
{
	if (len) {
		s->lex.lookbehind = xrealloc(s->lex.lookbehind, s->lex.lookbehindlen + len);
		memcpy(s->lex.lookbehind + s->lex.lookbehindlen, data, len);
		s->lex.lookbehindlen += len;
	}
}

static void lookbehind_reset(struct ut_state *s) {
	free(s->lex.lookbehind);
	s->lex.lookbehind = NULL;
	s->lex.lookbehindlen = 0;
}

static uint32_t lookbehind_to_text(struct ut_state *s, uint32_t pos, int type, const char *strip_trailing_chars) {
	uint32_t rv = 0;

	if (s->lex.lookbehind) {
		if (strip_trailing_chars) {
			while (s->lex.lookbehindlen > 0 && strchr(strip_trailing_chars, s->lex.lookbehind[s->lex.lookbehindlen-1]))
				s->lex.lookbehindlen--;
		}

		rv = emit_op(s, pos, type, xjs_new_string_len(s->lex.lookbehind, s->lex.lookbehindlen));

		lookbehind_reset(s);
	}

	return rv;
}

static inline size_t buf_remaining(struct ut_state *s) {
	return (s->lex.bufend - s->lex.bufstart);
}

static inline bool _buf_startswith(struct ut_state *s, const char *str, size_t len) {
	return (buf_remaining(s) >= len && !strncmp(s->lex.bufstart, str, len));
}

#define buf_startswith(s, str) _buf_startswith(s, str, sizeof(str) - 1)

static void buf_consume(struct ut_state *s, ssize_t len) {
	s->lex.bufstart += len;
	s->source->off += len;
}

static uint32_t
parse_comment(struct ut_state *s)
{
	const struct token *tok = s->lex.tok;
	const char *ptr, *end;
	size_t elen;

	if (!buf_remaining(s)) {
		ut_new_exception(s, s->lex.lastoff, "Syntax error: Unterminated comment");

		return 0;
	}

	if (!strcmp(tok->pat, "//")) {
		end = "\n";
		elen = 1;
	}
	else {
		end = "*/";
		elen = 2;
	}

	for (ptr = s->lex.bufstart; ptr < s->lex.bufend - elen; ptr++) {
		if (!strncmp(ptr, end, elen)) {
			buf_consume(s, (ptr - s->lex.bufstart) + elen);

			return UINT32_MAX;
		}
	}

	buf_consume(s, ptr - s->lex.bufstart);

	return 0;
}

static void append_utf8(struct ut_state *s, int code) {
	char ustr[8], *up;
	int rem;

	up = ustr;
	rem = sizeof(ustr);

	if (utf8enc(&up, &rem, code))
		lookbehind_append(s, ustr, up - ustr);
}

static uint32_t
parse_string(struct ut_state *s)
{
	const struct token *tok = s->lex.tok;
	char q = tok->pat[0];
	char *ptr, *c;
	uint32_t rv;
	int code;

	if (!buf_remaining(s)) {
		ut_new_exception(s, s->lex.lastoff, "Syntax error: Unterminated string");

		return 0;
	}

	for (ptr = s->lex.bufstart; ptr < s->lex.bufend; ptr++) {
		/* continuation of escape sequence */
		if (s->lex.is_escape) {
			if (s->lex.esclen == 0) {
				/* non-unicode escape following a lead surrogate, emit replacement... */
				if (s->lex.lead_surrogate && *ptr != 'u') {
					append_utf8(s, 0xFFFD);
					s->lex.lead_surrogate = 0;
				}

				switch (*ptr) {
				case 'u':
				case 'x':
					s->lex.esc[s->lex.esclen++] = *ptr;
					break;

				case '0':
				case '1':
				case '2':
				case '3':
				case '4':
				case '5':
				case '6':
				case '7':
				case '8':
				case '9':
					/* regex mode => backref, retain literally */
					if (q == '/') {
						s->lex.is_escape = false;
						lookbehind_append(s, "\\", 1);
						lookbehind_append(s, ptr, 1);
						buf_consume(s, (ptr + 1) - s->lex.bufstart);
					}

					/* string mode => likely octal */
					else if (*ptr < '8') {
						s->lex.esc[s->lex.esclen++] = 'o';
						s->lex.esc[s->lex.esclen++] = *ptr;
					}

					/* non-octal char, add verbatim */
					else {
						s->lex.is_escape = false;
						lookbehind_append(s, ptr, 1);
						buf_consume(s, (ptr + 1) - s->lex.bufstart);
					}

					break;

				default:
					s->lex.is_escape = false;
					c = strchr("a\ab\be\ef\fn\nr\rt\tv\v", *ptr);
					lookbehind_append(s, c ? c + 1 : ptr, 1);
					buf_consume(s, (ptr + 1) - s->lex.bufstart);
					break;
				}
			}
			else {
				switch (s->lex.esc[0]) {
				case 'u':
					if (s->lex.esclen < 5) {
						if (!isxdigit(*ptr)) {
							ut_new_exception(s, s->source->off + s->lex.esclen + 1, "Syntax error: Invalid escape sequence");

							return 0;
						}

						s->lex.esc[s->lex.esclen++] = *ptr;
					}

					if (s->lex.esclen == 5) {
						code = hex(s->lex.esc[1]) * 16 * 16 * 16 +
						       hex(s->lex.esc[2]) * 16 * 16 +
						       hex(s->lex.esc[3]) * 16 +
						       hex(s->lex.esc[4]);

						/* is a leading surrogate value */
						if ((code & 0xFC00) == 0xD800) {
							/* found a subsequent leading surrogate, ignore and emit replacement char for previous one */
							if (s->lex.lead_surrogate)
								append_utf8(s, 0xFFFD);

							/* store surrogate value and advance to next escape sequence */
							s->lex.lead_surrogate = code;
						}

						/* is a trailing surrogate value */
						else if ((code & 0xFC00) == 0xDC00) {
							/* found a trailing surrogate following a leading one, combine and encode */
							if (s->lex.lead_surrogate) {
								code = 0x10000 + ((s->lex.lead_surrogate & 0x3FF) << 10) + (code & 0x3FF);
								s->lex.lead_surrogate = 0;
							}

							/* trailing surrogate not following a leading one, ignore and use replacement char */
							else {
								code = 0xFFFD;
							}

							append_utf8(s, code);
						}

						/* is a normal codepoint */
						else {
							append_utf8(s, code);
						}

						s->lex.esclen = 0;
						s->lex.is_escape = false;
						buf_consume(s, (ptr + 1) - s->lex.bufstart);
					}

					break;

				case 'x':
					if (s->lex.esclen < 3) {
						if (!isxdigit(*ptr)) {
							ut_new_exception(s, s->source->off + s->lex.esclen + 1, "Syntax error: Invalid escape sequence");

							return 0;
						}

						s->lex.esc[s->lex.esclen++] = *ptr;
					}

					if (s->lex.esclen == 3) {
						append_utf8(s, hex(s->lex.esc[1]) * 16 + hex(s->lex.esc[2]));

						s->lex.esclen = 0;
						s->lex.is_escape = false;
						buf_consume(s, (ptr + 1) - s->lex.bufstart);
					}

					break;

				case 'o':
					if (s->lex.esclen < 4) {
						/* found a non-octal char */
						if (*ptr < '0' || *ptr > '7') {
							/* pad sequence to three chars */
							switch (s->lex.esclen) {
							case 3:
								s->lex.esc[3] = s->lex.esc[2];
								s->lex.esc[2] = s->lex.esc[1];
								s->lex.esc[1] = '0';
								break;

							case 2:
								s->lex.esc[3] = s->lex.esc[1];
								s->lex.esc[2] = '0';
								s->lex.esc[1] = '0';
								break;
							}

							s->lex.esclen = 4;
							buf_consume(s, ptr - s->lex.bufstart);
						}

						/* append */
						else {
							s->lex.esc[s->lex.esclen++] = *ptr;
							buf_consume(s, (ptr + 1) - s->lex.bufstart);
						}
					}

					if (s->lex.esclen == 4) {
						code = dec(s->lex.esc[1]) * 8 * 8 +
						       dec(s->lex.esc[2]) * 8 +
						       dec(s->lex.esc[3]);

						if (code > 255) {
							ut_new_exception(s, s->source->off + s->lex.esclen + 1, "Syntax error: Invalid escape sequence");

							return 0;
						}

						append_utf8(s, code);

						s->lex.esclen = 0;
						s->lex.is_escape = false;
					}

					break;
				}
			}
		}

		/* terminating char */
		else if (*ptr == q) {
			lookbehind_append(s, s->lex.bufstart, ptr - s->lex.bufstart);
			buf_consume(s, (ptr + 1) - s->lex.bufstart);

			rv = lookbehind_to_text(s, s->lex.lastoff, T_STRING, NULL);

			if (!rv)
				rv = emit_op(s, s->lex.lastoff, T_STRING, xjs_new_string_len("", 0));

			return rv;
		}

		/* escape sequence start */
		else if (*ptr == '\\') {
			s->lex.is_escape = true;
			lookbehind_append(s, s->lex.bufstart, ptr - s->lex.bufstart);
			buf_consume(s, ptr - s->lex.bufstart);
		}
	}

	lookbehind_append(s, s->lex.bufstart, ptr - s->lex.bufstart);
	buf_consume(s, ptr - s->lex.bufstart);

	return 0;
}


/*
 * Parses a regexp literal from the given buffer.
 *
 * Returns a negative value on error, otherwise the amount of consumed
 * characters from the given buffer.
 *
 * Error values:
 *  -UT_ERROR_UNTERMINATED_STRING	Unterminated regexp
 *  -UT_ERROR_INVALID_ESCAPE		Invalid escape sequence
 *  -UT_ERROR_OVERLONG_STRING		Regexp literal too long
 *  -UT_ERROR_INVALID_REGEXP        Could not compile regexp
 */

enum {
	UT_LEX_PARSE_REGEX_INIT,
	UT_LEX_PARSE_REGEX_PATTERN,
	UT_LEX_PARSE_REGEX_FLAGS
};

static uint32_t
parse_regexp(struct ut_state *s)
{
	struct json_object *pattern;
	struct ut_op *op;
	uint32_t rv;
	char *err;

	switch (s->lex.esc[0]) {
	case UT_LEX_PARSE_REGEX_INIT:
		if (s->lex.expect_div) {
			s->lex.expect_div = false;

			if (buf_startswith(s, "=")) {
				buf_consume(s, 1);

				return emit_op(s, s->source->off, T_ASDIV, NULL);
			}

			return emit_op(s, s->source->off, T_DIV, NULL);
		}

		s->lex.esc[0] = UT_LEX_PARSE_REGEX_PATTERN;
		break;

	case UT_LEX_PARSE_REGEX_PATTERN:
		rv = parse_string(s);

		if (rv != 0 && rv != UINT32_MAX) {
			s->lex.lookbehind = (char *)ut_get_op(s, rv);
			s->lex.esc[0] = UT_LEX_PARSE_REGEX_FLAGS;
		}

		break;

	case UT_LEX_PARSE_REGEX_FLAGS:
		op = (struct ut_op *)s->lex.lookbehind;

		while (s->lex.bufstart < s->lex.bufend) {
			switch (s->lex.bufstart[0]) {
			case 'g':
				buf_consume(s, 1);
				op->is_reg_global = true;
				break;

			case 'i':
				buf_consume(s, 1);
				op->is_reg_icase = true;
				break;

			case 's':
				buf_consume(s, 1);
				op->is_reg_newline = true;
				break;

			default:
				s->lex.lookbehind = NULL;

				pattern = ut_new_regexp(json_object_get_string(op->val),
				                        op->is_reg_icase,
				                        op->is_reg_newline,
				                        op->is_reg_global,
				                        &err);

				json_object_put(op->val);

				op->type = T_REGEXP;
				op->val = pattern;

				if (!pattern) {
					ut_new_exception(s, op->off, "Syntax error: %s", err);
					free(err);

					return 0;
				}

				return ut_get_off(s, op);
			}
		}

		break;
	}

	return 0;
}


/*
 * Parses a label from the given buffer.
 *
 * Returns a negative value on error, otherwise the amount of consumed
 * characters from the given buffer.
 *
 * Error values:
 *  -UT_ERROR_OVERLONG_STRING	Label too long
 */

static uint32_t
parse_label(struct ut_state *s)
{
	const struct token *tok = s->lex.tok;
	const struct token *word;
	uint32_t rv;
	char *ptr;
	size_t i;

	if (!s->lex.lookbehind && tok->plen)
		lookbehind_append(s, tok->pat, tok->plen);

	if (!buf_remaining(s) || (s->lex.bufstart[0] != '_' && !isalnum(s->lex.bufstart[0]))) {
		for (i = 0, word = &reserved_words[0]; i < ARRAY_SIZE(reserved_words); i++, word = &reserved_words[i]) {
			if (s->lex.lookbehindlen == word->plen && !strncmp(s->lex.lookbehind, word->pat, word->plen)) {
				lookbehind_reset(s);

				switch (word->type) {
				case T_DOUBLE:
					rv = emit_op(s, s->source->off - word->plen, word->type, ut_new_double(word->d));
					break;

				case T_BOOL:
					rv = emit_op(s, s->source->off - word->plen, word->type, xjs_new_boolean(word->b));
					break;

				default:
					rv = emit_op(s, s->source->off - word->plen, word->type, NULL);
				}

				return rv;
			}
		}

		return lookbehind_to_text(s, s->source->off - s->lex.lookbehindlen, T_LABEL, NULL);
	}

	for (ptr = s->lex.bufstart; ptr < s->lex.bufend && (*ptr == '_' || isalnum(*ptr)); ptr++)
		;

	lookbehind_append(s, s->lex.bufstart, ptr - s->lex.bufstart);
	buf_consume(s, ptr - s->lex.bufstart);

	return 0;
}


/*
 * Parses a number literal from the given buffer.
 *
 * Returns a negative value on error, otherwise the amount of consumed
 * characters from the given buffer.
 *
 * Error values:
 *  -UT_ERROR_INVALID_ESCAPE	Invalid number character
 */

static inline bool
is_numeric_char(struct ut_state *s, char c)
{
	char prev = s->lex.lookbehindlen ? s->lex.lookbehind[s->lex.lookbehindlen-1] : 0;

	if ((prev == 'e' || prev == 'E') && (c == '-' || c == '+'))
		return true;

	return (isxdigit(c) || c == 'x' || c == 'X' || c == '.');
}

static uint32_t
parse_number(struct ut_state *s)
{
	uint32_t rv = 0;
	long long int n;
	char *ptr, *e;
	double d;

	if (!buf_remaining(s) || !is_numeric_char(s, s->lex.bufstart[0])) {
		lookbehind_append(s, "\0", 1);

		n = strtoll(s->lex.lookbehind, &e, 0);

		if (*e == '.' || *e == 'e' || *e == 'E') {
			d = strtod(s->lex.lookbehind, &e);

			if (e > s->lex.lookbehind && *e == 0)
				rv = emit_op(s, s->source->off - (e - s->lex.lookbehind), T_DOUBLE, ut_new_double(d));
			else
				ut_new_exception(s, s->source->off - (s->lex.lookbehindlen - (e - s->lex.lookbehind) - 1),
				                 "Syntax error: Invalid number literal");
		}
		else if (*e == 0) {
			rv = emit_op(s, s->source->off - (e - s->lex.lookbehind), T_NUMBER, xjs_new_int64(n));
			ut_get_op(s, rv)->is_overflow = (errno == ERANGE);
		}
		else {
			ut_new_exception(s, s->source->off - (s->lex.lookbehindlen - (e - s->lex.lookbehind) - 1),
			                 "Syntax error: Invalid number literal");
		}

		lookbehind_reset(s);

		return rv;
	}

	for (ptr = s->lex.bufstart; ptr < s->lex.bufend && is_numeric_char(s, *ptr); ptr++)
		;

	lookbehind_append(s, s->lex.bufstart, ptr - s->lex.bufstart);
	buf_consume(s, ptr - s->lex.bufstart);

	return 0;
}

static uint32_t
lex_step(struct ut_state *s, FILE *fp)
{
	const struct token *tok;
	size_t rlen, rem;
	char *ptr, c;
	uint32_t rv;
	size_t i;

	/* only less than UT_LEX_MAX_TOKEN_LEN unreach buffer chars remaining,
	 * move the remaining bytes to the beginning and read more data */
	if (buf_remaining(s) < UT_LEX_MAX_TOKEN_LEN) {
		if (!s->lex.buf) {
			s->lex.buflen = 128;
			s->lex.buf = xalloc(s->lex.buflen);
		}

		rem = s->lex.bufend - s->lex.bufstart;

		memcpy(s->lex.buf, s->lex.bufstart, rem);

		rlen = fread(s->lex.buf + rem, 1, s->lex.buflen - rem, fp);

		s->lex.bufstart = s->lex.buf;
		s->lex.bufend   = s->lex.buf + rlen + rem;

		if (rlen == 0 && (ferror(fp) || feof(fp)))
			s->lex.eof = 1;
	}

	switch (s->lex.state) {
	case UT_LEX_IDENTIFY_BLOCK:
		/* previous block had strip trailing whitespace flag, skip leading whitespace */
		if (s->lex.skip_leading_whitespace) {
			while (buf_remaining(s) && isspace(s->lex.bufstart[0]))
				buf_consume(s, 1);

			s->lex.skip_leading_whitespace = false;
		}

		/* previous block was a statement block and trim_blocks is enabld, skip leading newline */
		else if (s->lex.skip_leading_newline) {
			if (buf_startswith(s, "\n"))
				buf_consume(s, 1);

			s->lex.skip_leading_newline = false;
		}

		/* scan forward through buffer to identify start token */
		for (ptr = s->lex.bufstart; ptr < s->lex.bufend - strlen("{#"); ptr++) {
			/* found start of comment block */
			if (!strncmp(ptr, "{#", 2)) {
				lookbehind_append(s, s->lex.bufstart, ptr - s->lex.bufstart);
				buf_consume(s, (ptr + 2) - s->lex.bufstart);
				s->lex.lastoff = s->source->off - 2;
				s->lex.state = UT_LEX_BLOCK_COMMENT_START;

				return 0;
			}

			/* found start of expression block */
			else if (!strncmp(ptr, "{{", 2)) {
				lookbehind_append(s, s->lex.bufstart, ptr - s->lex.bufstart);
				buf_consume(s, (ptr + 2) - s->lex.bufstart);
				s->lex.lastoff = s->source->off - 2;
				s->lex.state = UT_LEX_BLOCK_EXPRESSION_START;

				return 0;
			}

			/* found start of statement block */
			else if (!strncmp(ptr, "{%", 2)) {
				lookbehind_append(s, s->lex.bufstart, ptr - s->lex.bufstart);
				buf_consume(s, (ptr + 2) - s->lex.bufstart);
				s->lex.lastoff = s->source->off - 2;
				s->lex.state = UT_LEX_BLOCK_STATEMENT_START;

				return 0;
			}
		}

		/* we're at eof */
		if (s->lex.eof) {
			lookbehind_append(s, ptr, s->lex.bufend - ptr);
			s->lex.state = UT_LEX_EOF;

			return lookbehind_to_text(s, s->lex.lastoff, T_TEXT, NULL);
		}

		lookbehind_append(s, s->lex.bufstart, ptr - s->lex.bufstart);
		buf_consume(s, ptr - s->lex.bufstart);
		break;


	case UT_LEX_BLOCK_COMMENT_START:
	case UT_LEX_BLOCK_EXPRESSION_START:
	case UT_LEX_BLOCK_STATEMENT_START:
		rv = 0;
		s->lex.skip_leading_whitespace = 0;

		/* strip whitespace before block */
		if (buf_startswith(s, "-")) {
			rv = lookbehind_to_text(s, s->source->off, T_TEXT, " \n\t\v\f\r");
			buf_consume(s, 1);
		}

		/* disable lstrip flag (only valid for statement blocks) */
		else if (s->lex.state == UT_LEX_BLOCK_STATEMENT_START) {
			/* disable lstrip flag */
			if (buf_startswith(s, "+")) {
				rv = lookbehind_to_text(s, s->source->off, T_TEXT, NULL);
				buf_consume(s, 1);
			}

			/* global block lstrip */
			else if (s->lstrip_blocks) {
				rv = lookbehind_to_text(s, s->source->off, T_TEXT, " \t\v\f\r");
			}
		}
		else {
			rv = lookbehind_to_text(s, s->source->off, T_TEXT, NULL);
		}

		switch (s->lex.state) {
		case UT_LEX_BLOCK_COMMENT_START:
			s->lex.state = UT_LEX_BLOCK_COMMENT;
			break;

		case UT_LEX_BLOCK_STATEMENT_START:
			s->lex.within_statement_block = 1;
			s->lex.state = UT_LEX_IDENTIFY_TOKEN;
			break;

		case UT_LEX_BLOCK_EXPRESSION_START:
			s->lex.state = UT_LEX_BLOCK_EXPRESSION_EMIT_TAG;
			break;

		default:
			break;
		}

		return rv;


	case UT_LEX_BLOCK_COMMENT:
		/* scan forward through buffer to identify end token */
		while (s->lex.bufstart < s->lex.bufend - 2) {
			if (buf_startswith(s, "-#}")) {
				s->lex.state = UT_LEX_IDENTIFY_BLOCK;
				s->lex.skip_leading_whitespace = 1;
				buf_consume(s, 3);
				s->lex.lastoff = s->source->off;
				break;
			}
			else if (buf_startswith(s, "#}")) {
				s->lex.state = UT_LEX_IDENTIFY_BLOCK;
				s->lex.skip_leading_whitespace = 0;
				buf_consume(s, 2);
				s->lex.lastoff = s->source->off;
				break;
			}

			buf_consume(s, 1);
		}

		/* we're at eof */
		if (s->lex.eof)
			ut_new_exception(s, s->lex.lastoff, "Syntax error: Unterminated template block");

		break;


	case UT_LEX_BLOCK_EXPRESSION_EMIT_TAG:
		s->lex.within_expression_block = 1;
		s->lex.state = UT_LEX_IDENTIFY_TOKEN;

		return emit_op(s, s->source->off, T_LEXP, NULL);


	case UT_LEX_IDENTIFY_TOKEN:
		for (i = 0, tok = tokens; i < ARRAY_SIZE(tokens); tok = &tokens[++i]) {
			/* remaining buffer data is shorter than token, skip */
			if (tok->plen > buf_remaining(s))
				continue;

			c = s->lex.bufstart[0];

			if (tok->plen ? !strncmp(s->lex.bufstart, tok->pat, tok->plen)
			              : (c >= tok->pat[0] && c <= tok->pat[1])) {
				buf_consume(s, tok->plen);

				s->lex.lastoff = s->source->off - tok->plen;

				/* token has a parse method, switch state */
				if (tok->parse) {
					s->lex.tok = tok;
					s->lex.state = UT_LEX_PARSE_TOKEN;

					return 0;
				}

				/* disallow nesting blocks */
				if ((s->lex.within_expression_block &&
				     (tok->type == T_LSTM || tok->type == T_RSTM || tok->type == T_LEXP)) ||
				    (s->lex.within_statement_block &&
				     (tok->type == T_LEXP || tok->type == T_REXP || tok->type == T_LSTM))) {
					ut_new_exception(s, s->source->off - tok->plen, "Syntax error: Template blocks may not be nested");

					return 0;
				}

				/* found end of block */
				else if ((s->lex.within_statement_block && tok->type == T_RSTM) ||
				         (s->lex.within_expression_block && tok->type == T_REXP)) {
					/* emit additional empty statement (semicolon) at end of template block */
					if (!s->lex.semicolon_emitted) {
						s->lex.semicolon_emitted = true;

						/* rewind */
						buf_consume(s, -tok->plen);

						return emit_op(s, s->source->off, T_SCOL, NULL);
					}

					/* strip whitespace after block */
					if (tok->pat[0] == '-')
						s->lex.skip_leading_whitespace = true;

					/* strip newline after statement block */
					else if (s->lex.within_statement_block && s->trim_blocks)
						s->lex.skip_leading_newline = true;

					s->lex.semicolon_emitted = false;
					s->lex.within_statement_block = false;
					s->lex.within_expression_block = false;
					s->lex.state = UT_LEX_IDENTIFY_BLOCK;
					s->lex.lastoff = s->source->off;
				}

				/* do not report statement tags to the parser */
				if (tok->type != 0 && tok->type != T_LSTM && tok->type != T_RSTM)
					rv = emit_op(s, s->source->off - tok->plen, tok->type, NULL);
				else
					rv = 0;

				return rv;
			}
		}

		/* no token matched and we do have remaining data, junk */
		if (buf_remaining(s)) {
			ut_new_exception(s, s->source->off, "Syntax error: Unexpected character");

			return 0;
		}

		/* we're at eof, allow unclosed statement blocks */
		if (s->lex.within_statement_block) {
			s->lex.state = UT_LEX_EOF;

			return 0;
		}

		/* premature EOF */
		ut_new_exception(s, s->source->off, "Syntax error: Unterminated template block");

		break;


	case UT_LEX_PARSE_TOKEN:
		tok = s->lex.tok;
		rv = tok->parse(s);

		if (rv) {
			memset(s->lex.esc, 0, sizeof(s->lex.esc));
			s->lex.state = UT_LEX_IDENTIFY_TOKEN;
			s->lex.tok = NULL;

			if (rv == UINT32_MAX)
				rv = 0;

			return rv;
		}

		break;


	case UT_LEX_EOF:
		break;
	}

	return 0;
}

uint32_t
ut_get_token(struct ut_state *s, FILE *fp)
{
	uint32_t rv;

	while (s->lex.state != UT_LEX_EOF) {
		rv = lex_step(s, fp);

		if (rv == 0 && s->exception)
			break;

		if (rv > 0)
			return rv;
	}

	return 0;
}

const char *
ut_get_tokenname(int type)
{
	static char buf[sizeof("'endfunction'")];
	size_t i;

	switch (type) {
	case 0:        return "End of file";
	case T_STRING: return "String";
	case T_LABEL:  return "Label";
	case T_NUMBER: return "Number";
	case T_DOUBLE: return "Double";
	case T_REGEXP: return "Regexp";
	}

	for (i = 0; i < ARRAY_SIZE(tokens); i++) {
		if (tokens[i].type != type)
			continue;

		snprintf(buf, sizeof(buf), "'%s'", tokens[i].pat);

		return buf;
	}

	for (i = 0; i < ARRAY_SIZE(reserved_words); i++) {
		if (reserved_words[i].type != type)
			continue;

		snprintf(buf, sizeof(buf), "'%s'", reserved_words[i].pat);

		return buf;
	}

	return "?";
}
