/*
 * Copyright (C) 2020-2021 Jo-Philipp Wich <jo@mein.io>
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
#include <endian.h>

#include "ucode/vm.h"
#include "ucode/lib.h"
#include "ucode/lexer.h"

#define UC_LEX_CONTINUE_PARSING (void *)1

struct keyword {
	unsigned type;
	const char *pat;
	unsigned plen;
};

struct token {
	unsigned type;
	union {
		uint32_t patn;
		char pat[4];
	} u;
	unsigned plen;
	uc_token_t *(*parse)(uc_lexer_t *);
};

#define dec(o) \
	((o) - '0')

#define hex(x) \
	(((x) >= 'a') ? (10 + (x) - 'a') : \
		(((x) >= 'A') ? (10 + (x) - 'A') : dec(x)))

#ifndef NO_COMPILE

static uc_token_t *parse_comment(uc_lexer_t *);
static uc_token_t *parse_string(uc_lexer_t *);
static uc_token_t *parse_regexp(uc_lexer_t *);
static uc_token_t *parse_number(uc_lexer_t *);
static uc_token_t *parse_label(uc_lexer_t *);

static const struct token tokens[] = {
	{ TK_ASLEFT,	{ .pat = "<<=" },   3, NULL },
	{ TK_ASRIGHT,	{ .pat = ">>=" },   3, NULL },
	{ TK_LEXP,		{ .pat = "{{-" },   3, NULL },
	{ TK_REXP,		{ .pat = "-}}" },   3, NULL },
	{ TK_LSTM,		{ .pat = "{%+" },   3, NULL },
	{ TK_LSTM,		{ .pat = "{%-" },   3, NULL },
	{ TK_RSTM,		{ .pat = "-%}" },   3, NULL },
	{ TK_EQS,		{ .pat = "===" },   3, NULL },
	{ TK_NES,		{ .pat = "!==" },   3, NULL },
	{ TK_ELLIP,		{ .pat = "..." },   3, NULL },
	{ TK_QLBRACK,	{ .pat = "?.[" },   3, NULL },
	{ TK_QLPAREN,	{ .pat = "?.(" },   3, NULL },
	{ TK_AND,		{ .pat = "&&" },    2, NULL },
	{ TK_ASADD,		{ .pat = "+=" },    2, NULL },
	{ TK_ASBAND,	{ .pat = "&=" },    2, NULL },
	{ TK_ASBOR,		{ .pat = "|=" },    2, NULL },
	{ TK_ASBXOR,	{ .pat = "^=" },    2, NULL },
	//{ TK_ASDIV,	{ .pat = "/=" },    2, NULL },
	{ TK_ASMOD,		{ .pat = "%=" },    2, NULL },
	{ TK_ASMUL,		{ .pat = "*=" },    2, NULL },
	{ TK_ASSUB,		{ .pat = "-=" },    2, NULL },
	{ TK_DEC,		{ .pat = "--" },    2, NULL },
	{ TK_INC,		{ .pat = "++" },    2, NULL },
	{ TK_EQ,		{ .pat = "==" },    2, NULL },
	{ TK_NE,		{ .pat = "!=" },    2, NULL },
	{ TK_LE,		{ .pat = "<=" },    2, NULL },
	{ TK_GE,		{ .pat = ">=" },    2, NULL },
	{ TK_LSHIFT,	{ .pat = "<<" },    2, NULL },
	{ TK_RSHIFT,	{ .pat = ">>" },    2, NULL },
	{ 0,			{ .pat = "//" },    2, parse_comment },
	{ 0,			{ .pat = "/*" },    2, parse_comment },
	{ TK_OR,		{ .pat = "||" },    2, NULL },
	{ TK_LEXP,		{ .pat = "{{" },    2, NULL },
	{ TK_REXP,		{ .pat = "}}" },    2, NULL },
	{ TK_LSTM,		{ .pat = "{%" },    2, NULL },
	{ TK_RSTM,		{ .pat = "%}" },    2, NULL },
	{ TK_ARROW,		{ .pat = "=>" },    2, NULL },
	{ TK_QDOT,		{ .pat = "?." },    2, NULL },
	{ TK_ADD,		{ .pat = "+" },     1, NULL },
	{ TK_ASSIGN,	{ .pat = "=" },     1, NULL },
	{ TK_BAND,		{ .pat = "&" },     1, NULL },
	{ TK_BOR,		{ .pat = "|" },     1, NULL },
	{ TK_LBRACK,	{ .pat = "[" },     1, NULL },
	{ TK_RBRACK,	{ .pat = "]" },     1, NULL },
	{ TK_BXOR,		{ .pat = "^" },     1, NULL },
	{ TK_LBRACE,	{ .pat = "{" },     1, NULL },
	{ TK_RBRACE,	{ .pat = "}" },     1, NULL },
	{ TK_COLON,		{ .pat = ":" },     1, NULL },
	{ TK_COMMA,		{ .pat = "," },     1, NULL },
	{ TK_COMPL,		{ .pat = "~" },     1, NULL },
	//{ TK_DIV,		{ .pat = "/" },     1, NULL },
	{ TK_GT,		{ .pat = ">" },     1, NULL },
	{ TK_NOT,		{ .pat = "!" },     1, NULL },
	{ TK_LT,		{ .pat = "<" },     1, NULL },
	{ TK_MOD,		{ .pat = "%" },     1, NULL },
	{ TK_MUL,		{ .pat = "*" },     1, NULL },
	{ TK_LPAREN,	{ .pat = "(" },     1, NULL },
	{ TK_RPAREN,	{ .pat = ")" },     1, NULL },
	{ TK_QMARK,		{ .pat = "?" },     1, NULL },
	{ TK_SCOL,		{ .pat = ";" },     1, NULL },
	{ TK_SUB,		{ .pat = "-" },     1, NULL },
	{ TK_DOT,		{ .pat = "." },     1, NULL },
	{ TK_STRING,	{ .pat = "'" },     1, parse_string },
	{ TK_STRING,	{ .pat = "\"" },    1, parse_string },
	{ TK_REGEXP,	{ .pat = "/" },     1, parse_regexp },
	{ TK_LABEL,		{ .pat = "_" },     1, parse_label },
	{ TK_LABEL,		{ .pat = "az" },    0, parse_label },
	{ TK_LABEL,		{ .pat = "AZ" },    0, parse_label },
	{ TK_NUMBER,	{ .pat = "09" },    0, parse_number },
};

static const struct keyword reserved_words[] = {
	{ TK_ENDFUNC,	"endfunction", 11 },
	{ TK_CONTINUE,	"continue", 8 },
	{ TK_ENDWHILE,	"endwhile", 8 },
	{ TK_FUNC,		"function", 8 },
	{ TK_DEFAULT,	"default", 7 },
	{ TK_DELETE,	"delete", 6 },
	{ TK_RETURN,	"return", 6 },
	{ TK_ENDFOR,	"endfor", 6 },
	{ TK_SWITCH,	"switch", 6 },
	{ TK_ENDIF,		"endif", 5 },
	{ TK_WHILE,		"while", 5 },
	{ TK_BREAK,		"break", 5 },
	{ TK_CATCH,		"catch", 5 },
	{ TK_CONST,		"const", 5 },
	{ TK_FALSE,		"false", 5 },
	{ TK_TRUE,		"true",  4 },
	{ TK_ELIF,		"elif",  4 },
	{ TK_ELSE,		"else",  4 },
	{ TK_THIS,		"this",  4 },
	{ TK_NULL,		"null",  4 },
	{ TK_CASE,		"case",  4 },
	{ TK_TRY,		"try",   3 },
	{ TK_FOR,		"for",   3 },
	{ TK_LOCAL,		"let",   3 },
	{ TK_IF,		"if",    2 },
	{ TK_IN,		"in",    2 },
};


/* length of the longest token in our lookup table */
#define UC_LEX_MAX_TOKEN_LEN 3

static uc_token_t *
emit_op(uc_lexer_t *lex, uint32_t pos, int type, uc_value_t *uv)
{
	lex->curr.type = type;
	lex->curr.uv = uv;
	lex->curr.pos = pos;

	return &lex->curr;
}

static void lookbehind_append(uc_lexer_t *lex, const char *data, size_t len)
{
	if (len) {
		lex->lookbehind = xrealloc(lex->lookbehind, lex->lookbehindlen + len);
		memcpy(lex->lookbehind + lex->lookbehindlen, data, len);
		lex->lookbehindlen += len;
	}
}

static void lookbehind_reset(uc_lexer_t *lex) {
	free(lex->lookbehind);
	lex->lookbehind = NULL;
	lex->lookbehindlen = 0;
}

static uc_token_t *
lookbehind_to_text(uc_lexer_t *lex, uint32_t pos, int type, const char *strip_trailing_chars) {
	uc_token_t *rv = NULL;

	if (lex->lookbehind) {
		if (strip_trailing_chars) {
			while (lex->lookbehindlen > 0 && strchr(strip_trailing_chars, lex->lookbehind[lex->lookbehindlen-1]))
				lex->lookbehindlen--;
		}

		rv = emit_op(lex, pos, type, ucv_string_new_length(lex->lookbehind, lex->lookbehindlen));

		lookbehind_reset(lex);
	}

	return rv;
}

static inline size_t
buf_remaining(uc_lexer_t *lex) {
	return (lex->bufend - lex->bufstart);
}

static inline bool
_buf_startswith(uc_lexer_t *lex, const char *str, size_t len) {
	return (buf_remaining(lex) >= len && !strncmp(lex->bufstart, str, len));
}

#define buf_startswith(s, str) _buf_startswith(s, str, sizeof(str) - 1)


static void
buf_consume(uc_lexer_t *lex, size_t len) {
	size_t i, linelen;

	for (i = 0, linelen = 0; i < len; i++) {
		if (lex->bufstart[i] == '\n') {
			uc_source_line_update(lex->source, linelen);
			uc_source_line_next(lex->source);

			linelen = 0;
		}
		else {
			linelen++;
		}
	}

	if (linelen)
		uc_source_line_update(lex->source, linelen);

	lex->bufstart += len;
	lex->source->off += len;
}

static uc_token_t *
parse_comment(uc_lexer_t *lex)
{
	const struct token *tok = lex->tok;
	const char *ptr, *end;
	size_t elen;

	if (!strcmp(tok->u.pat, "//")) {
		end = "\n";
		elen = 1;
	}
	else {
		end = "*/";
		elen = 2;
	}

	for (ptr = lex->bufstart; ptr < lex->bufend - elen; ptr++) {
		if (!strncmp(ptr, end, elen)) {
			buf_consume(lex, (ptr - lex->bufstart) + elen);

			return UC_LEX_CONTINUE_PARSING;
		}
	}

	buf_consume(lex, ptr - lex->bufstart);

	if (lex->eof) {
		lex->state = UC_LEX_EOF;

		if (elen == 2)
			return emit_op(lex, lex->lastoff, TK_ERROR, ucv_string_new("Unterminated comment"));
	}

	return NULL;
}

static void
append_utf8(uc_lexer_t *lex, int code) {
	char ustr[8], *up;
	int rem;

	up = ustr;
	rem = sizeof(ustr);

	if (utf8enc(&up, &rem, code))
		lookbehind_append(lex, ustr, up - ustr);
}

static uc_token_t *
parse_string(uc_lexer_t *lex)
{
	const struct token *tok = lex->tok;
	char q = tok->u.pat[0];
	char *ptr, *c;
	uc_token_t *rv;
	int code;

	if (!buf_remaining(lex))
		return emit_op(lex, lex->lastoff, TK_ERROR, ucv_string_new("Unterminated string"));

	for (ptr = lex->bufstart; ptr < lex->bufend; ptr++) {
		/* continuation of escape sequence */
		if (lex->is_escape) {
			if (lex->esclen == 0) {
				/* non-unicode escape following a lead surrogate, emit replacement... */
				if (lex->lead_surrogate && *ptr != 'u') {
					append_utf8(lex, 0xFFFD);
					lex->lead_surrogate = 0;
				}

				switch ((q == '/') ? 0 : *ptr) {
				case 'u':
				case 'x':
					lex->esc[lex->esclen++] = *ptr;
					break;

				case '0':
				case '1':
				case '2':
				case '3':
				case '4':
				case '5':
				case '6':
				case '7':
					lex->esc[lex->esclen++] = 'o';
					lex->esc[lex->esclen++] = *ptr;
					break;

				default:
					lex->is_escape = false;
					c = strchr("a\ab\be\033f\fn\nr\rt\tv\v", *ptr);

					if (c && *c >= 'a') {
						lookbehind_append(lex, c + 1, 1);
					}
					else {
						/* regex mode => retain backslash */
						if (q == '/')
							lookbehind_append(lex, "\\", 1);

						lookbehind_append(lex, ptr, 1);
					}

					buf_consume(lex, (ptr + 1) - lex->bufstart);

					break;
				}
			}
			else {
				switch (lex->esc[0]) {
				case 'u':
					if (lex->esclen < 5) {
						if (!isxdigit(*ptr))
							return emit_op(lex, lex->source->off + lex->esclen + 1, TK_ERROR, ucv_string_new("Invalid escape sequence"));

						lex->esc[lex->esclen++] = *ptr;
					}

					if (lex->esclen == 5) {
						code = hex(lex->esc[1]) * 16 * 16 * 16 +
						       hex(lex->esc[2]) * 16 * 16 +
						       hex(lex->esc[3]) * 16 +
						       hex(lex->esc[4]);

						/* is a leading surrogate value */
						if ((code & 0xFC00) == 0xD800) {
							/* found a subsequent leading surrogate, ignore and emit replacement char for previous one */
							if (lex->lead_surrogate)
								append_utf8(lex, 0xFFFD);

							/* store surrogate value and advance to next escape sequence */
							lex->lead_surrogate = code;
						}

						/* is a trailing surrogate value */
						else if ((code & 0xFC00) == 0xDC00) {
							/* found a trailing surrogate following a leading one, combine and encode */
							if (lex->lead_surrogate) {
								code = 0x10000 + ((lex->lead_surrogate & 0x3FF) << 10) + (code & 0x3FF);
								lex->lead_surrogate = 0;
							}

							/* trailing surrogate not following a leading one, ignore and use replacement char */
							else {
								code = 0xFFFD;
							}

							append_utf8(lex, code);
						}

						/* is a normal codepoint */
						else {
							append_utf8(lex, code);
						}

						lex->esclen = 0;
						lex->is_escape = false;
						buf_consume(lex, (ptr + 1) - lex->bufstart);
					}

					break;

				case 'x':
					if (lex->esclen < 3) {
						if (!isxdigit(*ptr))
							return emit_op(lex, lex->source->off + lex->esclen + 1, TK_ERROR, ucv_string_new("Invalid escape sequence"));

						lex->esc[lex->esclen++] = *ptr;
					}

					if (lex->esclen == 3) {
						append_utf8(lex, hex(lex->esc[1]) * 16 + hex(lex->esc[2]));

						lex->esclen = 0;
						lex->is_escape = false;
						buf_consume(lex, (ptr + 1) - lex->bufstart);
					}

					break;

				case 'o':
					if (lex->esclen < 4) {
						/* found a non-octal char */
						if (*ptr < '0' || *ptr > '7') {
							/* pad sequence to three chars */
							switch (lex->esclen) {
							case 3:
								lex->esc[3] = lex->esc[2];
								lex->esc[2] = lex->esc[1];
								lex->esc[1] = '0';
								break;

							case 2:
								lex->esc[3] = lex->esc[1];
								lex->esc[2] = '0';
								lex->esc[1] = '0';
								break;
							}

							lex->esclen = 4;
							buf_consume(lex, ptr-- - lex->bufstart);
						}

						/* append */
						else {
							lex->esc[lex->esclen++] = *ptr;
							buf_consume(lex, (ptr + 1) - lex->bufstart);
						}
					}

					if (lex->esclen == 4) {
						code = dec(lex->esc[1]) * 8 * 8 +
						       dec(lex->esc[2]) * 8 +
						       dec(lex->esc[3]);

						if (code > 255)
							return emit_op(lex, lex->source->off + lex->esclen + 1, TK_ERROR, ucv_string_new("Invalid escape sequence"));

						append_utf8(lex, code);

						lex->esclen = 0;
						lex->is_escape = false;
					}

					break;
				}
			}
		}

		/* terminating char */
		else if (*ptr == q) {
			lookbehind_append(lex, lex->bufstart, ptr - lex->bufstart);
			buf_consume(lex, (ptr + 1) - lex->bufstart);

			rv = lookbehind_to_text(lex, lex->lastoff, TK_STRING, NULL);

			if (!rv)
				rv = emit_op(lex, lex->lastoff, TK_STRING, ucv_string_new_length("", 0));

			return rv;
		}

		/* escape sequence start */
		else if (*ptr == '\\') {
			lex->is_escape = true;
			lookbehind_append(lex, lex->bufstart, ptr - lex->bufstart);
			buf_consume(lex, (ptr - lex->bufstart) + 1);
		}
	}

	lookbehind_append(lex, lex->bufstart, ptr - lex->bufstart);
	buf_consume(lex, ptr - lex->bufstart);

	return NULL;
}


/*
 * Parses a regexp literal from the given buffer.
 *
 * Returns a negative value on error, otherwise the amount of consumed
 * characters from the given buffer.
 *
 * Error values:
 *  -UC_ERROR_UNTERMINATED_STRING	Unterminated regexp
 *  -UC_ERROR_INVALID_ESCAPE		Invalid escape sequence
 *  -UC_ERROR_OVERLONG_STRING		Regexp literal too long
 *  -UC_ERROR_INVALID_REGEXP        Could not compile regexp
 */

enum {
	UC_LEX_PARSE_REGEX_INIT,
	UC_LEX_PARSE_REGEX_PATTERN,
	UC_LEX_PARSE_REGEX_FLAGS
};

static uc_token_t *
parse_regexp(uc_lexer_t *lex)
{
	bool is_reg_global = false, is_reg_icase = false, is_reg_newline = false;
	uc_token_t *rv;
	size_t len;
	char *s;

	switch (lex->esc[0]) {
	case UC_LEX_PARSE_REGEX_INIT:
		if (lex->no_regexp) {
			if (buf_startswith(lex, "=")) {
				buf_consume(lex, 1);

				return emit_op(lex, lex->source->off, TK_ASDIV, NULL);
			}

			return emit_op(lex, lex->source->off, TK_DIV, NULL);
		}

		lex->esc[0] = UC_LEX_PARSE_REGEX_PATTERN;
		break;

	case UC_LEX_PARSE_REGEX_PATTERN:
		rv = parse_string(lex);

		if (rv && rv->type == TK_ERROR)
			return rv;

		if (rv != NULL && rv != UC_LEX_CONTINUE_PARSING) {
			lex->lookbehind = (char *)rv;
			lex->esc[0] = UC_LEX_PARSE_REGEX_FLAGS;
		}

		break;

	case UC_LEX_PARSE_REGEX_FLAGS:
		rv = (uc_token_t *)lex->lookbehind;

		while (lex->bufstart < lex->bufend || lex->eof) {
			switch (lex->eof ? EOF : lex->bufstart[0]) {
			case 'g':
				buf_consume(lex, 1);
				is_reg_global = true;
				break;

			case 'i':
				buf_consume(lex, 1);
				is_reg_icase = true;
				break;

			case 's':
				buf_consume(lex, 1);
				is_reg_newline = true;
				break;

			default:
				lex->lookbehind = NULL;

				len = xasprintf(&s, "%c%*s",
					(is_reg_global << 0) | (is_reg_icase << 1) | (is_reg_newline << 2),
					ucv_string_length(rv->uv),
					ucv_string_get(rv->uv));

				ucv_free(rv->uv, false);
				rv->uv = ucv_string_new_length(s, len);
				free(s);

				rv->type = TK_REGEXP;

				return rv;
			}
		}

		break;
	}

	return NULL;
}


/*
 * Parses a label from the given buffer.
 *
 * Returns a negative value on error, otherwise the amount of consumed
 * characters from the given buffer.
 *
 * Error values:
 *  -UC_ERROR_OVERLONG_STRING	Label too long
 */

static uc_token_t *
parse_label(uc_lexer_t *lex)
{
	const struct token *tok = lex->tok;
	const struct keyword *word;
	char *ptr;
	size_t i;

	if (!lex->lookbehind && tok->plen)
		lookbehind_append(lex, tok->u.pat, tok->plen);

	if (!buf_remaining(lex) || (lex->bufstart[0] != '_' && !isalnum(lex->bufstart[0]))) {
		if (lex->no_keyword == false) {
			for (i = 0, word = &reserved_words[0]; i < ARRAY_SIZE(reserved_words); i++, word = &reserved_words[i]) {
				if (lex->lookbehind && lex->lookbehindlen == word->plen && !strncmp(lex->lookbehind, word->pat, word->plen)) {
					lookbehind_reset(lex);

					return emit_op(lex, lex->source->off - word->plen, word->type, NULL);
				}
			}
		}

		return lookbehind_to_text(lex, lex->source->off - lex->lookbehindlen, TK_LABEL, NULL);
	}

	for (ptr = lex->bufstart; ptr < lex->bufend && (*ptr == '_' || isalnum(*ptr)); ptr++)
		;

	lookbehind_append(lex, lex->bufstart, ptr - lex->bufstart);
	buf_consume(lex, ptr - lex->bufstart);

	return NULL;
}


/*
 * Parses a number literal from the given buffer.
 *
 * Returns a negative value on error, otherwise the amount of consumed
 * characters from the given buffer.
 *
 * Error values:
 *  -UC_ERROR_INVALID_ESCAPE	Invalid number character
 */

static inline bool
is_numeric_char(uc_lexer_t *lex, char c)
{
	char prev = lex->lookbehindlen ? lex->lookbehind[lex->lookbehindlen-1] : 0;

	if ((prev == 'e' || prev == 'E') && (c == '-' || c == '+'))
		return true;

	return prev ? (isxdigit(c) || c == 'x' || c == 'X' || c == '.') : (isdigit(c) || c == '.');
}

static uc_token_t *
parse_number(uc_lexer_t *lex)
{
	uc_token_t *rv = NULL;
	uc_value_t *nv = NULL;
	const char *ptr;
	char *e;

	if (!buf_remaining(lex) || !is_numeric_char(lex, lex->bufstart[0])) {
		lookbehind_append(lex, "\0", 1);

		nv = uc_number_parse(lex->lookbehind, &e);

		switch (ucv_type(nv)) {
		case UC_DOUBLE:
			rv = emit_op(lex, lex->source->off - (e - lex->lookbehind), TK_DOUBLE, nv);
			break;

		case UC_INTEGER:
			rv = emit_op(lex, lex->source->off - (e - lex->lookbehind), TK_NUMBER, nv);
			break;

		default:
			rv = emit_op(lex, lex->source->off - (lex->lookbehindlen - (e - lex->lookbehind) - 1), TK_ERROR, ucv_string_new("Invalid number literal"));
		}

		lookbehind_reset(lex);

		return rv;
	}

	for (ptr = lex->bufstart; ptr < lex->bufend && is_numeric_char(lex, *ptr); ptr++)
		;

	lookbehind_append(lex, lex->bufstart, ptr - lex->bufstart);
	buf_consume(lex, ptr - lex->bufstart);

	return NULL;
}

static uc_token_t *
lex_step(uc_lexer_t *lex, FILE *fp)
{
	uint32_t masks[] = { 0, le32toh(0x000000ff), le32toh(0x0000ffff), le32toh(0x00ffffff), le32toh(0xffffffff) };
	union { uint32_t n; char str[4]; } search;
	const struct token *tok;
	size_t rlen, rem;
	char *ptr, c;
	uc_token_t *rv;
	size_t i;

	/* only less than UC_LEX_MAX_TOKEN_LEN unread buffer chars remaining,
	 * move the remaining bytes to the beginning and read more data */
	if (buf_remaining(lex) < UC_LEX_MAX_TOKEN_LEN) {
		if (!lex->buf) {
			lex->buflen = 128;
			lex->buf = xalloc(lex->buflen);
		}

		rem = lex->bufend - lex->bufstart;

		if (rem)
			memcpy(lex->buf, lex->bufstart, rem);

		rlen = fread(lex->buf + rem, 1, lex->buflen - rem, fp);

		lex->bufstart = lex->buf;
		lex->bufend   = lex->buf + rlen + rem;

		if (rlen == 0 && (ferror(fp) || feof(fp)))
			lex->eof = 1;
	}

	switch (lex->state) {
	case UC_LEX_IDENTIFY_BLOCK:
		/* previous block had strip trailing whitespace flag, skip leading whitespace */
		if (lex->modifier == MINUS) {
			while (buf_remaining(lex) && isspace(lex->bufstart[0]))
				buf_consume(lex, 1);

			lex->modifier = UNSPEC;
		}

		/* previous block was a statement block and trim_blocks is enabld, skip leading newline */
		else if (lex->modifier == NEWLINE) {
			if (buf_startswith(lex, "\n"))
				buf_consume(lex, 1);

			lex->modifier = UNSPEC;
		}

		/* scan forward through buffer to identify start token */
		for (ptr = lex->bufstart; ptr < lex->bufend - strlen("{#"); ptr++) {
			/* found start of comment block */
			if (!strncmp(ptr, "{#", 2)) {
				lookbehind_append(lex, lex->bufstart, ptr - lex->bufstart);
				buf_consume(lex, (ptr + 2) - lex->bufstart);
				lex->lastoff = lex->source->off - 2;
				lex->state = UC_LEX_BLOCK_COMMENT_START;

				return NULL;
			}

			/* found start of expression block */
			else if (!strncmp(ptr, "{{", 2)) {
				lookbehind_append(lex, lex->bufstart, ptr - lex->bufstart);
				buf_consume(lex, (ptr + 2) - lex->bufstart);
				lex->lastoff = lex->source->off - 2;
				lex->state = UC_LEX_BLOCK_EXPRESSION_START;

				return NULL;
			}

			/* found start of statement block */
			else if (!strncmp(ptr, "{%", 2)) {
				lookbehind_append(lex, lex->bufstart, ptr - lex->bufstart);
				buf_consume(lex, (ptr + 2) - lex->bufstart);
				lex->lastoff = lex->source->off - 2;
				lex->state = UC_LEX_BLOCK_STATEMENT_START;

				return NULL;
			}
		}

		/* we're at eof */
		if (lex->eof) {
			lookbehind_append(lex, ptr, lex->bufend - ptr);
			lex->state = UC_LEX_EOF;

			return lookbehind_to_text(lex, lex->lastoff, TK_TEXT, NULL);
		}

		lookbehind_append(lex, lex->bufstart, ptr - lex->bufstart);
		buf_consume(lex, ptr - lex->bufstart);
		break;


	case UC_LEX_BLOCK_COMMENT_START:
	case UC_LEX_BLOCK_EXPRESSION_START:
	case UC_LEX_BLOCK_STATEMENT_START:
		rv = NULL;
		lex->modifier = UNSPEC;

		/* strip whitespace before block */
		if (buf_startswith(lex, "-")) {
			rv = lookbehind_to_text(lex, lex->source->off, TK_TEXT, " \n\t\v\f\r");
			buf_consume(lex, 1);
		}

		/* disable lstrip flag (only valid for statement blocks) */
		else if (lex->state == UC_LEX_BLOCK_STATEMENT_START) {
			/* disable lstrip flag */
			if (buf_startswith(lex, "+")) {
				rv = lookbehind_to_text(lex, lex->source->off, TK_TEXT, NULL);
				buf_consume(lex, 1);
			}

			/* global block lstrip */
			else if (lex->config && lex->config->lstrip_blocks) {
				rv = lookbehind_to_text(lex, lex->source->off, TK_TEXT, " \t\v\f\r");
			}
		}
		else {
			rv = lookbehind_to_text(lex, lex->source->off, TK_TEXT, NULL);
		}

		switch (lex->state) {
		case UC_LEX_BLOCK_COMMENT_START:
			lex->state = UC_LEX_BLOCK_COMMENT;
			lex->block = COMMENT;
			break;

		case UC_LEX_BLOCK_STATEMENT_START:
			lex->state = UC_LEX_IDENTIFY_TOKEN;
			lex->block = STATEMENTS;
			break;

		case UC_LEX_BLOCK_EXPRESSION_START:
			lex->state = UC_LEX_BLOCK_EXPRESSION_EMIT_TAG;
			break;

		default:
			break;
		}

		return rv;


	case UC_LEX_BLOCK_COMMENT:
		/* scan forward through buffer to identify end token */
		while (lex->bufstart < lex->bufend - 2) {
			if (buf_startswith(lex, "-#}")) {
				lex->state = UC_LEX_IDENTIFY_BLOCK;
				lex->modifier = MINUS;
				buf_consume(lex, 3);
				lex->lastoff = lex->source->off;
				break;
			}
			else if (buf_startswith(lex, "#}")) {
				lex->state = UC_LEX_IDENTIFY_BLOCK;
				buf_consume(lex, 2);
				lex->lastoff = lex->source->off;
				break;
			}

			buf_consume(lex, 1);
		}

		/* we're at eof */
		if (lex->eof) {
			lex->state = UC_LEX_EOF;

			buf_consume(lex, lex->bufend - lex->bufstart);

			return emit_op(lex, lex->lastoff, TK_ERROR, ucv_string_new("Unterminated template block"));
		}

		break;


	case UC_LEX_BLOCK_EXPRESSION_EMIT_TAG:
		lex->state = UC_LEX_IDENTIFY_TOKEN;
		lex->block = EXPRESSION;

		return emit_op(lex, lex->source->off, TK_LEXP, NULL);


	case UC_LEX_IDENTIFY_TOKEN:
		/* skip leading whitespace */
		for (i = 0; i < buf_remaining(lex) && isspace(lex->bufstart[i]); i++)
			;

		buf_consume(lex, i);

		if (i > 0 && buf_remaining(lex) < UC_LEX_MAX_TOKEN_LEN)
			return NULL;

		for (i = 0; i < sizeof(search.str); i++)
			search.str[i] = (i < buf_remaining(lex)) ? lex->bufstart[i] : 0;

		for (i = 0, tok = tokens; i < ARRAY_SIZE(tokens); tok = &tokens[++i]) {
			/* remaining buffer data is shorter than token, skip */
			if (tok->plen > buf_remaining(lex))
				continue;

			c = buf_remaining(lex) ? lex->bufstart[0] : 0;

			if (tok->plen ? ((search.n & masks[tok->plen]) == tok->u.patn)
			              : (c >= tok->u.pat[0] && c <= tok->u.pat[1])) {
				lex->lastoff = lex->source->off;

				/* token has a parse method, switch state */
				if (tok->parse) {
					lex->tok = tok;
					lex->state = UC_LEX_PARSE_TOKEN;

					buf_consume(lex, tok->plen);

					return NULL;
				}

				/* in raw code mode, ignore template tag tokens */
				if (lex->config && lex->config->raw_mode &&
				    (tok->type == TK_LSTM || tok->type == TK_RSTM ||
				     tok->type == TK_LEXP || tok->type == TK_REXP)) {
					continue;
				}

				/* disallow nesting blocks */
				if (tok->type == TK_LSTM || tok->type == TK_LEXP) {
					buf_consume(lex, tok->plen);

					return emit_op(lex, lex->source->off - tok->plen, TK_ERROR, ucv_string_new("Template blocks may not be nested"));
				}

				/* found end of block */
				else if ((lex->block == STATEMENTS && tok->type == TK_RSTM) ||
				         (lex->block == EXPRESSION && tok->type == TK_REXP)) {
					/* strip whitespace after block */
					if (tok->u.pat[0] == '-')
						lex->modifier = MINUS;

					/* strip newline after statement block */
					else if (lex->block == STATEMENTS &&
					         lex->config && lex->config->trim_blocks)
						lex->modifier = NEWLINE;

					lex->state = UC_LEX_IDENTIFY_BLOCK;
					lex->block = NONE;
				}

				/* do not report statement tags to the parser */
				if (tok->type != 0 && tok->type != TK_LSTM)
					rv = emit_op(lex, lex->source->off,
						(tok->type == TK_RSTM) ? TK_SCOL : tok->type, NULL);
				else
					rv = NULL;

				buf_consume(lex, tok->plen);

				return rv;
			}
		}

		/* no possible return beyond this point can advance,
		   mark lex state as eof */
		lex->state = UC_LEX_EOF;

		/* no token matched and we do have remaining data, junk */
		if (buf_remaining(lex))
			return emit_op(lex, lex->source->off, TK_ERROR, ucv_string_new("Unexpected character"));

		/* we're at eof, allow unclosed statement blocks */
		if (lex->block == STATEMENTS)
			return NULL;

		/* premature EOF */
		return emit_op(lex, lex->source->off, TK_ERROR, ucv_string_new("Unterminated template block"));


	case UC_LEX_PARSE_TOKEN:
		tok = lex->tok;
		rv = tok->parse(lex);

		if (rv) {
			memset(lex->esc, 0, sizeof(lex->esc));
			lex->state = UC_LEX_IDENTIFY_TOKEN;
			lex->tok = NULL;

			if (rv == UC_LEX_CONTINUE_PARSING)
				rv = NULL;

			return rv;
		}

		break;


	case UC_LEX_EOF:
		break;
	}

	return NULL;
}

void
uc_lexer_init(uc_lexer_t *lex, uc_parse_config_t *config, uc_source_t *source)
{
	lex->state = UC_LEX_IDENTIFY_BLOCK;

	lex->config = config;
	lex->source = uc_source_get(source);

	lex->eof = 0;
	lex->is_escape = 0;

	lex->block = NONE;
	lex->modifier = UNSPEC;

	lex->buflen = 0;
	lex->buf = NULL;
	lex->bufstart = NULL;
	lex->bufend = NULL;

	lex->lookbehindlen = 0;
	lex->lookbehind = NULL;

	lex->tok = NULL;

	lex->esclen = 0;
	memset(lex->esc, 0, sizeof(lex->esc));

	lex->lead_surrogate = 0;

	lex->lastoff = 0;

	if (config && config->raw_mode) {
		lex->state = UC_LEX_IDENTIFY_TOKEN;
		lex->block = STATEMENTS;
	}
}

void
uc_lexer_free(uc_lexer_t *lex)
{
	uc_source_put(lex->source);

	free(lex->lookbehind);
	free(lex->buf);
}

uc_token_t *
uc_lexer_next_token(uc_lexer_t *lex)
{
	uc_token_t *rv = NULL;

	while (lex->state != UC_LEX_EOF) {
		rv = lex_step(lex, lex->source->fp);

		if (rv != NULL)
			break;
	}

	if (rv) {
		lex->no_keyword = false;
		lex->no_regexp = false;

		return rv;
	}

	return emit_op(lex, lex->source->off, TK_EOF, NULL);
}

const char *
uc_tokenname(unsigned type)
{
	static char buf[sizeof("'endfunction'")];
	size_t i;

	switch (type) {
	case 0:        return "End of file";
	case TK_STRING: return "String";
	case TK_LABEL:  return "Label";
	case TK_NUMBER: return "Number";
	case TK_DOUBLE: return "Double";
	case TK_REGEXP: return "Regexp";
	}

	for (i = 0; i < ARRAY_SIZE(tokens); i++) {
		if (tokens[i].type != type)
			continue;

		snprintf(buf, sizeof(buf), "'%s'", tokens[i].u.pat);

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

bool
uc_lexer_is_keyword(uc_value_t *label)
{
	size_t i;

	if (ucv_type(label) != UC_STRING)
		return false;

	for (i = 0; i < ARRAY_SIZE(reserved_words); i++)
		if (!strcmp(reserved_words[i].pat, ucv_string_get(label)))
			return true;

	return false;
}

#endif /* NO_COMPILE */

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
