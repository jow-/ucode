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
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <sys/stat.h>

#ifdef JSONC
	#include <json.h>
#else
	#include <json-c/json.h>
#endif

#include "lexer.h"
#include "parser.h"
#include "eval.h"


static void
print_usage(char *app)
{
	printf(
	"== Usage ==\n\n"
	"  # %s [-d] {-i <file> | -s \"utpl script...\"}\n"
	"  -h, --help	Print this help\n"
	"  -i file	Specify an utpl script to parse\n"
	"  -s \"utpl script...\"	Specify an utpl code fragment to parse\n"
	"  -d Instead of executing the script, dump the resulting AST as dot\n",
		app);
}

static void
print_error_context(const char *expr, size_t off)
{
	int eoff, eline, padlen;
	const char *p, *nl;
	int i;

	/* skip lines until error line */
	for (p = nl = expr, eline = 0; *p && p < expr + off; p++) {
		if (*p == '\n') {
			nl = p + 1;
			eline++;
		}
	}

	eoff = p - nl;

	fprintf(stderr, "In line %u, byte %d:\n\n `", eline + 1, eoff);

	for (p = nl, padlen = 0; *p != '\n' && *p != '\0'; p++) {
		switch (*p) {
		case '\t':
			fprintf(stderr, "    ");
			if (p < nl + eoff)
				padlen += 4;
			break;

		case '\r':
		case '\v':
			fprintf(stderr, " ");
			if (p < nl + eoff)
				padlen++;
			break;

		default:
			fprintf(stderr, "%c", *p);
			if (p < nl + eoff)
				padlen++;
		}
	}

	fprintf(stderr, "`\n  ");

	if (padlen < strlen("Near here ^")) {
		for (i = 0; i < padlen; i++)
			fprintf(stderr, " ");

		fprintf(stderr, "^-- Near here\n");
	}
	else {
		fprintf(stderr, "Near here ");

		for (i = strlen("Near here "); i < padlen; i++)
			fprintf(stderr, "-");

		fprintf(stderr, "^\n");
	}

	fprintf(stderr, "\n");
}

static void
print_error(struct ut_state *state, const char *expr)
{
	size_t off = state ? state->off : 0;
	struct ut_opcode *tag;
	bool first = true;
	int i, max_i;

	switch (state ? state->error.code : UT_ERROR_OUT_OF_MEMORY) {
	case UT_ERROR_NO_ERROR:
		return;

	case UT_ERROR_OUT_OF_MEMORY:
		fprintf(stderr, "Runtime error: Out of memory\n");
		break;

	case UT_ERROR_UNTERMINATED_COMMENT:
		fprintf(stderr, "Syntax error: Unterminated comment\n");
		break;

	case UT_ERROR_UNTERMINATED_STRING:
		fprintf(stderr, "Syntax error: Unterminated string\n");
		break;

	case UT_ERROR_UNTERMINATED_BLOCK:
		fprintf(stderr, "Syntax error: Unterminated template block\n");
		break;

	case UT_ERROR_UNEXPECTED_CHAR:
		fprintf(stderr, "Syntax error: Unexpected character\n");
		break;

	case UT_ERROR_OVERLONG_STRING:
		fprintf(stderr, "Syntax error: String or label literal too long\n");
		break;

	case UT_ERROR_INVALID_ESCAPE:
		fprintf(stderr, "Syntax error: Invalid escape sequence\n");
		break;

	case UT_ERROR_NESTED_BLOCKS:
		fprintf(stderr, "Syntax error: Template blocks may not be nested\n");
		break;

	case UT_ERROR_UNEXPECTED_TOKEN:
		fprintf(stderr, "Syntax error: Unexpected token\n");

		for (i = 0, max_i = 0; i < sizeof(state->error.info.tokens) * 8; i++)
			if ((state->error.info.tokens[i / 64] & ((unsigned)1 << (i % 64))) && tokennames[i])
				max_i = i;

		for (i = 0; i < sizeof(state->error.info.tokens) * 8; i++) {
			if ((state->error.info.tokens[i / 64] & ((unsigned)1 << (i % 64))) && tokennames[i]) {
				if (first) {
					fprintf(stderr, "Expecting %s", tokennames[i]);
					first = false;
				}
				else if (i < max_i) {
					fprintf(stderr, ", %s", tokennames[i]);
				}
				else {
					fprintf(stderr, " or %s", tokennames[i]);
				}
			}
		}

		fprintf(stderr, "\n");
		break;

	case UT_ERROR_EXCEPTION:
		tag = json_object_get_userdata(state->error.info.exception);
		off = (tag && tag->operand[0]) ? tag->operand[0]->off : 0;

		fprintf(stderr, "%s\n", json_object_get_string(state->error.info.exception));
		break;
	}

	if (off)
		print_error_context(expr, off);
}

#ifndef NDEBUG
static void dump(struct ut_opcode *op, int level);

static void dump_node(struct ut_opcode *op) {
	const char *p;

	switch (op->type) {
	case T_NUMBER:
		printf("n%p [label=\"%"PRId64"\"];\n", op, json_object_get_int64(op->val));
		break;

	case T_DOUBLE:
		printf("n%p [label=\"%f\"];\n", op, json_object_get_double(op->val));
		break;

	case T_BOOL:
		printf("n%p [label=\"%s\"];\n", op, json_object_get_boolean(op->val) ? "true" : "false");
		break;

	case T_STRING:
	case T_LABEL:
	case T_TEXT:
		printf("n%p [label=\"%s<", op, tokennames[op->type]);

		for (p = json_object_get_string(op->val); *p; p++)
			switch (*p) {
			case '\n':
				printf("\\\n");
				break;

			case '\t':
				printf("\\\t");
				break;

			case '"':
				printf("\\\"");
				break;

			default:
				printf("%c", *p);
			}

		printf(">\"];\n");
		break;

	default:
		printf("n%p [label=\"%s\"];\n", op, tokennames[op->type]);
	}
}

static void dump(struct ut_opcode *op, int level) {
	struct ut_opcode *prev, *cur;
	int i;

	if (level == 0) {
		printf("digraph G {\nmain [shape=box];\n");
	}

	for (prev = NULL, cur = op; cur; prev = cur, cur = cur->sibling) {
		dump_node(cur);

		for (i = 0; i < sizeof(cur->operand) / sizeof(cur->operand[0]); i++) {
			if (cur->operand[i]) {
				dump(cur->operand[i], level + 1);
				printf("n%p -> n%p [label=\"op%d\"];\n", cur, cur->operand[i], i + 1);
			}
		}

		if (prev)
			printf("n%p -> n%p [style=dotted];\n", prev, cur);
	}

	if (level == 0) {
		printf("main -> n%p [style=dotted];\n", op);

		printf("}\n");
	}
}
#endif /* NDEBUG */

static enum ut_error_type
parse(const char *source, bool dumponly)
{
	struct ut_state *state = calloc(1, sizeof(*state));
	enum ut_error_type err;

	err = ut_parse(state, source);

	if (!err) {
		if (dumponly) {
#ifdef NDEBUG
			fprintf(stderr, "Debug support not compiled in\n");
			err = UT_ERROR_EXCEPTION;
#else /* NDEBUG */
			dump(state->main, 0);
#endif /* NDEBUG */
		}
		else {
			err = ut_run(state);
		}
	}

	if (err)
		print_error(state, source);

	ut_free(state);

	return err;
}

int
main(int argc, char **argv)
{
	size_t rlen, tlen = 0;
	bool dumponly = false;
	char buf[1024], *tmp;
	char *source = NULL;
	FILE *input = NULL;
	int opt, rv = 0;

	if (argc == 1)
	{
		print_usage(argv[0]);
		goto out;
	}

	while ((opt = getopt(argc, argv, "dhi:s:")) != -1)
	{
		switch (opt) {
		case 'h':
			print_usage(argv[0]);
			goto out;

		case 'i':
			input = strcmp(optarg, "-") ? fopen(optarg, "r") : stdin;

			if (!input) {
				fprintf(stderr, "Failed to open %s: %s\n", optarg, strerror(errno));
				rv = UT_ERROR_EXCEPTION;
				goto out;
			}

			break;

		case 'd':
			dumponly = true;
			break;

		case 's':
			source = optarg;
			break;
		}
	}

	if (!source) {
		while (1) {
			rlen = fread(buf, 1, sizeof(buf), input);

			if (rlen == 0)
				break;

			tmp = realloc(source, tlen + rlen + 1);

			if (!tmp) {
				print_error(NULL, "");
				rv = UT_ERROR_OUT_OF_MEMORY;
				goto out;
			}

			source = tmp;
			memcpy(source + tlen, buf, rlen);
			source[tlen + rlen] = 0;
			tlen += rlen;
		}
	}

	rv = parse(source, dumponly);

out:
	if (input && input != stdin)
		fclose(input);

	return rv;
}
