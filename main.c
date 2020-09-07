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
#include "lib.h"


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

#ifndef NDEBUG
static void dump(struct ut_state *s, uint32_t off, int level);

static void dump_node(struct ut_op *op) {
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

static void dump(struct ut_state *s, uint32_t off, int level) {
	struct ut_op *prev, *cur, *child;
	int i;

	if (level == 0) {
		printf("digraph G {\nmain [shape=box];\n");
	}

	for (prev = NULL, cur = ut_get_op(s, off); cur; prev = cur, cur = ut_get_op(s, cur->tree.next)) {
		dump_node(cur);

		if (cur->type < __T_MAX) {
			for (i = 0; i < ARRAY_SIZE(cur->tree.operand) && cur->tree.operand[i]; i++) {
				child = ut_get_op(s, cur->tree.operand[i]);

				if (cur->tree.operand[i]) {
					dump(s, cur->tree.operand[i], level + 1);
					printf("n%p -> n%p [label=\"op%d\"];\n", cur, child, i + 1);
				}
			}
		}

		if (prev)
			printf("n%p -> n%p [style=dotted];\n", prev, cur);
	}

	if (level == 0) {
		printf("main -> n%p [style=dotted];\n", ut_get_op(s, off));

		printf("}\n");
	}
}
#endif /* NDEBUG */

static enum ut_error_type
parse(const char *source, bool dumponly)
{
	struct ut_state *state = calloc(1, sizeof(*state));
	enum ut_error_type err;
	char *msg;

	err = ut_parse(state, source);

	if (!err) {
		if (dumponly) {
#ifdef NDEBUG
			fprintf(stderr, "Debug support not compiled in\n");
			err = UT_ERROR_EXCEPTION;
#else /* NDEBUG */
			dump(state, state->main, 0);
#endif /* NDEBUG */
		}
		else {
			err = ut_run(state);
		}
	}

	if (err) {
		msg = ut_format_error(state, source);

		fprintf(stderr, "%s\n", msg);
		free(msg);
	}

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
				tmp = ut_format_error(NULL, "");

				fprintf(stderr, "%s\n", tmp);
				free(tmp);

				rv = UT_ERROR_OUT_OF_MEMORY;
				goto out;
			}

			source = tmp;
			memcpy(source + tlen, buf, rlen);
			source[tlen + rlen] = 0;
			tlen += rlen;
		}
	}

	rv = source ? parse(source, dumponly) : 0;

out:
	if (input && input != stdin)
		fclose(input);

	return rv;
}
