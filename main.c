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
	"  # %s [-d] [-l] [-r] [-S] [-e '{\"var\": ...}'] [-E env.json] {-i <file> | -s \"utpl script...\"}\n"
	"  -h, --help	Print this help\n"
	"  -i file	Specify an utpl script to parse\n"
	"  -s \"utpl script...\"	Specify an utpl code fragment to parse\n"
	"  -d Instead of executing the script, dump the resulting AST as dot\n"
	"  -l Do not strip leading block whitespace\n"
	"  -r Do not trim trailing block newlines\n"
	"  -S Enable strict mode\n"
	"  -e Set global variables from given JSON object\n"
	"  -E Set global variables from given JSON file\n",
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
		printf("n%p [label=\"%s", op, tokennames[op->type]);

		if (op->is_postfix)
			printf(", postfix");

		printf("\"];\n");
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
			for (i = 0; i < ARRAY_SIZE(cur->tree.operand); i++) {
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
parse(struct ut_state *state, const char *source, bool dumponly, struct json_object *env)
{
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
			err = ut_run(state, env);
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

static bool stdin_used = false;

static char *
read_file(const char *path) {
	char buf[64], *s = NULL, *tmp;
	size_t rlen, tlen = 0;
	FILE *fp = NULL;

	if (!strcmp(path, "-")) {
		if (stdin_used) {
			fprintf(stderr, "Can read from stdin only once\n");
			goto out;
		}

		fp = stdin;
		stdin_used = true;
	}
	else {
		fp = fopen(path, "r");

		if (!fp) {
			fprintf(stderr, "Failed to open %s: %s\n", path, strerror(errno));
			goto out;
		}
	}

	while (1) {
		rlen = fread(buf, 1, sizeof(buf), fp);

		if (rlen == 0)
			break;

		tmp = realloc(s, tlen + rlen + 1);

		if (!tmp) {
			fprintf(stderr, "Out or memory\n");
			free(s);
			s = NULL;
			goto out;
		}

		s = tmp;
		memcpy(s + tlen, buf, rlen);
		s[tlen + rlen] = 0;
		tlen += rlen;
	}

out:
	if (fp != NULL && fp != stdin)
		fclose(fp);

	return s;
}

int
main(int argc, char **argv)
{
	char *srcstr = NULL, *srcfile = NULL, *envstr = NULL;
	struct json_object *env = NULL, *o;
	struct ut_state *state;
	bool dumponly = false;
	int opt, rv = 0;

	if (argc == 1)
	{
		print_usage(argv[0]);
		goto out;
	}

	state = calloc(1, sizeof(*state));

	if (!state) {
		rv = UT_ERROR_OUT_OF_MEMORY;
		goto out;
	}

	state->lstrip_blocks = 1;
	state->trim_blocks = 1;

	while ((opt = getopt(argc, argv, "dhlrSe:E:i:s:")) != -1)
	{
		switch (opt) {
		case 'h':
			print_usage(argv[0]);
			goto out;

		case 'i':
			srcfile = read_file(optarg);

			if (!srcfile) {
				rv = UT_ERROR_EXCEPTION;
				goto out;
			}

			break;

		case 'd':
			dumponly = true;
			break;

		case 'l':
			state->lstrip_blocks = 0;
			break;

		case 'r':
			state->trim_blocks = 0;
			break;

		case 's':
			srcstr = optarg;
			break;

		case 'S':
			state->strict_declarations = 1;
			break;

		case 'e':
			envstr = optarg;
			/* fallthrough */

		case 'E':
			if (!envstr) {
				envstr = read_file(optarg);

				if (!envstr) {
					rv = UT_ERROR_EXCEPTION;
					goto out;
				}
			}

			o = json_tokener_parse(envstr);

			if (envstr != optarg)
				free(envstr);

			if (!json_object_is_type(o, json_type_object)) {
				fprintf(stderr, "Option -%c must point to a valid JSON object\n", opt);

				rv = UT_ERROR_EXCEPTION;
				goto out;
			}

			env = env ? env : json_object_new_object();

			json_object_object_foreach(o, key, val)
				json_object_object_add(env, key, val);

			break;
		}
	}

	if ((srcstr && srcfile) || (!srcstr && !srcfile)) {
		fprintf(stderr, srcstr ? "Options -i and -s are exclusive\n" : "One of -i or -s is required\n");

		rv = UT_ERROR_EXCEPTION;
		goto out;
	}

	rv = parse(state, srcstr ? srcstr : srcfile, dumponly, env);

out:
	free(srcfile);

	return rv;
}
