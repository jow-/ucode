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
	"  -E Set global variables from given JSON file\n"
	"  -m Preload given module\n",
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
		printf("n%p [label=\"%s<", op, ut_get_tokenname(op->type));

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
		printf("n%p [label=\"%s", op, ut_get_tokenname(op->type));

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

static int
parse(struct ut_state *state, struct ut_source *src, bool dumponly,
      bool skip_shebang, struct json_object *env, struct json_object *modules)
{
	struct json_object *rv;
	char c, c2, *msg;
	int rc = 0;

	if (skip_shebang) {
		c = fgetc(src->fp);
		c2 = fgetc(src->fp);

		if (c == '#' && c2 == '!') {
			while ((c = fgetc(src->fp)) != EOF) {
				src->off++;

				if (c == '\n')
					break;
			}
		}
		else {
			ungetc(c2, src->fp);
			ungetc(c, src->fp);
		}
	}

	if (dumponly) {
#ifdef NDEBUG
		rv = ut_new_exception(state, 0, "Debug support not compiled in");
#else /* NDEBUG */
		rv = ut_parse(state, src->fp);

		if (!ut_is_type(rv, T_EXCEPTION))
			dump(state, state->main, 0);
#endif /* NDEBUG */
	}
	else {
		rv = ut_run(state, env, modules);
	}

	if (ut_is_type(rv, T_EXCEPTION)) {
		msg = ut_format_error(state, src->fp);
		fprintf(stderr, "%s\n\n", msg);
		free(msg);
		rc = 1;
	}

	json_object_put(rv);

	return rc;
}

static FILE *
read_stdin(char **ptr)
{
	size_t rlen = 0, tlen = 0;
	char buf[128];

	if (*ptr) {
		fprintf(stderr, "Can read from stdin only once\n");
		errno = EINVAL;

		return NULL;
	}

	while (true) {
		rlen = fread(buf, 1, sizeof(buf), stdin);

		if (rlen == 0)
			break;

		*ptr = xrealloc(*ptr, tlen + rlen);
		memcpy(*ptr + tlen, buf, rlen);
		tlen += rlen;
	}

	return fmemopen(*ptr, tlen, "rb");
}

static struct json_object *
parse_envfile(FILE *fp)
{
	struct json_object *rv = NULL;
	enum json_tokener_error err;
	struct json_tokener *tok;
	char buf[128];
	size_t rlen;

	tok = xjs_new_tokener();

	while (true) {
		rlen = fread(buf, 1, sizeof(buf), fp);

		if (rlen == 0)
			break;

		rv = json_tokener_parse_ex(tok, buf, rlen);
		err = json_tokener_get_error(tok);

		if (err != json_tokener_continue)
			break;
	}

	if (err != json_tokener_success || !json_object_is_type(rv, json_type_object)) {
		json_object_put(rv);
		rv = NULL;
	}

	json_tokener_free(tok);

	return rv;
}

int
main(int argc, char **argv)
{
	struct json_object *env = NULL, *modules = NULL, *o;
	struct ut_state *state = NULL;
	struct ut_source source = {};
	bool dumponly = false;
	bool shebang = false;
	FILE *envfile = NULL;
	char *stdin = NULL;
	int opt, rv = 0;

	if (argc == 1)
	{
		print_usage(argv[0]);
		goto out;
	}

	state = xalloc(sizeof(*state));
	state->lstrip_blocks = 1;
	state->trim_blocks = 1;

	while ((opt = getopt(argc, argv, "dhlrSe:E:i:s:m:")) != -1)
	{
		switch (opt) {
		case 'h':
			print_usage(argv[0]);
			goto out;

		case 'i':
			if (source.fp)
				fprintf(stderr, "Options -i and -s are exclusive\n");

			if (!strcmp(optarg, "-")) {
				source.fp = read_stdin(&stdin);
				source.filename = xstrdup("[stdin]");
			}
			else {
				source.fp = fopen(optarg, "rb");
				source.filename = xstrdup(optarg);
			}

			if (!source.fp) {
				fprintf(stderr, "Failed to open %s: %s\n", optarg, strerror(errno));
				rv = 1;
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
			if (source.fp)
				fprintf(stderr, "Options -i and -s are exclusive\n");

			source.fp = fmemopen(optarg, strlen(optarg), "rb");
			source.filename = xstrdup("[-s argument]");
			break;

		case 'S':
			state->strict_declarations = 1;
			break;

		case 'e':
			envfile = fmemopen(optarg, strlen(optarg), "rb");
			/* fallthrough */

		case 'E':
			if (!envfile) {
				if (!strcmp(optarg, "-"))
					envfile = read_stdin(&stdin);
				else
					envfile = fopen(optarg, "rb");

				if (!envfile) {
					fprintf(stderr, "Failed to open %s: %s\n", optarg, strerror(errno));
					rv = 1;
					goto out;
				}
			}

			o = parse_envfile(envfile);

			fclose(envfile);

			if (!o) {
				fprintf(stderr, "Option -%c must point to a valid JSON object\n", opt);
				rv = 1;
				goto out;
			}

			env = env ? env : xjs_new_object();

			json_object_object_foreach(o, key, val)
				json_object_object_add(env, key, json_object_get(val));

			json_object_put(o);

			break;

		case 'm':
			modules = modules ? modules : xjs_new_array();

			json_object_array_add(modules, xjs_new_string(optarg));

			break;
		}
	}

	if (!source.fp && argv[optind] != NULL) {
		source.fp = fopen(argv[optind], "rb");
		source.filename = xstrdup(argv[optind]);

		if (!source.fp) {
			fprintf(stderr, "Failed to open %s: %s\n", argv[optind], strerror(errno));
			rv = 1;
			goto out;
		}

		shebang = true;
	}

	if (!source.fp) {
		fprintf(stderr, "One of -i or -s is required\n");
		rv = 1;
		goto out;
	}

	state->source = xalloc(sizeof(source));
	state->sources = state->source;
	*state->source = source;

	rv = parse(state, state->source, dumponly, shebang, env, modules);

out:
	json_object_put(modules);
	json_object_put(env);

	ut_free(state);
	free(stdin);

	return rv;
}
