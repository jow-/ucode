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
	"  # %s [-d] [-l] [-r] [-S] [-e '[prefix=]{\"var\": ...}'] [-E [prefix=]env.json] {-i <file> | -s \"ucode script...\"}\n"
	"  -h, --help	Print this help\n"
	"  -i file	Specify an ucode script to parse\n"
	"  -s \"ucode script...\"	Specify an ucode fragment to parse\n"
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
static void dump(struct uc_state *state, uint32_t off, int level);

static void dump_node(struct uc_state *state, uint32_t off) {
	const char *p;

	switch (OP_TYPE(off)) {
	case T_NUMBER:
		printf("n%u [label=\"%"PRId64"\"];\n", off, json_object_get_int64(OP_VAL(off)));
		break;

	case T_DOUBLE:
		printf("n%u [label=\"%f\"];\n", off, json_object_get_double(OP_VAL(off)));
		break;

	case T_BOOL:
		printf("n%u [label=\"%s\"];\n", off, json_object_get_boolean(OP_VAL(off)) ? "true" : "false");
		break;

	case T_STRING:
	case T_LABEL:
	case T_TEXT:
		printf("n%u [label=\"%s<", off, uc_get_tokenname(OP_TYPE(off)));

		for (p = json_object_get_string(OP_VAL(off)); *p; p++)
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
		printf("n%u [label=\"%s", off, uc_get_tokenname(OP_TYPE(off)));

		if (OP_IS_POSTFIX(off))
			printf(", postfix");

		printf("\"];\n");
	}
}

static void dump(struct uc_state *state, uint32_t off, int level) {
	uint32_t prev_off, cur_off, child_off;
	int i;

	if (level == 0) {
		printf("digraph G {\nmain [shape=box];\n");
	}

	for (prev_off = 0, cur_off = off; cur_off != 0; prev_off = cur_off, cur_off = OP_NEXT(cur_off)) {
		dump_node(state, cur_off);

		if (OP_TYPE(cur_off) < __T_MAX) {
			for (i = 0; i < OPn_NUM; i++) {
				child_off = OPn(cur_off, i);

				if (child_off) {
					dump(state, child_off, level + 1);
					printf("n%u -> n%u [label=\"op%d\"];\n", cur_off, child_off, i + 1);
				}
			}
		}

		if (prev_off)
			printf("n%u -> n%u [style=dotted];\n", prev_off, cur_off);
	}

	if (level == 0) {
		printf("main -> n%u [style=dotted];\n", off);

		printf("}\n");
	}
}
#endif /* NDEBUG */

static int
parse(struct uc_state *state, struct uc_source *src, bool dumponly,
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
		rv = uc_new_exception(state, 0, "Debug support not compiled in");
#else /* NDEBUG */
		rv = uc_parse(state, src->fp);

		if (!uc_is_type(rv, T_EXCEPTION))
			dump(state, state->main, 0);
#endif /* NDEBUG */
	}
	else {
		rv = uc_run(state, env, modules);
	}

	if (uc_is_type(rv, T_EXCEPTION)) {
		msg = uc_format_error(state, src->fp);
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
	struct json_object *env = NULL, *modules = NULL, *o, *p;
	struct uc_state *state = NULL;
	struct uc_source source = {};
	char *stdin = NULL, *c;
	bool dumponly = false;
	bool shebang = false;
	FILE *envfile = NULL;
	int opt, rv = 0;

	if (argc == 1)
	{
		print_usage(argv[0]);
		goto out;
	}

	state = xalloc(sizeof(*state));
	state->lstrip_blocks = 1;
	state->trim_blocks = 1;

	/* reserve opcode slot 0 */
	uc_new_op(state, 0, NULL, UINT32_MAX);

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
			c = strchr(optarg, '=');

			if (c)
				*c++ = 0;
			else
				c = optarg;

			envfile = fmemopen(c, strlen(c), "rb");
			/* fallthrough */

		case 'E':
			if (!envfile) {
				c = strchr(optarg, '=');

				if (c)
					*c++ = 0;
				else
					c = optarg;

				if (!strcmp(c, "-"))
					envfile = read_stdin(&stdin);
				else
					envfile = fopen(c, "rb");

				if (!envfile) {
					fprintf(stderr, "Failed to open %s: %s\n", c, strerror(errno));
					rv = 1;
					goto out;
				}
			}

			o = parse_envfile(envfile);

			fclose(envfile);

			envfile = NULL;

			if (!o) {
				fprintf(stderr, "Option -%c must point to a valid JSON object\n", opt);
				rv = 1;
				goto out;
			}

			env = env ? env : xjs_new_object();

			if (c > optarg && optarg[0]) {
				p = xjs_new_object();
				json_object_object_add(env, optarg, p);
			}
			else {
				p = env;
			}

			json_object_object_foreach(o, key, val)
				json_object_object_add(p, key, json_object_get(val));

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

	uc_free(state);
	free(stdin);

	return rv;
}
