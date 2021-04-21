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
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <ctype.h>
#include <sys/stat.h>

#ifdef JSONC
	#include <json.h>
#else
	#include <json-c/json.h>
#endif

#include "compiler.h"
#include "lexer.h"
#include "lib.h"
#include "vm.h"
#include "source.h"


static void
print_usage(const char *app)
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
		basename(app));
}

static void
globals_init(uc_vm *vm, uc_value_t *scope)
{
	uc_value_t *arr = ucv_array_new(vm);
	const char *p, *last;

	for (p = last = LIB_SEARCH_PATH;; p++) {
		if (*p == ':' || *p == '\0') {
			ucv_array_push(arr, ucv_string_new_length(last, p - last));

			if (!*p)
				break;

			last = p + 1;
		}
	}

	ucv_object_add(scope, "REQUIRE_SEARCH_PATH", arr);
}

static void
register_variable(uc_value_t *scope, const char *key, uc_value_t *val)
{
	char *name = strdup(key);
	char *p;

	if (!name)
		return;

	for (p = name; *p; p++)
		if (!isalnum(*p) && *p != '_')
			*p = '_';

	ucv_object_add(scope, name, val);
	free(name);
}


static int
parse(uc_parse_config *config, uc_source *src,
      bool skip_shebang, uc_value_t *env, uc_value_t *modules)
{
	uc_value_t *globals = NULL;
	uc_function_t *entry;
	uc_vm vm = {};
	char c, c2, *err;
	int rc = 0;

	uc_vm_init(&vm, config);

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

	entry = uc_compile(config, src, &err);

	if (!entry) {
		fprintf(stderr, "%s", err);
		free(err);
		rc = 2;
		goto out;
	}

	globals = ucv_object_new(&vm);

	/* load global variables */
	globals_init(&vm, globals);

	/* load env variables */
	if (env) {
		ucv_object_foreach(env, key, val)
			register_variable(globals, key, ucv_get(val));
	}

	/* load std functions into global scope */
	uc_lib_init(globals);

	/* create instance of global scope, set "global" property on it */
	ucv_object_add(globals, "global", ucv_get(globals));

	rc = uc_vm_execute(&vm, entry, globals, modules);

	if (rc) {
		rc = 1;
		goto out;
	}

out:
	uc_vm_free(&vm);

	return rc;
}

static uc_source *
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

	return uc_source_new_buffer("[stdin]", *ptr, tlen);
}

static uc_value_t *
parse_envfile(FILE *fp)
{
	enum json_tokener_error err = json_tokener_continue;
	struct json_tokener *tok;
	json_object *jso = NULL;
	uc_value_t *rv;
	char buf[128];
	size_t rlen;

	tok = xjs_new_tokener();

	while (true) {
		rlen = fread(buf, 1, sizeof(buf), fp);

		if (rlen == 0)
			break;

		jso = json_tokener_parse_ex(tok, buf, rlen);
		err = json_tokener_get_error(tok);

		if (err != json_tokener_continue)
			break;
	}

	if (err != json_tokener_success || !json_object_is_type(jso, json_type_object)) {
		json_object_put(jso);

		return NULL;
	}

	json_tokener_free(tok);

	rv = ucv_from_json(NULL, jso);

	json_object_put(jso);

	return rv;
}

int
main(int argc, char **argv)
{
	uc_value_t *env = NULL, *modules = NULL, *o, *p;
	uc_source *source = NULL, *envfile = NULL;
	char *stdin = NULL, *c;
	bool shebang = false;
	int opt, rv = 0;

	uc_parse_config config = {
		.strict_declarations = false,
		.lstrip_blocks = true,
		.trim_blocks = true
	};

	if (argc == 1)
	{
		print_usage(argv[0]);
		goto out;
	}

	while ((opt = getopt(argc, argv, "hlrSe:E:i:s:m:")) != -1)
	{
		switch (opt) {
		case 'h':
			print_usage(argv[0]);
			goto out;

		case 'i':
			if (source)
				fprintf(stderr, "Options -i and -s are exclusive\n");

			if (!strcmp(optarg, "-"))
				source = read_stdin(&stdin);
			else
				source = uc_source_new_file(optarg);

			if (!source) {
				fprintf(stderr, "Failed to open %s: %s\n", optarg, strerror(errno));
				rv = 1;
				goto out;
			}

			break;

		case 'l':
			config.lstrip_blocks = false;
			break;

		case 'r':
			config.trim_blocks = false;
			break;

		case 's':
			if (source)
				fprintf(stderr, "Options -i and -s are exclusive\n");

			source = uc_source_new_buffer("[-s argument]", xstrdup(optarg), strlen(optarg));
			break;

		case 'S':
			config.strict_declarations = true;
			break;

		case 'e':
			c = strchr(optarg, '=');

			if (c)
				*c++ = 0;
			else
				c = optarg;

			envfile = uc_source_new_buffer("[-e argument]", xstrdup(c), strlen(c));
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
					envfile = uc_source_new_file(c);

				if (!envfile) {
					fprintf(stderr, "Failed to open %s: %s\n", c, strerror(errno));
					rv = 1;
					goto out;
				}
			}

			o = parse_envfile(envfile->fp);

			uc_source_put(envfile);

			envfile = NULL;

			if (!o) {
				fprintf(stderr, "Option -%c must point to a valid JSON object\n", opt);
				rv = 1;
				goto out;
			}

			env = env ? env : ucv_object_new(NULL);

			if (c > optarg && optarg[0]) {
				p = ucv_object_new(NULL);
				ucv_object_add(env, optarg, p);
			}
			else {
				p = env;
			}

			ucv_object_foreach(o, key, val)
				ucv_object_add(p, key, ucv_get(val));

			ucv_put(o);

			break;

		case 'm':
			modules = modules ? modules : ucv_array_new(NULL);

			ucv_array_push(modules, ucv_string_new(optarg));

			break;
		}
	}

	if (!source && argv[optind] != NULL) {
		source = uc_source_new_file(argv[optind]);

		if (!source) {
			fprintf(stderr, "Failed to open %s: %s\n", argv[optind], strerror(errno));
			rv = 1;
			goto out;
		}

		shebang = true;
	}

	if (!source) {
		fprintf(stderr, "One of -i or -s is required\n");
		rv = 1;
		goto out;
	}

	rv = parse(&config, source, shebang, env, modules);

out:
	ucv_put(modules);
	ucv_put(env);

	uc_source_put(source);

	return rv;
}
