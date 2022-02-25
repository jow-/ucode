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

#if defined(__APPLE__)
	#include <libgen.h>
#endif

#include "ucode/compiler.h"
#include "ucode/lexer.h"
#include "ucode/lib.h"
#include "ucode/vm.h"
#include "ucode/source.h"
#include "ucode/program.h"


static void
print_usage(char *app)
{
	printf(
	"Usage\n\n"
	"  # %s [-t] [-l] [-r] [-S] [-R] [-x function [-x ...]] [-e '[prefix=]{\"var\": ...}'] [-E [prefix=]env.json] {-i <file> | -s \"ucode script...\"}\n"
	"  -h, --help	Print this help\n"
	"  -i file	Execute the given ucode script file\n"
	"  -s \"ucode script...\"	Execute the given string as ucode script\n"
	"  -t Enable VM execution tracing\n"
	"  -l Do not strip leading block whitespace\n"
	"  -r Do not trim trailing block newlines\n"
	"  -S Enable strict mode\n"
	"  -R Enable raw code mode\n"
	"  -e Set global variables from given JSON object\n"
	"  -E Set global variables from given JSON file\n"
	"  -x Disable given function\n"
	"  -m Preload given module\n"
	"  -o Write precompiled byte code to given file\n"
	"  -O Write precompiled byte code to given file and strip debug information\n",
		basename(app));
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
compile(uc_vm_t *vm, uc_source_t *src, FILE *precompile, bool strip)
{
	uc_value_t *res = NULL;
	uc_program_t *program;
	int rc = 0;
	char *err;

	program = uc_compile(vm->config, src, &err);

	if (!program) {
		fprintf(stderr, "%s", err);
		free(err);
		rc = -1;
		goto out;
	}

	if (precompile) {
		uc_program_write(program, precompile, !strip);
		fclose(precompile);
		goto out;
	}

	rc = uc_vm_execute(vm, program, &res);

	switch (rc) {
	case STATUS_OK:
		rc = 0;
		break;

	case STATUS_EXIT:
		rc = (int)ucv_int64_get(res);
		break;

	case ERROR_COMPILE:
		rc = -1;
		break;

	case ERROR_RUNTIME:
		rc = -2;
		break;
	}

out:
	uc_program_put(program);
	ucv_put(res);

	return rc;
}

static uc_source_t *
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
	uc_source_t *source = NULL, *envfile = NULL;
	FILE *precompile = NULL;
	char *stdin = NULL, *c;
	bool strip = false;
	uc_vm_t vm = { 0 };
	uc_value_t *o, *p;
	int opt, rv = 0;

	uc_parse_config_t config = {
		.strict_declarations = false,
		.lstrip_blocks = true,
		.trim_blocks = true
	};

	if (argc == 1)
	{
		print_usage(argv[0]);
		goto out;
	}

	uc_vm_init(&vm, &config);

	/* load std functions into global scope */
	uc_stdlib_load(uc_vm_scope_get(&vm));

	/* register ARGV array */
	o = ucv_array_new_length(&vm, argc);

	for (opt = 0; opt < argc; opt++)
		ucv_array_push(o, ucv_string_new(argv[opt]));

	ucv_object_add(uc_vm_scope_get(&vm), "ARGV", o);

	/* parse options */
	while ((opt = getopt(argc, argv, "hlrtSRe:E:i:s:m:x:o:O:")) != -1)
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

			c = xstrdup(optarg);
			source = uc_source_new_buffer("[-s argument]", c, strlen(c));

			if (!source)
				free(c);

			break;

		case 'S':
			config.strict_declarations = true;
			break;

		case 'R':
			config.raw_mode = true;
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

			if (c > optarg && optarg[0]) {
				p = ucv_object_new(&vm);
				ucv_object_add(uc_vm_scope_get(&vm), optarg, p);
			}
			else {
				p = uc_vm_scope_get(&vm);
			}

			ucv_object_foreach(o, key, val)
				register_variable(p, key, ucv_get(val));

			ucv_put(o);

			break;

		case 'm':
			p = ucv_string_new(optarg);
			o = uc_vm_invoke(&vm, "require", 1, p);

			if (o)
				register_variable(uc_vm_scope_get(&vm), optarg, o);

			ucv_put(p);

			break;

		case 't':
			uc_vm_trace_set(&vm, 1);
			break;

		case 'x':
			o = ucv_object_get(uc_vm_scope_get(&vm), optarg, NULL);

			if (ucv_is_callable(o))
				ucv_object_delete(uc_vm_scope_get(&vm), optarg);
			else
				fprintf(stderr, "Unknown function %s specified\n", optarg);

			break;

		case 'o':
		case 'O':
			strip = (opt == 'O');

			if (!strcmp(optarg, "-")) {
				precompile = stdout;
			}
			else {
				precompile = fopen(optarg, "wb");

				if (!precompile) {
					fprintf(stderr, "Unable to open output file %s: %s\n",
					        optarg, strerror(errno));

					goto out;
				}
			}

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
	}

	if (!source) {
		fprintf(stderr, "One of -i or -s is required\n");
		rv = 1;
		goto out;
	}

	rv = compile(&vm, source, precompile, strip);

out:
	uc_source_put(source);

	uc_vm_free(&vm);

	return rv;
}
