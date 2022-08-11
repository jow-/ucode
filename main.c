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
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "json-c-compat.h"

#include "ucode/compiler.h"
#include "ucode/lexer.h"
#include "ucode/lib.h"
#include "ucode/vm.h"
#include "ucode/source.h"
#include "ucode/program.h"

static FILE *stdin_unused;

static void
print_usage(const char *app)
{
	printf(
	"Usage:\n"
	"  %1$s -h\n"
	"  %1$s -e \"expression\"\n"
	"  %1$s input.uc [input2.uc ...]\n"
	"  %1$s -c [-s] [-o output.uc] input.uc [input2.uc ...]\n\n"

	"-h\n"
	"  Help display this help.\n\n"

	"-e \"expression\"\n"
	"  Execute the given expression as ucode program.\n\n"

	"-t\n"
	"  Enable VM execution tracing.\n\n"

	"-g interval\n"
	"  Perform periodic garbage collection every `interval` object\n"
	"  allocations.\n\n"

	"-S\n"
	"  Enable strict mode.\n\n"

	"-R\n"
	"  Process source file(s) as raw script code (default).\n\n"

	"-T[flag,flag,...]\n"
	"  Process the source file(s) as templates, not as raw script code.\n"
	"  Supported flags: no-lstrip (don't strip leading whitespace before\n"
	"  block tags), no-rtrim (don't strip trailing newline after block tags).\n\n"

	"-D [name=]value\n"
	"  Define global variable. If `name` is omitted, a JSON dictionary is\n"
	"  expected with each property becoming a global variable set to the\n"
	"  corresponding value. If `name` is specified, it is defined as global\n"
	"  variable set to `value` parsed as JSON (or the literal `value` string\n"
	"  if JSON parsing fails).\n\n"

	"-F [name=]path\n"
	"  Like `-D` but reading the value from the file in `path`. The given\n"
	"  file must contain a single, well-formed JSON dictionary.\n\n"

	"-U name\n"
	"  Undefine the given global variable name.\n\n"

	"-l [name=]library\n"
	"  Preload the given `library`, optionally aliased to `name`.\n\n"

	"-L pattern\n"
	"  Append given `pattern` to default library search paths. If the pattern\n"
	"  contains no `*`, it is added twice, once with `/*.so` and once with\n"
	"  `/*.uc` appended to it.\n\n"

	"-c[flag,flag,...]\n"
	"  Compile the given source file(s) to bytecode instead of executing them.\n"
	"  Supported flags: no-interp (omit interpreter line), interp=... (over-\n"
	"  ride interpreter line with ...), dynlink=... (force import from ... to\n"
	"  be treated as shared extensions loaded at runtime).\n\n"

	"-o path\n"
	"  Output file path when compiling. If omitted, the compiled byte code\n"
	"  is written to `./uc.out`. Only meaningful in conjunction with `-c`.\n\n"

	"-s\n"
	"  Omit (strip) debug information when compiling files.\n"
	"  Only meaningful in conjunction with `-c`.\n\n",
		app);
}


static int
compile(uc_vm_t *vm, uc_source_t *src, FILE *precompile, bool strip, char *interp)
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
		if (interp)
			fprintf(precompile, "#!%s\n", interp);

		uc_program_write(program, precompile, !strip);
		fclose(precompile);
		goto out;
	}

	if (vm->gc_interval)
		uc_vm_gc_start(vm, vm->gc_interval);

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
read_stdin(void)
{
	size_t rlen = 0, tlen = 0;
	char buf[128], *p = NULL;

	if (!stdin_unused) {
		fprintf(stderr, "The stdin can only be read once\n");
		errno = EINVAL;

		return NULL;
	}

	while (true) {
		rlen = fread(buf, 1, sizeof(buf), stdin_unused);

		if (rlen == 0)
			break;

		p = xrealloc(p, tlen + rlen);
		memcpy(p + tlen, buf, rlen);
		tlen += rlen;
	}

	stdin_unused = NULL;

	return uc_source_new_buffer("[stdin]", p, tlen);
}

static void
parse_template_modeflags(char *opt, uc_parse_config_t *config)
{
	char *p;

	if (!opt)
		return;

	for (p = strtok(opt, ", "); p; p = strtok(NULL, ", ")) {
		if (!strcmp(p, "no-lstrip"))
			config->lstrip_blocks = false;
		else if (!strcmp(p, "no-rtrim"))
			config->trim_blocks = false;
		else
			fprintf(stderr, "Unrecognized -T flag \"%s\", ignoring\n", p);
	}
}

static void
parse_compile_flags(char *opt, char **interp, uc_search_path_t *dynlink_list)
{
	char *p, *k, *v;

	if (!opt)
		return;

	for (p = strtok(opt, ","); p; p = strtok(NULL, ",")) {
		k = p;
		v = strchr(p, '=');

		if (v)
			*v++ = 0;

		if (!strcmp(k, "no-interp")) {
			if (v)
				fprintf(stderr, "Compile flag \"%s\" takes no value, ignoring\n", k);

			*interp = NULL;
		}
		else if (!strcmp(k, "interp")) {
			if (!v)
				fprintf(stderr, "Compile flag \"%s\" requires a value, ignoring\n", k);
			else
				*interp = v;
		}
		else if (!strcmp(k, "dynlink")) {
			if (!v)
				fprintf(stderr, "Compile flag \"%s\" requires a value, ignoring\n", k);
			else
				uc_vector_push(dynlink_list, v);
		}
		else {
			fprintf(stderr, "Unrecognized -c flag \"%s\", ignoring\n", k);
		}
	}
}

static bool
parse_define_file(char *opt, uc_value_t *globals)
{
	enum json_tokener_error err = json_tokener_continue;
	char buf[128], *name = NULL, *p;
	struct json_tokener *tok;
	json_object *jso = NULL;
	size_t rlen;
	FILE *fp;

	p = strchr(opt, '=');

	if (p) {
		name = opt;
		*p++ = 0;
	}
	else {
		p = opt;
	}

	if (!strcmp(p, "-")) {
		if (!stdin_unused) {
			fprintf(stderr, "The stdin can only be read once\n");

			return false;
		}

		fp = stdin_unused;
		stdin_unused = NULL;
	}
	else
		fp = fopen(p, "r");

	if (!fp) {
		fprintf(stderr, "Unable to open definition file \"%s\": %s\n",
		        p, strerror(errno));

		return true;
	}

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

	json_tokener_free(tok);
	fclose(fp);

	if (err != json_tokener_success || !json_object_is_type(jso, json_type_object)) {
		json_object_put(jso);

		fprintf(stderr, "Invalid definition file \"%s\": %s\n",
		        p, (err != json_tokener_success)
		             ? "JSON parse failure" : "Not a valid JSON object");

		return false;
	}

	if (name && *name) {
		ucv_object_add(globals, name, ucv_from_json(NULL, jso));
	}
	else {
		json_object_object_foreach(jso, key, val)
			ucv_object_add(globals, key, ucv_from_json(NULL, val));
	}

	json_object_put(jso);

	return true;
}

static bool
parse_define_string(char *opt, uc_value_t *globals)
{
	enum json_tokener_error err;
	struct json_tokener *tok;
	json_object *jso = NULL;
	char *name = NULL, *p;
	bool rv = false;
	size_t len;

	p = strchr(opt, '=');

	if (p) {
		name = opt;
		*p++ = 0;
	}
	else {
		p = opt;
	}

	len = strlen(p);
	tok = xjs_new_tokener();

	/* NB: the len + 1 here is intentional to pass the terminating \0 byte
	 * to the json-c parser. This is required to work-around upstream
	 * issue #681 <https://github.com/json-c/json-c/issues/681> */
	jso = json_tokener_parse_ex(tok, p, len + 1);

	err = json_tokener_get_error(tok);

	/* Treat trailing bytes after a parsed value as error */
	if (err == json_tokener_success && json_tokener_get_parse_end(tok) < len)
		err = json_tokener_error_parse_unexpected;

	json_tokener_free(tok);

	if (err != json_tokener_success) {
		json_object_put(jso);

		if (!name || !*name) {
			fprintf(stderr, "Invalid -D option value \"%s\": %s\n",
			        p, json_tokener_error_desc(err));

			return false;
		}

		ucv_object_add(globals, name, ucv_string_new(p));

		return true;
	}

	if (name && *name) {
		ucv_object_add(globals, name, ucv_from_json(NULL, jso));
		rv = true;
	}
	else if (json_object_is_type(jso, json_type_object)) {
		json_object_object_foreach(jso, key, val)
			ucv_object_add(globals, key, ucv_from_json(NULL, val));
		rv = true;
	}
	else {
		fprintf(stderr, "Invalid -D option value \"%s\": Not a valid JSON object\n", p);
	}

	json_object_put(jso);

	return rv;
}

static void
parse_search_path(char *pattern, uc_parse_config_t *config)
{
	size_t len;
	char *p;

	if (strchr(pattern, '*')) {
		uc_search_path_add(&config->module_search_path, pattern);
		return;
	}

	len = strlen(pattern);

	if (!len)
		return;

	while (pattern[len-1] == '/')
		pattern[--len] = 0;

	xasprintf(&p, "%s/*.so", pattern);
	uc_search_path_add(&config->module_search_path, p);
	free(p);

	xasprintf(&p, "%s/*.uc", pattern);
	uc_search_path_add(&config->module_search_path, p);
	free(p);
}

static bool
parse_library_load(char *opt, uc_vm_t *vm)
{
	char *name = NULL, *p;
	uc_value_t *lib, *ctx;

	p = strchr(opt, '=');

	if (p) {
		name = opt;
		*p++ = 0;
	}
	else {
		p = opt;
	}

	lib = ucv_string_new(p);
	ctx = uc_vm_invoke(vm, "require", 1, lib);
	ucv_put(lib);

	if (!ctx)
		return vm->exception.type == EXCEPTION_NONE;

	ucv_object_add(uc_vm_scope_get(vm), name ? name : p, ctx);

	return true;
}

static const char *
appname(const char *argv0)
{
	const char *p;

	if (!argv0)
		return "ucode";

	p = strrchr(argv0, '/');

	if (p)
		return p + 1;

	return argv0;
}

int
main(int argc, char **argv)
{
	const char *optspec = "he:tg:ST::RD:F:U:l:L:c::o:s";
	char *interp = "/usr/bin/env ucode";
	uc_source_t *source = NULL;
	FILE *precompile = NULL;
	char *outfile = NULL;
	bool strip = false;
	uc_vm_t vm = { 0 };
	int opt, rv = 0;
	const char *app;
	uc_value_t *o;
	int fd;

	uc_parse_config_t config = {
		.strict_declarations = false,
		.lstrip_blocks = true,
		.trim_blocks = true,
		.raw_mode = true
	};

	uc_search_path_init(&config.module_search_path);

	app = appname(argv[0]);

	if (argc == 1) {
		print_usage(app);
		goto out;
	}

	if (!strcmp(app, "utpl"))
		config.raw_mode = false;
	else if (!strcmp(app, "ucc"))
		outfile = "./uc.out";

	stdin_unused = stdin;

	/* parse options iteration 1: parse config related options */
	while ((opt = getopt(argc, argv, optspec)) != -1)
	{
		switch (opt) {
		case 'L':
			parse_search_path(optarg, &config);
			break;

		case 'S':
			config.strict_declarations = true;
			break;

		case 'R':
			config.raw_mode = true;
			break;

		case 'T':
			config.raw_mode = false;
			parse_template_modeflags(optarg, &config);
			break;
		}
	}

	optind = 1;

	uc_vm_init(&vm, &config);

	/* load std functions into global scope */
	uc_stdlib_load(uc_vm_scope_get(&vm));

	/* register ARGV array but populate it later (to allow for -U ARGV) */
	o = ucv_array_new(&vm);

	ucv_object_add(uc_vm_scope_get(&vm), "ARGV", ucv_get(o));

	/* parse options iteration 2: process remaining options */
	while ((opt = getopt(argc, argv, optspec)) != -1)
	{
		switch (opt) {
		case 'h':
			print_usage(argv[0]);
			goto out;

		case 'e':
			source = uc_source_new_buffer("[-e argument]", xstrdup(optarg), strlen(optarg));
			break;

		case 't':
			uc_vm_trace_set(&vm, 1);
			break;

		case 'g':
			vm.gc_interval = atoi(optarg);
			break;

		case 'D':
			if (!parse_define_string(optarg, uc_vm_scope_get(&vm))) {
				rv = 1;
				goto out;
			}

			break;

		case 'F':
			if (!parse_define_file(optarg, uc_vm_scope_get(&vm))) {
				rv = 1;
				goto out;
			}

			break;

		case 'U':
			ucv_object_delete(uc_vm_scope_get(&vm), optarg);
			break;

		case 'l':
			if (!parse_library_load(optarg, &vm)) {
				rv = 1;
				goto out;
			}

			break;

		case 'c':
			outfile = "./uc.out";
			parse_compile_flags(optarg, &interp, &config.force_dynlink_list);
			break;

		case 's':
			strip = true;
			break;

		case 'o':
			outfile = optarg;
			break;
		}
	}

	if (!source && argv[optind] != NULL) {
		if (!strcmp(argv[optind], "-"))
			source = read_stdin();
		else
			source = uc_source_new_file(argv[optind]);

		if (!source) {
			fprintf(stderr, "Failed to open \"%s\": %s\n", argv[optind], strerror(errno));
			rv = 1;
			goto out;
		}

		optind++;
	}

	if (!source) {
		fprintf(stderr, "Require either -e expression or source file\n");
		rv = 1;
		goto out;
	}

	if (outfile) {
		if (!strcmp(outfile, "-")) {
			precompile = stdout;
		}
		else {
			fd = open(outfile, O_WRONLY|O_CREAT|O_TRUNC, 0777);

			if (fd == -1) {
				fprintf(stderr, "Unable to open output file %s: %s\n",
				        outfile, strerror(errno));

				rv = 1;
				goto out;
			}

			precompile = fdopen(fd, "wb");
		}
	}

	/* populate ARGV array */
	for (; optind < argc; optind++)
		ucv_array_push(o, ucv_string_new(argv[optind]));

	ucv_put(o);

	rv = compile(&vm, source, precompile, strip, interp);

out:
	uc_search_path_free(&config.module_search_path);
	uc_vector_clear(&config.force_dynlink_list);

	uc_source_put(source);

	uc_vm_free(&vm);

	return rv;
}
