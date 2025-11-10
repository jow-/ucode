/*
 * Copyright (C) 2021 Jo-Philipp Wich <jo@mein.io>
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

#include <ucode/compiler.h>
#include <ucode/lib.h>
#include <ucode/vm.h>


#define MULTILINE_STRING(...) #__VA_ARGS__

static const char *program_code = MULTILINE_STRING(
	{%
		function fail() {
			/* invoke not existing function to raise runtime error */
			doesnotexist();
		}

		map([1], x => fail(x));
	%}
);

static uc_parse_config_t config = {
	.strict_declarations = false,
	.lstrip_blocks = true,
	.trim_blocks = true
};

static void
log_exception(uc_vm_t *vm, uc_exception_t *ex)
{
	char *trace = ucv_to_jsonstring_formatted(vm, ex->stacktrace, ' ', 2);

	printf("Program raised an exception:\n");
	printf("  type=%d\n", ex->type);
	printf("  message=%s\n", ex->message);
	printf("  stacktrace=%s\n", trace);

	free(trace);
}

int main(int argc, char **argv)
{
	int exit_code = 0;

	/* create a source buffer containing the program code */
	uc_source_t *src = uc_source_new_buffer("my program", strdup(program_code), strlen(program_code));

	/* compile source buffer into function */
	char *syntax_error = NULL;
	uc_program_t *program = uc_compile(&config, src, &syntax_error);

	/* release source buffer */
	uc_source_put(src);

	/* check if compilation failed */
	if (!program) {
		fprintf(stderr, "Failed to compile program: %s\n", syntax_error);
		free(syntax_error);

		return 1;
	}

	/* initialize default module search path */
	uc_search_path_init(&config.module_search_path);

	/* initialize VM context */
	uc_vm_t vm = { 0 };
	uc_vm_init(&vm, &config);

	/* load standard library into global VM scope */
	uc_stdlib_load(uc_vm_scope_get(&vm));

	/* register custom exception handler */
	uc_vm_exception_handler_set(&vm, log_exception);

	/* execute program function */
	int return_code = uc_vm_execute(&vm, program, NULL);

	/* handle return status */
	if (return_code == ERROR_COMPILE || return_code == ERROR_RUNTIME) {
		printf("An error occurred while running the program\n");
		exit_code = 1;
	}

	/* free VM context */
	uc_vm_free(&vm);

	/* free search module path vector */
	uc_search_path_free(&config.module_search_path);

	return exit_code;
}
