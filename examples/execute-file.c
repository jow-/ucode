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


static uc_parse_config_t config = {
	.strict_declarations = false,
	.lstrip_blocks = true,
	.trim_blocks = true
};

int main(int argc, char **argv)
{
	int exit_code = 0;

	if (argc != 2) {
		fprintf(stderr, "Usage: %s sourcefile.uc\n", argv[0]);

		return 1;
	}

	/* create a source buffer from the given input file */
	uc_source_t *src = uc_source_new_file(argv[1]);

	/* check if source file could be opened */
	if (!src) {
		fprintf(stderr, "Unable to open source file %s\n", argv[1]);

		return 1;
	}

	/* compile source buffer into function */
	char *syntax_error = NULL;
	uc_program_t *program = uc_compile(&config, src, &syntax_error);

	/* release source buffer */
	uc_source_put(src);

	/* check if compilation failed */
	if (!program) {
		fprintf(stderr, "Failed to compile program: %s\n", syntax_error);

		return 1;
	}

	/* initialize default module search path */
	uc_search_path_init(&config.module_search_path);

	/* initialize VM context */
	uc_vm_t vm = { 0 };
	uc_vm_init(&vm, &config);

	/* load standard library into global VM scope */
	uc_stdlib_load(uc_vm_scope_get(&vm));

	/* add global variables x and y to VM scope */
	ucv_object_add(uc_vm_scope_get(&vm), "x", ucv_int64_new(123));
	ucv_object_add(uc_vm_scope_get(&vm), "y", ucv_int64_new(456));

	/* execute compiled program function */
	uc_value_t *last_expression_result = NULL;
	int return_code = uc_vm_execute(&vm, program, &last_expression_result);

	/* handle return status */
	switch (return_code) {
	case STATUS_OK:
		exit_code = 0;

		char *s = ucv_to_string(&vm, last_expression_result);

		printf("Program finished successfully.\n");
		printf("Function return value is %s\n", s);
		free(s);
		break;

	case STATUS_EXIT:
		exit_code = (int)ucv_int64_get(last_expression_result);

		printf("The invoked program called exit().\n");
		printf("Exit code is %d\n", exit_code);
		break;

	case ERROR_COMPILE:
		exit_code = 1;

		printf("A compilation error occurred while running the program\n");
		break;

	case ERROR_RUNTIME:
		exit_code = 2;

		printf("A runtime error occurred while running the program\n");
		break;
	}

	/* free last expression result */
	ucv_put(last_expression_result);

	/* free VM context */
	uc_vm_free(&vm);

	/* free search module path vector */
	uc_search_path_free(&config.module_search_path);

	return exit_code;
}
