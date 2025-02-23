/*
 * Copyright (C) 2025 Isaac de Wolff <idewolff@gmx.com>
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

/*******
 * This example demonstrates how to offload work to another thread to fullfill
 * a promise.
 */

#include <stdio.h>
#include <pthread.h>

#include <ucode/compiler.h>
#include <ucode/lib.h>
#include <ucode/vm.h>
#include <ucode/async.h>


#define MULTILINE_STRING(...) #__VA_ARGS__

static const char *program_code = MULTILINE_STRING(
	{%
        import * as async from 'async';

        let promises = [ worker( 1000 ), worker( 2000 ), worker( 3000 ) ];

        async.PromiseAll( promises )
        .then( (res)=>
        {
            print( 'result:', res, '\n' );
        });
	%}
);

static uc_parse_config_t config = {
	.strict_declarations = false,
	.lstrip_blocks = true,
	.trim_blocks = true
};

static uc_value_t *
worker(uc_vm_t *vm, size_t nargs);

int main(int argc, char **argv)
{
	int exit_code = 0;

	/* create a source buffer containing the program code */
	uc_source_t *src = uc_source_new_buffer("my program", strdup(program_code), strlen(program_code));

	/* initialize default module search path */
	uc_search_path_init(&config.module_search_path);
    uc_search_path_add(&config.module_search_path,"../" );

	/* compile source buffer into function */
	char *syntax_error = NULL;
	uc_program_t *program = uc_compile(&config, src, &syntax_error);

	/* release source buffer */
	uc_source_put(src);

	/* check if compilation failed */
	if (!program) {
		fprintf(stderr, "Failed to compile program: %s\n", syntax_error);
    	/* free search module path vector */
	    uc_search_path_free(&config.module_search_path);
		return 1;
	}

	/* initialize VM context */
	uc_vm_t vm = { 0 };
	uc_vm_init(&vm, &config);

	/* load standard library into global VM scope */
	uc_stdlib_load(uc_vm_scope_get(&vm));

	/* register our native function as "worker" */
	uc_function_register(uc_vm_scope_get(&vm), "worker", worker);

	/* execute program function */
	int return_code = uc_vm_execute(&vm, program, NULL);

	/* release program */
	uc_program_put(program);

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

struct worker_data
{
    int value;
    uc_async_promise_resolver_t *resolver;
    const uc_async_callback_queuer_t *queuer;
    pthread_t tid;
};

// function runs in script thread
static int worker_finish( uc_vm_t *vm, void *user, int flags )
{
    struct worker_data *worker = user;
    if( flags & UC_ASYNC_CALLBACK_FLAG_EXECUTE )
    {
        printf( "Inside the callback for thread %llu\n", (long long unsigned)worker->tid );

        // resolve the promise
        uc_async_promise_resolve( vm, &worker->resolver, ucv_int64_new( worker->value ) );
    }
    if( flags & UC_ASYNC_CALLBACK_FLAG_CLEANUP )
    {
        uc_async_callback_queuer_free( &worker->queuer );
        void *res;
        pthread_join( worker->tid, &res );
        free( worker );
    }
    return EXCEPTION_NONE;
}

// Function runs in worker thread
static void *worker_thread( void *p )
{
    struct worker_data *worker = p;
    printf( "In worker thread %llu\n", (long long unsigned)worker->tid );

    // do some work (but make sure you don't get tired ;)
    struct timespec wait;
    wait.tv_sec = worker->value / 1000;
    wait.tv_nsec = (worker->value % 1000) * 1000000;
    nanosleep(&wait, 0);

    // and request a callback in the script thread.
    printf( "About to request a callback from thread %llu\n", (long long unsigned)worker->tid );
    uc_async_request_callback( worker->queuer, worker_finish, worker );
    return 0;
}


static uc_value_t *
worker(uc_vm_t *vm, size_t nargs)
{
    int value = ucv_to_integer( uc_fn_arg(0) );

    // try to create a promise
    uc_async_promise_resolver_t *resolver = 0;
    uc_value_t *promise =  uc_async_promise_new( vm, &resolver );
    if( 0 == promise )
    {
        uc_vm_raise_exception( vm, EXCEPTION_RUNTIME, "need the 'async' plugin to be loaded" );
        return 0;
    }

    // setup worker struct
    struct worker_data *worker = xalloc( sizeof( struct worker_data ));
    worker->value = value;
    worker->resolver = resolver;
    worker->queuer = uc_async_callback_queuer_new( vm );

    // start thread
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_create( &worker->tid,&attr,worker_thread,worker);
    pthread_attr_destroy(&attr);

    // and return promise
    return promise;
}
