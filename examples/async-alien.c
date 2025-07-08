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
 * This example demonstrates how to do 'alien' calls from outside threads 
 * to the script.
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

        function CalledFromAlien( name, counter )
        {
            print( `${async.uptime()} '${name}' ${counter}\n` );
            return counter + 7;
        }

        init_alien( 'alienA', CalledFromAlien );
        init_alien( 'alienB', CalledFromAlien );
        init_alien( 'alienC', CalledFromAlien );
	%}
);

static uc_parse_config_t config = {
	.strict_declarations = false,
	.lstrip_blocks = true,
	.trim_blocks = true
};

static uc_value_t *
init_alien(uc_vm_t *vm, size_t nargs);

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

	/* register our native function as "init_alien" */
	uc_function_register(uc_vm_scope_get(&vm), "init_alien", init_alien );

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

struct alien_data
{
    char *name;
    uc_value_t *callback;
    int counter;
    int return_value;
    const uc_async_alient_t *alien_manager;
    pthread_t tid;
};

static int alien_call( uc_vm_t *vm, void *p, int flags )
{
    struct alien_data *worker = p;
    if( flags & UC_ASYNC_CALLBACK_FLAG_EXECUTE )
    {
   		uc_value_push(ucv_get( worker->callback));
   		uc_value_push(ucv_string_new( worker->name ) );
		uc_value_push(ucv_int64_new( worker->counter ) );

		int ex = uc_call(2);

		if( EXCEPTION_NONE == ex )
        {
            uc_value_t *ret = uc_value_pop();
            worker->return_value = ucv_int64_get( ret );
            ucv_put( ret );
            return 0;
        }
        return INT_MIN;
    }
    return INT_MIN;
}

// Function runs in worker thread
static void *worker_thread( void *p )
{
    struct alien_data *worker = p;
    printf( "In worker thread %llu\n", (long long unsigned)worker->tid );

    // Call the callback function 1000 times
    for( int i=0; i<1000; i++ )
    {
        worker->counter = i;
        uc_async_alien_call( worker->alien_manager, alien_call, worker );
        printf( "outside script %s: func(%d) -> %d\n", worker->name, worker->counter, worker->return_value );
        // and wait for a msec
        struct timespec wait;
        wait.tv_sec = 0;
        wait.tv_nsec = 1000000;
        nanosleep(&wait, 0);
    }

    // Cleanup
    free( worker->name );
    uc_async_alien_free( &worker->alien_manager );
    free( worker );

    // Alas we'll leak some thread data, as we can't thread_join() from here.
    return 0;
}


static uc_value_t *
init_alien(uc_vm_t *vm, size_t nargs)
{
    char *name = ucv_to_string( vm, uc_fn_arg( 0 ) );
    uc_value_t *callback = uc_fn_arg( 1 );

    // try to create an alien manager
    const uc_async_alient_t *alien_manager = uc_async_alien_new( vm );
    if( !alien_manager )
    {
        uc_vm_raise_exception( vm, EXCEPTION_RUNTIME, "Cannot create alien manager" );
        return 0;
    }

    // setup worker struct
    struct alien_data *worker = xalloc( sizeof( struct alien_data ));
    worker->name = name;
    worker->callback = ucv_get( callback );
    worker->alien_manager = alien_manager;

    // start thread
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_create( &worker->tid,&attr,worker_thread,worker);
    pthread_attr_destroy(&attr);

    return 0;
}
