#include <errno.h>
#include <string.h>
#include <limits.h>
#include <unistd.h>
#include <termios.h>
#include <sys/ioctl.h>

#include "ucode/module.h"

#define err_return(err) do { \
	uc_vm_registry_set(vm, "serial.last_error", ucv_int64_new(err)); \
	return NULL; \
} while(0)

static int
get_fd(uc_vm_t *vm, uc_value_t *val)
{
	uc_value_t *fn = ucv_property_get(val, "fileno");
	int64_t n;

	errno = 0;

	if (ucv_is_callable(fn)) {
		uc_vm_stack_push(vm, ucv_get(val));
		uc_vm_stack_push(vm, ucv_get(fn));

		if (uc_vm_call(vm, true, 0) != EXCEPTION_NONE)
			return -1;

		val = uc_vm_stack_pop(vm);
		n = ucv_int64_get(val);
		ucv_put(val);
	}
	else {
		n = ucv_int64_get(val);
	}

	if (errno || n < 0 || n > (int64_t)INT_MAX)
		return -1;

	return (int)n;
}

static uc_value_t *
uc_serial_error(uc_vm_t *vm, size_t nargs)
{
	int last_error = ucv_int64_get(uc_vm_registry_get(vm, "serial.last_error"));

	if (last_error == 0)
		return NULL;

	uc_vm_registry_set(vm, "serial.last_error", ucv_int64_new(0));

	return ucv_string_new(strerror(last_error));
}

static uc_value_t *
uc_serial_isatty(uc_vm_t *vm, size_t nargs)
{
	int fd = get_fd(vm, uc_fn_arg(0));

	if (fd < 0)
		err_return(EBADF);

	return ucv_boolean_new(isatty(fd) == 1);
}

static const uc_function_list_t global_fns[] = {
	{ "error",  uc_serial_error },
	{ "isatty", uc_serial_isatty },
};

void uc_module_init(uc_vm_t *vm, uc_value_t *scope)
{
	uc_function_list_register(scope, global_fns);
}
