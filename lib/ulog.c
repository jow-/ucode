/*
 * Copyright (C) 2021 John Crispin <john@phrozen.org>
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

#include <libubox/ulog.h>

#include "ucode/module.h"

static uc_cfn_ptr_t fmtfn;
static char *ulog_identity;

static uc_value_t *
uc_ulog(uc_vm_t *vm, size_t nargs, int severity)
{
	uc_value_t *res;

	if (!fmtfn) {
		fmtfn = uc_stdlib_function("sprintf");

		if (!fmtfn)
			return ucv_int64_new(-1);
	}

	res = fmtfn(vm, nargs);

	if (!res)
		return ucv_int64_new(-1);

	ulog(severity, "%s", ucv_string_get(res));
	ucv_put(res);

	return ucv_int64_new(0);
}

static uc_value_t *
uc_ulog_info(uc_vm_t *vm, size_t nargs)
{
	return uc_ulog(vm, nargs, LOG_INFO);
}

static uc_value_t *
uc_ulog_note(uc_vm_t *vm, size_t nargs)
{
	return uc_ulog(vm, nargs, LOG_NOTICE);
}

static uc_value_t *
uc_ulog_warn(uc_vm_t *vm, size_t nargs)
{
	return uc_ulog(vm, nargs, LOG_WARNING);
}

static uc_value_t *
uc_ulog_error(uc_vm_t *vm, size_t nargs)
{
	return uc_ulog(vm, nargs, LOG_ERR);
}

static uc_value_t *
uc_ulog_open(uc_vm_t *vm, size_t nargs)
{
	uc_value_t *ulog = uc_fn_arg(0);
	uc_value_t *identity, *channels;
	unsigned int flags = 0, channel;

	/* check if the log has already been opened */
	if (ulog_identity)
		return ucv_int64_new(-1);

	/* make sure the declartion is complete */
	if (ucv_type(ulog) != UC_OBJECT)
		return ucv_int64_new(-1);

	identity = ucv_object_get(ulog, "identity", NULL);
	channels = ucv_object_get(ulog, "channels", NULL);

	if (ucv_type(identity) != UC_STRING || ucv_type(channels) != UC_ARRAY)
		return ucv_int64_new(-1);

	/* figure out which channels were requested */
	for (channel = 0; channel < ucv_array_length(channels); channel++) {
		uc_value_t *val = ucv_array_get(channels, channel);
		char *v;

		if (ucv_type(val) != UC_STRING)
			continue;

		v = ucv_string_get(val);

		if (!strcmp(v, "kmsg"))
			flags |= ULOG_KMSG;
		else if (!strcmp(v, "syslog"))
			flags |= ULOG_SYSLOG;
		else if (!strcmp(v, "stdio"))
			flags |= ULOG_STDIO;
	}

	/* open the log */
	ulog_identity = strdup(ucv_string_get(identity));
	ulog_open(flags, LOG_DAEMON, ulog_identity);

	return ucv_int64_new(0);
}

static uc_value_t *
uc_ulog_close(uc_vm_t *vm, size_t nargs)
{
	ulog_close();

	return ucv_int64_new(0);
}

static const uc_function_list_t global_fns[] = {
	{ "info",	 uc_ulog_info  },
	{ "note",	 uc_ulog_note  },
	{ "warn",	 uc_ulog_warn  },
	{ "error",	 uc_ulog_error },
	{ "open",	 uc_ulog_open  },
	{ "close",	 uc_ulog_close },
};

void uc_module_init(uc_vm_t *vm, uc_value_t *scope)
{
	uc_function_list_register(scope, global_fns);
}
