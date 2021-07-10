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

#ifndef __MODULE_H_
#define __MODULE_H_

#include "lib.h"
#include "vm.h"

#define register_functions(scope, functions) \
	if (scope) \
		for (int i = 0; i < ARRAY_SIZE(functions); i++) \
			json_object_object_add(scope->header.jso, functions[i].name, \
				ops->value.cfunc(functions[i].name, functions[i].func))

#define alloc_prototype(functions) ({ \
	uc_prototype *__proto = uc_object_as_prototype(ops->value.proto(NULL)); \
	register_functions(__proto, functions); \
	__proto; \
})

#define declare_type(name, proto, freefn) \
	ucv_ressource_type_add(name, proto, freefn)

#define alloc_ressource(data, type) \
	ucv_ressource_new(ucv_object_new(NULL), type, data)

#define register_ressource(scope, key, res) \
	json_object_object_add((scope)->header.jso, key, (res)->header.jso)

void uc_module_init(uc_vm_t *vm, uc_value_t *scope) __attribute__((weak));

void uc_module_entry(uc_vm_t *vm, uc_value_t *scope);
void uc_module_entry(uc_vm_t *vm, uc_value_t *scope)
{
	if (uc_module_init)
		uc_module_init(vm, scope);
}

#endif /* __MODULE_H_ */
