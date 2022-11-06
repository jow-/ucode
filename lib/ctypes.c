/*
 * Copyright (C) 2022 Tjeu Kayim <15987676+TjeuKayim@users.noreply.github.com>
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

#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <limits.h>
#include <assert.h>

#include <ffi.h>
#include <dlfcn.h>

#include "ucode/module.h"

static uc_resource_type_t *ptr_type;
static uc_resource_type_t *cif_type;

typedef struct {
	void *void_ptr;
	void (*free)(void *);
	size_t initialized_bytes;
} ptr_box_t;

typedef struct {
	ffi_cif cif;
	// reusable buffer to store the argument types and argument value pointers
	void *values[0];
} uc_cif_t;

static uc_value_t *
ptr_new_common(void *void_ptr, void (*freefn)(void *), size_t initialized)
{
	ptr_box_t *box = xalloc(sizeof(ptr_box_t));
	box->void_ptr = void_ptr;
	box->free = freefn;
	box->initialized_bytes = initialized;

	// TODO: Consider optimization: this function and uc_struct_new() could store the data directly after the
	// uc_value_t, like how ucv_cfunction_new() stores the uc_value_t and the name string in one allocation.
	return uc_resource_new(ptr_type, box);
}

static uc_value_t *
ctypes_symbol(uc_vm_t *vm, size_t nargs)
{
	ptr_box_t **handle = (ptr_box_t **)ucv_resource_dataptr(uc_fn_arg(0), "ctypes.ptr");
	uc_value_t *name = uc_fn_arg(1);
	if (nargs != 2 ||  ucv_type(name) != UC_STRING || !handle || !*handle) {
		uc_vm_raise_exception(vm, EXCEPTION_TYPE,
			"Expected ctypes.ptr and string arguments");

		return NULL;
	}

	void *symbol = dlsym((**handle).void_ptr, ucv_string_get(name));

	return symbol ? ptr_new_common(symbol, NULL, 0) : NULL;
}

static uc_value_t *
ctypes_new_ptr(uc_vm_t *vm, size_t nargs)
{
	if (nargs != 1) {
		return NULL;
	}

	uc_value_t *arg0 = uc_fn_arg(0);
	switch (ucv_type(arg0)) {
	case UC_INTEGER:
		void *void_ptr = (void*) (intptr_t) ucv_int64_get(arg0);
		return ptr_new_common(void_ptr, NULL, 0);
	case UC_STRING:
		// TODO: it would be nice if struct.pack had a variant that returned a pointer, then this conversion is less
		// necessary.
		char *borrow = ucv_string_get(arg0);
		size_t length = ucv_string_length(arg0);
		char *clone = xalloc(length);
		memcpy(clone, borrow, length);
		return ptr_new_common(clone, free, length);
	default:
		return NULL;
	}
}

static uc_value_t *
ctypes_prepare_cif(uc_vm_t *vm, size_t nargs)
{
	uc_value_t *abi_arg = uc_fn_arg(0);

	if (nargs < 2 || ucv_type(abi_arg) != UC_INTEGER) {
		return NULL;
	}

	size_t cif_argument_count = nargs - 2;

	size_t types_buffer_length = cif_argument_count * 2 + 1;
	uc_cif_t *cif = xalloc(
		sizeof(uc_cif_t) +
		sizeof(void*) * types_buffer_length +
		sizeof(size_t) * (cif_argument_count + 1)
	);

	ffi_type **types = (ffi_type**) &cif->values;

	for (size_t i = 0; i < cif_argument_count + 1; i++)
	{
		uc_value_t *arg = uc_fn_arg(1 + i);
		ffi_type **destination = &types[i];
		bool is_return = i == 0;

		switch (ucv_type(arg)) {
		case UC_NULL:
			if (!is_return) {
				uc_vm_raise_exception(vm, EXCEPTION_TYPE, "Only the return type can be void");
				goto fail;
			}
			*destination = &ffi_type_void;
			break;
		case UC_RESOURCE:
			ptr_box_t **box = (ptr_box_t **)ucv_resource_dataptr(arg, "ctypes.ptr");
			if (!box || !*box) {
				uc_vm_raise_exception(vm, EXCEPTION_TYPE, "Unexpected resource type");
				goto fail;
			}
			ffi_type *type = (**box).void_ptr;
			if (!type) {
				uc_vm_raise_exception(vm, EXCEPTION_TYPE, "null ctypes.ptr");
				goto fail;
			}
			*destination = type;
			break;
		default:
			uc_vm_raise_exception(vm, EXCEPTION_TYPE, "Unexpected type");
			goto fail;
		}
	}

	ffi_abi abi = ucv_uint64_get(abi_arg);
	if (ffi_prep_cif(&cif->cif, abi, cif_argument_count, types[0], &types[1]) != FFI_OK) {
		uc_vm_raise_exception(vm, EXCEPTION_RUNTIME, "ffi_prep_cif failed");
		goto fail;
	}

	ffi_type arg_struct_type;
	arg_struct_type.type = FFI_TYPE_STRUCT;
	arg_struct_type.size = 0;
	arg_struct_type.alignment = 0;
	arg_struct_type.elements = cif->cif.rtype->type == FFI_TYPE_VOID ? &types[1] : &types[0];
	types[cif_argument_count + 1] = NULL;

	size_t *arg_struct_offsets = (size_t*) &cif->values[types_buffer_length];
	if (ffi_get_struct_offsets(abi, &arg_struct_type, arg_struct_offsets) != FFI_OK) {
		uc_vm_raise_exception(vm, EXCEPTION_RUNTIME, "ffi_get_struct_offsets failed");
		goto fail;
	}

	return uc_resource_new(cif_type, cif);

fail:
	free(cif);
	return NULL;
}

static void
ptr_gc(void *ud)
{
	ptr_box_t *box = ud;

	if (box->free) {
		box->free(box->void_ptr);
	}

	free(box);
}

static uc_value_t *
ptr_as_int(uc_vm_t *vm, size_t nargs)
{
	ptr_box_t **box = uc_fn_this("ctypes.ptr");

	if (!box || !*box)
		return NULL;

	return ucv_int64_new((intptr_t) (**box).void_ptr);
}

static uc_value_t *
ptr_copy_uc_string(uc_vm_t *vm, size_t nargs)
{
	ptr_box_t **box = uc_fn_this("ctypes.ptr");

	if (!box || !*box)
		return NULL;

	if (nargs > 1) {
		uc_vm_raise_exception(vm, EXCEPTION_TYPE, "Unexpected argument count");
		return NULL;
	}

	size_t length = 0;
	uc_value_t *length_arg = uc_fn_arg(0);
	if (nargs == 1) {
		if (ucv_type(length_arg) != UC_INTEGER) {
			return NULL;
		}
		length = ucv_int64_get(length_arg);
	}

	size_t initialized_bytes = (**box).initialized_bytes;
	if (length == 0) {
		length = initialized_bytes;
	}

	return ucv_string_new_length((char*) (**box).void_ptr, length);
}

static uc_value_t *
ptr_drop(uc_vm_t *vm, size_t nargs)
{
	ptr_box_t **box = uc_fn_this("ctypes.ptr");

	if (!box || !*box)
		return NULL;

	if ((**box).free) {
		(**box).free((**box).void_ptr);
		(**box).free = NULL;
		return ucv_boolean_new(true);
	}

	return ucv_boolean_new(false);
}

static uc_value_t *
ptr_forget(uc_vm_t *vm, size_t nargs)
{
	ptr_box_t **box = uc_fn_this("ctypes.ptr");

	if (!box || !*box)
		return NULL;

	if ((**box).free) {
		(**box).free = NULL;
		return ucv_boolean_new(true);
	}

	return ucv_boolean_new(false);
}

static uc_value_t *
ptr_tostring(uc_vm_t *vm, size_t nargs)
{
	ptr_box_t **box = uc_fn_this("ctypes.ptr");

	if (!box || !*box)
		return NULL;

	uc_stringbuf_t *buf = ucv_stringbuf_new();

	ucv_stringbuf_append(buf, "ctypes.ptr( ");
	if ((**box).free) {
		ucv_stringbuf_append(buf, "garbage-collected ");
	}
	ucv_stringbuf_printf(buf, "*%p )", (**box).void_ptr);

	return ucv_stringbuf_finish(buf);
}

static uc_value_t *
cif_call(uc_vm_t *vm, size_t nargs)
{
	uc_cif_t **cif = uc_fn_this("ctypes.cif");

	if (!cif || !*cif) {
		uc_vm_raise_exception(vm, EXCEPTION_TYPE, "Unexpected this");
		return NULL;
	}

	size_t cif_argument_count = (**cif).cif.nargs;
	if (nargs == 1 || nargs > 2) {
		uc_vm_raise_exception(vm, EXCEPTION_TYPE, "Unexpected argument count");
		return NULL;
	}

	size_t types_buffer_length = cif_argument_count * 2 + 1;
	size_t *arg_struct_offsets = (size_t*) &(**cif).values[types_buffer_length];

	ptr_box_t **target_fn = (ptr_box_t **)ucv_resource_dataptr(uc_fn_arg(0), "ctypes.ptr");
	if (!target_fn || !*target_fn) {
		uc_vm_raise_exception(vm, EXCEPTION_TYPE, "First argument must be ctypes.ptr to a function");
		return NULL;
	}

	void *return_value;
	void **argument_values = (void**) &(**cif).values[cif_argument_count + 1];
	bool returns_void = (**cif).cif.rtype->type == FFI_TYPE_VOID;

	uc_value_t *arg_value = uc_fn_arg(1);
	switch (ucv_type(arg_value)) {
	case UC_NULL:
		if (cif_argument_count != 0 || !returns_void) {
			uc_vm_raise_exception(vm, EXCEPTION_TYPE, "Only pass null for void(void) signature");
			return NULL;
		}
		break;
	case UC_RESOURCE:
		ptr_box_t **box = (ptr_box_t **)ucv_resource_dataptr(arg_value, "ctypes.ptr");
		if (!box || !*box) {
			uc_vm_raise_exception(vm, EXCEPTION_TYPE, "Unexpected resource type");
			return NULL;
		}
		void *void_ptr = (**box).void_ptr;
		if (!void_ptr) {
			uc_vm_raise_exception(vm, EXCEPTION_TYPE, "Unexpected null ctypes.ptr");
			return NULL;
		}

		size_t arg_struct_index = 0;
		if (!returns_void) {
			return_value = void_ptr + arg_struct_offsets[0];
			arg_struct_index = 1;
		}

		for (size_t i = 0; i < cif_argument_count; i++)
		{
			argument_values[i] = void_ptr + arg_struct_offsets[arg_struct_index++];
		}

		break;
	default:
		uc_vm_raise_exception(vm, EXCEPTION_TYPE, "Unexpected type");
		return NULL;
	}

	void *widened_return_value = return_value;
	ffi_sarg sarg;
	ffi_arg uarg;

	if ((**cif).cif.rtype->size < sizeof(ffi_arg)) {
		// these are special cases in libffi "for historical reasons"
		switch ((**cif).cif.rtype->type) {
		case FFI_TYPE_SINT8:
		case FFI_TYPE_SINT16:
		case FFI_TYPE_SINT32:
			widened_return_value = &sarg;
			break;
		case FFI_TYPE_UINT8:
		case FFI_TYPE_UINT16:
		case FFI_TYPE_UINT32:
			widened_return_value = &uarg;
			break;
		default:
			break;
		}
	}

	ffi_call(&(**cif).cif, FFI_FN((**target_fn).void_ptr), widened_return_value, argument_values);

	if (widened_return_value != return_value) {
		switch ((**cif).cif.rtype->type) {
		case FFI_TYPE_SINT8:
			*(int8_t*)return_value = *(ffi_sarg*)widened_return_value;
			break;
		case FFI_TYPE_SINT16:
			*(int16_t*)return_value = *(ffi_sarg*)widened_return_value;
			break;
		case FFI_TYPE_SINT32:
			*(int32_t*)return_value = *(ffi_sarg*)widened_return_value;
			break;
		case FFI_TYPE_UINT8:
			*(uint8_t*)return_value = *(ffi_sarg*)widened_return_value;
			break;
		case FFI_TYPE_UINT16:
			*(uint16_t*)return_value = *(ffi_sarg*)widened_return_value;
			break;
		case FFI_TYPE_UINT32:
			*(uint32_t*)return_value = *(ffi_sarg*)widened_return_value;
			break;
		default:
			break;
		}
	}

	return ucv_boolean_new(true);
}

static void
cif_gc(void *ud)
{
	uc_cif_t *cif = ud;

	free(cif);
}

static void
register_constants(uc_vm_t *vm, uc_value_t *scope)
{
	uc_value_t *const_object = ucv_object_new(vm);
#define ADD_CONST_PTR(x) ucv_object_add(const_object, #x, ptr_new_common(x, NULL, 0))
#define ADD_CONST_INT(x) ucv_object_add(const_object, #x, ucv_int64_new(x))
	ADD_CONST_PTR(RTLD_DEFAULT);
	ADD_CONST_PTR(RTLD_NEXT);
	ADD_CONST_INT(RTLD_NOW);

	ADD_CONST_INT(FFI_LAST_ABI);
	ADD_CONST_INT(FFI_DEFAULT_ABI);
	// TODO: find a way to iterate over the names of the other ffi_abi enum values even though they differ between
	// libffi versions and CPU architectures

	ADD_CONST_INT(FFI_SIZEOF_ARG);
	static_assert(sizeof(ffi_arg) == FFI_SIZEOF_ARG, "Expected different ffi_arg size");

	ucv_object_add(scope, "const", const_object);

	uc_value_t *ffi_types_object = ucv_object_new(vm);
#define ADD_FFI_TYPE(x) ucv_object_add(ffi_types_object, #x, ptr_new_common(&ffi_type_ ## x, NULL, sizeof(ffi_type)))

	ADD_FFI_TYPE(uchar);
	ADD_FFI_TYPE(schar);
	ADD_FFI_TYPE(ushort);
	ADD_FFI_TYPE(sshort);
	ADD_FFI_TYPE(uint);
	ADD_FFI_TYPE(sint);
	ADD_FFI_TYPE(ulong);
	ADD_FFI_TYPE(slong);

	// The types below are not macros, so can also be accessed as symbol, e.g.:
	// const c = require('ctypes'); c.symbol(c.const.RTLD_NEXT, 'ffi_type_uint8')
	// For completeness, they are added here anyway.
	ADD_FFI_TYPE(void);
	ADD_FFI_TYPE(uint8);
	ADD_FFI_TYPE(sint8);
	ADD_FFI_TYPE(uint16);
	ADD_FFI_TYPE(sint16);
	ADD_FFI_TYPE(uint32);
	ADD_FFI_TYPE(sint32);
	ADD_FFI_TYPE(uint64);
	ADD_FFI_TYPE(sint64);
	ADD_FFI_TYPE(float);
	ADD_FFI_TYPE(double);
	ADD_FFI_TYPE(pointer);
	ADD_FFI_TYPE(longdouble);

	ucv_object_add(scope, "ffi_type", ffi_types_object);
};

static const uc_function_list_t ptr_fns[] = {
	{ "as_int",         ptr_as_int },
	{ "ucv_string_new", ptr_copy_uc_string },
	{ "drop",           ptr_drop },
	{ "forget",         ptr_forget },
	{ "tostring",       ptr_tostring },
};

static const uc_function_list_t cif_fns[] = {
	{ "call", cif_call },
};

static const uc_function_list_t global_fns[] = {
	{ "ptr",    ctypes_new_ptr },
	{ "symbol", ctypes_symbol },
	{ "prep",   ctypes_prepare_cif },
};

void uc_module_init(uc_vm_t *vm, uc_value_t *scope)
{
	uc_function_list_register(scope, global_fns);

	ptr_type = uc_type_declare(vm, "ctypes.ptr", ptr_fns, ptr_gc);
	cif_type = uc_type_declare(vm, "ctypes.cif", cif_fns, cif_gc);

	register_constants(vm, scope);
}
