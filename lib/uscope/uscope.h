#pragma once

#include <stddef.h>

#include "ucode/types.h"
#include "jsdoc.h"


#define uscope_vector_get(vec, i) \
	(((i) < (vec)->count) ? &(vec)->entries[i] : NULL)


typedef enum {
	ACCESS_DECLARATION,
	ACCESS_READ,
	ACCESS_WRITE,
	ACCESS_UPDATE,
	ACCESS_EXPORT,
} uscope_access_kind_t;

typedef struct {
	size_t offset;
	size_t line;
	size_t column;
} uscope_position_t;

typedef struct {
	uscope_position_t location;
	size_t token_id;
	uscope_access_kind_t access_kind;
	uc_value_t *value;
	bool optional;
} uscope_reference_t;

typedef struct {
	uc_value_t *base;
	uc_value_t *name;
	uc_value_t *value;
	uc_type_t type;
	bool constant;
	bool export;
	bool initialized;
	bool global;
	bool property;
	bool superseded;
	struct {
		size_t count;
		uscope_reference_t *entries;
	} references;
	struct {
		uscope_position_t start;
		uscope_position_t end;
	} range;
	jsdoc_t *jsdoc;
} uscope_variable_t;


uc_value_t *uscope_resolve_variable(uc_vm_t *, uc_value_t *, bool);
