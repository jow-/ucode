#pragma once

#include <stddef.h>

#include "ucode/types.h"


typedef enum {
	TYPE_UNSPEC,
	TYPE_ARRAY,
	TYPE_OBJECT,
	TYPE_FUNCTION,
	TYPE_INTEGER,
	TYPE_DOUBLE,
	TYPE_NUMBER,
	TYPE_BOOLEAN,
	TYPE_STRING,
	TYPE_ANY,
	TYPE_UNION,
	TYPE_TYPENAME,
} jsdoc_type_t;

typedef enum {
	KIND_UNSPEC,
	KIND_CLASS,
	KIND_CONSTANT,
	KIND_EVENT,
	KIND_EXTERNAL,
	KIND_FILE,
	KIND_FUNCTION,
	KIND_MEMBER,
	KIND_MIXIN,
	KIND_MODULE,
	KIND_NAMESPACE,
	KIND_ENUM,
	KIND_TYPEDEF,
} jsdoc_kind_t;

typedef enum {
	MERGE_TYPEONLY = (1u << 0),
	MERGE_UNION    = (1u << 1),
	MERGE_NOELEMS  = (1u << 2),
} jsdoc_merge_flag_t;

struct jsdoc_typedef;

typedef struct {
	uc_value_t *description;
	struct jsdoc_typedef *type;
} jsdoc_throws_t;

typedef struct {
	uc_value_t *name;
	uc_value_t *description;
	uc_value_t *defval;
	struct jsdoc_typedef *type;
	bool optional;
} jsdoc_property_t;

typedef struct {
	uc_value_t *name;
	uc_value_t *description;
	struct jsdoc_typedef *type;
} jsdoc_element_t;

typedef struct {
	uc_value_t *name;
	uc_value_t *description;
	uc_value_t *defval;
	struct jsdoc_typedef *type;
	bool optional;
	bool restarg;
} jsdoc_param_t;

typedef struct jsdoc_typedef {
	jsdoc_type_t type;
	uc_value_t *value;
	bool nullable;
	bool required;
	union {
		struct {
			struct jsdoc_typedef *key_type;
			struct jsdoc_typedef *val_type;
			struct {
				size_t count;
				jsdoc_property_t *entries;
			} properties;
		} object;
		struct {
			struct jsdoc_typedef *item_type;
			struct {
				size_t count;
				jsdoc_element_t *entries;
			} elements;
		} array;
		struct {
			size_t count;
			struct jsdoc_typedef **entries;
		} alternatives;
		struct {
			struct {
				size_t count;
				jsdoc_param_t *entries;
			} params;
			struct {
				size_t count;
				jsdoc_throws_t *entries;
			} throws;
			struct jsdoc_typedef *return_type;
			uc_value_t *return_description;
		} function;
		uc_value_t *typename;
	} details;
} jsdoc_typedef_t;

typedef struct {
	jsdoc_kind_t kind;
	jsdoc_typedef_t *type;
	uc_value_t *name;
	uc_value_t *subject;
	uc_value_t *description;
	uc_value_t *defval;
	bool constant;
} jsdoc_t;


jsdoc_t *jsdoc_new(jsdoc_type_t);
jsdoc_t *jsdoc_merge(const jsdoc_t *, const jsdoc_t *, unsigned int);
jsdoc_t *jsdoc_parse(const char *, size_t, jsdoc_t *);

jsdoc_t *jsdoc_from_property(jsdoc_kind_t, const jsdoc_property_t *);
jsdoc_t *jsdoc_from_element(jsdoc_kind_t, const jsdoc_element_t *);
jsdoc_t *jsdoc_from_param(jsdoc_kind_t, const jsdoc_param_t *);
jsdoc_t *jsdoc_from_return(jsdoc_kind_t, const jsdoc_typedef_t *);

jsdoc_t *jsdoc_from_uv(uc_vm_t *, uc_value_t *, jsdoc_t *);
uc_value_t *jsdoc_to_uv(uc_vm_t *, const jsdoc_t *);

void jsdoc_reset(jsdoc_t *);
void jsdoc_free(jsdoc_t *);

jsdoc_typedef_t *jsdoc_typedef_new(jsdoc_type_t);
bool jsdoc_typedef_merge(jsdoc_typedef_t **, const jsdoc_typedef_t *, unsigned int);
void jsdoc_typedef_free(jsdoc_typedef_t *);

jsdoc_typedef_t *jsdoc_typedef_from_uv(uc_vm_t *, uc_value_t *);
