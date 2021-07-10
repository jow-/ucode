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

#include <string.h>
#include <uci.h>

#include "ucode/module.h"

#define err_return(err) do { last_error = err; return NULL; } while(0)

static int last_error = 0;
static uc_ressource_type_t *cursor_type;

enum pkg_cmd {
	CMD_SAVE,
	CMD_COMMIT,
	CMD_REVERT
};

static uc_value_t *
uc_uci_error(uc_vm_t *vm, size_t nargs)
{
	char buf[sizeof("Unknown error: -9223372036854775808")];
	uc_value_t *errmsg;

	const char *errstr[] = {
		[UCI_ERR_MEM] =       "Out of memory",
		[UCI_ERR_INVAL] =     "Invalid argument",
		[UCI_ERR_NOTFOUND] =  "Entry not found",
		[UCI_ERR_IO] =        "I/O error",
		[UCI_ERR_PARSE] =     "Parse error",
		[UCI_ERR_DUPLICATE] = "Duplicate entry",
		[UCI_ERR_UNKNOWN] =   "Unknown error",
	};

	if (last_error == 0)
		return NULL;

	if (last_error >= 0 && (unsigned)last_error < ARRAY_SIZE(errstr)) {
		errmsg = ucv_string_new(errstr[last_error]);
	}
	else {
		snprintf(buf, sizeof(buf), "Unknown error: %d", last_error);
		errmsg = ucv_string_new(buf);
	}

	last_error = 0;

	return errmsg;
}


static uc_value_t *
uc_uci_cursor(uc_vm_t *vm, size_t nargs)
{
	uc_value_t *cdir = uc_get_arg(0);
	uc_value_t *sdir = uc_get_arg(1);
	struct uci_context *c;
	int rv;

	if ((cdir && ucv_type(cdir) != UC_STRING) ||
	    (sdir && ucv_type(sdir) != UC_STRING))
		err_return(UCI_ERR_INVAL);

	c = uci_alloc_context();

	if (!c)
		err_return(UCI_ERR_MEM);

	if (cdir) {
		rv = uci_set_confdir(c, ucv_string_get(cdir));

		if (rv)
			err_return(rv);
	}

	if (sdir) {
		rv = uci_set_savedir(c, ucv_string_get(sdir));

		if (rv)
			err_return(rv);
	}

	return uc_alloc_ressource(cursor_type, c);
}


static uc_value_t *
uc_uci_load(uc_vm_t *vm, size_t nargs)
{
	struct uci_context **c = uc_get_self("uci.cursor");
	uc_value_t *conf = uc_get_arg(0);
	struct uci_element *e;
	char *s;

	if (!c || !*c)
		err_return(UCI_ERR_INVAL);

	if (ucv_type(conf) != UC_STRING)
		err_return(UCI_ERR_INVAL);

	s = ucv_string_get(conf);

	uci_foreach_element(&(*c)->root, e) {
		if (!strcmp(e->name, s)) {
			uci_unload(*c, uci_to_package(e));
			break;
		}
	}

	if (uci_load(*c, s, NULL))
		err_return((*c)->err);

	return ucv_boolean_new(true);
}

static uc_value_t *
uc_uci_unload(uc_vm_t *vm, size_t nargs)
{
	struct uci_context **c = uc_get_self("uci.cursor");
	uc_value_t *conf = uc_get_arg(0);
	struct uci_element *e;

	if (!c || !*c)
		err_return(UCI_ERR_INVAL);

	if (ucv_type(conf) != UC_STRING)
		err_return(UCI_ERR_INVAL);

	uci_foreach_element(&(*c)->root, e) {
		if (!strcmp(e->name, ucv_string_get(conf))) {
			uci_unload(*c, uci_to_package(e));

			return ucv_boolean_new(true);
		}
	}

	return ucv_boolean_new(false);
}

static int
lookup_extended(struct uci_context *ctx, struct uci_ptr *ptr, bool extended)
{
	int rv;
	struct uci_ptr lookup;

	/* use a copy of the passed ptr since failing lookups will
	 * clobber the state */
	lookup = *ptr;
	lookup.flags |= UCI_LOOKUP_EXTENDED;

	rv = uci_lookup_ptr(ctx, &lookup, NULL, extended);

	/* copy to passed ptr on success */
	if (!rv)
		*ptr = lookup;

	return rv;
}

static int
lookup_ptr(struct uci_context *ctx, struct uci_ptr *ptr, bool extended)
{
	if (ptr && !ptr->s && ptr->section && *ptr->section == '@')
		return lookup_extended(ctx, ptr, extended);

	return uci_lookup_ptr(ctx, ptr, NULL, extended);
}

static uc_value_t *
option_to_uval(uc_vm_t *vm, struct uci_option *o)
{
	struct uci_element *e;
	uc_value_t *arr;

	switch (o->type) {
	case UCI_TYPE_STRING:
		return ucv_string_new(o->v.string);

	case UCI_TYPE_LIST:
		arr = ucv_array_new(vm);

		if (arr)
			uci_foreach_element(&o->v.list, e)
				ucv_array_push(arr, ucv_string_new(e->name));

		return arr;

	default:
		return NULL;
	}
}

static uc_value_t *
section_to_uval(uc_vm_t *vm, struct uci_section *s, int index)
{
	uc_value_t *so = ucv_object_new(vm);
	struct uci_element *e;
	struct uci_option *o;

	if (!so)
		return NULL;

	ucv_object_add(so, ".anonymous", ucv_boolean_new(s->anonymous));
	ucv_object_add(so, ".type", ucv_string_new(s->type));
	ucv_object_add(so, ".name", ucv_string_new(s->e.name));

	if (index >= 0)
		ucv_object_add(so, ".index", ucv_int64_new(index));

	uci_foreach_element(&s->options, e) {
		o = uci_to_option(e);
		ucv_object_add(so, o->e.name, option_to_uval(vm, o));
	}

	return so;
}

static uc_value_t *
package_to_uval(uc_vm_t *vm, struct uci_package *p)
{
	uc_value_t *po = ucv_object_new(vm);
	uc_value_t *so;
	struct uci_element *e;
	int i = 0;

	if (!po)
		return NULL;

	uci_foreach_element(&p->sections, e) {
		so = section_to_uval(vm, uci_to_section(e), i++);
		ucv_object_add(po, e->name, so);
	}

	return po;
}

static uc_value_t *
uc_uci_get_any(uc_vm_t *vm, size_t nargs, bool all)
{
	struct uci_context **c = uc_get_self("uci.cursor");
	uc_value_t *conf = uc_get_arg(0);
	uc_value_t *sect = uc_get_arg(1);
	uc_value_t *opt = uc_get_arg(2);
	struct uci_ptr ptr = { 0 };
	int rv;

	if (!c || !*c)
		err_return(UCI_ERR_INVAL);

	if ((ucv_type(conf) != UC_STRING) ||
	    (sect && ucv_type(sect) != UC_STRING) ||
	    (opt && ucv_type(opt) != UC_STRING))
		err_return(UCI_ERR_INVAL);

	if ((!sect && !all) || (opt && all))
		err_return(UCI_ERR_INVAL);

	ptr.package = ucv_string_get(conf);
	ptr.section = sect ? ucv_string_get(sect) : NULL;
	ptr.option = opt ? ucv_string_get(opt) : NULL;

	rv = lookup_ptr(*c, &ptr, true);

	if (rv != UCI_OK)
		err_return(rv);

	if (!(ptr.flags & UCI_LOOKUP_COMPLETE))
		err_return(UCI_ERR_NOTFOUND);

	if (all) {
		if (ptr.section) {
			if (!ptr.s)
				err_return(UCI_ERR_NOTFOUND);

			return section_to_uval(vm, ptr.s, -1);
		}

		if (!ptr.p)
			err_return(UCI_ERR_NOTFOUND);

		return package_to_uval(vm, ptr.p);
	}

	if (ptr.option) {
		if (!ptr.o)
			err_return(UCI_ERR_NOTFOUND);

		return option_to_uval(vm, ptr.o);
	}

	if (!ptr.s)
		err_return(UCI_ERR_NOTFOUND);

	return ucv_string_new(ptr.s->type);
}

static uc_value_t *
uc_uci_get(uc_vm_t *vm, size_t nargs)
{
	return uc_uci_get_any(vm, nargs, false);
}

static uc_value_t *
uc_uci_get_all(uc_vm_t *vm, size_t nargs)
{
	return uc_uci_get_any(vm, nargs, true);
}

static uc_value_t *
uc_uci_get_first(uc_vm_t *vm, size_t nargs)
{
	struct uci_context **c = uc_get_self("uci.cursor");
	uc_value_t *conf = uc_get_arg(0);
	uc_value_t *type = uc_get_arg(1);
	uc_value_t *opt = uc_get_arg(2);
	struct uci_package *p = NULL;
	struct uci_section *sc;
	struct uci_element *e;
	struct uci_ptr ptr = { 0 };
	int rv;

	if (ucv_type(conf) != UC_STRING ||
	    ucv_type(type) != UC_STRING ||
	    (opt && ucv_type(opt) != UC_STRING))
		err_return(UCI_ERR_INVAL);

	uci_foreach_element(&(*c)->root, e) {
		if (strcmp(e->name, ucv_string_get(conf)))
			continue;

		p = uci_to_package(e);
		break;
	}

	if (!p)
		err_return(UCI_ERR_NOTFOUND);

	uci_foreach_element(&p->sections, e) {
		sc = uci_to_section(e);

		if (strcmp(sc->type, ucv_string_get(type)))
			continue;

		if (!opt)
			return ucv_string_new(sc->e.name);

		ptr.package = ucv_string_get(conf);
		ptr.section = sc->e.name;
		ptr.option = ucv_string_get(opt);
		ptr.p = p;
		ptr.s = sc;

		rv = lookup_ptr(*c, &ptr, false);

		if (rv != UCI_OK)
			err_return(rv);

		if (!(ptr.flags & UCI_LOOKUP_COMPLETE))
			err_return(UCI_ERR_NOTFOUND);

		return option_to_uval(vm, ptr.o);
	}

	err_return(UCI_ERR_NOTFOUND);
}

static uc_value_t *
uc_uci_add(uc_vm_t *vm, size_t nargs)
{
	struct uci_context **c = uc_get_self("uci.cursor");
	uc_value_t *conf = uc_get_arg(0);
	uc_value_t *type = uc_get_arg(1);
	struct uci_element *e = NULL;
	struct uci_package *p = NULL;
	struct uci_section *sc = NULL;
	int rv;

	if (ucv_type(conf) != UC_STRING ||
	    ucv_type(type) != UC_STRING)
	    err_return(UCI_ERR_INVAL);

	uci_foreach_element(&(*c)->root, e) {
		if (!strcmp(e->name, ucv_string_get(conf))) {
			p = uci_to_package(e);
			break;
		}
	}

	if (!p)
		err_return(UCI_ERR_NOTFOUND);

	rv = uci_add_section(*c, p, ucv_string_get(type), &sc);

	if (rv != UCI_OK)
		err_return(rv);
	else if (!sc)
		err_return(UCI_ERR_NOTFOUND);

	return ucv_string_new(sc->e.name);
}

static bool
uval_to_uci(uc_vm_t *vm, uc_value_t *val, const char **p, bool *is_list)
{
	uc_value_t *item;

	*p = NULL;

	if (is_list)
		*is_list = false;

	switch (ucv_type(val)) {
	case UC_ARRAY:
		if (ucv_array_length(val) == 0)
			return false;

		item = ucv_array_get(val, 0);

		/* don't recurse */
		if (ucv_type(item) == UC_ARRAY)
			return false;

		if (is_list)
			*is_list = true;

		return uval_to_uci(vm, item, p, NULL);

	case UC_BOOLEAN:
		*p = xstrdup(ucv_boolean_get(val) ? "1" : "0");

		return true;

	case UC_DOUBLE:
	case UC_INTEGER:
	case UC_STRING:
		*p = ucv_to_string(vm, val);
		/* fall through */

	case UC_NULL:
		return true;

	default:
		return false;
	}
}

static uc_value_t *
uc_uci_set(uc_vm_t *vm, size_t nargs)
{
	struct uci_context **c = uc_get_self("uci.cursor");
	uc_value_t *conf = uc_get_arg(0);
	uc_value_t *sect = uc_get_arg(1);
	uc_value_t *opt = NULL, *val = NULL;
	struct uci_ptr ptr = { 0 };
	bool is_list = false;
	size_t i;
	int rv;

	if (ucv_type(conf) != UC_STRING ||
	    ucv_type(sect) != UC_STRING)
	    err_return(UCI_ERR_INVAL);

	switch (nargs) {
	/* conf, sect, opt, val */
	case 4:
		opt = uc_get_arg(2);
		val = uc_get_arg(3);

		if (ucv_type(opt) != UC_STRING)
			err_return(UCI_ERR_INVAL);

		break;

	/* conf, sect, type */
	case 3:
		val = uc_get_arg(2);

		if (ucv_type(val) != UC_STRING)
			err_return(UCI_ERR_INVAL);

		break;

	default:
		err_return(UCI_ERR_INVAL);
	}

	ptr.package = ucv_string_get(conf);
	ptr.section = ucv_string_get(sect);
	ptr.option = opt ? ucv_string_get(opt) : NULL;

	rv = lookup_ptr(*c, &ptr, true);

	if (rv != UCI_OK)
		err_return(rv);

	if (!ptr.s && ptr.option)
		err_return(UCI_ERR_NOTFOUND);

	if (!uval_to_uci(vm, val, &ptr.value, &is_list))
		err_return(UCI_ERR_INVAL);

	if (is_list) {
		/* if we got a one-element array, delete existing option (if any)
		 * and iterate array at offset 0 */
		if (ucv_array_length(val) == 1) {
			i = 0;

			free((char *)ptr.value);
			ptr.value = NULL;

			if (ptr.o) {
				rv = uci_delete(*c, &ptr);

				if (rv != UCI_OK)
					err_return(rv);
			}
		}
		/* if we get a multi element array, overwrite existing option (if any)
		 * with first value and iterate remaining array at offset 1 */
		else {
			i = 1;

			rv = uci_set(*c, &ptr);
			free((char *)ptr.value);

			if (rv != UCI_OK)
				err_return(rv);
		}

		for (; i < ucv_array_length(val); i++) {
			if (!uval_to_uci(vm, ucv_array_get(val, i), &ptr.value, NULL))
				continue;

			rv = uci_add_list(*c, &ptr);
			free((char *)ptr.value);

			if (rv != UCI_OK)
				err_return(rv);
		}
	}
	else {
		rv = uci_set(*c, &ptr);
		free((char *)ptr.value);

		if (rv != UCI_OK)
			err_return(rv);
	}

	return ucv_boolean_new(true);
}

static uc_value_t *
uc_uci_delete(uc_vm_t *vm, size_t nargs)
{
	struct uci_context **c = uc_get_self("uci.cursor");
	uc_value_t *conf = uc_get_arg(0);
	uc_value_t *sect = uc_get_arg(1);
	uc_value_t *opt = uc_get_arg(2);
	struct uci_ptr ptr = { 0 };
	int rv;

	if (ucv_type(conf) != UC_STRING ||
	    ucv_type(sect) != UC_STRING ||
	    (opt && ucv_type(opt) != UC_STRING))
	    err_return(UCI_ERR_INVAL);

	ptr.package = ucv_string_get(conf);
	ptr.section = ucv_string_get(sect);
	ptr.option = opt ? ucv_string_get(opt) : NULL;

	rv = lookup_ptr(*c, &ptr, true);

	if (rv != UCI_OK)
		err_return(rv);

	if (opt ? !ptr.o : !ptr.s)
		err_return(UCI_ERR_NOTFOUND);

	rv = uci_delete(*c, &ptr);

	if (rv != UCI_OK)
		err_return(rv);

	return ucv_boolean_new(true);
}

static uc_value_t *
uc_uci_rename(uc_vm_t *vm, size_t nargs)
{
	struct uci_context **c = uc_get_self("uci.cursor");
	uc_value_t *conf = uc_get_arg(0);
	uc_value_t *sect = uc_get_arg(1);
	uc_value_t *opt = NULL, *val = NULL;
	struct uci_ptr ptr = { 0 };
	int rv;

	if (ucv_type(conf) != UC_STRING ||
	    ucv_type(sect) != UC_STRING)
	    err_return(UCI_ERR_INVAL);

	switch (nargs) {
	/* conf, sect, opt, val */
	case 4:
		opt = uc_get_arg(2);
		val = uc_get_arg(3);

		if (ucv_type(opt) != UC_STRING ||
		    ucv_type(val) != UC_STRING)
			err_return(UCI_ERR_INVAL);

		break;

	/* conf, sect, type */
	case 3:
		val = uc_get_arg(2);

		if (ucv_type(val) != UC_STRING)
			err_return(UCI_ERR_INVAL);

		break;

	default:
		err_return(UCI_ERR_INVAL);
	}

	ptr.package = ucv_string_get(conf);
	ptr.section = ucv_string_get(sect);
	ptr.option = opt ? ucv_string_get(opt) : NULL;
	ptr.value = ucv_string_get(val);

	rv = lookup_ptr(*c, &ptr, true);

	if (rv != UCI_OK)
		err_return(rv);

	if (!ptr.s && ptr.option)
		err_return(UCI_ERR_NOTFOUND);

	rv = uci_rename(*c, &ptr);

	if (rv != UCI_OK)
		err_return(rv);

	return ucv_boolean_new(true);
}

static uc_value_t *
uc_uci_reorder(uc_vm_t *vm, size_t nargs)
{
	struct uci_context **c = uc_get_self("uci.cursor");
	uc_value_t *conf = uc_get_arg(0);
	uc_value_t *sect = uc_get_arg(1);
	uc_value_t *val = uc_get_arg(2);
	struct uci_ptr ptr = { 0 };
	int64_t n;
	int rv;

	if (ucv_type(conf) != UC_STRING ||
	    ucv_type(sect) != UC_STRING ||
	    ucv_type(val) != UC_INTEGER)
	    err_return(UCI_ERR_INVAL);

	n = ucv_int64_get(val);

	if (n < 0)
		err_return(UCI_ERR_INVAL);

	ptr.package = ucv_string_get(conf);
	ptr.section = ucv_string_get(sect);

	rv = lookup_ptr(*c, &ptr, true);

	if (rv != UCI_OK)
		err_return(rv);

	if (!ptr.s)
		err_return(UCI_ERR_NOTFOUND);

	rv = uci_reorder_section(*c, ptr.s, n);

	if (rv != UCI_OK)
		err_return(rv);

	return ucv_boolean_new(true);
}

static uc_value_t *
uc_uci_pkg_command(uc_vm_t *vm, size_t nargs, enum pkg_cmd cmd)
{
	struct uci_context **c = uc_get_self("uci.cursor");
	uc_value_t *conf = uc_get_arg(0);
	struct uci_element *e, *tmp;
	struct uci_package *p;
	struct uci_ptr ptr = { 0 };
	int rv, res = UCI_OK;

	if (cmd != CMD_REVERT && conf)
		err_return(UCI_ERR_INVAL);

	if (conf && ucv_type(conf) != UC_STRING)
		err_return(UCI_ERR_INVAL);

	uci_foreach_element_safe(&(*c)->root, tmp, e) {
		p = uci_to_package(e);

		if (conf && strcmp(e->name, ucv_string_get(conf)))
			continue;

		switch (cmd) {
		case CMD_COMMIT:
			rv = uci_commit(*c, &p, false);
			break;

		case CMD_SAVE:
			rv = uci_save(*c, p);
			break;

		case CMD_REVERT:
			ptr.p = p;
			rv = uci_revert(*c, &ptr);
			break;

		default:
			rv = UCI_ERR_INVAL;
		}

		if (rv != UCI_OK)
			res = rv;
	}

	if (res != UCI_OK)
		err_return(res);

	return ucv_boolean_new(true);
}

static uc_value_t *
uc_uci_save(uc_vm_t *vm, size_t nargs)
{
	return uc_uci_pkg_command(vm, nargs, CMD_SAVE);
}

static uc_value_t *
uc_uci_commit(uc_vm_t *vm, size_t nargs)
{
	return uc_uci_pkg_command(vm, nargs, CMD_COMMIT);
}

static uc_value_t *
uc_uci_revert(uc_vm_t *vm, size_t nargs)
{
	return uc_uci_pkg_command(vm, nargs, CMD_REVERT);
}

static uc_value_t *
change_to_uval(uc_vm_t *vm, struct uci_delta *d)
{
	const char *types[] = {
		[UCI_CMD_REORDER]  = "order",
		[UCI_CMD_REMOVE]   = "remove",
		[UCI_CMD_RENAME]   = "rename",
		[UCI_CMD_ADD]      = "add",
		[UCI_CMD_LIST_ADD] = "list-add",
		[UCI_CMD_LIST_DEL] = "list-del",
		[UCI_CMD_CHANGE]   = "set",
	};

	uc_value_t *a;

	if (!d->section)
		return NULL;

	a = ucv_array_new(vm);

	if (!a)
		return NULL;

	ucv_array_push(a, ucv_string_new(types[d->cmd]));
	ucv_array_push(a, ucv_string_new(d->section));

	if (d->e.name)
		ucv_array_push(a, ucv_string_new(d->e.name));

	if (d->value) {
		if (d->cmd == UCI_CMD_REORDER)
			ucv_array_push(a, ucv_int64_new(strtoul(d->value, NULL, 10)));
		else
			ucv_array_push(a, ucv_string_new(d->value));
	}

	return a;
}

static uc_value_t *
changes_to_uval(uc_vm_t *vm, struct uci_context *ctx, const char *package)
{
	uc_value_t *a = NULL, *c;
	struct uci_package *p = NULL;
	struct uci_element *e;
	bool unload = false;

	uci_foreach_element(&ctx->root, e) {
		if (strcmp(e->name, package))
			continue;

		p = uci_to_package(e);
	}

	if (!p) {
		unload = true;
		uci_load(ctx, package, &p);
	}

	if (!p)
		return NULL;

	if (!uci_list_empty(&p->delta) || !uci_list_empty(&p->saved_delta)) {
		a = ucv_array_new(vm);

		if (!a)
			err_return(UCI_ERR_MEM);

		uci_foreach_element(&p->saved_delta, e) {
			c = change_to_uval(vm, uci_to_delta(e));

			if (c)
				ucv_array_push(a, c);
		}

		uci_foreach_element(&p->delta, e) {
			c = change_to_uval(vm, uci_to_delta(e));

			if (c)
				ucv_array_push(a, c);
		}
	}

	if (unload)
		uci_unload(ctx, p);

	return a;
}

static uc_value_t *
uc_uci_changes(uc_vm_t *vm, size_t nargs)
{
	struct uci_context **c = uc_get_self("uci.cursor");
	uc_value_t *conf = uc_get_arg(0);
	uc_value_t *res, *chg;
	char **configs;
	int rv, i;

	if (conf && ucv_type(conf) != UC_STRING)
		err_return(UCI_ERR_INVAL);

	rv = uci_list_configs(*c, &configs);

	if (rv != UCI_OK)
		err_return(rv);

	res = ucv_object_new(vm);

	for (i = 0; configs[i]; i++) {
		if (conf && strcmp(configs[i], ucv_string_get(conf)))
			continue;

		chg = changes_to_uval(vm, *c, configs[i]);

		if (chg)
			ucv_object_add(res, configs[i], chg);
	}

	free(configs);

	return res;
}

static uc_value_t *
uc_uci_foreach(uc_vm_t *vm, size_t nargs)
{
	struct uci_context **c = uc_get_self("uci.cursor");
	uc_value_t *conf = uc_get_arg(0);
	uc_value_t *type = uc_get_arg(1);
	uc_value_t *func = uc_get_arg(2);
	uc_value_t *rv = NULL;
	struct uci_package *p = NULL;
	struct uci_element *e, *tmp;
	struct uci_section *sc;
	uc_exception_type_t ex;
	bool stop = false;
	bool ret = false;
	int i = 0;

	if (ucv_type(conf) != UC_STRING ||
	    (type && ucv_type(type) != UC_STRING))
	    err_return(UCI_ERR_INVAL);

	uci_foreach_element(&(*c)->root, e) {
		if (strcmp(e->name, ucv_string_get(conf)))
			continue;

		p = uci_to_package(e);
		break;
	}

	if (!p)
		err_return(UCI_ERR_NOTFOUND);

	uci_foreach_element_safe(&p->sections, tmp, e) {
		sc = uci_to_section(e);
		i++;

		if (type && strcmp(sc->type, ucv_string_get(type)))
			continue;

		uc_push_val(ucv_get(func));
		uc_push_val(section_to_uval(vm, sc, i - 1));

		ex = uc_call(1);

		/* stop on exception in callback */
		if (ex)
			break;

		ret = true;
		rv = uc_pop_val();
		stop = (ucv_type(rv) == UC_BOOLEAN && !ucv_boolean_get(rv));

		ucv_put(rv);

		if (stop)
			break;
	}

	/* XXX: rethrow */

	return ucv_boolean_new(ret);
}

static uc_value_t *
uc_uci_configs(uc_vm_t *vm, size_t nargs)
{
	struct uci_context **c = uc_get_self("uci.cursor");
	uc_value_t *a;
	char **configs;
	int i, rv;

	rv = uci_list_configs(*c, &configs);

	if (rv != UCI_OK)
		err_return(rv);

	a = ucv_array_new(vm);

	for (i = 0; configs[i]; i++)
		ucv_array_push(a, ucv_string_new(configs[i]));

	free(configs);

	return a;
}


static const uc_cfunction_list_t cursor_fns[] = {
	{ "load",		uc_uci_load },
	{ "unload",		uc_uci_unload },
	{ "get",		uc_uci_get },
	{ "get_all",	uc_uci_get_all },
	{ "get_first",	uc_uci_get_first },
	{ "add",		uc_uci_add },
	{ "set",		uc_uci_set },
	{ "rename",		uc_uci_rename },
	{ "save",		uc_uci_save },
	{ "delete",		uc_uci_delete },
	{ "commit",		uc_uci_commit },
	{ "revert",		uc_uci_revert },
	{ "reorder",	uc_uci_reorder },
	{ "changes",	uc_uci_changes },
	{ "foreach",	uc_uci_foreach },
	{ "configs",	uc_uci_configs },
	{ "error",		uc_uci_error },
};

static const uc_cfunction_list_t global_fns[] = {
	{ "error",		uc_uci_error },
	{ "cursor",		uc_uci_cursor },
};


static void close_uci(void *ud) {
	uci_free_context((struct uci_context *)ud);
}

void uc_module_init(uc_vm_t *vm, uc_value_t *scope)
{
	uc_add_functions(scope, global_fns);

	cursor_type = uc_declare_type(vm, "uci.cursor", cursor_fns, close_uci);
}
