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

#include "../module.h"

#define err_return(err) do { last_error = err; return NULL; } while(0)

static int last_error = 0;
static uc_ressource_type *cursor_type;

enum pkg_cmd {
	CMD_SAVE,
	CMD_COMMIT,
	CMD_REVERT
};

static json_object *
uc_uci_error(uc_vm *vm, size_t nargs)
{
	char buf[sizeof("Unknown error: -9223372036854775808")];
	json_object *errmsg;

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

	if (last_error >= 0 && last_error < ARRAY_SIZE(errstr)) {
		errmsg = json_object_new_string(errstr[last_error]);
	}
	else {
		snprintf(buf, sizeof(buf), "Unknown error: %d", last_error);
		errmsg = json_object_new_string(buf);
	}

	last_error = 0;

	return errmsg;
}


static json_object *
uc_uci_cursor(uc_vm *vm, size_t nargs)
{
	json_object *cdir = uc_get_arg(0);
	json_object *sdir = uc_get_arg(1);
	struct uci_context *c;
	int rv;

	if ((cdir && !json_object_is_type(cdir, json_type_string)) ||
	    (sdir && !json_object_is_type(sdir, json_type_string)))
		err_return(UCI_ERR_INVAL);

	c = uci_alloc_context();

	if (!c)
		err_return(UCI_ERR_MEM);

	if (cdir) {
		rv = uci_set_confdir(c, json_object_get_string(cdir));

		if (rv)
			err_return(rv);
	}

	if (sdir) {
		rv = uci_set_savedir(c, json_object_get_string(sdir));

		if (rv)
			err_return(rv);
	}

	return uc_alloc_ressource(cursor_type, c);
}


static json_object *
uc_uci_load(uc_vm *vm, size_t nargs)
{
	struct uci_context **c = uc_get_self("uci.cursor");
	json_object *conf = uc_get_arg(0);
	struct uci_element *e;

	if (!c || !*c)
		err_return(UCI_ERR_INVAL);

	if (!json_object_is_type(conf, json_type_string))
		err_return(UCI_ERR_INVAL);

	uci_foreach_element(&(*c)->root, e) {
		if (!strcmp(e->name, json_object_get_string(conf))) {
			uci_unload(*c, uci_to_package(e));
			break;
		}
	}

	if (uci_load(*c, json_object_get_string(conf), NULL))
		err_return((*c)->err);

	return json_object_new_boolean(true);
}

static json_object *
uc_uci_unload(uc_vm *vm, size_t nargs)
{
	struct uci_context **c = uc_get_self("uci.cursor");
	json_object *conf = uc_get_arg(0);
	struct uci_element *e;

	if (!c || !*c)
		err_return(UCI_ERR_INVAL);

	if (!json_object_is_type(conf, json_type_string))
		err_return(UCI_ERR_INVAL);

	uci_foreach_element(&(*c)->root, e) {
		if (!strcmp(e->name, json_object_get_string(conf))) {
			uci_unload(*c, uci_to_package(e));

			return json_object_new_boolean(true);
		}
	}

	return json_object_new_boolean(false);
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

static json_object *
option_to_json(struct uci_option *o)
{
	json_object *arr;
	struct uci_element *e;

	switch (o->type) {
	case UCI_TYPE_STRING:
		return json_object_new_string(o->v.string);

	case UCI_TYPE_LIST:
		arr = json_object_new_array();

		if (arr)
			uci_foreach_element(&o->v.list, e)
				json_object_array_add(arr, json_object_new_string(e->name));

		return arr;

	default:
		return NULL;
	}
}

static json_object *
section_to_json(struct uci_section *s, int index)
{
	json_object *so = json_object_new_object();
	struct uci_element *e;
	struct uci_option *o;

	if (!so)
		return NULL;

	json_object_object_add(so, ".anonymous", json_object_new_boolean(s->anonymous));
	json_object_object_add(so, ".type", json_object_new_string(s->type));
	json_object_object_add(so, ".name", json_object_new_string(s->e.name));

	if (index >= 0)
		json_object_object_add(so, ".index", json_object_new_int64(index));

	uci_foreach_element(&s->options, e) {
		o = uci_to_option(e);
		json_object_object_add(so, o->e.name, option_to_json(o));
	}

	return so;
}

static json_object *
package_to_json(struct uci_package *p)
{
	json_object *po = json_object_new_object();
	json_object *so;
	struct uci_element *e;
	int i = 0;

	if (!po)
		return NULL;

	uci_foreach_element(&p->sections, e) {
		so = section_to_json(uci_to_section(e), i++);
		json_object_object_add(po, e->name, so);
	}

	return po;
}

static json_object *
uc_uci_get_any(uc_vm *vm, size_t nargs, bool all)
{
	struct uci_context **c = uc_get_self("uci.cursor");
	json_object *conf = uc_get_arg(0);
	json_object *sect = uc_get_arg(1);
	json_object *opt = uc_get_arg(2);
	struct uci_ptr ptr = {};
	int rv;

	if (!c || !*c)
		err_return(UCI_ERR_INVAL);

	if (!json_object_is_type(conf, json_type_string) ||
	    (sect && !json_object_is_type(sect, json_type_string)) ||
	    (opt && !json_object_is_type(opt, json_type_string)))
		err_return(UCI_ERR_INVAL);

	if ((!sect && !all) || (opt && all))
		err_return(UCI_ERR_INVAL);

	ptr.package = json_object_get_string(conf);
	ptr.section = sect ? json_object_get_string(sect) : NULL;
	ptr.option = opt ? json_object_get_string(opt) : NULL;

	rv = lookup_ptr(*c, &ptr, true);

	if (rv != UCI_OK)
		err_return(rv);

	if (!(ptr.flags & UCI_LOOKUP_COMPLETE))
		err_return(UCI_ERR_NOTFOUND);

	if (all) {
		if (ptr.section) {
			if (!ptr.s)
				err_return(UCI_ERR_NOTFOUND);

			return section_to_json(ptr.s, -1);
		}

		if (!ptr.p)
			err_return(UCI_ERR_NOTFOUND);

		return package_to_json(ptr.p);
	}

	if (ptr.option) {
		if (!ptr.o)
			err_return(UCI_ERR_NOTFOUND);

		return option_to_json(ptr.o);
	}

	if (!ptr.s)
		err_return(UCI_ERR_NOTFOUND);

	return json_object_new_string(ptr.s->type);
}

static json_object *
uc_uci_get(uc_vm *vm, size_t nargs)
{
	return uc_uci_get_any(vm, nargs, false);
}

static json_object *
uc_uci_get_all(uc_vm *vm, size_t nargs)
{
	return uc_uci_get_any(vm, nargs, true);
}

static json_object *
uc_uci_get_first(uc_vm *vm, size_t nargs)
{
	struct uci_context **c = uc_get_self("uci.cursor");
	json_object *conf = uc_get_arg(0);
	json_object *type = uc_get_arg(1);
	json_object *opt = uc_get_arg(2);
	struct uci_package *p = NULL;
	struct uci_section *sc;
	struct uci_element *e;
	struct uci_ptr ptr = {};
	int rv;

	if (!json_object_is_type(conf, json_type_string) ||
	    !json_object_is_type(type, json_type_string) ||
	    (opt && !json_object_is_type(opt, json_type_string)))
		err_return(UCI_ERR_INVAL);

	uci_foreach_element(&(*c)->root, e) {
		if (strcmp(e->name, json_object_get_string(conf)))
			continue;

		p = uci_to_package(e);
		break;
	}

	if (!p)
		err_return(UCI_ERR_NOTFOUND);

	uci_foreach_element(&p->sections, e) {
		sc = uci_to_section(e);

		if (strcmp(sc->type, json_object_get_string(type)))
			continue;

		if (!opt)
			return json_object_new_string(sc->e.name);

		ptr.package = json_object_get_string(conf);
		ptr.section = sc->e.name;
		ptr.option = json_object_get_string(opt);
		ptr.p = p;
		ptr.s = sc;

		rv = lookup_ptr(*c, &ptr, false);

		if (rv != UCI_OK)
			err_return(rv);

		if (!(ptr.flags & UCI_LOOKUP_COMPLETE))
			err_return(UCI_ERR_NOTFOUND);

		return option_to_json(ptr.o);
	}

	err_return(UCI_ERR_NOTFOUND);
}

static json_object *
uc_uci_add(uc_vm *vm, size_t nargs)
{
	struct uci_context **c = uc_get_self("uci.cursor");
	json_object *conf = uc_get_arg(0);
	json_object *type = uc_get_arg(1);
	struct uci_element *e = NULL;
	struct uci_package *p = NULL;
	struct uci_section *sc = NULL;
	int rv;

	if (!json_object_is_type(conf, json_type_string) ||
	    !json_object_is_type(type, json_type_string))
	    err_return(UCI_ERR_INVAL);

	uci_foreach_element(&(*c)->root, e) {
		if (!strcmp(e->name, json_object_get_string(conf))) {
			p = uci_to_package(e);
			break;
		}
	}

	if (!p)
		err_return(UCI_ERR_NOTFOUND);

	rv = uci_add_section(*c, p, json_object_get_string(type), &sc);

	if (rv != UCI_OK)
		err_return(rv);
	else if (!sc)
		err_return(UCI_ERR_NOTFOUND);

	return json_object_new_string(sc->e.name);
}

static bool
json_to_value(json_object *val, const char **p, bool *is_list)
{
	json_object *item;

	*p = NULL;

	if (is_list)
		*is_list = false;

	switch (json_object_get_type(val)) {
	case json_type_object:
		return false;

	case json_type_array:
		if (json_object_array_length(val) == 0)
			return false;

		item = json_object_array_get_idx(val, 0);

		/* don't recurse */
		if (json_object_is_type(item, json_type_array))
			return false;

		if (is_list)
			*is_list = true;

		return json_to_value(item, p, NULL);

	case json_type_boolean:
		*p = json_object_get_boolean(val) ? "1" : "0";

		return true;

	case json_type_null:
		return true;

	default:
		*p = json_object_get_string(val);

		return true;
	}
}

static json_object *
uc_uci_set(uc_vm *vm, size_t nargs)
{
	struct uci_context **c = uc_get_self("uci.cursor");
	json_object *conf = uc_get_arg(0);
	json_object *sect = uc_get_arg(1);
	json_object *opt = NULL, *val = NULL;
	struct uci_ptr ptr = {};
	bool is_list = false;
	int rv, i;

	if (!json_object_is_type(conf, json_type_string) ||
	    !json_object_is_type(sect, json_type_string))
	    err_return(UCI_ERR_INVAL);

	switch (nargs) {
	/* conf, sect, opt, val */
	case 4:
		opt = uc_get_arg(2);
		val = uc_get_arg(3);

		if (!json_object_is_type(opt, json_type_string))
			err_return(UCI_ERR_INVAL);

		break;

	/* conf, sect, type */
	case 3:
		val = uc_get_arg(2);

		if (!json_object_is_type(val, json_type_string))
			err_return(UCI_ERR_INVAL);

		break;

	default:
		err_return(UCI_ERR_INVAL);
	}

	ptr.package = json_object_get_string(conf);
	ptr.section = json_object_get_string(sect);
	ptr.option = opt ? json_object_get_string(opt) : NULL;

	rv = lookup_ptr(*c, &ptr, true);

	if (rv != UCI_OK)
		err_return(rv);

	if (!ptr.s && ptr.option)
		err_return(UCI_ERR_NOTFOUND);

	if (!json_to_value(val, &ptr.value, &is_list))
		err_return(UCI_ERR_INVAL);

	if (is_list) {
		/* if we got a one-element array, delete existing option (if any)
		 * and iterate array at offset 0 */
		if (json_object_array_length(val) == 1) {
			i = 0;

			if (ptr.o) {
				ptr.value = NULL;

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

			if (rv != UCI_OK)
				err_return(rv);
		}

		for (; i < json_object_array_length(val); i++) {
			if (!json_to_value(json_object_array_get_idx(val, i), &ptr.value, NULL))
				continue;

			rv = uci_add_list(*c, &ptr);

			if (rv != UCI_OK)
				err_return(rv);
		}
	}
	else {
		rv = uci_set(*c, &ptr);

		if (rv != UCI_OK)
			err_return(rv);
	}

	return json_object_new_boolean(true);
}

static json_object *
uc_uci_delete(uc_vm *vm, size_t nargs)
{
	struct uci_context **c = uc_get_self("uci.cursor");
	json_object *conf = uc_get_arg(0);
	json_object *sect = uc_get_arg(1);
	json_object *opt = uc_get_arg(2);
	struct uci_ptr ptr = {};
	int rv;

	if (!json_object_is_type(conf, json_type_string) ||
	    !json_object_is_type(sect, json_type_string) ||
	    (opt && !json_object_is_type(opt, json_type_string)))
	    err_return(UCI_ERR_INVAL);

	ptr.package = json_object_get_string(conf);
	ptr.section = json_object_get_string(sect);
	ptr.option = opt ? json_object_get_string(opt) : NULL;

	rv = lookup_ptr(*c, &ptr, true);

	if (rv != UCI_OK)
		err_return(rv);

	if (opt ? !ptr.o : !ptr.s)
		err_return(UCI_ERR_NOTFOUND);

	rv = uci_delete(*c, &ptr);

	if (rv != UCI_OK)
		err_return(rv);

	return json_object_new_boolean(true);
}

static json_object *
uc_uci_rename(uc_vm *vm, size_t nargs)
{
	struct uci_context **c = uc_get_self("uci.cursor");
	json_object *conf = uc_get_arg(0);
	json_object *sect = uc_get_arg(1);
	json_object *opt = NULL, *val = NULL;
	struct uci_ptr ptr = {};
	int rv;

	if (!json_object_is_type(conf, json_type_string) ||
	    !json_object_is_type(sect, json_type_string))
	    err_return(UCI_ERR_INVAL);

	switch (nargs) {
	/* conf, sect, opt, val */
	case 4:
		opt = uc_get_arg(2);
		val = uc_get_arg(3);

		if (!json_object_is_type(opt, json_type_string) ||
		    !json_object_is_type(val, json_type_string))
			err_return(UCI_ERR_INVAL);

		break;

	/* conf, sect, type */
	case 3:
		val = uc_get_arg(2);

		if (!json_object_is_type(val, json_type_string))
			err_return(UCI_ERR_INVAL);

		break;

	default:
		err_return(UCI_ERR_INVAL);
	}

	ptr.package = json_object_get_string(conf);
	ptr.section = json_object_get_string(sect);
	ptr.option = opt ? json_object_get_string(opt) : NULL;
	ptr.value = json_object_get_string(val);

	rv = lookup_ptr(*c, &ptr, true);

	if (rv != UCI_OK)
		err_return(rv);

	if (!ptr.s && ptr.option)
		err_return(UCI_ERR_NOTFOUND);

	rv = uci_rename(*c, &ptr);

	if (rv != UCI_OK)
		err_return(rv);

	return json_object_new_boolean(true);
}

static json_object *
uc_uci_reorder(uc_vm *vm, size_t nargs)
{
	struct uci_context **c = uc_get_self("uci.cursor");
	json_object *conf = uc_get_arg(0);
	json_object *sect = uc_get_arg(1);
	json_object *val = uc_get_arg(2);
	struct uci_ptr ptr = {};
	int64_t n;
	int rv;

	if (!json_object_is_type(conf, json_type_string) ||
	    !json_object_is_type(sect, json_type_string) ||
	    !json_object_is_type(val, json_type_int))
	    err_return(UCI_ERR_INVAL);

	n = json_object_get_int64(val);

	if (n < 0)
		err_return(UCI_ERR_INVAL);

	ptr.package = json_object_get_string(conf);
	ptr.section = json_object_get_string(sect);

	rv = lookup_ptr(*c, &ptr, true);

	if (rv != UCI_OK)
		err_return(rv);

	if (!ptr.s)
		err_return(UCI_ERR_NOTFOUND);

	rv = uci_reorder_section(*c, ptr.s, n);

	if (rv != UCI_OK)
		err_return(rv);

	return json_object_new_boolean(true);
}

static json_object *
uc_uci_pkg_command(uc_vm *vm, size_t nargs, enum pkg_cmd cmd)
{
	struct uci_context **c = uc_get_self("uci.cursor");
	json_object *conf = uc_get_arg(0);
	struct uci_element *e, *tmp;
	struct uci_package *p;
	struct uci_ptr ptr = {};
	int rv, res = UCI_OK;

	if (cmd != CMD_REVERT && conf)
		err_return(UCI_ERR_INVAL);

	if (conf && !json_object_is_type(conf, json_type_string))
		err_return(UCI_ERR_INVAL);

	uci_foreach_element_safe(&(*c)->root, tmp, e) {
		p = uci_to_package(e);

		if (conf && strcmp(e->name, json_object_get_string(conf)))
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

	return json_object_new_boolean(true);
}

static json_object *
uc_uci_save(uc_vm *vm, size_t nargs)
{
	return uc_uci_pkg_command(vm, nargs, CMD_SAVE);
}

static json_object *
uc_uci_commit(uc_vm *vm, size_t nargs)
{
	return uc_uci_pkg_command(vm, nargs, CMD_COMMIT);
}

static json_object *
uc_uci_revert(uc_vm *vm, size_t nargs)
{
	return uc_uci_pkg_command(vm, nargs, CMD_REVERT);
}

static json_object *
change_to_json(struct uci_delta *d)
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

	json_object *a;

	if (!d->section)
		return NULL;

	a = json_object_new_array();

	if (!a)
		return NULL;

	json_object_array_add(a, json_object_new_string(types[d->cmd]));
	json_object_array_add(a, json_object_new_string(d->section));

	if (d->e.name)
		json_object_array_add(a, json_object_new_string(d->e.name));

	if (d->value) {
		if (d->cmd == UCI_CMD_REORDER)
			json_object_array_add(a, json_object_new_int64(strtoul(d->value, NULL, 10)));
		else
			json_object_array_add(a, json_object_new_string(d->value));
	}

	return a;
}

static json_object *
changes_to_json(struct uci_context *ctx, const char *package)
{
	json_object *a = NULL, *c;
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
		a = json_object_new_array();

		if (!a)
			err_return(UCI_ERR_MEM);

		uci_foreach_element(&p->saved_delta, e) {
			c = change_to_json(uci_to_delta(e));

			if (c)
				json_object_array_add(a, c);
		}

		uci_foreach_element(&p->delta, e) {
			c = change_to_json(uci_to_delta(e));

			if (c)
				json_object_array_add(a, c);
		}
	}

	if (unload)
		uci_unload(ctx, p);

	return a;
}

static json_object *
uc_uci_changes(uc_vm *vm, size_t nargs)
{
	struct uci_context **c = uc_get_self("uci.cursor");
	json_object *conf = uc_get_arg(0);
	json_object *res, *chg;
	char **configs;
	int rv, i;

	if (conf && !json_object_is_type(conf, json_type_string))
		err_return(UCI_ERR_INVAL);

	rv = uci_list_configs(*c, &configs);

	if (rv != UCI_OK)
		err_return(rv);

	res = json_object_new_object();

	if (!res) {
		free(configs);
		err_return(UCI_ERR_MEM);
	}

	for (i = 0; configs[i]; i++) {
		if (conf && strcmp(configs[i], json_object_get_string(conf)))
			continue;

		chg = changes_to_json(*c, configs[i]);

		if (chg)
			json_object_object_add(res, configs[i], chg);
	}

	free(configs);

	return res;
}

static json_object *
uc_uci_foreach(uc_vm *vm, size_t nargs)
{
	struct uci_context **c = uc_get_self("uci.cursor");
	json_object *conf = uc_get_arg(0);
	json_object *type = uc_get_arg(1);
	json_object *func = uc_get_arg(2);
	json_object *rv = NULL;
	struct uci_package *p = NULL;
	struct uci_element *e, *tmp;
	struct uci_section *sc;
	uc_exception_type_t ex;
	bool stop = false;
	bool ret = false;
	int i = 0;

	if (!json_object_is_type(conf, json_type_string) ||
	    (type && !json_object_is_type(type, json_type_string)))
	    err_return(UCI_ERR_INVAL);

	uci_foreach_element(&(*c)->root, e) {
		if (strcmp(e->name, json_object_get_string(conf)))
			continue;

		p = uci_to_package(e);
		break;
	}

	if (!p)
		err_return(UCI_ERR_NOTFOUND);

	uci_foreach_element_safe(&p->sections, tmp, e) {
		sc = uci_to_section(e);
		i++;

		if (type && strcmp(sc->type, json_object_get_string(type)))
			continue;

		uc_push_val(uc_value_get(func));
		uc_push_val(section_to_json(sc, i - 1));

		ex = uc_call(1);

		/* stop on exception in callback */
		if (ex)
			break;

		ret = true;
		rv = uc_pop_val();
		stop = (json_object_is_type(rv, json_type_boolean) && !json_object_get_boolean(rv));

		json_object_put(rv);

		if (stop)
			break;
	}

	/* XXX: rethrow */

	return json_object_new_boolean(ret);
}

static json_object *
uc_uci_configs(uc_vm *vm, size_t nargs)
{
	struct uci_context **c = uc_get_self("uci.cursor");
	json_object *a;
	char **configs;
	int i, rv;

	rv = uci_list_configs(*c, &configs);

	if (rv != UCI_OK)
		err_return(rv);

	a = json_object_new_array();

	if (!a) {
		free(configs);
		err_return(UCI_ERR_MEM);
	}

	for (i = 0; configs[i]; i++)
		json_object_array_add(a, json_object_new_string(configs[i]));

	free(configs);

	return a;
}


static const uc_cfunction_list cursor_fns[] = {
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

static const uc_cfunction_list global_fns[] = {
	{ "error",		uc_uci_error },
	{ "cursor",		uc_uci_cursor },
};


static void close_uci(void *ud) {
	uci_free_context((struct uci_context *)ud);
}

void uc_module_init(uc_prototype *scope)
{
	uc_add_proto_functions(scope, global_fns);

	cursor_type = uc_declare_type("uci.cursor", cursor_fns, close_uci);
}
