/*
 * Copyright (C) 2020 Jo-Philipp Wich <jo@mein.io>
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

#include "../module.h"

#include <string.h>
#include <uci.h>

#define err_return(err) do { last_error = err; return NULL; } while(0)

static const struct ut_ops *ops;

static struct json_object *uci_proto;

static int last_error = 0;

enum pkg_cmd {
	CMD_SAVE,
	CMD_COMMIT,
	CMD_REVERT
};

static struct json_object *
ut_uci_error(struct ut_state *s, uint32_t off, struct json_object *args)
{
	char buf[sizeof("Unknown error: -9223372036854775808")];
	struct json_object *errmsg;

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

	if (errstr[last_error]) {
		errmsg = json_object_new_string(errstr[last_error]);
	}
	else {
		snprintf(buf, sizeof(buf), "Unknown error: %d", last_error);
		errmsg = json_object_new_string(buf);
	}

	last_error = 0;

	return errmsg;
}


static struct json_object *
ut_uci_cursor(struct ut_state *s, uint32_t off, struct json_object *args)
{
	struct json_object *cdir = json_object_array_get_idx(args, 0);
	struct json_object *sdir = json_object_array_get_idx(args, 1);
	struct json_object *co;
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

	co = json_object_new_object();

	if (!co) {
		uci_free_context(c);
		err_return(UCI_ERR_MEM);
	}

	return ops->set_type(co, uci_proto, "uci.cursor", c);
}


static struct json_object *
ut_uci_load(struct ut_state *s, uint32_t off, struct json_object *args)
{
	struct uci_context **c = (struct uci_context **)ops->get_type(s->ctx, "uci.cursor");
	struct json_object *conf = json_object_array_get_idx(args, 0);
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

static struct json_object *
ut_uci_unload(struct ut_state *s, uint32_t off, struct json_object *args)
{
	struct uci_context **c = (struct uci_context **)ops->get_type(s->ctx, "uci.cursor");
	struct json_object *conf = json_object_array_get_idx(args, 0);
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

static struct json_object *
option_to_json(struct uci_option *o)
{
	struct json_object *arr;
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

static struct json_object *
section_to_json(struct uci_section *s, int index)
{
	struct json_object *so = json_object_new_object();
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

static struct json_object *
package_to_json(struct uci_package *p)
{
	struct json_object *po = json_object_new_object();
	struct json_object *so;
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

static struct json_object *
ut_uci_get_any(struct ut_state *s, uint32_t off, struct json_object *args, bool all)
{
	struct uci_context **c = (struct uci_context **)ops->get_type(s->ctx, "uci.cursor");
	struct json_object *conf = json_object_array_get_idx(args, 0);
	struct json_object *sect = json_object_array_get_idx(args, 1);
	struct json_object *opt = json_object_array_get_idx(args, 2);
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

static struct json_object *
ut_uci_get(struct ut_state *s, uint32_t off, struct json_object *args)
{
	return ut_uci_get_any(s, off, args, false);
}

static struct json_object *
ut_uci_get_all(struct ut_state *s, uint32_t off, struct json_object *args)
{
	return ut_uci_get_any(s, off, args, true);
}

static struct json_object *
ut_uci_get_first(struct ut_state *s, uint32_t off, struct json_object *args)
{
	struct uci_context **c = (struct uci_context **)ops->get_type(s->ctx, "uci.cursor");
	struct json_object *conf = json_object_array_get_idx(args, 0);
	struct json_object *type = json_object_array_get_idx(args, 1);
	struct json_object *opt = json_object_array_get_idx(args, 2);
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

static struct json_object *
ut_uci_add(struct ut_state *s, uint32_t off, struct json_object *args)
{
	struct uci_context **c = (struct uci_context **)ops->get_type(s->ctx, "uci.cursor");
	struct json_object *conf = json_object_array_get_idx(args, 0);
	struct json_object *type = json_object_array_get_idx(args, 1);
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
json_to_value(struct json_object *val, const char **p, bool *is_list)
{
	struct json_object *item;

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

static struct json_object *
ut_uci_set(struct ut_state *s, uint32_t off, struct json_object *args)
{
	struct uci_context **c = (struct uci_context **)ops->get_type(s->ctx, "uci.cursor");
	struct json_object *conf = json_object_array_get_idx(args, 0);
	struct json_object *sect = json_object_array_get_idx(args, 1);
	struct json_object *opt = NULL, *val = NULL;
	struct uci_ptr ptr = {};
	bool is_list = false;
	int rv, i;

	if (!json_object_is_type(conf, json_type_string) ||
	    !json_object_is_type(sect, json_type_string))
	    err_return(UCI_ERR_INVAL);

	switch (json_object_array_length(args)) {
	/* conf, sect, opt, val */
	case 4:
		opt = json_object_array_get_idx(args, 2);
		val = json_object_array_get_idx(args, 3);

		if (!json_object_is_type(opt, json_type_string))
			err_return(UCI_ERR_INVAL);

		break;

	/* conf, sect, type */
	case 3:
		val = json_object_array_get_idx(args, 2);

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

static struct json_object *
ut_uci_delete(struct ut_state *s, uint32_t off, struct json_object *args)
{
	struct uci_context **c = (struct uci_context **)ops->get_type(s->ctx, "uci.cursor");
	struct json_object *conf = json_object_array_get_idx(args, 0);
	struct json_object *sect = json_object_array_get_idx(args, 1);
	struct json_object *opt = json_object_array_get_idx(args, 2);
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

static struct json_object *
ut_uci_rename(struct ut_state *s, uint32_t off, struct json_object *args)
{
	struct uci_context **c = (struct uci_context **)ops->get_type(s->ctx, "uci.cursor");
	struct json_object *conf = json_object_array_get_idx(args, 0);
	struct json_object *sect = json_object_array_get_idx(args, 1);
	struct json_object *opt = NULL, *val = NULL;
	struct uci_ptr ptr = {};
	int rv;

	if (!json_object_is_type(conf, json_type_string) ||
	    !json_object_is_type(sect, json_type_string))
	    err_return(UCI_ERR_INVAL);

	switch (json_object_array_length(args)) {
	/* conf, sect, opt, val */
	case 4:
		opt = json_object_array_get_idx(args, 2);
		val = json_object_array_get_idx(args, 3);

		if (!json_object_is_type(opt, json_type_string) ||
		    !json_object_is_type(val, json_type_string))
			err_return(UCI_ERR_INVAL);

		break;

	/* conf, sect, type */
	case 3:
		val = json_object_array_get_idx(args, 2);

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

static struct json_object *
ut_uci_reorder(struct ut_state *s, uint32_t off, struct json_object *args)
{
	struct uci_context **c = (struct uci_context **)ops->get_type(s->ctx, "uci.cursor");
	struct json_object *conf = json_object_array_get_idx(args, 0);
	struct json_object *sect = json_object_array_get_idx(args, 1);
	struct json_object *val = json_object_array_get_idx(args, 2);
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

static struct json_object *
ut_uci_pkg_command(struct ut_state *s, uint32_t off, struct json_object *args, enum pkg_cmd cmd)
{
	struct uci_context **c = (struct uci_context **)ops->get_type(s->ctx, "uci.cursor");
	struct json_object *conf = json_object_array_get_idx(args, 0);
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
		}

		if (rv != UCI_OK)
			res = rv;
	}

	if (res != UCI_OK)
		err_return(res);

	return json_object_new_boolean(true);
}

static struct json_object *
ut_uci_save(struct ut_state *s, uint32_t off, struct json_object *args)
{
	return ut_uci_pkg_command(s, off, args, CMD_SAVE);
}

static struct json_object *
ut_uci_commit(struct ut_state *s, uint32_t off, struct json_object *args)
{
	return ut_uci_pkg_command(s, off, args, CMD_COMMIT);
}

static struct json_object *
ut_uci_revert(struct ut_state *s, uint32_t off, struct json_object *args)
{
	return ut_uci_pkg_command(s, off, args, CMD_REVERT);
}

static struct json_object *
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

	struct json_object *a;

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

static struct json_object *
changes_to_json(struct uci_context *ctx, const char *package)
{
	struct json_object *a = NULL, *c;
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

static struct json_object *
ut_uci_changes(struct ut_state *s, uint32_t off, struct json_object *args)
{
	struct uci_context **c = (struct uci_context **)ops->get_type(s->ctx, "uci.cursor");
	struct json_object *conf = json_object_array_get_idx(args, 0);
	struct json_object *res, *chg;
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

static struct json_object *
ut_uci_foreach(struct ut_state *s, uint32_t off, struct json_object *args)
{
	struct uci_context **c = (struct uci_context **)ops->get_type(s->ctx, "uci.cursor");
	struct json_object *conf = json_object_array_get_idx(args, 0);
	struct json_object *type = json_object_array_get_idx(args, 1);
	struct json_object *func = json_object_array_get_idx(args, 2);
	struct json_object *fnargs, *rv = NULL;
	struct uci_package *p = NULL;
	struct uci_element *e, *tmp;
	struct uci_section *sc;
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

	fnargs = json_object_new_array();

	if (!fnargs)
		err_return(UCI_ERR_MEM);

	uci_foreach_element_safe(&p->sections, tmp, e) {
		sc = uci_to_section(e);
		i++;

		if (type && strcmp(sc->type, json_object_get_string(type)))
			continue;

		json_object_array_put_idx(fnargs, 0, section_to_json(sc, i - 1));

		rv = ops->invoke(s, off, NULL, func, fnargs);

		/* forward exceptions from callback function */
		if (ut_is_type(rv, T_EXCEPTION))
			return rv;

		ret = true;
		stop = (json_object_is_type(rv, json_type_boolean) && !json_object_get_boolean(rv));

		json_object_put(rv);

		if (stop)
			break;
	}

	return json_object_new_boolean(ret);
}

static struct json_object *
ut_uci_configs(struct ut_state *s, uint32_t off, struct json_object *args)
{
	struct uci_context **c = (struct uci_context **)ops->get_type(s->ctx, "uci.cursor");
	struct json_object *a;
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


static const struct { const char *name; ut_c_fn *func; } cursor_fns[] = {
	{ "load",		ut_uci_load },
	{ "unload",		ut_uci_unload },
	{ "get",		ut_uci_get },
	{ "get_all",	ut_uci_get_all },
	{ "get_first",	ut_uci_get_first },
	{ "add",		ut_uci_add },
	{ "set",		ut_uci_set },
	{ "rename",		ut_uci_rename },
	{ "save",		ut_uci_save },
	{ "delete",		ut_uci_delete },
	{ "commit",		ut_uci_commit },
	{ "revert",		ut_uci_revert },
	{ "reorder",	ut_uci_reorder },
	{ "changes",	ut_uci_changes },
	{ "foreach",	ut_uci_foreach },
	{ "configs",	ut_uci_configs },
};

static const struct { const char *name; ut_c_fn *func; } global_fns[] = {
	{ "error",		ut_uci_error },
	{ "cursor",		ut_uci_cursor },
};


static void close_uci(void *ud) {
	uci_free_context((struct uci_context *)ud);
}

void ut_module_init(const struct ut_ops *ut, struct ut_state *s, struct json_object *scope)
{
	ops = ut;
	ops->register_type("uci.cursor", close_uci);

	uci_proto = ops->new_object(NULL);

	register_functions(ops, global_fns, scope);
	register_functions(ops, cursor_fns, uci_proto);
}
