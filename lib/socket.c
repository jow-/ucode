/*
 * Copyright (C) 2024 Jo-Philipp Wich <jo@mein.io>
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

/**
 * # Socket Module
 *
 * The `socket` module provides functions for interacting with sockets.
 *
 * Functions can be individually imported and directly accessed using the
 * {@link https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Statements/import#named_import named import}
 * syntax:
 *
 *   ```javascript
 *   import { AF_INET, SOCK_STREAM, create as socket } from 'socket';
 *
 *   let sock = socket(AF_INET, SOCK_STREAM, 0);
 *   sock.connect('192.168.1.1', 80);
 *   sock.send(…);
 *   sock.recv(…);
 *   sock.close();
 *   ```
 *
 * Alternatively, the module namespace can be imported
 * using a wildcard import statement:
 *
 *   ```javascript
 *   import * as socket from 'socket';
 *
 *   let sock = socket.create(socket.AF_INET, socket.SOCK_STREAM, 0);
 *   sock.connect('192.168.1.1', 80);
 *   sock.send(…);
 *   sock.recv(…);
 *   sock.close();
 *   ```
 *
 * Additionally, the socket module namespace may also be imported by invoking
 * the `ucode` interpreter with the `-lsocket` switch.
 *
 * @module socket
 */

#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <net/if.h>
#include <netdb.h>
#include <poll.h>
#include <limits.h>
#include <dirent.h>
#include <assert.h>

#include "ucode/module.h"
#include "ucode/platform.h"

#if defined(__linux__)
# include <linux/if_packet.h>
# include <linux/filter.h>

# ifndef SO_TIMESTAMP_OLD
#  define SO_TIMESTAMP_OLD SO_TIMESTAMP
# endif

# ifndef SO_TIMESTAMPNS_OLD
#  define SO_TIMESTAMPNS_OLD SO_TIMESTAMP
# endif
#endif

#if defined(__APPLE__)
# include <sys/ucred.h>

# define SOCK_NONBLOCK (1 << 16)
# define SOCK_CLOEXEC  (1 << 17)
#endif

#ifndef NI_IDN
# define NI_IDN 0
#endif

#ifndef AI_IDN
# define AI_IDN 0
#endif

#ifndef AI_CANONIDN
# define AI_CANONIDN 0
#endif

#ifndef IPV6_FLOWINFO
# define IPV6_FLOWINFO 11
#endif

#ifndef IPV6_FLOWLABEL_MGR
# define IPV6_FLOWLABEL_MGR 32
#endif

#ifndef IPV6_FLOWINFO_SEND
# define IPV6_FLOWINFO_SEND 33
#endif

#define ok_return(expr) do { set_error(0, NULL); return (expr); } while(0)
#define err_return(err, ...) do { set_error(err, __VA_ARGS__); return NULL; } while(0)

static struct {
	int code;
	char *msg;
} last_error;

__attribute__((format(printf, 2, 3))) static void
set_error(int errcode, const char *fmt, ...)
{
	va_list ap;

	free(last_error.msg);

	last_error.code = errcode;
	last_error.msg = NULL;

	if (fmt) {
		va_start(ap, fmt);
		xvasprintf(&last_error.msg, fmt, ap);
		va_end(ap);
	}
}

static char *
arg_type_(uc_type_t type)
{
	switch (type) {
	case UC_INTEGER:  return "an integer value";
	case UC_BOOLEAN:  return "a boolean value";
	case UC_STRING:   return "a string value";
	case UC_DOUBLE:   return "a double value";
	case UC_ARRAY:    return "an array";
	case UC_OBJECT:   return "an object";
	case UC_REGEXP:   return "a regular expression";
	case UC_CLOSURE:  return "a function";
	case UC_RESOURCE: return "a resource value";
	default:          return "the expected type";
	}
}

static bool
args_get_(uc_vm_t *vm, size_t nargs, int *fdptr, ...)
{
	const char *name, *rtype = NULL;
	uc_value_t **ptr, *arg;
	uc_type_t type, t;
	size_t index = 0;
	int *sockfd;
	va_list ap;
	bool opt;

	if (fdptr) {
		sockfd = uc_fn_this("socket");

		if (!sockfd || *sockfd == -1)
			err_return(EBADF, "Invalid socket context");

		*fdptr = *sockfd;
	}

	va_start(ap, fdptr);

	while (true) {
		name = va_arg(ap, const char *);

		if (!name)
			break;

		arg = uc_fn_arg(index++);

		type = va_arg(ap, uc_type_t);
		opt = va_arg(ap, int);
		ptr = va_arg(ap, uc_value_t **);

		if (type == UC_RESOURCE) {
			rtype = name;
			name = strrchr(rtype, '.');
			name = name ? name + 1 : rtype;

			if (arg && !ucv_resource_dataptr(arg, rtype))
				err_return(EINVAL,
					"Argument %s is not a %s resource", name, rtype);
		}

		if (!opt && !arg)
			err_return(EINVAL,
				"Argument %s is required", name);

		t = ucv_type(arg);

		if (t == UC_CFUNCTION)
			t = UC_CLOSURE;

		if (arg && type != UC_NULL && t != type)
			err_return(EINVAL,
				"Argument %s is not %s", name, arg_type_(type));

		*ptr = arg;
	}

	va_end(ap);

	ok_return(true);
}

#define args_get(vm, nargs, fdptr, ...) do { \
	if (!args_get_(vm, nargs, fdptr, ##__VA_ARGS__, NULL)) \
		return NULL; \
} while(0)

static void
strbuf_free(uc_stringbuf_t *sb)
{
	printbuf_free(sb);
}

static bool
strbuf_grow(uc_stringbuf_t *sb, size_t size)
{
	if (size > 0) {
		if (printbuf_memset(sb, sizeof(uc_string_t) + size - 1, '\0', 1))
			err_return(ENOMEM, "Out of memory");
	}

	return true;
}

static char *
strbuf_data(uc_stringbuf_t *sb)
{
	return sb->buf + sizeof(uc_string_t);
}

static size_t
strbuf_size(uc_stringbuf_t *sb)
{
	return (size_t)sb->bpos - sizeof(uc_string_t);
}

static uc_value_t *
strbuf_finish(uc_stringbuf_t **sb, size_t final_size)
{
	size_t buffer_size;
	uc_string_t *us;

	if (!sb || !*sb)
		return NULL;

	buffer_size = strbuf_size(*sb);
	us = (uc_string_t *)(*sb)->buf;

	if (final_size > buffer_size)
		final_size = buffer_size;

	free(*sb);
	*sb = NULL;

	us = xrealloc(us, sizeof(uc_string_t) + final_size + 1);
	us->length = final_size;
	us->str[us->length] = 0;

	return &us->header;
}

static uc_stringbuf_t *
strbuf_alloc(size_t size)
{
	uc_stringbuf_t *sb = ucv_stringbuf_new();

	if (!strbuf_grow(sb, size)) {
		printbuf_free(sb);

		return NULL;
	}

	return sb;
}

#if defined(__linux__)
static uc_value_t *
hwaddr_to_uv(uint8_t *addr, size_t alen)
{
	char buf[sizeof("FF:FF:FF:FF:FF:FF:FF:FF")], *p = buf;
	const char *hex = "0123456789ABCDEF";

	if (alen > 8)
		alen = 8;

	for (size_t i = 0; i < alen; i++) {
		if (i) *p++ = ':';
		*p++ = hex[addr[i] / 16];
		*p++ = hex[addr[i] % 16];
	}

	return ucv_string_new_length(buf, alen);
}

static bool
uv_to_hwaddr(uc_value_t *addr, uint8_t *out, size_t *outlen)
{
	const char *p;
	size_t len;

	memset(out, 0, 8);
	*outlen = 0;

	if (ucv_type(addr) != UC_STRING)
		goto err;

	len = ucv_string_length(addr);
	p = ucv_string_get(addr);

	while (len > 0 && isxdigit(*p) && *outlen < 8) {
		uint8_t n = (*p > '9') ? 10 + (*p|32) - 'a' : *p - '0';
		p++, len--;

		if (len > 0 && isxdigit(*p)) {
			n = n * 16 + ((*p > '9') ? 10 + (*p|32) - 'a' : *p - '0');
			p++, len--;
		}

		if (len > 0 && (*p == ':' || *p == '-' || *p == '.'))
			p++, len--;

		out[(*outlen)++] = n;
	}

	if (len == 0 || *p == 0)
		return true;

err:
	err_return(EINVAL, "Invalid hardware address");
}
#endif

static bool
sockaddr_to_uv(struct sockaddr_storage *ss, uc_value_t *addrobj)
{
	char *ifname, addrstr[INET6_ADDRSTRLEN];
	struct sockaddr_in6 *s6;
	struct sockaddr_in *s4;
	struct sockaddr_un *su;
#if defined(__linux__)
	struct sockaddr_ll *sl;
#endif

	ucv_object_add(addrobj, "family", ucv_uint64_new(ss->ss_family));

	switch (ss->ss_family) {
	case AF_INET6:
		s6 = (struct sockaddr_in6 *)ss;

		inet_ntop(AF_INET6, &s6->sin6_addr, addrstr, sizeof(addrstr));
		ucv_object_add(addrobj, "address",
			ucv_string_new(addrstr));

		ucv_object_add(addrobj, "port",
			ucv_uint64_new(ntohs(s6->sin6_port)));

		ucv_object_add(addrobj, "flowinfo",
			ucv_uint64_new(ntohl(s6->sin6_flowinfo)));

		if (s6->sin6_scope_id) {
			ifname = if_indextoname(s6->sin6_scope_id, addrstr);

			if (ifname)
				ucv_object_add(addrobj, "interface",
					ucv_string_new(ifname));
			else
				ucv_object_add(addrobj, "interface",
					ucv_uint64_new(s6->sin6_scope_id));
		}

		return true;

	case AF_INET:
		s4 = (struct sockaddr_in *)ss;

		inet_ntop(AF_INET, &s4->sin_addr, addrstr, sizeof(addrstr));
		ucv_object_add(addrobj, "address",
			ucv_string_new(addrstr));

		ucv_object_add(addrobj, "port",
			ucv_uint64_new(ntohs(s4->sin_port)));

		return true;

	case AF_UNIX:
		su = (struct sockaddr_un *)ss;

		ucv_object_add(addrobj, "path",
			ucv_string_new(su->sun_path));

		return true;

#if defined(__linux__)
	case AF_PACKET:
		sl = (struct sockaddr_ll *)ss;

		ucv_object_add(addrobj, "protocol",
			ucv_uint64_new(ntohs(sl->sll_protocol)));

		ifname = (sl->sll_ifindex > 0)
			? if_indextoname(sl->sll_ifindex, addrstr) : NULL;

		if (ifname)
			ucv_object_add(addrobj, "interface",
				ucv_string_new(ifname));
		else if (sl->sll_ifindex != 0)
			ucv_object_add(addrobj, "interface",
				ucv_int64_new(sl->sll_ifindex));

		ucv_object_add(addrobj, "hardware_type",
			ucv_uint64_new(sl->sll_hatype));

		ucv_object_add(addrobj, "packet_type",
			ucv_uint64_new(sl->sll_pkttype));

		ucv_object_add(addrobj, "address",
			hwaddr_to_uv(sl->sll_addr, sl->sll_halen));

		return true;
#endif
	}

	return false;
}

static int64_t
parse_integer(char *s, size_t len)
{
	union { int8_t i8; int16_t i16; int32_t i32; int64_t i64; } v;

	memcpy(&v, s, len < sizeof(v) ? len : sizeof(v));

	switch (len) {
	case 1:  return v.i8;
	case 2:  return v.i16;
	case 4:  return v.i32;
	case 8:  return v.i64;
	default: return 0;
	}
}

static uint64_t
parse_unsigned(char *s, size_t len)
{
	union { uint8_t u8; uint16_t u16; uint32_t u32; uint64_t u64; } v;

	memcpy(&v, s, len < sizeof(v) ? len : sizeof(v));

	switch (len) {
	case 1:  return v.u8;
	case 2:  return v.u16;
	case 4:  return v.u32;
	case 8:  return v.u64;
	default: return 0;
	}
}

static bool
parse_addr(char *addr, struct sockaddr_storage *ss)
{
	bool v6 = (ss->ss_family == 0 || ss->ss_family == AF_INET6);
	bool v4 = (ss->ss_family == 0 || ss->ss_family == AF_INET);
	struct sockaddr_in6 *s6 = (struct sockaddr_in6 *)ss;
	struct sockaddr_in *s4 = (struct sockaddr_in *)ss;
	unsigned long n;
	char *scope, *e;

	if (v6 && (scope = strchr(addr, '%')) != NULL) {
		*scope++ = 0;
		n = strtoul(scope, &e, 10);

		if (e == scope || *e != 0) {
			n = if_nametoindex(scope);

			if (n == 0)
				err_return(errno, "Unable to resolve interface %s", scope);
		}

		if (inet_pton(AF_INET6, addr, &s6->sin6_addr) != 1)
			err_return(errno, "Invalid IPv6 address");

		s6->sin6_family = AF_INET6;
		s6->sin6_scope_id = n;

		return true;
	}
	else if (v6 && inet_pton(AF_INET6, addr, &s6->sin6_addr) == 1) {
		s6->sin6_family = AF_INET6;

		return true;
	}
	else if (v4 && inet_pton(AF_INET, addr, &s4->sin_addr) == 1) {
		s4->sin_family = AF_INET;

		return true;
	}

	err_return(EINVAL, "Unable to parse IP address");
}

static bool
uv_to_sockaddr(uc_value_t *addr, struct sockaddr_storage *ss, socklen_t *slen)
{
	char *s, *p, addrstr[sizeof("ffff:ffff:ffff:ffff:ffff:ffff:255.255.255.255%2147483648")];
	struct sockaddr_in6 *s6 = (struct sockaddr_in6 *)ss;
	struct sockaddr_in *s4 = (struct sockaddr_in *)ss;
	struct sockaddr_un *su = (struct sockaddr_un *)ss;
#if defined(__linux__)
	struct sockaddr_ll *sl = (struct sockaddr_ll *)ss;
#endif
	uc_value_t *item;
	unsigned long n;
	size_t len;

	memset(ss, 0, sizeof(*ss));

	if (ucv_type(addr) == UC_STRING) {
		s = ucv_string_get(addr);
		len = ucv_string_length(addr);

		if (memchr(s, '/', len) != NULL) {
			if (len >= sizeof(su->sun_path))
				len = sizeof(su->sun_path) - 1;

			memcpy(su->sun_path, s, len);
			su->sun_path[len++] = 0;
			su->sun_family = AF_UNIX;
			*slen = sizeof(*su);

			ok_return(true);
		}

		if (len == 0)
			err_return(EINVAL, "Invalid IP address");

		if (*s == '[') {
			p = memchr(++s, ']', --len);

			if (!p || (size_t)(p - s) >= sizeof(addrstr))
				err_return(EINVAL, "Invalid IPv6 address");

			memcpy(addrstr, s, p - s);
			addrstr[(p - s) + 1] = 0;

			ss->ss_family = AF_INET6;
			len -= ((p - s) + 1);
			s = p + 1;
		}
		else if ((p = memchr(s, ':', len)) != NULL &&
		         memchr(p + 1, ':', len - ((p - s) + 1)) == NULL) {
			if ((size_t)(p - s) >= sizeof(addrstr))
				err_return(EINVAL, "Invalid IP address");

			memcpy(addrstr, s, p - s);
			addrstr[p - s + 1] = 0;

			ss->ss_family = AF_INET;
			len -= (p - s);
			s = p;
		}
		else {
			if (len >= sizeof(addrstr))
				err_return(EINVAL, "Invalid IP address");

			memcpy(addrstr, s, len);
			addrstr[len] = 0;

			ss->ss_family = 0;
			len = 0;
			s = NULL;
		}

		if (!parse_addr(addrstr, ss))
			return NULL;

		if (s && *s == ':') {
			if (len <= 1)
				err_return(EINVAL, "Invalid port number");

			for (s++, len--, n = 0; len > 0; len--, s++) {
				if (*s < '0' || *s > '9')
					err_return(EINVAL, "Invalid port number");

				n = n * 10 + (*s - '0');
			}

			if (n > 65535)
				err_return(EINVAL, "Invalid port number");

			s6->sin6_port = htons(n);
		}

		*slen = (ss->ss_family == AF_INET6) ? sizeof(*s6) : sizeof(*s4);

		ok_return(true);
	}
	else if (ucv_type(addr) == UC_ARRAY) {
		if (ucv_array_length(addr) == 16) {
			uint8_t *u8 = (uint8_t *)&s6->sin6_addr;

			for (size_t i = 0; i < 16; i++) {
				item = ucv_array_get(addr, i);
				n = ucv_uint64_get(item);

				if (ucv_type(item) != UC_INTEGER || errno != 0 || n > 255)
					err_return(EINVAL, "Invalid IP address array");

				u8[i] = n;
			}

			s6->sin6_family = AF_INET6;
			*slen = sizeof(*s6);

			ok_return(true);
		}
		else if (ucv_array_length(addr) == 4) {
			s4->sin_addr.s_addr = 0;

			for (size_t i = 0; i < 4; i++) {
				item = ucv_array_get(addr, i);
				n = ucv_uint64_get(item);

				if (ucv_type(item) != UC_INTEGER || errno != 0 || n > 255)
					err_return(EINVAL, "Invalid IP address array");

				s4->sin_addr.s_addr = s4->sin_addr.s_addr * 256 + n;
			}

			s4->sin_addr.s_addr = htonl(s4->sin_addr.s_addr);
			s4->sin_family = AF_INET;
			*slen = sizeof(*s4);

			ok_return(true);
		}

		err_return(EINVAL, "Invalid IP address array");
	}
	else if (ucv_type(addr) == UC_OBJECT) {
		n = ucv_to_unsigned(ucv_object_get(addr, "family", NULL));

		if (n == 0) {
			if (ucv_type(ucv_object_get(addr, "path", NULL)) == UC_STRING) {
				n = AF_UNIX;
			}
			else {
				item = ucv_object_get(addr, "address", NULL);
				len = ucv_string_length(item);
				s = ucv_string_get(item);
				n = (s && memchr(s, ':', len) != NULL) ? AF_INET6 : AF_INET;
			}

			if (n == 0)
				err_return(EINVAL, "Invalid address object");
		}

		switch (n) {
		case AF_INET6:
			item = ucv_object_get(addr, "flowinfo", NULL);
			s6->sin6_flowinfo = htonl(ucv_to_unsigned(item));

			item = ucv_object_get(addr, "interface", NULL);

			if (ucv_type(item) == UC_STRING) {
				s6->sin6_scope_id = if_nametoindex(ucv_string_get(item));

				if (s6->sin6_scope_id == 0)
					err_return(errno, "Unable to resolve interface %s",
						ucv_string_get(item));
			}
			else if (item != NULL) {
				s6->sin6_scope_id = ucv_to_unsigned(item);

				if (errno != 0)
					err_return(errno, "Invalid scope ID");
			}

			/* fall through */

		case AF_INET:
			ss->ss_family = n;
			*slen = (n == AF_INET6) ? sizeof(*s6) : sizeof(*s4);

			item = ucv_object_get(addr, "port", NULL);
			n = ucv_to_unsigned(item);

			if (errno != 0 || n > 65535)
				err_return(EINVAL, "Invalid port number");

			s6->sin6_port = htons(n);

			item = ucv_object_get(addr, "address", NULL);
			len = ucv_string_length(item);
			s = ucv_string_get(item);

			if (len >= sizeof(addrstr))
				err_return(EINVAL, "Invalid IP address");

			if (len > 0) {
				memcpy(addrstr, s, len);
				addrstr[len] = 0;

				if (!parse_addr(addrstr, ss))
					return NULL;
			}

			ok_return(true);

		case AF_UNIX:
			item = ucv_object_get(addr, "path", NULL);
			len = ucv_string_length(item);

			if (len == 0 || len >= sizeof(su->sun_path))
				err_return(EINVAL, "Invalid path value");

			memcpy(su->sun_path, ucv_string_get(item), len);
			su->sun_path[len++] = 0;
			su->sun_family = AF_UNIX;
			*slen = sizeof(*su);

			ok_return(true);

#if defined(__linux__)
		case AF_PACKET:
			item = ucv_object_get(addr, "protocol", NULL);

			if (item) {
				n = ucv_to_unsigned(item);

				if (errno != 0 || n > 65535)
					err_return(EINVAL, "Invalid protocol number");

				sl->sll_protocol = htons(n);
			}

			item = ucv_object_get(addr, "address", NULL);

			if (uv_to_hwaddr(item, sl->sll_addr, &len))
				sl->sll_halen = len;
			else
				return false;

			item = ucv_object_get(addr, "interface", NULL);

			if (ucv_type(item) == UC_STRING) {
				sl->sll_ifindex = if_nametoindex(ucv_string_get(item));

				if (sl->sll_ifindex == 0)
					err_return(errno, "Unable to resolve interface %s",
						ucv_string_get(item));
			}
			else if (item != NULL) {
				sl->sll_ifindex = ucv_to_integer(item);

				if (errno)
					err_return(errno, "Unable to convert interface to integer");
			}

			item = ucv_object_get(addr, "hardware_type", NULL);

			if (item) {
				n = ucv_to_unsigned(item);

				if (errno != 0 || n > 65535)
					err_return(EINVAL, "Invalid hardware type");

				sl->sll_hatype = n;
			}

			item = ucv_object_get(addr, "packet_type", NULL);

			if (item) {
				n = ucv_to_unsigned(item);

				if (errno != 0 || n > 255)
					err_return(EINVAL, "Invalid packet type");

				sl->sll_pkttype = n;
			}

			sl->sll_family = AF_PACKET;
			*slen = sizeof(*sl);

			ok_return(true);
#endif
		}
	}

	err_return(EINVAL, "Invalid address value");
}

static bool
uv_to_fileno(uc_vm_t *vm, uc_value_t *val, int *fileno)
{
	uc_value_t *fn;
	int *fdptr;

	fdptr = (int *)ucv_resource_dataptr(val, "socket");

	if (fdptr) {
		if (*fdptr < 0)
			err_return(EBADF, "Socket is closed");

		*fileno = *fdptr;

		return true;
	}

	fn = ucv_property_get(val, "fileno");

	if (ucv_is_callable(fn)) {
		uc_vm_stack_push(vm, ucv_get(val));
		uc_vm_stack_push(vm, ucv_get(fn));

		if (uc_vm_call(vm, true, 0) != EXCEPTION_NONE)
			return false;

		val = uc_vm_stack_pop(vm);
	}
	else {
		ucv_get(val);
	}

	*fileno = ucv_int64_get(val);

	ucv_put(val);

	if (errno != 0 || *fileno < 0)
		err_return(EBADF, "Invalid file descriptor number");

	return true;
}

static uc_value_t *
uv_to_pollfd(uc_vm_t *vm, uc_value_t *val, struct pollfd *pfd)
{
	uc_value_t *rv;
	int64_t flags;

	if (ucv_type(val) == UC_ARRAY) {
		if (!uv_to_fileno(vm, ucv_array_get(val, 0), &pfd->fd))
			return NULL;

		flags = ucv_to_integer(ucv_array_get(val, 1));

		if (errno != 0 || flags < -32768 || flags > 32767)
			err_return(ERANGE, "Flags value out of range");

		pfd->events = flags;
		pfd->revents = 0;

		return ucv_get(val);
	}

	if (!uv_to_fileno(vm, val, &pfd->fd))
		return NULL;

	pfd->events = POLLIN | POLLERR | POLLHUP;
	pfd->revents = 0;

	rv = ucv_array_new_length(vm, 2);

	ucv_array_set(rv, 0, ucv_get(val));
	ucv_array_set(rv, 1, ucv_uint64_new(pfd->events));

	return rv;
}

static uc_value_t *
ucv_socket_new(uc_vm_t *vm, int fd)
{
	return ucv_resource_new(
		ucv_resource_type_lookup(vm, "socket"),
		(void *)(intptr_t)fd
	);
}

static bool
xclose(int *fdptr)
{
	bool rv = true;

	if (fdptr) {
		if (*fdptr >= 0)
			rv = (close(*fdptr) == 0);

		*fdptr = -1;
	}

	return rv;
}


typedef struct {
    const char *name;
    enum { DT_SIGNED, DT_UNSIGNED, DT_IPV4ADDR, DT_IPV6ADDR, DT_CALLBACK } type;
	union {
    	size_t offset;
		bool (*to_c)(void *, uc_value_t *);
	} u1;
	union {
		size_t size;
		uc_value_t *(*to_uv)(void *);
	} u2;
} member_t;

typedef struct {
	size_t size;
	member_t *members;
} struct_t;

typedef struct {
	int level;
	int option;
	struct_t *ctype;
} sockopt_t;

typedef struct {
	int level;
	int type;
	struct_t *ctype;
} cmsgtype_t;

#define STRUCT_MEMBER_NP(struct_name, member_name, data_type)	\
	{ #member_name, data_type,									\
	  { .offset = offsetof(struct struct_name, member_name) },	\
	  { .size = sizeof(((struct struct_name *)NULL)->member_name) } }

#define STRUCT_MEMBER_CB(member_name, to_c_fn, to_uv_fn)		\
	{ #member_name, DT_CALLBACK, { .to_c = to_c_fn }, { .to_uv = to_uv_fn } }

#define STRUCT_MEMBER(struct_name, member_prefix, member_name, data_type)			\
	{ #member_name, data_type, 														\
	  { .offset = offsetof(struct struct_name, member_prefix##_##member_name) },	\
	  { .size = sizeof(((struct struct_name *)NULL)->member_prefix##_##member_name) } }

static struct_t st_timeval = {
	.size = sizeof(struct timeval),
	.members = (member_t []){
		STRUCT_MEMBER(timeval, tv, sec, DT_SIGNED),
		STRUCT_MEMBER(timeval, tv, usec, DT_SIGNED),
		{ 0 }
	}
};

#if defined(__linux__)
static bool
filter_to_c(void *st, uc_value_t *uv)
{
	struct sock_fprog **fpp = st;
	struct sock_fprog *fp = *fpp;
	size_t i, len;

	if (ucv_type(uv) == UC_STRING) {
		size_t len = ucv_string_length(uv);

		if (len == 0 || (len % sizeof(struct sock_filter)) != 0)
			err_return(EINVAL, "Filter program length not a multiple of %zu",
				sizeof(struct sock_filter));

		fp = *fpp = xrealloc(fp, sizeof(struct sock_fprog) + len);
		fp->filter = memcpy((char *)fp + sizeof(struct sock_fprog), ucv_string_get(uv), len);

		if (fp->len == 0)
			fp->len = len / sizeof(struct sock_filter);
	}
	else if (ucv_type(uv) == UC_ARRAY) {
		/* Opcode array of array. Each sub-array is a 4 element tuple */
		if (ucv_type(ucv_array_get(uv, 0)) == UC_ARRAY) {
			len = ucv_array_length(uv);

			fp = *fpp = xrealloc(fp, sizeof(struct sock_fprog)
				+ (len * sizeof(struct sock_filter)));

			fp->filter = (struct sock_filter *)((char *)fp + sizeof(struct sock_fprog));

			for (i = 0; i < len; i++) {
				uc_value_t *op = ucv_array_get(uv, i);

				if (ucv_type(op) != UC_ARRAY)
					continue;

				fp->filter[i].code = ucv_to_unsigned(ucv_array_get(op, 0));
				fp->filter[i].jt = ucv_to_unsigned(ucv_array_get(op, 1));
				fp->filter[i].jf = ucv_to_unsigned(ucv_array_get(op, 2));
				fp->filter[i].k = ucv_to_unsigned(ucv_array_get(op, 3));
			}
		}

		/* Flat opcode array, must be a multiple of 4 */
		else {
			len = ucv_array_length(uv);

			if (len % 4)
				err_return(EINVAL, "Opcode array length not a multiple of 4");

			len /= 4;

			fp = *fpp = xrealloc(fp, sizeof(struct sock_fprog)
				+ (len * sizeof(struct sock_filter)));

			fp->filter = (struct sock_filter *)((char *)fp + sizeof(struct sock_fprog));

			for (i = 0; i < len; i++) {
				fp->filter[i].code = ucv_to_unsigned(ucv_array_get(uv, i * 4 + 0));
				fp->filter[i].jt = ucv_to_unsigned(ucv_array_get(uv, i * 4 + 1));
				fp->filter[i].jf = ucv_to_unsigned(ucv_array_get(uv, i * 4 + 2));
				fp->filter[i].k = ucv_to_unsigned(ucv_array_get(uv, i * 4 + 3));
			}
		}

		if (fp->len == 0)
			fp->len = i;
	}
	else {
		err_return(EINVAL, "Expecting either BPF bytecode string or array of opcodes");
	}

	return true;
}

static struct_t st_sock_fprog = {
	.size = sizeof(struct sock_fprog),
	.members = (member_t []){
		STRUCT_MEMBER_NP(sock_fprog, len, DT_UNSIGNED),
		STRUCT_MEMBER_CB(filter, filter_to_c, NULL),
		{ 0 }
	}
};

static struct_t st_ucred = {
	.size = sizeof(struct ucred),
	.members = (member_t []){
		STRUCT_MEMBER_NP(ucred, pid, DT_SIGNED),
		STRUCT_MEMBER_NP(ucred, uid, DT_SIGNED),
		STRUCT_MEMBER_NP(ucred, gid, DT_SIGNED),
		{ 0 }
	}
};
#endif

static struct_t st_linger = {
	.size = sizeof(struct linger),
	.members = (member_t []){
		STRUCT_MEMBER(linger, l, onoff, DT_SIGNED),
		STRUCT_MEMBER(linger, l, linger, DT_SIGNED),
		{ 0 }
	}
};

static struct_t st_ip_mreqn = {
	.size = sizeof(struct ip_mreqn),
	.members = (member_t []){
		STRUCT_MEMBER(ip_mreqn, imr, multiaddr, DT_IPV4ADDR),
		STRUCT_MEMBER(ip_mreqn, imr, address, DT_IPV4ADDR),
		STRUCT_MEMBER(ip_mreqn, imr, ifindex, DT_SIGNED),
		{ 0 }
	}
};

static struct_t st_ip_mreq_source = {
	.size = sizeof(struct ip_mreq_source),
	.members = (member_t []){
		STRUCT_MEMBER(ip_mreq_source, imr, multiaddr, DT_IPV4ADDR),
		STRUCT_MEMBER(ip_mreq_source, imr, interface, DT_IPV4ADDR),
		STRUCT_MEMBER(ip_mreq_source, imr, sourceaddr, DT_IPV4ADDR),
		{ 0 }
	}
};

/* This structure is declared in kernel, but not libc headers, so redeclare it
   locally */
struct in6_flowlabel_req_local {
	struct in6_addr	flr_dst;
	uint32_t flr_label;
	uint8_t flr_action;
	uint8_t flr_share;
	uint16_t flr_flags;
	uint16_t flr_expires;
	uint16_t flr_linger;
};

static struct_t st_in6_flowlabel_req = {
	.size = sizeof(struct in6_flowlabel_req_local),
	.members = (member_t []){
		STRUCT_MEMBER(in6_flowlabel_req_local, flr, dst, DT_IPV6ADDR),
		STRUCT_MEMBER(in6_flowlabel_req_local, flr, label, DT_UNSIGNED),
		STRUCT_MEMBER(in6_flowlabel_req_local, flr, action, DT_UNSIGNED),
		STRUCT_MEMBER(in6_flowlabel_req_local, flr, share, DT_UNSIGNED),
		STRUCT_MEMBER(in6_flowlabel_req_local, flr, flags, DT_UNSIGNED),
		STRUCT_MEMBER(in6_flowlabel_req_local, flr, expires, DT_UNSIGNED),
		STRUCT_MEMBER(in6_flowlabel_req_local, flr, linger, DT_UNSIGNED),
		{ 0 }
	}
};

#if defined(__linux__)
static uc_value_t *
in6_ifindex_to_uv(void *st)
{
	char ifname[IF_NAMESIZE] = { 0 };
	struct ipv6_mreq *mr = st;

	if (mr->ipv6mr_interface > 0 && if_indextoname(mr->ipv6mr_interface, ifname))
		return ucv_string_new(ifname);

	return ucv_int64_new(mr->ipv6mr_interface);
}

static bool
in6_ifindex_to_c(void *st, uc_value_t *uv)
{
	struct ipv6_mreq *mr = *(struct ipv6_mreq **)st;

	if (ucv_type(uv) == UC_STRING) {
		mr->ipv6mr_interface = if_nametoindex(ucv_string_get(uv));

		if (mr->ipv6mr_interface == 0)
			err_return(errno, "Unable to resolve interface %s",
				ucv_string_get(uv));
	}
	else {
		mr->ipv6mr_interface = ucv_to_integer(uv);

		if (errno)
			err_return(errno, "Unable to convert interface to integer");
	}

	return true;
}

static struct_t st_ipv6_mreq = {
	.size = sizeof(struct ipv6_mreq),
	.members = (member_t []){
		STRUCT_MEMBER(ipv6_mreq, ipv6mr, multiaddr, DT_IPV6ADDR),
		STRUCT_MEMBER_CB(interface, in6_ifindex_to_c, in6_ifindex_to_uv),
		{ 0 }
	}
};

/* NB: this is the same layout as struct ipv6_mreq, so we reuse the callbacks */
static struct_t st_in6_pktinfo = {
	.size = sizeof(struct in6_pktinfo),
	.members = (member_t []){
		STRUCT_MEMBER(in6_pktinfo, ipi6, addr, DT_IPV6ADDR),
		STRUCT_MEMBER_CB(interface, in6_ifindex_to_c, in6_ifindex_to_uv),
		{ 0 }
	}
};

struct ipv6_recv_error_local {
	struct {
		uint32_t ee_errno;
		uint8_t ee_origin;
		uint8_t ee_type;
		uint8_t ee_code;
		uint8_t ee_pad;
		uint32_t ee_info;
		union {
			uint32_t ee_data;
			struct {
				uint16_t ee_len;
				uint8_t ee_flags;
				uint8_t ee_reserved;
			} ee_rfc4884;
		} u;
	} ee;
	struct sockaddr_in6 offender;
};

static uc_value_t *
offender_to_uv(void *st)
{
	struct ipv6_recv_error_local *e = st;
	uc_value_t *addr = ucv_object_new(NULL);

	if (sockaddr_to_uv((struct sockaddr_storage *)&e->offender, addr))
		return addr;

	ucv_put(addr);

	return NULL;
}

static struct_t st_ip_recv_error = {
	.size = sizeof(struct ipv6_recv_error_local),
	.members = (member_t []){
		STRUCT_MEMBER(ipv6_recv_error_local, ee.ee, errno, DT_UNSIGNED),
		STRUCT_MEMBER(ipv6_recv_error_local, ee.ee, origin, DT_UNSIGNED),
		STRUCT_MEMBER(ipv6_recv_error_local, ee.ee, type, DT_UNSIGNED),
		STRUCT_MEMBER(ipv6_recv_error_local, ee.ee, code, DT_UNSIGNED),
		STRUCT_MEMBER(ipv6_recv_error_local, ee.ee, info, DT_UNSIGNED),
		STRUCT_MEMBER(ipv6_recv_error_local, ee.u.ee, data, DT_UNSIGNED),
		STRUCT_MEMBER(ipv6_recv_error_local, ee.u.ee_rfc4884.ee, len, DT_UNSIGNED),
		STRUCT_MEMBER(ipv6_recv_error_local, ee.u.ee_rfc4884.ee, flags, DT_UNSIGNED),
		STRUCT_MEMBER_CB(offender, NULL, offender_to_uv),
		{ 0 }
	}
};

static uc_value_t *
ip6m_addr_to_uv(void *st)
{
	struct ip6_mtuinfo *mi = st;
	uc_value_t *addr = ucv_object_new(NULL);

	if (sockaddr_to_uv((struct sockaddr_storage *)&mi->ip6m_addr, addr))
		return addr;

	ucv_put(addr);

	return NULL;
}

static struct_t st_ip6_mtuinfo = {
	.size = sizeof(struct ip6_mtuinfo),
	.members = (member_t []){
		STRUCT_MEMBER_CB(addr, NULL, ip6m_addr_to_uv),
		STRUCT_MEMBER(ip6_mtuinfo, ip6m, mtu, DT_UNSIGNED),
		{ 0 }
	}
};

static struct_t st_ip_msfilter = {
	.size = sizeof(struct ip_msfilter),
	.members = (member_t []){
		STRUCT_MEMBER(ip_msfilter, imsf, multiaddr, DT_IPV4ADDR),
		STRUCT_MEMBER(ip_msfilter, imsf, interface, DT_IPV4ADDR),
		STRUCT_MEMBER(ip_msfilter, imsf, fmode, DT_SIGNED),
		STRUCT_MEMBER(ip_msfilter, imsf, numsrc, DT_SIGNED),
		STRUCT_MEMBER(ip_msfilter, imsf, slist, DT_SIGNED),
		{ 0 }
	}
};

static uc_value_t *
snd_wscale_to_uv(void *st)
{
	return ucv_uint64_new(((struct tcp_info *)st)->tcpi_snd_wscale);
}

static uc_value_t *
rcv_wscale_to_uv(void *st)
{
	return ucv_uint64_new(((struct tcp_info *)st)->tcpi_rcv_wscale);
}

static bool
snd_wscale_to_c(void *st, uc_value_t *uv)
{
	struct tcp_info *ti = *(struct tcp_info **)st;

	ti->tcpi_snd_wscale = ucv_to_unsigned(uv);

	if (errno)
		err_return(errno, "Unable to convert field snd_wscale to unsigned");

	return true;
}

static bool
rcv_wscale_to_c(void *st, uc_value_t *uv)
{
	struct tcp_info *ti = *(struct tcp_info **)st;

	ti->tcpi_rcv_wscale = ucv_to_unsigned(uv);

	if (errno)
		err_return(errno, "Unable to convert field rcv_wscale to unsigned");

	return true;
}

static struct_t st_tcp_info = {
	.size = sizeof(struct tcp_info),
	.members = (member_t []){
		STRUCT_MEMBER(tcp_info, tcpi, state, DT_UNSIGNED),
		STRUCT_MEMBER(tcp_info, tcpi, ca_state, DT_UNSIGNED),
		STRUCT_MEMBER(tcp_info, tcpi, retransmits, DT_UNSIGNED),
		STRUCT_MEMBER(tcp_info, tcpi, probes, DT_UNSIGNED),
		STRUCT_MEMBER(tcp_info, tcpi, backoff, DT_UNSIGNED),
		STRUCT_MEMBER(tcp_info, tcpi, options, DT_UNSIGNED),
		STRUCT_MEMBER_CB(snd_wscale, snd_wscale_to_c, snd_wscale_to_uv),
		STRUCT_MEMBER_CB(rcv_wscale, rcv_wscale_to_c, rcv_wscale_to_uv),
		STRUCT_MEMBER(tcp_info, tcpi, rto, DT_UNSIGNED),
		STRUCT_MEMBER(tcp_info, tcpi, ato, DT_UNSIGNED),
		STRUCT_MEMBER(tcp_info, tcpi, snd_mss, DT_UNSIGNED),
		STRUCT_MEMBER(tcp_info, tcpi, rcv_mss, DT_UNSIGNED),
		STRUCT_MEMBER(tcp_info, tcpi, unacked, DT_UNSIGNED),
		STRUCT_MEMBER(tcp_info, tcpi, sacked, DT_UNSIGNED),
		STRUCT_MEMBER(tcp_info, tcpi, lost, DT_UNSIGNED),
		STRUCT_MEMBER(tcp_info, tcpi, retrans, DT_UNSIGNED),
		STRUCT_MEMBER(tcp_info, tcpi, fackets, DT_UNSIGNED),
		STRUCT_MEMBER(tcp_info, tcpi, last_data_sent, DT_UNSIGNED),
		STRUCT_MEMBER(tcp_info, tcpi, last_ack_sent, DT_UNSIGNED),
		STRUCT_MEMBER(tcp_info, tcpi, last_data_recv, DT_UNSIGNED),
		STRUCT_MEMBER(tcp_info, tcpi, last_ack_recv, DT_UNSIGNED),
		STRUCT_MEMBER(tcp_info, tcpi, pmtu, DT_UNSIGNED),
		STRUCT_MEMBER(tcp_info, tcpi, rcv_ssthresh, DT_UNSIGNED),
		STRUCT_MEMBER(tcp_info, tcpi, rtt, DT_UNSIGNED),
		STRUCT_MEMBER(tcp_info, tcpi, rttvar, DT_UNSIGNED),
		STRUCT_MEMBER(tcp_info, tcpi, snd_ssthresh, DT_UNSIGNED),
		STRUCT_MEMBER(tcp_info, tcpi, snd_cwnd, DT_UNSIGNED),
		STRUCT_MEMBER(tcp_info, tcpi, advmss, DT_UNSIGNED),
		STRUCT_MEMBER(tcp_info, tcpi, reordering, DT_UNSIGNED),
		STRUCT_MEMBER(tcp_info, tcpi, rcv_rtt, DT_UNSIGNED),
		STRUCT_MEMBER(tcp_info, tcpi, rcv_space, DT_UNSIGNED),
		STRUCT_MEMBER(tcp_info, tcpi, total_retrans, DT_UNSIGNED),
		{ 0 }
	}
};
#endif

static uc_value_t *
ai_addr_to_uv(void *st)
{
	uc_value_t *rv = ucv_object_new(NULL);
	struct sockaddr_storage ss = { 0 };
	struct addrinfo *ai = st;

	memcpy(&ss, ai->ai_addr, ai->ai_addrlen);

	if (!sockaddr_to_uv(&ss, rv)) {
		ucv_put(rv);
		return NULL;
	}

	return rv;
}

static uc_value_t *
ai_canonname_to_uv(void *st)
{
	struct addrinfo *ai = st;
	return ai->ai_canonname ? ucv_string_new(ai->ai_canonname) : NULL;
}

/**
 * Represents a network address information object returned by
 * {@link module:socket#addrinfo|`addrinfo()`}.
 *
 * @typedef {Object} module:socket.AddressInfo
 *
 * @property {module:socket.socket.SocketAddress} addr - A socket address structure.
 * @property {string} [canonname=null] - The canonical hostname associated with the address.
 * @property {number} family - The address family (e.g., `2` for `AF_INET`, `10` for `AF_INET6`).
 * @property {number} flags - Additional flags indicating properties of the address.
 * @property {number} protocol - The protocol number.
 * @property {number} socktype - The socket type (e.g., `1` for `SOCK_STREAM`, `2` for `SOCK_DGRAM`).
 */
static struct_t st_addrinfo = {
	.size = sizeof(struct addrinfo),
	.members = (member_t []){
		STRUCT_MEMBER(addrinfo, ai, flags, DT_SIGNED),
		STRUCT_MEMBER(addrinfo, ai, family, DT_SIGNED),
		STRUCT_MEMBER(addrinfo, ai, socktype, DT_SIGNED),
		STRUCT_MEMBER(addrinfo, ai, protocol, DT_SIGNED),
		STRUCT_MEMBER_CB(addr, NULL, ai_addr_to_uv),
		STRUCT_MEMBER_CB(canonname, NULL, ai_canonname_to_uv),
		{ 0 }
	}
};

#if defined(__linux__)
static uc_value_t *
mr_ifindex_to_uv(void *st)
{
	char ifname[IF_NAMESIZE] = { 0 };
	struct packet_mreq *mr = st;

	if (mr->mr_ifindex > 0 && if_indextoname(mr->mr_ifindex, ifname))
		return ucv_string_new(ifname);

	return ucv_int64_new(mr->mr_ifindex);
}

static bool
mr_ifindex_to_c(void *st, uc_value_t *uv)
{
	struct packet_mreq *mr = *(struct packet_mreq **)st;

	if (ucv_type(uv) == UC_STRING) {
		mr->mr_ifindex = if_nametoindex(ucv_string_get(uv));

		if (mr->mr_ifindex == 0)
			err_return(errno, "Unable to resolve interface %s",
				ucv_string_get(uv));
	}
	else {
		mr->mr_ifindex = ucv_to_integer(uv);

		if (errno)
			err_return(errno, "Unable to convert interface to integer");
	}

	return true;
}

static uc_value_t *
mr_address_to_uv(void *st)
{
	struct packet_mreq *mr = st;

	return hwaddr_to_uv(mr->mr_address, mr->mr_alen);
}

static bool
mr_address_to_c(void *st, uc_value_t *uv)
{
	struct packet_mreq *mr = *(struct packet_mreq **)st;
	size_t len;

	if (!uv_to_hwaddr(uv, mr->mr_address, &len))
		return false;

	mr->mr_alen = len;

	return true;
}

static struct_t st_packet_mreq = {
	.size = sizeof(struct packet_mreq),
	.members = (member_t []){
		STRUCT_MEMBER_CB(interface, mr_ifindex_to_c, mr_ifindex_to_uv),
		STRUCT_MEMBER(packet_mreq, mr, type, DT_UNSIGNED),
		STRUCT_MEMBER_CB(address, mr_address_to_c, mr_address_to_uv),
		{ 0 }
	}
};

static struct_t st_tpacket_req = {
	.size = sizeof(struct tpacket_req),
	.members = (member_t []){
		STRUCT_MEMBER(tpacket_req, tp, block_size, DT_UNSIGNED),
		STRUCT_MEMBER(tpacket_req, tp, block_nr, DT_UNSIGNED),
		STRUCT_MEMBER(tpacket_req, tp, frame_size, DT_UNSIGNED),
		STRUCT_MEMBER(tpacket_req, tp, frame_nr, DT_UNSIGNED),
		{ 0 }
	}
};

static struct_t st_tpacket_stats = {
	.size = sizeof(struct tpacket_stats),
	.members = (member_t []){
		STRUCT_MEMBER(tpacket_stats, tp, packets, DT_UNSIGNED),
		STRUCT_MEMBER(tpacket_stats, tp, drops, DT_UNSIGNED),
		{ 0 }
	}
};

static struct_t st_tpacket_auxdata = {
	.size = sizeof(struct tpacket_auxdata),
	.members = (member_t []){
		STRUCT_MEMBER(tpacket_auxdata, tp, status, DT_UNSIGNED),
		STRUCT_MEMBER(tpacket_auxdata, tp, len, DT_UNSIGNED),
		STRUCT_MEMBER(tpacket_auxdata, tp, snaplen, DT_UNSIGNED),
		STRUCT_MEMBER(tpacket_auxdata, tp, mac, DT_UNSIGNED),
		STRUCT_MEMBER(tpacket_auxdata, tp, net, DT_UNSIGNED),
		STRUCT_MEMBER(tpacket_auxdata, tp, vlan_tci, DT_UNSIGNED),
		STRUCT_MEMBER(tpacket_auxdata, tp, vlan_tpid, DT_UNSIGNED),
		{ 0 }
	}
};

struct fanout_args_local {
#if __BYTE_ORDER == __LITTLE_ENDIAN
	uint16_t id;
	uint16_t type_flags;
#else
	uint16_t type_flags;
	uint16_t id;
#endif
	uint32_t max_num_members;
};

static struct_t st_fanout_args = {
	.size = sizeof(struct fanout_args_local),
	.members = (member_t []){
		STRUCT_MEMBER_NP(fanout_args_local, id, DT_UNSIGNED),
		STRUCT_MEMBER_NP(fanout_args_local, type_flags, DT_UNSIGNED),
		STRUCT_MEMBER_NP(fanout_args_local, max_num_members, DT_UNSIGNED),
		{ 0 }
	}
};

struct timeval_old_local {
	long tv_sec;
#if defined(__sparc__) && defined(__arch64__)
	int tv_usec;
#else
	long tv_usec;
#endif
};

static struct_t st_timeval_old = {
	.size = sizeof(struct timeval_old_local),
	.members = (member_t []){
		STRUCT_MEMBER(timeval_old_local, tv, sec, DT_SIGNED),
		STRUCT_MEMBER(timeval_old_local, tv, usec, DT_SIGNED),
		{ 0 }
	}
};

# ifdef SO_TIMESTAMP_NEW
struct timeval_new_local { int64_t tv_sec; int64_t tv_usec; };
static struct_t st_timeval_new = {
	.size = sizeof(struct timeval_old_local),
	.members = (member_t []){
		STRUCT_MEMBER(timeval_new_local, tv, sec, DT_SIGNED),
		STRUCT_MEMBER(timeval_new_local, tv, usec, DT_SIGNED),
		{ 0 }
	}
};
# endif

struct timespec_old_local { long tv_sec; long tv_nsec; };
static struct_t st_timespec_old = {
	.size = sizeof(struct timespec_old_local),
	.members = (member_t []){
		STRUCT_MEMBER(timespec_old_local, tv, sec, DT_SIGNED),
		STRUCT_MEMBER(timespec_old_local, tv, nsec, DT_SIGNED),
		{ 0 }
	}
};

# ifdef SO_TIMESTAMPNS_NEW
struct timespec_new_local { long long tv_sec; long long tv_nsec; };
static struct_t st_timespec_new = {
	.size = sizeof(struct timespec_new_local),
	.members = (member_t []){
		STRUCT_MEMBER(timespec_new_local, tv, sec, DT_SIGNED),
		STRUCT_MEMBER(timespec_new_local, tv, nsec, DT_SIGNED),
		{ 0 }
	}
};
# endif
#endif

#define SV_VOID		(struct_t *)0
#define SV_INT		(struct_t *)1
#define SV_INT_RO	(struct_t *)2
#define SV_BOOL		(struct_t *)3
#define SV_STRING	(struct_t *)4
#define SV_IFNAME	(struct_t *)5

#define CV_INT		(struct_t *)0
#define CV_UINT		(struct_t *)1
#define CV_BE32		(struct_t *)2
#define CV_STRING	(struct_t *)3
#define CV_SOCKADDR	(struct_t *)4
#define CV_FDS		(struct_t *)5

static sockopt_t sockopts[] = {
    { SOL_SOCKET, SO_ACCEPTCONN, SV_BOOL },
    { SOL_SOCKET, SO_BROADCAST, SV_BOOL },
    { SOL_SOCKET, SO_DEBUG, SV_BOOL },
    { SOL_SOCKET, SO_ERROR, SV_INT_RO },
    { SOL_SOCKET, SO_DONTROUTE, SV_BOOL },
    { SOL_SOCKET, SO_KEEPALIVE, SV_BOOL },
    { SOL_SOCKET, SO_LINGER, &st_linger },
    { SOL_SOCKET, SO_OOBINLINE, SV_BOOL },
    { SOL_SOCKET, SO_RCVBUF, SV_INT },
    { SOL_SOCKET, SO_RCVLOWAT, SV_INT },
    { SOL_SOCKET, SO_RCVTIMEO, &st_timeval },
    { SOL_SOCKET, SO_REUSEADDR, SV_BOOL },
    { SOL_SOCKET, SO_REUSEPORT, SV_BOOL },
    { SOL_SOCKET, SO_SNDBUF, SV_INT },
    { SOL_SOCKET, SO_SNDLOWAT, SV_INT },
    { SOL_SOCKET, SO_SNDTIMEO, &st_timeval },
    { SOL_SOCKET, SO_TIMESTAMP, SV_BOOL },
    { SOL_SOCKET, SO_TYPE, SV_INT },
#if defined(__linux__)
    { SOL_SOCKET, SO_ATTACH_FILTER, &st_sock_fprog },
    { SOL_SOCKET, SO_ATTACH_BPF, SV_INT },
    { SOL_SOCKET, SO_ATTACH_REUSEPORT_CBPF, SV_STRING },
    { SOL_SOCKET, SO_ATTACH_REUSEPORT_EBPF, SV_INT },
    { SOL_SOCKET, SO_BINDTODEVICE, SV_STRING },
    { SOL_SOCKET, SO_DETACH_FILTER, SV_VOID },
    { SOL_SOCKET, SO_DETACH_BPF, SV_VOID },
    { SOL_SOCKET, SO_DOMAIN, SV_INT_RO },
    { SOL_SOCKET, SO_INCOMING_CPU, SV_INT },
    { SOL_SOCKET, SO_INCOMING_NAPI_ID, SV_INT_RO },
    { SOL_SOCKET, SO_LOCK_FILTER, SV_INT },
    { SOL_SOCKET, SO_MARK, SV_INT },
    { SOL_SOCKET, SO_PASSCRED, SV_BOOL },
    { SOL_SOCKET, SO_PASSSEC, SV_BOOL },
    { SOL_SOCKET, SO_PEEK_OFF, SV_INT },
    { SOL_SOCKET, SO_PEERCRED, &st_ucred },
    { SOL_SOCKET, SO_PEERSEC, SV_STRING },
    { SOL_SOCKET, SO_PRIORITY, SV_INT },
    { SOL_SOCKET, SO_PROTOCOL, SV_INT },
    { SOL_SOCKET, SO_RCVBUFFORCE, SV_INT },
    { SOL_SOCKET, SO_RXQ_OVFL, SV_BOOL },
    { SOL_SOCKET, SO_SNDBUFFORCE, SV_INT },
    { SOL_SOCKET, SO_TIMESTAMPNS, SV_BOOL },
    { SOL_SOCKET, SO_BUSY_POLL, SV_INT },
#endif

    { IPPROTO_IP, IP_ADD_MEMBERSHIP, &st_ip_mreqn },
    { IPPROTO_IP, IP_ADD_SOURCE_MEMBERSHIP, &st_ip_mreq_source },
    { IPPROTO_IP, IP_BLOCK_SOURCE, &st_ip_mreq_source },
    { IPPROTO_IP, IP_DROP_MEMBERSHIP, &st_ip_mreqn },
    { IPPROTO_IP, IP_DROP_SOURCE_MEMBERSHIP, &st_ip_mreq_source },
    { IPPROTO_IP, IP_HDRINCL, SV_BOOL },
    { IPPROTO_IP, IP_MULTICAST_IF, &st_ip_mreqn },
    { IPPROTO_IP, IP_MULTICAST_LOOP, SV_BOOL },
    { IPPROTO_IP, IP_MULTICAST_TTL, SV_INT },
    { IPPROTO_IP, IP_OPTIONS, SV_STRING },
    { IPPROTO_IP, IP_PKTINFO, SV_BOOL },
    { IPPROTO_IP, IP_RECVOPTS, SV_BOOL },
    { IPPROTO_IP, IP_RECVTOS, SV_BOOL },
    { IPPROTO_IP, IP_RECVTTL, SV_BOOL },
    { IPPROTO_IP, IP_RETOPTS, SV_BOOL },
    { IPPROTO_IP, IP_TOS, SV_INT },
    { IPPROTO_IP, IP_TTL, SV_INT },
    { IPPROTO_IP, IP_UNBLOCK_SOURCE, &st_ip_mreq_source },
#if defined(__linux__)
    { IPPROTO_IP, IP_MSFILTER, &st_ip_msfilter },
    { IPPROTO_IP, IP_BIND_ADDRESS_NO_PORT, SV_BOOL },
    { IPPROTO_IP, IP_FREEBIND, SV_BOOL },
    { IPPROTO_IP, IP_MTU, SV_INT },
    { IPPROTO_IP, IP_MTU_DISCOVER, SV_INT },
    { IPPROTO_IP, IP_MULTICAST_ALL, SV_BOOL },
    { IPPROTO_IP, IP_NODEFRAG, SV_BOOL },
    { IPPROTO_IP, IP_PASSSEC, SV_BOOL },
    { IPPROTO_IP, IP_RECVERR, SV_BOOL },
    { IPPROTO_IP, IP_RECVORIGDSTADDR, SV_BOOL },
    { IPPROTO_IP, IP_ROUTER_ALERT, SV_BOOL },
    { IPPROTO_IP, IP_TRANSPARENT, SV_BOOL },
#endif

	{ IPPROTO_IPV6, IPV6_FLOWINFO_SEND, SV_BOOL },
	{ IPPROTO_IPV6, IPV6_FLOWINFO, SV_BOOL },
	{ IPPROTO_IPV6, IPV6_FLOWLABEL_MGR, &st_in6_flowlabel_req },
	{ IPPROTO_IPV6, IPV6_MULTICAST_HOPS, SV_INT },
	{ IPPROTO_IPV6, IPV6_MULTICAST_IF, SV_IFNAME },
	{ IPPROTO_IPV6, IPV6_MULTICAST_LOOP, SV_BOOL },
	{ IPPROTO_IPV6, IPV6_RECVTCLASS, SV_BOOL },
	{ IPPROTO_IPV6, IPV6_TCLASS, SV_INT },
	{ IPPROTO_IPV6, IPV6_UNICAST_HOPS, SV_INT },
	{ IPPROTO_IPV6, IPV6_V6ONLY, SV_BOOL },
#if defined(__linux__)
	{ IPPROTO_IPV6, IPV6_ADD_MEMBERSHIP, &st_ipv6_mreq },
	{ IPPROTO_IPV6, IPV6_ADDR_PREFERENCES, SV_INT },
	{ IPPROTO_IPV6, IPV6_ADDRFORM, SV_INT },
	{ IPPROTO_IPV6, IPV6_AUTHHDR, SV_BOOL },
	{ IPPROTO_IPV6, IPV6_AUTOFLOWLABEL, SV_BOOL },
	{ IPPROTO_IPV6, IPV6_DONTFRAG, SV_BOOL },
	{ IPPROTO_IPV6, IPV6_DROP_MEMBERSHIP, &st_ipv6_mreq },
	{ IPPROTO_IPV6, IPV6_DSTOPTS, SV_STRING },
	{ IPPROTO_IPV6, IPV6_FREEBIND, SV_BOOL },
	{ IPPROTO_IPV6, IPV6_HOPLIMIT, SV_BOOL },
	{ IPPROTO_IPV6, IPV6_HOPOPTS, SV_STRING },
	{ IPPROTO_IPV6, IPV6_JOIN_ANYCAST, &st_ipv6_mreq },
	{ IPPROTO_IPV6, IPV6_LEAVE_ANYCAST, &st_ipv6_mreq },
	{ IPPROTO_IPV6, IPV6_MINHOPCOUNT, SV_INT },
	{ IPPROTO_IPV6, IPV6_MTU_DISCOVER, SV_INT },
	{ IPPROTO_IPV6, IPV6_MTU, SV_INT },
	{ IPPROTO_IPV6, IPV6_MULTICAST_ALL, SV_BOOL },
	{ IPPROTO_IPV6, IPV6_PKTINFO, &st_in6_pktinfo },
	{ IPPROTO_IPV6, IPV6_RECVDSTOPTS, SV_BOOL },
	{ IPPROTO_IPV6, IPV6_RECVERR, SV_BOOL },
	{ IPPROTO_IPV6, IPV6_RECVFRAGSIZE, SV_BOOL },
	{ IPPROTO_IPV6, IPV6_RECVHOPLIMIT, SV_BOOL },
	{ IPPROTO_IPV6, IPV6_RECVHOPOPTS, SV_BOOL },
	{ IPPROTO_IPV6, IPV6_RECVORIGDSTADDR, SV_BOOL },
	{ IPPROTO_IPV6, IPV6_RECVPATHMTU, SV_BOOL },
	{ IPPROTO_IPV6, IPV6_RECVPKTINFO, SV_BOOL },
	{ IPPROTO_IPV6, IPV6_RECVRTHDR, SV_BOOL },
	{ IPPROTO_IPV6, IPV6_ROUTER_ALERT_ISOLATE, SV_BOOL },
	{ IPPROTO_IPV6, IPV6_ROUTER_ALERT, SV_BOOL },
	{ IPPROTO_IPV6, IPV6_RTHDR, SV_STRING },
	{ IPPROTO_IPV6, IPV6_RTHDRDSTOPTS, SV_STRING },
	{ IPPROTO_IPV6, IPV6_TRANSPARENT, SV_BOOL },
	{ IPPROTO_IPV6, IPV6_UNICAST_IF, SV_IFNAME },
#endif

    { IPPROTO_TCP, TCP_KEEPCNT, SV_INT },
    { IPPROTO_TCP, TCP_KEEPINTVL, SV_INT },
    { IPPROTO_TCP, TCP_MAXSEG, SV_INT },
    { IPPROTO_TCP, TCP_NODELAY, SV_BOOL },
    { IPPROTO_TCP, TCP_FASTOPEN, SV_INT },
#if defined(__linux__)
    { IPPROTO_TCP, TCP_CONGESTION, SV_STRING },
    { IPPROTO_TCP, TCP_CORK, SV_BOOL },
    { IPPROTO_TCP, TCP_DEFER_ACCEPT, SV_INT },
	{ IPPROTO_TCP, TCP_INFO, &st_tcp_info },
    { IPPROTO_TCP, TCP_KEEPIDLE, SV_INT },
    { IPPROTO_TCP, TCP_LINGER2, SV_INT },
    { IPPROTO_TCP, TCP_QUICKACK, SV_BOOL },
    { IPPROTO_TCP, TCP_SYNCNT, SV_INT },
    { IPPROTO_TCP, TCP_USER_TIMEOUT, SV_INT },
    { IPPROTO_TCP, TCP_WINDOW_CLAMP, SV_INT },
    { IPPROTO_TCP, TCP_FASTOPEN_CONNECT, SV_INT },
#endif

#if defined(__linux__)
    { IPPROTO_UDP, UDP_CORK, SV_BOOL },
#endif

#if defined(__linux__)
	{ SOL_PACKET, PACKET_ADD_MEMBERSHIP, &st_packet_mreq },
	{ SOL_PACKET, PACKET_DROP_MEMBERSHIP, &st_packet_mreq },
	{ SOL_PACKET, PACKET_AUXDATA, SV_BOOL },
	{ SOL_PACKET, PACKET_FANOUT, &st_fanout_args },
	{ SOL_PACKET, PACKET_LOSS, SV_BOOL },
	{ SOL_PACKET, PACKET_RESERVE, SV_INT },
	{ SOL_PACKET, PACKET_RX_RING, &st_tpacket_req },
	{ SOL_PACKET, PACKET_STATISTICS, &st_tpacket_stats },
	{ SOL_PACKET, PACKET_TIMESTAMP, SV_INT },
	{ SOL_PACKET, PACKET_TX_RING, &st_tpacket_req },
	{ SOL_PACKET, PACKET_VERSION, SV_INT },
	{ SOL_PACKET, PACKET_QDISC_BYPASS, SV_BOOL },
#endif
};

static cmsgtype_t cmsgtypes[] = {
#if defined(__linux__)
	{ SOL_PACKET, PACKET_AUXDATA, &st_tpacket_auxdata },

	{ SOL_SOCKET, SO_TIMESTAMP_OLD, &st_timeval_old },
# ifdef SO_TIMESTAMP_NEW
	{ SOL_SOCKET, SO_TIMESTAMP_NEW, &st_timeval_new },
# endif
	{ SOL_SOCKET, SO_TIMESTAMPNS_OLD, &st_timespec_old },
# ifdef SO_TIMESTAMPNS_NEW
	{ SOL_SOCKET, SO_TIMESTAMPNS_NEW, &st_timespec_new },
# endif

	{ SOL_SOCKET, SCM_CREDENTIALS, &st_ucred },
	{ SOL_SOCKET, SCM_RIGHTS, CV_FDS },
#endif

	{ IPPROTO_IP, IP_RECVOPTS, SV_STRING },
	{ IPPROTO_IP, IP_RETOPTS, SV_STRING },
	{ IPPROTO_IP, IP_TOS, CV_INT },
	{ IPPROTO_IP, IP_TTL, CV_INT },
#if defined(__linux__)
	{ IPPROTO_IP, IP_CHECKSUM, CV_UINT },
	{ IPPROTO_IP, IP_ORIGDSTADDR, CV_SOCKADDR },
	{ IPPROTO_IP, IP_RECVERR, &st_ip_recv_error },
	{ IPPROTO_IP, IP_RECVFRAGSIZE, CV_INT },
#endif

	{ IPPROTO_IPV6, IPV6_TCLASS, CV_INT },
	{ IPPROTO_IPV6, IPV6_FLOWINFO, CV_BE32 },
#if defined(__linux__)
	{ IPPROTO_IPV6, IPV6_DSTOPTS, CV_STRING },
	{ IPPROTO_IPV6, IPV6_HOPLIMIT, CV_INT },
	{ IPPROTO_IPV6, IPV6_HOPOPTS, CV_STRING },
	{ IPPROTO_IPV6, IPV6_ORIGDSTADDR, CV_SOCKADDR },
	{ IPPROTO_IPV6, IPV6_PATHMTU, &st_ip6_mtuinfo },
	{ IPPROTO_IPV6, IPV6_PKTINFO, &st_in6_pktinfo },
	{ IPPROTO_IPV6, IPV6_RECVERR, &st_ip_recv_error },
	{ IPPROTO_IPV6, IPV6_RECVFRAGSIZE, CV_INT },
	{ IPPROTO_IPV6, IPV6_RTHDR, CV_STRING },

	{ IPPROTO_TCP, TCP_CM_INQ, CV_INT },
	{ IPPROTO_UDP, UDP_GRO, CV_INT },
#endif
};


static char *
uv_to_struct(uc_value_t *uv, struct_t *spec)
{
	uc_value_t *fv;
	const char *s;
	uint64_t u64;
	int64_t s64;
	member_t *m;
	bool found;
	char *st;

	union {
		int8_t s8;
		int16_t s16;
		int32_t s32;
		int64_t s64;
		uint8_t u8;
		uint16_t u16;
		uint32_t u32;
		uint64_t u64;
	} v;

	st = xalloc(spec->size);

	for (size_t i = 0; spec->members[i].name; i++) {
		m = &spec->members[i];
		fv = ucv_object_get(uv, m->name, &found);

		if (!found || !fv)
			continue;

		switch (spec->members[i].type) {
		case DT_UNSIGNED:
			u64 = ucv_to_unsigned(fv);

			if (errno) {
				free(st);
				err_return(errno,
					"Unable to convert field %s to unsigned",
					m->name);
			}

			switch (m->u2.size) {
			case 1:  v.u8 =  (uint8_t)u64; break;
			case 2: v.u16 = (uint16_t)u64; break;
			case 4: v.u32 = (uint32_t)u64; break;
			case 8: v.u64 = (uint64_t)u64; break;
			}

			memcpy(st + m->u1.offset, &v, m->u2.size);
			break;

		case DT_SIGNED:
			s64 = ucv_to_integer(fv);

			if (errno) {
				free(st);
				err_return(errno,
					"Unable to convert field %s to integer", m->name);
			}

			switch (m->u2.size) {
			case 1:  v.s8 =  (int8_t)s64; break;
			case 2: v.s16 = (int16_t)s64; break;
			case 4: v.s32 = (int32_t)s64; break;
			case 8: v.s64 = (int64_t)s64; break;
			}

			memcpy(st + m->u1.offset, &v, m->u2.size);
			break;

		case DT_IPV4ADDR:
			s = ucv_string_get(fv);

			if (!s || inet_pton(AF_INET, s, st + m->u1.offset) != 1) {
				free(st);
				err_return(EINVAL,
					"Unable to convert field %s to IP address", m->name);
			}

			break;

		case DT_IPV6ADDR:
			s = ucv_string_get(fv);

			if (!s || inet_pton(AF_INET6, s, st + m->u1.offset) != 1) {
				free(st);
				err_return(EINVAL,
					"Unable to convert field %s to IPv6 address", m->name);
			}

			break;

		case DT_CALLBACK:
			if (m->u1.to_c && !m->u1.to_c(&st, fv)) {
				free(st);
				return NULL;
			}

			break;
		}
	}

	return st;
}

static uc_value_t *
struct_to_uv(char *st, struct_t *spec)
{
	char s[sizeof("ffff:ffff:ffff:ffff:ffff:ffff:255.255.255.255")];
	uc_value_t *uv, *fv;
	member_t *m;

	uv = ucv_object_new(NULL);

	for (size_t i = 0; spec->members[i].name; i++) {
		m = &spec->members[i];
		fv = NULL;

		switch (spec->members[i].type) {
		case DT_UNSIGNED:
			switch (spec->members[i].u2.size) {
			case 1:
				fv = ucv_uint64_new(*(uint8_t *)(st + m->u1.offset));
				break;

			case 2:
				fv = ucv_uint64_new(*(uint16_t *)(st + m->u1.offset));
				break;

			case 4:
				fv = ucv_uint64_new(*(uint32_t *)(st + m->u1.offset));
				break;

			case 8:
				fv = ucv_uint64_new(*(uint64_t *)(st + m->u1.offset));
				break;
			}

			break;

		case DT_SIGNED:
			switch (spec->members[i].u2.size) {
			case 1:
				fv = ucv_int64_new(*(int8_t *)(st + m->u1.offset));
				break;

			case 2:
				fv = ucv_int64_new(*(int16_t *)(st + m->u1.offset));
				break;

			case 4:
				fv = ucv_int64_new(*(int32_t *)(st + m->u1.offset));
				break;

			case 8:
				fv = ucv_int64_new(*(int64_t *)(st + m->u1.offset));
				break;
			}

			break;

		case DT_IPV4ADDR:
			if (inet_ntop(AF_INET, st + m->u1.offset, s, sizeof(s)))
				fv = ucv_string_new(s);

			break;

		case DT_IPV6ADDR:
			if (inet_ntop(AF_INET6, st + m->u1.offset, s, sizeof(s)))
				fv = ucv_string_new(s);

			break;

		case DT_CALLBACK:
			fv = m->u2.to_uv ? m->u2.to_uv(st) : NULL;
			break;
		}

		ucv_object_add(uv, m->name, fv);
	}

	return uv;
}

/**
 * Sets options on the socket.
 *
 * Sets the specified option on the socket to the given value.
 *
 * Returns `true` if the option was successfully set.
 *
 * Returns `null` if an error occurred.
 *
 * @function module:socket.socket#setopt
 *
 * @param {number} level
 * The protocol level at which the option resides. This can be a level such as
 * `SOL_SOCKET` for the socket API level or a specific protocol level defined
 * by the system.
 *
 * @param {number} option
 * The socket option to set. This can be an integer representing the option,
 * such as `SO_REUSEADDR`, or a constant defined by the system.
 *
 * @param {*} value
 * The value to set the option to. The type of this argument depends on the
 * specific option being set. It can be an integer, a boolean, a string, or a
 * dictionary representing the value to set. If a dictionary is provided, it is
 * internally translated to the corresponding C struct type required by the
 * option.
 *
 * @returns {?boolean}
 */
static uc_value_t *
uc_socket_inst_setopt(uc_vm_t *vm, size_t nargs)
{
	int sockfd, solvl, soopt, soval, ret;
	uc_value_t *level, *option, *value;
	void *valptr = NULL, *st = NULL;
	socklen_t vallen = 0;
	size_t i;

	args_get(vm, nargs, &sockfd,
		"level", UC_INTEGER, false, &level,
		"option", UC_INTEGER, false, &option,
		"value", UC_NULL, false, &value);

	solvl = ucv_int64_get(level);
	soopt = ucv_int64_get(option);

	for (i = 0; i < ARRAY_SIZE(sockopts); i++) {
		if (sockopts[i].level != solvl || sockopts[i].option != soopt)
			continue;

		switch ((uintptr_t)sockopts[i].ctype) {
		case (uintptr_t)SV_INT_RO:
			err_return(EOPNOTSUPP, "Socket option is read only");

		case (uintptr_t)SV_VOID:
			valptr = NULL;
			vallen = 0;
			break;

		case (uintptr_t)SV_INT:
			soval = ucv_to_integer(value);

			if (errno)
				err_return(errno, "Unable to convert value to integer");

			valptr = &soval;
			vallen = sizeof(int);
			break;

		case (uintptr_t)SV_BOOL:
			soval = ucv_to_unsigned(value) ? 1 : 0;

			if (errno)
				err_return(errno, "Unable to convert value to boolean");

			valptr = &soval;
			vallen = sizeof(int);
			break;

		case (uintptr_t)SV_STRING:
			valptr = ucv_string_get(value);
			vallen = ucv_string_length(value);
			break;

		case (uintptr_t)SV_IFNAME:
			if (ucv_type(value) == UC_STRING) {
				soval = if_nametoindex(ucv_string_get(value));

				if (soval <= 0)
					err_return(errno, "Unable to resolve interface %s",
						ucv_string_get(value));
			}
			else {
				soval = ucv_to_integer(value);

				if (errno)
					err_return(errno, "Unable to convert value to integer");
			}

			valptr = &soval;
			vallen = sizeof(int);
			break;

		default:
			st = uv_to_struct(value, sockopts[i].ctype);
			valptr = st;
			vallen = sockopts[i].ctype->size;
			break;
		}

		break;
	}

	if (i == ARRAY_SIZE(sockopts))
		err_return(EINVAL, "Unknown socket level or option");

	ret = setsockopt(sockfd, solvl, soopt, valptr, vallen);

	free(st);

	if (ret == -1)
		err_return(errno, "setsockopt()");

	ok_return(ucv_boolean_new(true));
}

/**
 * Gets options from the socket.
 *
 * Retrieves the value of the specified option from the socket.
 *
 * Returns the value of the requested option.
 *
 * Returns `null` if an error occurred or if the option is not supported.
 *
 * @function module:socket.socket#getopt
 *
 * @param {number} level
 * The protocol level at which the option resides. This can be a level such as
 * `SOL_SOCKET` for the socket API level or a specific protocol level defined
 * by the system.
 *
 * @param {number} option
 * The socket option to retrieve. This can be an integer representing the
 * option, such as `SO_REUSEADDR`, or a constant defined by the system.
 *
 * @returns {?*}
 * The value of the requested option. The type of the returned value depends
 * on the specific option being retrieved. It can be an integer, a boolean, a
 * string, or a dictionary representing a complex data structure.
 */
static uc_value_t *
uc_socket_inst_getopt(uc_vm_t *vm, size_t nargs)
{
	uc_value_t *level, *option, *value = NULL;
	char ival[sizeof(int64_t)] = { 0 };
	void *valptr = NULL, *st = NULL;
	int sockfd, solvl, soopt, ret;
	uc_stringbuf_t *sb = NULL;
	socklen_t vallen;
	size_t i;

	args_get(vm, nargs, &sockfd,
		"level", UC_INTEGER, false, &level,
		"option", UC_INTEGER, false, &option);

	solvl = ucv_int64_get(level);
	soopt = ucv_int64_get(option);

	for (i = 0; i < ARRAY_SIZE(sockopts); i++) {
		if (sockopts[i].level != solvl || sockopts[i].option != soopt)
			continue;

		switch ((uintptr_t)sockopts[i].ctype) {
		case (uintptr_t)SV_VOID:
			err_return(EOPNOTSUPP, "Socket option is write only");

		case (uintptr_t)SV_INT:
		case (uintptr_t)SV_INT_RO:
		case (uintptr_t)SV_BOOL:
		case (uintptr_t)SV_IFNAME:
			valptr = ival;
			vallen = sizeof(ival);
			break;

		case (uintptr_t)SV_STRING:
			sb = strbuf_alloc(64);
			valptr = strbuf_data(sb);
			vallen = strbuf_size(sb);
			break;

		default:
			st = xalloc(sockopts[i].ctype->size);
			valptr = st;
			vallen = sockopts[i].ctype->size;
			break;
		}

		break;
	}

	if (i == ARRAY_SIZE(sockopts))
		err_return(EINVAL, "Unknown socket level or option");

	while (true) {
		ret = getsockopt(sockfd, solvl, soopt, valptr, &vallen);

		if (sockopts[i].ctype == SV_STRING &&
		    (ret == 0 || (ret == -1 && errno == ERANGE)) &&
		    vallen > strbuf_size(sb)) {

			if (!strbuf_grow(sb, vallen))
				return NULL;

			valptr = strbuf_data(sb);
			continue;
		}

		break;
	}

	if (ret == 0) {
		char ifname[IF_NAMESIZE];
		int ifidx;

		switch ((uintptr_t)sockopts[i].ctype) {
		case (uintptr_t)SV_VOID:
			break;

		case (uintptr_t)SV_INT:
		case (uintptr_t)SV_INT_RO:
			value = ucv_int64_new(parse_integer(ival, vallen));
			break;

		case (uintptr_t)SV_BOOL:
			value = ucv_boolean_new(parse_integer(ival, vallen) != 0);
			break;

		case (uintptr_t)SV_STRING:
			value = strbuf_finish(&sb, vallen);
			break;

		case (uintptr_t)SV_IFNAME:
			ifidx = parse_integer(ival, vallen);
			if (if_indextoname(ifidx, ifname))
				value = ucv_string_new(ifname);
			else
				value = ucv_int64_new(ifidx);
			break;

		default:
			value = struct_to_uv(st, sockopts[i].ctype);
			break;
		}
	}

	strbuf_free(sb);
	free(st);

	if (ret == -1)
		err_return(errno, "getsockopt()");

	ok_return(value);
}

/**
 * Returns the UNIX file descriptor number associated with the socket.
 *
 * Returns the file descriptor number.
 *
 * Returns `-1` if an error occurred.
 *
 * @function module:socket.socket#fileno
 *
 * @returns {number}
 */
static uc_value_t *
uc_socket_inst_fileno(uc_vm_t *vm, size_t nargs)
{
	int sockfd;

	args_get(vm, nargs, &sockfd);

	ok_return(ucv_int64_new(sockfd));
}

/**
 * Query error information.
 *
 * Returns a string containing a description of the last occurred error when
 * the *numeric* argument is absent or false.
 *
 * Returns a positive (`errno`) or negative (`EAI_*` constant) error code number
 * when the *numeric* argument is `true`.
 *
 * Returns `null` if there is no error information.
 *
 * @function module:socket#error
 *
 * @param {boolean} [numeric]
 * Whether to return a numeric error code (`true`) or a human readable error
 * message (false).
 *
 * @returns {?string|?number}
 *
 * @example
 * // Trigger socket error by attempting to bind IPv6 address with IPv4 socket
 * socket.create(socket.AF_INET, socket.SOCK_STREAM, 0).bind("::", 8080);
 *
 * // Print error (should yield "Address family not supported by protocol")
 * print(socket.error(), "\n");
 *
 * // Trigger resolve error
 * socket.addrinfo("doesnotexist.org");
 *
 * // Query error code (should yield -2 for EAI_NONAME)
 * print(socket.error(true), "\n");  //
 */
static uc_value_t *
uc_socket_error(uc_vm_t *vm, size_t nargs)
{
	uc_value_t *numeric = uc_fn_arg(0), *rv;
	uc_stringbuf_t *buf;

	if (last_error.code == 0)
		return NULL;

	if (ucv_is_truish(numeric)) {
		rv = ucv_int64_new(last_error.code);
	}
	else {
		buf = ucv_stringbuf_new();

		if (last_error.msg)
			ucv_stringbuf_printf(buf, "%s: ", last_error.msg);

		if (last_error.code >= 0)
			ucv_stringbuf_printf(buf, "%s", strerror(last_error.code));
		else
			ucv_stringbuf_printf(buf, "%s", gai_strerror(last_error.code));

		rv = ucv_stringbuf_finish(buf);
	}

	return rv;
}

/**
 * Returns a string containing a description of the positive (`errno`) or
 * negative (`EAI_*` constant) error code number given by the *code* argument.
 *
 * Returns `null` if the error code number is unknown.
 *
 * @function module:socket#strerror
 *
 * @param {number} code
 * The error code.
 *
 * @returns {?string}
 *
 * @example
 * // Should output 'Name or service not known'.
 * print(socket.strerror(-2), '\n');
 *
 * // Should output 'No route to host'.
 * print(socket.strerror(113), '\n');
 */
static uc_value_t *
uc_socket_strerror(uc_vm_t *vm, size_t nargs)
{
	uc_value_t *codearg, *rv;
	int code;

	args_get(vm, nargs, NULL,
		"code", UC_INTEGER, false, &codearg);

	code = ucv_to_integer(codearg);

	if (code < 0)
		rv = ucv_string_new( gai_strerror(code) );
	else
		rv = ucv_string_new( strerror(code) );

	return rv;
}

/**
 * @typedef {Object} module:socket.socket.SocketAddress
 * @property {number} family
 * Address family, one of AF_INET, AF_INET6, AF_UNIX or AF_PACKET.
 *
 * @property {string} address
 * IPv4/IPv6 address string (AF_INET or AF_INET6 only) or hardware address in
 * hexadecimal notation (AF_PACKET only).
 *
 * @property {number} [port]
 * Port number (AF_INET or AF_INET6 only).
 *
 * @property {number} [flowinfo]
 * IPv6 flow information (AF_INET6 only).
 *
 * @property {string|number} [interface]
 * Link local address scope (for IPv6 sockets) or bound network interface
 * (for packet sockets), either a network device name string or a nonzero
 * positive integer representing a network interface index (AF_INET6 and
 * AF_PACKET only).
 *
 * @property {string} path
 * Domain socket filesystem path (AF_UNIX only).
 *
 * @property {number} [protocol=0]
 * Physical layer protocol (AF_PACKET only).
 *
 * @property {number} [hardware_type=0]
 * ARP hardware type (AF_PACKET only).
 *
 * @property {number} [packet_type=PACKET_HOST]
 * Packet type (AF_PACKET only).
 */

/**
 * Parses the provided address value into a socket address representation.
 *
 * This function parses the given address value into a socket address
 * representation required for a number of socket operations. The address value
 * can be provided in various formats:
 * - For IPv4 addresses, it can be a string representing the IP address,
 *   optionally followed by a port number separated by colon, e.g.
 *   `192.168.0.1:8080`.
 * - For IPv6 addresses, it must be an address string enclosed in square
 *   brackets if a port number is specified, otherwise the brackets are
 *   optional. The address string may also include a scope ID in the form
 *   `%ifname` or `%number`, e.g. `[fe80::1%eth0]:8080` or `fe80::1%15`.
 * - Any string value containing a slash is treated as UNIX domain socket path.
 * - Alternatively, it can be provided as an array returned by
 *   {@link module:core#iptoarr|iptoarr()}, representing the address octets.
 * - It can also be an object representing a network address, with properties
 *   for `address` (the IP address) and `port` or a single property `path` to
 *   denote a UNIX domain socket address.
 *
 * @function module:socket#sockaddr
 *
 * @param {string|number[]|module:socket.socket.SocketAddress} address
 * The address value to parse.
 *
 * @returns {?module:socket.socket.SocketAddress}
 * A socket address representation of the provided address value, or `null` if
 * the address could not be parsed.
 *
 * @example
 * // Parse an IP address string with port
 * const address1 = sockaddr('192.168.0.1:8080');
 *
 * // Parse an IPv6 address string with port and scope identifier
 * const address2 = sockaddr('[fe80::1%eth0]:8080');
 *
 * // Parse an array representing an IP address
 * const address3 = sockaddr([192, 168, 0, 1]);
 *
 * // Parse a network address object
 * const address4 = sockaddr({ address: '192.168.0.1', port: 8080 });
 *
 * // Convert a path value to a UNIX domain socket address
 * const address5 = sockaddr('/var/run/daemon.sock');
 */
static uc_value_t *
uc_socket_sockaddr(uc_vm_t *vm, size_t nargs)
{
	struct sockaddr_storage ss = { 0 };
	uc_value_t *addr, *rv;
	socklen_t slen;

	args_get(vm, nargs, NULL,
		"address", UC_NULL, false, &addr);

	if (!uv_to_sockaddr(addr, &ss, &slen))
		return NULL;

	rv = ucv_object_new(vm);

	if (!sockaddr_to_uv(&ss, rv)) {
		ucv_put(rv);
		return NULL;
	}

	ok_return(rv);
}

/**
 * Resolves the given network address into hostname and service name.
 *
 * The `nameinfo()` function provides an API for reverse DNS lookup and service
 * name resolution. It returns an object containing the following properties:
 * - `hostname`: The resolved hostname.
 * - `service`: The resolved service name.
 *
 * Returns an object representing the resolved hostname and service name.
 * Return `null` if an error occurred during resolution.
 *
 * @function module:socket#nameinfo
 *
 * @param {string|module:socket.socket.SocketAddress} address
 * The network address to resolve. It can be specified as:
 * - A string representing the IP address.
 * - An object representing the address with properties `address` and `port`.
 *
 * @param {number} [flags]
 * Optional flags that provide additional control over the resolution process,
 * specified as bitwise OR-ed number of `NI_*` constants.
 *
 * @returns {?{hostname: string, service: string}}
 *
 * @see {@link module:socket~"Socket Types"|Socket Types}
 * @see {@link module:socket~"Name Info Constants"|AName Info Constants}
 *
 * @example
 * // Resolve a network address into hostname and service name
 * const result = network.getnameinfo('192.168.1.1:80');
 * print(result); // { "hostname": "example.com", "service": "http" }
 */
static uc_value_t *
uc_socket_nameinfo(uc_vm_t *vm, size_t nargs)
{
	char host[NI_MAXHOST], serv[NI_MAXSERV];
	uc_value_t *addr, *flags, *rv;
	struct sockaddr_storage ss;
	socklen_t slen;
	int ret;

	args_get(vm, nargs, NULL,
		"address", UC_NULL, false, &addr,
		"flags", UC_INTEGER, true, &flags);

	if (!uv_to_sockaddr(addr, &ss, &slen))
		return NULL;

	ret = getnameinfo((struct sockaddr *)&ss, slen,
		host, sizeof(host), serv, sizeof(serv),
		flags ? ucv_int64_get(flags) : 0);

	if (ret != 0)
		err_return((ret == EAI_SYSTEM) ? errno : ret, "getnameinfo()");

	rv = ucv_object_new(vm);

	ucv_object_add(rv, "hostname", ucv_string_new(host));
	ucv_object_add(rv, "service", ucv_string_new(serv));

	ok_return(rv);
}

/**
 * Resolves the given hostname and optional service name into a list of network
 * addresses, according to the provided hints.
 *
 * The `addrinfo()` function provides an API for performing DNS and service name
 * resolution. It returns an array of objects, each representing a resolved
 * address.
 *
 * Returns an array of resolved addresses.
 * Returns `null` if an error occurred during resolution.
 *
 * @function module:socket#addrinfo
 *
 * @param {string} hostname
 * The hostname to resolve.
 *
 * @param {string} [service]
 * Optional service name to resolve. If not provided, the service field of the
 * resulting address information structures is left uninitialized.
 *
 * @param {Object} [hints]
 * Optional hints object that provides additional control over the resolution
 * process. It can contain the following properties:
 * - `family`: The preferred address family (`AF_INET` or `AF_INET6`).
 * - `socktype`: The socket type (`SOCK_STREAM`, `SOCK_DGRAM`, etc.).
 * - `protocol`: The protocol of returned addresses.
 * - `flags`: Bitwise OR-ed `AI_*` flags to control the resolution behavior.
 *
 * @returns {?module:socket.AddressInfo[]}
 *
 * @see {@link module:socket~"Socket Types"|Socket Types}
 * @see {@link module:socket~"Address Info Flags"|Address Info Flags}
 *
 * @example
 * // Resolve all addresses
 * const addresses = socket.addrinfo('example.org');
 *
 * // Resolve IPv4 addresses for a given hostname and service
 * const ipv4addresses = socket.addrinfo('example.com', 'http', { family: socket.AF_INET });
 *
 * // Resolve IPv6 addresses without specifying a service
 * const ipv6Addresses = socket.addrinfo('example.com', null, { family: socket.AF_INET6 });
 */

static uc_value_t *
uc_socket_addrinfo(uc_vm_t *vm, size_t nargs)
{
	struct addrinfo *ai_hints = NULL, *ai_res;
	uc_value_t *host, *serv, *hints, *rv;
	char *servstr;
	int ret;

	args_get(vm, nargs, NULL,
		"hostname", UC_STRING, false, &host,
		"service", UC_NULL, true, &serv,
		"hints", UC_OBJECT, true, &hints);

	if (hints) {
		ai_hints = (struct addrinfo *)uv_to_struct(hints, &st_addrinfo);

		if (!ai_hints)
			return NULL;
	}

	servstr = (serv && ucv_type(serv) != UC_STRING) ? ucv_to_string(vm, serv) : NULL;
	ret = getaddrinfo(ucv_string_get(host),
		servstr ? servstr : ucv_string_get(serv),
		ai_hints, &ai_res);

	free(ai_hints);
	free(servstr);

	if (ret != 0)
		err_return((ret == EAI_SYSTEM) ? errno : ret, "getaddrinfo()");

	rv = ucv_array_new(vm);

	for (struct addrinfo *ai = ai_res; ai; ai = ai->ai_next) {
		uc_value_t *item = struct_to_uv((char *)ai, &st_addrinfo);

		if (item)
			ucv_array_push(rv, item);
	}

	freeaddrinfo(ai_res);

	ok_return(rv);
}

/**
 * Represents a poll state serving as input parameter and return value type for
 * {@link module:socket#poll|`poll()`}.
 *
 * @typedef {Array} module:socket.PollSpec
 * @property {module:socket.socket} 0
 * The polled socket instance.
 *
 * @property {number} 1
 * Requested or returned status flags of the polled socket instance.
 */

/**
 * Polls a number of sockets for state changes.
 *
 * Returns an array of `[socket, flags]` tuples for each socket with pending
 * events. When a tuple is passed as socket argument, it is included as-is into
 * the result tuple array, with the flags entry changed to a bitwise OR-ed value
 * describing the pending events for this socket. When a plain socket instance
 * (or another kind of handle) is passed, a new tuple array is created for this
 * socket within the result tuple array, containing this socket as first and the
 * bitwise OR-ed pending events as second element.
 *
 * Returns `null` if an error occurred.
 *
 * @function module:socket#poll
 *
 * @param {number} timeout
 * Amount of milliseconds to wait for socket activity before aborting the poll
 * call. If set to `0`, the poll call will return immediately if none of the
 * provided sockets has pending events, if set to a negative value, the poll
 * call will wait indefinitely, in all other cases the poll call will wait at
 * most for the given amount of milliseconds before returning.
 *
 * @param {...(module:socket.socket|module:socket.PollSpec)} sockets
 * An arbitrary amount of socket arguments. Each argument may be either a plain
 * {@link module:socket.socket|socket instance} (or any other kind of handle
 * implementing a `fileno()` method) or a `[socket, flags]` tuple specifying the
 * socket and requested poll flags. If a plain socket (or other kind of handle)
 * instead of a tuple is provided, the requested poll flags default to
 * `POLLIN|POLLERR|POLLHUP` for this socket.
 *
 * @returns {module:socket.PollSpec[]}
 *
 * @example
 * let x = socket.connect("example.org", 80);
 * let y = socket.connect("example.com", 80);
 *
 * // Pass plain socket arguments
 * let events = socket.poll(10, x, y);
 * print(events); // [ [ "<socket 0x7>", 0 ], [ "<socket 0x8>", 0 ] ]
 *
 * // Passing tuples allows attaching state information and requesting
 * // different I/O events
 * let events = socket.poll(10,
 * 	[ x, socket.POLLOUT | socket.POLLHUP, "This is example.org" ],
 * 	[ y, socket.POLLOUT | socket.POLLHUP, "This is example.com" ]
 * );
 * print(events); // [ [ "<socket 0x7>", 4, "This is example.org" ],
 *                //   [ "<socket 0x8>", 4, "This is example.com" ] ]
 */
static uc_value_t *
uc_socket_poll(uc_vm_t *vm, size_t nargs)
{
	struct { struct pollfd *entries; size_t count; } pfds = { 0 };
	uc_value_t *timeoutarg, *rv, *item;
	int64_t timeout;
	int ret;

	args_get(vm, nargs, NULL, "timeout", UC_INTEGER, false, &timeoutarg);

	timeout = ucv_to_integer(timeoutarg);

	if (errno != 0 || timeout < (int64_t)INT_MIN || timeout > (int64_t)INT_MAX)
		err_return(ERANGE, "Invalid timeout value");

	rv = ucv_array_new(vm);

	for (size_t i = 1; i < nargs; i++) {
		uc_vector_grow(&pfds);
		item = uv_to_pollfd(vm, uc_fn_arg(i), &pfds.entries[pfds.count]);

		if (item)
			ucv_array_set(rv, pfds.count++, item);
	}

	ret = poll(pfds.entries, pfds.count, timeout);

	if (ret == -1) {
		ucv_put(rv);
		uc_vector_clear(&pfds);
		err_return(errno, "poll()");
	}

	for (size_t i = 0; i < pfds.count; i++)
		ucv_array_set(ucv_array_get(rv, i), 1,
			ucv_int64_new(pfds.entries[i].revents));

	uc_vector_clear(&pfds);
	ok_return(rv);
}

static bool
should_resolve(uc_value_t *host)
{
	char *s = ucv_string_get(host);

	return (s != NULL && memchr(s, '/', ucv_string_length(host)) == NULL);
}

/**
 * Creates a network socket and connects it to the specified host and service.
 *
 * This high level function combines the functionality of
 * {@link module:socket#create|create()},
 * {@link module:socket#addrinfo|addrinfo()} and
 * {@link module:socket.socket#connect|connect()} to simplify connection
 * establishment with the socket module.
 *
 * @function module:socket#connect
 *
 * @param {string|number[]|module:socket.socket.SocketAddress} host
 * The host to connect to, can be an IP address, hostname,
 * {@link module:socket.socket.SocketAddress|SocketAddress}, or an array value
 * returned by {@link module:core#iptoarr|iptoarr()}.
 *
 * @param {string|number} [service]
 * The service to connect to, can be a symbolic service name (such as "http") or
 * a port number. Optional if host is specified as
 * {@link module:socket.socket.SocketAddress|SocketAddress}.
 *
 * @param {Object} [hints]
 * Optional preferences for the socket. It can contain the following properties:
 * - `family`: The preferred address family (`AF_INET` or `AF_INET6`).
 * - `socktype`: The socket type (`SOCK_STREAM`, `SOCK_DGRAM`, etc.).
 * - `protocol`: The protocol of the created socket.
 * - `flags`: Bitwise OR-ed `AI_*` flags to control the resolution behavior.
 *
 * If no hints are not provided, the default socket type preference is set to
 * `SOCK_STREAM`.
 *
 * @param {number} [timeout=-1]
 * The timeout in milliseconds for socket connect operations. If set to a
 * negative value, no specifc time limit is imposed and the function will
 * block until either a connection was successfull or the underlying operating
 * system timeout is reached.
 *
 * @returns {module:socket.socket}
 *
 * @example
 * // Resolve host, try to connect to both resulting IPv4 and IPv6 addresses
 * let conn = socket.connect("example.org", 80);
 *
 * // Enforce usage of IPv6
 * let conn = socket.connect("example.com", 80, { family: socket.AF_INET6 });
 *
 * // Connect a UDP socket
 * let conn = socket.connect("192.168.1.1", 53, { socktype: socket.SOCK_DGRAM });
 *
 * // Bypass name resolution by specifying a SocketAddress structure
 * let conn = socket.connect({ address: "127.0.0.1", port: 9000 });
 *
 * // Use SocketAddress structure to connect a UNIX domain socket
 * let conn = socket.connect({ path: "/var/run/daemon.sock" });
 */
static uc_value_t *
uc_socket_connect(uc_vm_t *vm, size_t nargs)
{
	struct address {
		struct sockaddr_storage ss;
		struct addrinfo ai;
		int flags;
		int fd;
	} *ap;

	struct { struct address *entries; size_t count; } addresses = { 0 };
	struct { struct pollfd *entries; size_t count; } pollfds = { 0 };
	struct addrinfo *ai_results, *ai_hints, *ai;
	uc_value_t *host, *serv, *hints, *timeout;
	const char *errmsg = NULL;
	struct pollfd *pp = NULL;
	size_t slot, connected;
	int ret, err;

	args_get(vm, nargs, NULL,
		"host", UC_NULL, false, &host,
		"service", UC_NULL, true, &serv,
		"hints", UC_OBJECT, true, &hints,
		"timeout", UC_INTEGER, true, &timeout);

	ai_hints = hints
		? (struct addrinfo *)uv_to_struct(hints, &st_addrinfo) : NULL;

	if (should_resolve(host)) {
		char *servstr = (ucv_type(serv) != UC_STRING)
			? ucv_to_string(vm, serv) : NULL;

		ret = getaddrinfo(ucv_string_get(host),
			servstr ? servstr : ucv_string_get(serv),
			ai_hints ? ai_hints : &(struct addrinfo){
				.ai_socktype = SOCK_STREAM
			}, &ai_results);

		if (ret != 0) {
			free(servstr);
			free(ai_hints);
			err_return((ret == EAI_SYSTEM) ? errno : ret,
				"getaddrinfo()");
		}

		for (ai = ai_results; ai != NULL; ai = ai->ai_next) {
			if (ai->ai_family != AF_INET && ai->ai_family != AF_INET6)
				continue;

			uc_vector_grow(&addresses);
			ap = &addresses.entries[addresses.count++];
			memcpy(&ap->ss, ai->ai_addr, ai->ai_addrlen);
			memcpy(&ap->ai, ai, sizeof(*ai));
			ap->ai.ai_addr = (struct sockaddr *)&ap->ss;
		}

		freeaddrinfo(ai_results);
		free(servstr);
	}
	else {
		uc_vector_grow(&addresses);
		ap = &addresses.entries[addresses.count++];

		if (!uv_to_sockaddr(host, &ap->ss, &ap->ai.ai_addrlen)) {
			free(ai_hints);
			uc_vector_clear(&addresses);
			return NULL;
		}

		if (serv) {
			uint64_t port = ucv_to_unsigned(serv);

			if (port > 65535)
				errno = ERANGE;

			if (errno != 0) {
				free(ai_hints);
				uc_vector_clear(&addresses);
				err_return(errno, "Invalid port number");
			}

			((struct sockaddr_in *)&ap->ss)->sin_port = htons(port);
		}

		ap->ai.ai_addr = (struct sockaddr *)&ap->ss;
		ap->ai.ai_family = ap->ss.ss_family;
		ap->ai.ai_socktype = ai_hints ? ai_hints->ai_socktype : SOCK_STREAM;
		ap->ai.ai_protocol = ai_hints ? ai_hints->ai_protocol : 0;
	}

	free(ai_hints);

	for (connected = 0, slot = 0, ap = &addresses.entries[slot];
	     slot < addresses.count;
	     slot++, ap = &addresses.entries[slot])
	{
		uc_vector_grow(&pollfds);
		pp = &pollfds.entries[pollfds.count++];
		pp->events = POLLIN | POLLOUT | POLLHUP | POLLERR;
		pp->fd = socket(ap->ai.ai_family, ap->ai.ai_socktype, ap->ai.ai_protocol);

		if (pp->fd == -1)
			continue;

		if ((ap->flags = fcntl(pp->fd, F_GETFL, 0)) == -1) {
			xclose(&pp->fd);
			continue;
		}

		if (fcntl(pp->fd, F_SETFL, ap->flags | O_NONBLOCK) == -1) {
			xclose(&pp->fd);
			continue;
		}

		ret = connect(pp->fd, ap->ai.ai_addr, ap->ai.ai_addrlen);

		if (ret == -1 && errno != EINPROGRESS) {
			xclose(&pp->fd);
			continue;
		}

		connected++;
	}

	if (connected == 0) {
		err = EAI_NONAME;
		errmsg = "Could not connect to any host address";
		goto out;
	}

	ret = poll(pollfds.entries, pollfds.count,
		timeout ? ucv_int64_get(timeout) : -1);

	if (ret == -1) {
		err = errno;
		errmsg = "poll()";
		goto out;
	}

	err = 0;
	errmsg = NULL;

	for (slot = 0, ap = NULL, pp = NULL; slot < pollfds.count; slot++) {
		if (pollfds.entries[slot].revents & (POLLIN|POLLOUT)) {
			ret = getsockopt(pollfds.entries[slot].fd, SOL_SOCKET, SO_ERROR,
			                 &err, &(socklen_t){ sizeof(err) });

			if (ret == -1) {
				err = errno;
				errmsg = "getsockopt()";
				continue;
			}
			else if (err != 0) {
				errmsg = "connect()";
				continue;
			}

			ap = &addresses.entries[slot];
			pp = &pollfds.entries[slot];
			break;
		}
	}

	if (!ap) {
		if (!errmsg) {
			err = ETIMEDOUT;
			errmsg = "Connection timed out";
		}

		goto out;
	}

	if (fcntl(pp->fd, F_SETFL, ap->flags) == -1) {
		err = errno;
		errmsg = "fcntl(F_SETFL)";
		goto out;
	}

out:
	for (slot = 0, ret = -1; slot < pollfds.count; slot++) {
		if (pp == &pollfds.entries[slot])
			ret = pollfds.entries[slot].fd;
		else
			xclose(&pollfds.entries[slot].fd);
	}

	uc_vector_clear(&addresses);
	uc_vector_clear(&pollfds);

	if (errmsg)
		err_return(err, "%s", errmsg);

	ok_return(ucv_socket_new(vm, ret));
}

/**
 * Binds a listening network socket to the specified host and service.
 *
 * This high-level function combines the functionality of
 * {@link module:socket#create|create()},
 * {@link module:socket#addrinfo|addrinfo()},
 * {@link module:socket.socket#bind|bind()}, and
 * {@link module:socket.socket#listen|listen()} to simplify setting up a
 * listening socket with the socket module.
 *
 * @function module:socket#listen
 *
 * @param {string|number[]|module:socket.socket.SocketAddress} host
 * The host to bind to, can be an IP address, hostname,
 * {@link module:socket.socket.SocketAddress|SocketAddress}, or an array value
 * returned by {@link module:core#iptoarr|iptoarr()}.
 *
 * @param {string|number} [service]
 * The service to listen on, can be a symbolic service name (such as "http") or
 * a port number. Optional if host is specified as
 * {@link module:socket.socket.SocketAddress|SocketAddress}.
 *
 * @param {Object} [hints]
 * Optional preferences for the socket. It can contain the following properties:
 * - `family`: The preferred address family (`AF_INET` or `AF_INET6`).
 * - `socktype`: The socket type (`SOCK_STREAM`, `SOCK_DGRAM`, etc.).
 * - `protocol`: The protocol of the created socket.
 * - `flags`: Bitwise OR-ed `AI_*` flags to control the resolution behavior.
 *
 * If no hints are provided, the default socket type preference is set to
 * `SOCK_STREAM`.
 *
 * @param {number} [backlog=128]
 * The maximum length of the queue of pending connections.
 *
 * @param {boolean} [reuseaddr]
 * Whether to set the SO_REUSEADDR option before calling bind().
 *
 * @returns {module:socket.socket}
 *
 * @example
 * // Listen for incoming TCP connections on port 80
 * let server = socket.listen("localhost", 80);
 *
 * // Listen on IPv6 address only
 * let server = socket.listen("machine.local", 8080, { family: socket.AF_INET6 });
 *
 * // Listen on a UNIX domain socket
 * let server = socket.listen({ path: "/var/run/server.sock" });
 */
static uc_value_t *
uc_socket_listen(uc_vm_t *vm, size_t nargs)
{
	int ret, fd, curr_weight, prev_weight, socktype = 0, protocol = 0;
	struct addrinfo *ai_results, *ai_hints, *ai;
	uc_value_t *host, *serv, *hints, *backlog, *reuseaddr;
	struct sockaddr_storage ss = { 0 };
	bool v6, lo, ll;
	socklen_t slen;

	args_get(vm, nargs, NULL,
		"host", UC_NULL, true, &host,
		"service", UC_NULL, true, &serv,
		"hints", UC_OBJECT, true, &hints,
		"backlog", UC_INTEGER, true, &backlog,
		"reuseaddr", UC_BOOLEAN, true, &reuseaddr);

	ai_hints = hints
		? (struct addrinfo *)uv_to_struct(hints, &st_addrinfo) : NULL;

	if (host == NULL || should_resolve(host)) {
		char *servstr = (ucv_type(serv) != UC_STRING)
			? ucv_to_string(vm, serv) : NULL;

		ret = getaddrinfo(ucv_string_get(host),
			servstr ? servstr : ucv_string_get(serv),
			ai_hints ? ai_hints : &(struct addrinfo){
				.ai_flags = AI_PASSIVE | AI_ADDRCONFIG,
				.ai_socktype = SOCK_STREAM
			}, &ai_results);

		free(servstr);

		if (ret != 0) {
			free(ai_hints);
			err_return((ret == EAI_SYSTEM) ? errno : ret,
				"getaddrinfo()");
		}

		for (ai = ai_results, prev_weight = -1; ai != NULL; ai = ai->ai_next) {
			struct sockaddr_in6 *s6 = (struct sockaddr_in6 *)ai->ai_addr;
			struct sockaddr_in *s4 = (struct sockaddr_in *)ai->ai_addr;

			v6 = (s6->sin6_family == AF_INET6);
			ll = v6
				? IN6_IS_ADDR_LINKLOCAL(&s6->sin6_addr)
				: ((ntohl(s4->sin_addr.s_addr) & 0xffff0000) == 0xa9fe0000);
			lo = v6
				? IN6_IS_ADDR_LOOPBACK(&s6->sin6_addr)
				: ((ntohl(s4->sin_addr.s_addr) & 0xff000000) == 0x7f000000);

			curr_weight = (!lo << 2) | (v6 << 1) | (!ll << 0);

			if (curr_weight > prev_weight) {
				prev_weight = curr_weight;
				socktype = ai->ai_socktype;
				protocol = ai->ai_protocol;
				slen     = ai->ai_addrlen;
				memcpy(&ss, ai->ai_addr, slen);
			}
		}

		freeaddrinfo(ai_results);
	}
	else {
		if (!uv_to_sockaddr(host, &ss, &slen)) {
			free(ai_hints);
			return NULL;
		}

		if (serv) {
			uint64_t port = ucv_to_unsigned(serv);

			if (port > 65535)
				errno = ERANGE;

			if (errno != 0) {
				free(ai_hints);
				err_return(errno, "Invalid port number");
			}

			((struct sockaddr_in *)&ss)->sin_port = htons(port);
		}

		int default_socktype = SOCK_STREAM;

		if (ss.ss_family != AF_INET && ss.ss_family != AF_INET6)
			default_socktype = SOCK_DGRAM;

		socktype = ai_hints ? ai_hints->ai_socktype : default_socktype;
		protocol = ai_hints ? ai_hints->ai_protocol : 0;
	}

	free(ai_hints);

	if (ss.ss_family == AF_UNSPEC)
		err_return(EAI_NONAME, "Could not resolve host address");

	fd = socket(ss.ss_family, socktype, protocol);

	if (fd == -1)
		err_return(errno, "socket()");

	if (ucv_is_truish(reuseaddr)) {
		ret = setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &(int){ 1 }, sizeof(int));

		if (ret == -1)
			err_return(errno, "setsockopt()");
	}

	ret = bind(fd, (struct sockaddr *)&ss, slen);

	if (ret == -1) {
		close(fd);
		err_return(errno, "bind()");
	}

	ret = listen(fd, backlog ? ucv_to_unsigned(backlog) : 128);

	if (ret == -1 && errno != EOPNOTSUPP) {
		close(fd);
		err_return(errno, "listen()");
	}

	ok_return(ucv_socket_new(vm, fd));
}

/**
 * Represents a socket handle.
 *
 * @class module:socket.socket
 * @hideconstructor
 *
 * @borrows module:socket#error as module:socket.socket#error
 *
 * @see {@link module:socket#create|create()}
 *
 * @example
 *
 * const sock = create(…);
 *
 * sock.getopt(…);
 * sock.setopt(…);
 *
 * sock.connect(…);
 * sock.listen(…);
 * sock.accept(…);
 * sock.bind(…);
 *
 * sock.send(…);
 * sock.recv(…);
 *
 * sock.shutdown(…);
 *
 * sock.fileno();
 * sock.peername();
 * sock.sockname();
 *
 * sock.close();
 *
 * sock.error();
 */

/**
 * Creates a network socket instance.
 *
 * This function creates a new network socket with the specified domain and
 * type, determined by one of the modules `AF_*` and `SOCK_*` constants
 * respectively, and returns the resulting socket instance for use in subsequent
 * socket operations.
 *
 * The domain argument specifies the protocol family, such as AF_INET or
 * AF_INET6, and defaults to AF_INET if not provided.
 *
 * The type argument specifies the socket type, such as SOCK_STREAM or
 * SOCK_DGRAM, and defaults to SOCK_STREAM if not provided. It may also
 * be bitwise OR-ed with SOCK_NONBLOCK to enable non-blocking mode or
 * SOCK_CLOEXEC to enable close-on-exec semantics.
 *
 * The protocol argument may be used to indicate a particular protocol
 * to be used with the socket, and it defaults to 0 (automatically
 * determined protocol) if not provided.
 *
 * Returns a socket descriptor representing the newly created socket.
 *
 * Returns `null` if an error occurred during socket creation.
 *
 * @function module:socket#create
 *
 * @param {number} [domain=AF_INET]
 * The communication domain for the socket, e.g., AF_INET or AF_INET6.
 *
 * @param {number} [type=SOCK_STREAM]
 * The socket type, e.g., SOCK_STREAM or SOCK_DGRAM. It may also be
 * bitwise OR-ed with SOCK_NONBLOCK or SOCK_CLOEXEC.
 *
 * @param {number} [protocol=0]
 * The protocol to be used with the socket.
 *
 * @returns {?module:socket.socket}
 * A socket instance representing the newly created socket.
 *
 * @example
 * // Create a TCP socket
 * const tcp_socket = create(AF_INET, SOCK_STREAM);
 *
 * // Create a nonblocking IPv6 UDP socket
 * const udp_socket = create(AF_INET6, SOCK_DGRAM | SOCK_NONBLOCK);
 */
static uc_value_t *
uc_socket_create(uc_vm_t *vm, size_t nargs)
{
	uc_value_t *domain, *type, *protocol;
	int sockfd, socktype;

	args_get(vm, nargs, NULL,
		"domain", UC_INTEGER, true, &domain,
		"type", UC_INTEGER, true, &type,
		"protocol", UC_INTEGER, true, &protocol);

	socktype = type ? (int)ucv_int64_get(type) : SOCK_STREAM;

	sockfd = socket(
		domain ? (int)ucv_int64_get(domain) : AF_INET,
#if defined(__APPLE__)
		socktype & ~(SOCK_NONBLOCK|SOCK_CLOEXEC),
#else
		socktype,
#endif
		protocol ? (int)ucv_int64_get(protocol) : 0);

	if (sockfd == -1)
		err_return(errno, "socket()");

#if defined(__APPLE__)
	if (socktype & SOCK_NONBLOCK) {
		int flags = fcntl(sockfd, F_GETFL);

		if (flags == -1) {
			close(sockfd);
			err_return(errno, "fcntl(F_GETFL)");
		}

		if (fcntl(sockfd, F_SETFL, flags | O_NONBLOCK) == -1) {
			close(sockfd);
			err_return(errno, "fcntl(F_SETFL)");
		}
	}

	if (socktype & SOCK_CLOEXEC) {
		if (fcntl(sockfd, F_SETFD, FD_CLOEXEC) == -1) {
			close(sockfd);
			err_return(errno, "fcntl(F_SETFD)");
		}
	}
#endif

	ok_return(ucv_socket_new(vm, sockfd));
}

/**
 * Creates a connected socket instance with a pair file descriptor.
 *
 * This function creates new network sockets with the specified type,
 * determined by one of the `SOCK_*` constants, and returns resulting socket
 * instances for use in subsequent socket operations.
 *
 * The type argument specifies the socket type, such as SOCK_STREAM or
 * SOCK_DGRAM, and defaults to SOCK_STREAM if not provided. It may also
 * be bitwise OR-ed with SOCK_NONBLOCK to enable non-blocking mode or
 * SOCK_CLOEXEC to enable close-on-exec semantics.
 *
 * Returns an array of socket descriptors.
 *
 * Returns `null` if an error occurred during socket creation.
 *
 * @function module:socket#pair
 *
 * @param {number} [type=SOCK_STREAM]
 * The socket type, e.g., SOCK_STREAM or SOCK_DGRAM. It may also be
 * bitwise OR-ed with SOCK_NONBLOCK or SOCK_CLOEXEC.
 *
 * @returns {Array.<?module:socket.socket>}
 * Socket instances representing the newly created sockets.
 *
 * @example
 * // Create a TCP socket pair
 * const tcp_sockets = pair(SOCK_STREAM);
 *
 * // Create a nonblocking IPv6 UDP socket pair
 * const udp_sockets = pair(SOCK_DGRAM | SOCK_NONBLOCK);
 */
static uc_value_t *
uc_socket_pair(uc_vm_t *vm, size_t nargs)
{
	uc_value_t *type, *res;
	int sockfds[2], socktype;

	args_get(vm, nargs, NULL,
		"type", UC_INTEGER, true, &type);

	socktype = type ? (int)ucv_int64_get(type) : SOCK_STREAM;

	if (socketpair(AF_UNIX,
#if defined(__APPLE__)
		socktype & ~(SOCK_NONBLOCK|SOCK_CLOEXEC),
#else
		socktype,
#endif
		0, sockfds) < 0)
		err_return(errno, "socketpair()");

#if defined(__APPLE__)
	if (socktype & SOCK_NONBLOCK) {
		int flags = fcntl(sockfds[0], F_GETFL);

		if (flags == -1)
			goto error;

		if (fcntl(sockfds[0], F_SETFL, flags | O_NONBLOCK) == -1)
			goto error;
	}

	if (socktype & SOCK_CLOEXEC) {
		if (fcntl(sockfds[0], F_SETFD, FD_CLOEXEC) == -1)
			goto error;
	}
#endif

	res = ucv_array_new(vm);
	ucv_array_set(res, 0, ucv_socket_new(vm, sockfds[0]));
	ucv_array_set(res, 1, ucv_socket_new(vm, sockfds[1]));
	ok_return(res);

#if defined(__APPLE__)
error:
#endif
	close(sockfds[0]);
	close(sockfds[1]);
	err_return(errno, "fcntl");
}

/**
 * Connects the socket to a remote address.
 *
 * Attempts to establish a connection to the specified remote address.
 *
 * Returns `true` if the connection is successfully established.
 * Returns `null` if an error occurred during the connection attempt.
 *
 * @function module:socket.socket#connect
 *
 * @param {string|module:socket.socket.SocketAddress} address
 * The address of the remote endpoint to connect to.
 *
 * @param {number} port
 * The port number of the remote endpoint to connect to.
 *
 * @returns {?boolean}
 */
static uc_value_t *
uc_socket_inst_connect(uc_vm_t *vm, size_t nargs)
{
	struct sockaddr_storage ss;
	uc_value_t *addr, *port;
	unsigned long n;
	int ret, sockfd;
	socklen_t slen;

	args_get(vm, nargs, &sockfd,
		"address", UC_NULL, false, &addr,
		"port", UC_INTEGER, true, &port);

	if (!uv_to_sockaddr(addr, &ss, &slen))
		return NULL;

	if (port) {
		 if (ss.ss_family != AF_INET && ss.ss_family != AF_INET6)
			err_return(EINVAL, "Port argument is only valid for IPv4 and IPv6 addresses");

		n = ucv_to_unsigned(port);

		if (n > 65535)
			errno = ERANGE;

		if (errno != 0)
			err_return(errno, "Invalid port number");

		((struct sockaddr_in6 *)&ss)->sin6_port = htons(n);
	}

	ret = connect(sockfd, (struct sockaddr *)&ss, slen);

	if (ret == -1)
		err_return(errno, "connect()");

	ok_return(ucv_boolean_new(true));
}

/**
 * Sends data through the socket.
 *
 * Sends the provided data through the socket handle to the specified remote
 * address, if provided.
 *
 * Returns the number of bytes sent.
 * Returns `null` if an error occurred during the send operation.
 *
 * @function module:socket.socket#send
 *
 * @param {*} data
 * The data to be sent through the socket. String data is sent as-is, any other
 * type is implicitly converted to a string first before being sent on the
 * socket.
 *
 * @param {number} [flags]
 * Optional flags that modify the behavior of the send operation.
 *
 * @param {module:socket.socket.SocketAddress|number[]|string} [address]
 * The address of the remote endpoint to send the data to. It can be either an
 * IP address string, an array returned by {@link module:core#iptoarr|iptoarr()},
 * or an object representing a network address. If not provided, the data is
 * sent to the remote endpoint the socket is connected to.
 *
 * @returns {?number}
 *
 * @see {@link module:socket#sockaddr|sockaddr()}
 *
 * @example
 * // Send to connected socket
 * let tcp_sock = socket.create(socket.AF_INET, socket.SOCK_STREAM);
 * tcp_sock.connect("192.168.1.1", 80);
 * tcp_sock.send("GET / HTTP/1.0\r\n\r\n");
 *
 * // Send a datagram on unconnected socket
 * let udp_sock = socket.create(socket.AF_INET, socket.SOCK_DGRAM);
 * udp_sock.send("Hello there!", 0, "255.255.255.255:9000");
 * udp_sock.send("Hello there!", 0, {
 *   family: socket.AF_INET,      // optional
 *   address: "255.255.255.255",
 *   port: 9000
 * });
 */
static uc_value_t *
uc_socket_inst_send(uc_vm_t *vm, size_t nargs)
{
	uc_value_t *data, *flags, *addr;
	struct sockaddr_storage ss = { 0 };
	struct sockaddr *sa = NULL;
	socklen_t salen = 0;
	char *buf = NULL;
	ssize_t ret;
	int sockfd;

	args_get(vm, nargs, &sockfd,
		"data", UC_NULL, false, &data,
		"flags", UC_INTEGER, true, &flags,
		"address", UC_NULL, true, &addr);

	if (addr) {
		if (!uv_to_sockaddr(addr, &ss, &salen))
			return NULL;

		sa = (struct sockaddr *)&ss;
	}

	if (ucv_type(data) != UC_STRING)
		buf = ucv_to_string(vm, data);

	ret = sendto(sockfd,
		buf ? buf : ucv_string_get(data),
		buf ? strlen(buf) : ucv_string_length(data),
		(flags ? ucv_int64_get(flags) : 0) | MSG_NOSIGNAL, sa, salen);

	free(buf);

	if (ret == -1)
		err_return(errno, "send()");

	ok_return(ucv_int64_new(ret));
}

/**
 * Receives data from the socket.
 *
 * Receives data from the socket handle, optionally specifying the maximum
 * length of data to receive, flags to modify the receive behavior, and an
 * optional address dictionary where the function will place the address from
 * which the data was received (for unconnected sockets).
 *
 * Returns a string containing the received data.
 * Returns an empty string if the remote side closed the socket.
 * Returns `null` if an error occurred during the receive operation.
 *
 * @function module:socket.socket#recv
 *
 * @param {number} [length=4096]
 * The maximum number of bytes to receive.
 *
 * @param {number} [flags]
 * Optional flags that modify the behavior of the receive operation.
 *
 * @param {Object} [address]
 * An object where the function will store the address from which the data was
 * received. If provided, it will be filled with the details obtained from the
 * sockaddr argument of the underlying `recvfrom()` syscall. See the type
 * definition of {@link module:socket.socket.SocketAddress|SocketAddress} for
 * details on the format.
 *
 * @returns {?string}
 */
static uc_value_t *
uc_socket_inst_recv(uc_vm_t *vm, size_t nargs)
{
	uc_value_t *length, *flags, *addrobj;
	struct sockaddr_storage ss = { 0 };
	uc_stringbuf_t *buf;
	ssize_t len, ret;
	socklen_t sslen;
	int sockfd;

	args_get(vm, nargs, &sockfd,
		"length", UC_INTEGER, true, &length,
		"flags", UC_INTEGER, true, &flags,
		"address", UC_OBJECT, true, &addrobj);

	len = length ? ucv_to_integer(length) : 4096;

	if (errno || len <= 0)
		err_return(errno, "Invalid length argument");

	buf = strbuf_alloc(len);

	if (!buf)
		return NULL;

	do {
		sslen = sizeof(ss);
		ret = recvfrom(sockfd, strbuf_data(buf), len,
			flags ? ucv_int64_get(flags) : 0, (struct sockaddr *)&ss, &sslen);
	} while (ret == -1 && errno == EINTR);

	if (ret == -1) {
		strbuf_free(buf);
		err_return(errno, "recv()");
	}

	if (addrobj)
		sockaddr_to_uv(&ss, addrobj);

	ok_return(strbuf_finish(&buf, ret));
}

uc_declare_vector(strbuf_array_t, uc_stringbuf_t *);

#if defined(__linux__)
static void optmem_max(size_t *sz) {
	char buf[sizeof("18446744073709551615")] = { 0 };
	int fd, rv;

	fd = open("/proc/sys/net/core/optmem_max", O_RDONLY);

	if (fd >= 0) {
		if (read(fd, buf, sizeof(buf) - 1) > 0) {
			rv = strtol(buf, NULL, 10);

			if (rv > 0 && (size_t)rv < *sz)
				*sz = rv;
		}

		if (fd > 2)
			close(fd);
	}
}
#else
# define optmem_max(x)
#endif


/**
 * Represents a single control (ancillary data) message returned
 * in the *ancillary* array by {@link module:socket.socket#recvmsg|`recvmsg()`}.
 *
 * @typedef {Object} module:socket.socket.ControlMessage
 * @property {number} level
 * The message socket level (`cmsg_level`), e.g. `SOL_SOCKET`.
 *
 * @property {number} type
 * The protocol specific message type (`cmsg_type`), e.g. `SCM_RIGHTS`.
 *
 * @property {*} data
 * The payload of the control message. If the control message type is known by
 * the socket module, it is represented as a mixed value (array, object, number,
 * etc.) with structure specific to the control message type. If the control
 * message cannot be decoded, *data* is set to a string value containing the raw
 * payload.
 */
static uc_value_t *
decode_cmsg(uc_vm_t *vm, struct cmsghdr *cmsg)
{
	char *s = (char *)CMSG_DATA(cmsg);
	size_t sz = cmsg->cmsg_len - sizeof(*cmsg);
	struct sockaddr_storage *ss;
	uc_value_t *fdarr;
	struct stat st;
	int *fds;

	for (size_t i = 0; i < ARRAY_SIZE(cmsgtypes); i++) {

		if (cmsgtypes[i].level != cmsg->cmsg_level)
			continue;

		if (cmsgtypes[i].type != cmsg->cmsg_type)
			continue;

		switch ((uintptr_t)cmsgtypes[i].ctype) {
		case (uintptr_t)CV_INT:
			return ucv_int64_new(parse_integer(s, sz));

		case (uintptr_t)CV_UINT:
		case (uintptr_t)CV_BE32:
			return ucv_uint64_new(parse_unsigned(s, sz));

		case (uintptr_t)CV_SOCKADDR:
			ss = (struct sockaddr_storage *)s;

			if ((sz >= sizeof(struct sockaddr_in) &&
			     ss->ss_family == AF_INET) ||
			    (sz >= sizeof(struct sockaddr_in6) &&
			     ss->ss_family == AF_INET6))
			{
				uc_value_t *addr = ucv_object_new(vm);

				if (sockaddr_to_uv(ss, addr))
					return addr;

				ucv_put(addr);
			}

			return NULL;

		case (uintptr_t)CV_FDS:
			fdarr = ucv_array_new_length(vm, sz / sizeof(int));
			fds = (int *)s;

			for (size_t i = 0; i < sz / sizeof(int); i++) {
				if (fstat(fds[i], &st) == 0) {
					uc_resource_type_t *t;

					if (S_ISSOCK(st.st_mode)) {
						t = ucv_resource_type_lookup(vm, "socket");

						ucv_array_push(fdarr,
							ucv_resource_new(t, (void *)(intptr_t)fds[i]));

						continue;
					}
					else if (S_ISDIR(st.st_mode)) {
						t = ucv_resource_type_lookup(vm, "fs.dir");

						if (t) {
							DIR *d = fdopendir(fds[i]);

							if (d) {
								ucv_array_push(fdarr, ucv_resource_new(t, d));
								continue;
							}
						}
					}
					else {
						t = ucv_resource_type_lookup(vm, "fs.file");

						if (t) {
							int n = fcntl(fds[i], F_GETFL);
							const char *mode;

							if (n <= 0 || (n & O_ACCMODE) == O_RDONLY)
								mode = "r";
							else if ((n & O_ACCMODE) == O_WRONLY)
								mode = (n & O_APPEND) ? "a" : "w";
							else
								mode = (n & O_APPEND) ? "a+" : "w+";

							FILE *f = fdopen(fds[i], mode);

							if (f) {
								ucv_array_push(fdarr, uc_resource_new(t, f));
								continue;
							}
						}
					}
				}

				ucv_array_push(fdarr, ucv_int64_new(fds[i]));
			}

			return fdarr;

		case (uintptr_t)CV_STRING:
			break;

		default:
			if (sz >= cmsgtypes[i].ctype->size)
				return struct_to_uv(s, cmsgtypes[i].ctype);
		}

		break;
	}

	return ucv_string_new_length(s, sz);
}

static size_t
estimate_cmsg_size(uc_value_t *uv)
{
	int cmsg_level = ucv_to_integer(ucv_object_get(uv, "level", NULL));
	int cmsg_type = ucv_to_integer(ucv_object_get(uv, "type", NULL));
	uc_value_t *val = ucv_object_get(uv, "data", NULL);

	for (size_t i = 0; i < ARRAY_SIZE(cmsgtypes); i++) {
		if (cmsgtypes[i].level != cmsg_level)
			continue;

		if (cmsgtypes[i].type != cmsg_type)
			continue;

		switch ((uintptr_t)cmsgtypes[i].ctype) {
		case (uintptr_t)CV_INT:      return sizeof(int);
		case (uintptr_t)CV_UINT:     return sizeof(unsigned int);
		case (uintptr_t)CV_BE32:     return sizeof(uint32_t);
		case (uintptr_t)CV_SOCKADDR: return sizeof(struct sockaddr_storage);
		case (uintptr_t)CV_FDS:      return ucv_array_length(val) * sizeof(int);
		case (uintptr_t)CV_STRING:   return ucv_string_length(val);
		default:                     return cmsgtypes[i].ctype->size;
		}
	}

	switch (ucv_type(val)) {
		case UC_BOOLEAN: return sizeof(unsigned int);
		case UC_INTEGER: return sizeof(int);
		case UC_STRING:  return ucv_string_length(val);
		default:         return 0;
	}
}

static bool
encode_cmsg(uc_vm_t *vm, uc_value_t *uv, struct cmsghdr *cmsg)
{
	struct { int *entries; size_t count; } fds = { 0 };
	void *dataptr = NULL;
	socklen_t datasz = 0;
	char *st = NULL;
	size_t i;
	union {
		int i;
		unsigned int u;
		uint32_t u32;
		struct sockaddr_storage ss;
	} val;

	cmsg->cmsg_level = ucv_to_integer(ucv_object_get(uv, "level", NULL));
	cmsg->cmsg_type = ucv_to_integer(ucv_object_get(uv, "type", NULL));

	uc_value_t *data = ucv_object_get(uv, "data", NULL);

	for (i = 0; i < ARRAY_SIZE(cmsgtypes); i++) {
		if (cmsgtypes[i].level != cmsg->cmsg_level)
			continue;

		if (cmsgtypes[i].type != cmsg->cmsg_type)
			continue;

		switch ((uintptr_t)cmsgtypes[i].ctype) {
		case (uintptr_t)CV_INT:
			val.i = ucv_to_integer(data);
			datasz = sizeof(val.i);
			dataptr = &val;
			break;

		case (uintptr_t)CV_UINT:
			val.u = ucv_to_unsigned(data);
			datasz = sizeof(val.u);
			dataptr = &val;
			break;

		case (uintptr_t)CV_BE32:
			val.u32 = ucv_to_unsigned(data);
			datasz = sizeof(val.u32);
			dataptr = &val;
			break;

		case (uintptr_t)CV_SOCKADDR:
			if (uv_to_sockaddr(data, &val.ss, &datasz))
				dataptr = &val;
			else
				datasz = 0, dataptr = NULL;
			break;

		case (uintptr_t)CV_FDS:
			if (ucv_type(data) == UC_ARRAY) {
				for (size_t i = 0; i < ucv_array_length(data); i++) {
					int fd;

					if (uv_to_fileno(vm, ucv_array_get(data, i), &fd))
						uc_vector_push(&fds, fd);
				}
			}

			datasz = sizeof(fds.entries[0]) * fds.count;
			dataptr = fds.entries;
			break;

		case (uintptr_t)CV_STRING:
			datasz = ucv_string_length(data);
			dataptr = ucv_string_get(data);
			break;

		default:
			st = uv_to_struct(data, cmsgtypes[i].ctype);
			datasz = st ? cmsgtypes[i].ctype->size : 0;
			dataptr = st;
			break;
		}

		break;
	}

	/* we don't know this kind of control message, guess encoding */
	if (i == ARRAY_SIZE(cmsgtypes)) {
		switch (ucv_type(data)) {
		/* treat boolean as int with values 1 or 0 */
		case UC_BOOLEAN:
			val.u = ucv_boolean_get(data);
			dataptr = &val;
			datasz = sizeof(val.u);
			break;

		/* treat integers as int */
		case UC_INTEGER:
			if (ucv_is_u64(data)) {
				val.u = ucv_uint64_get(data);
				datasz = sizeof(val.u);
			}
			else {
				val.i = ucv_int64_get(data);
				datasz = sizeof(val.i);
			}

			dataptr = &val;
			break;

		/* pass strings as-is */
		case UC_STRING:
			dataptr = ucv_string_get(data);
			datasz = ucv_string_length(data);
			break;

		default:
			break;
		}
	}

	cmsg->cmsg_len = CMSG_LEN(datasz);

	if (dataptr)
		memcpy(CMSG_DATA(cmsg), dataptr, datasz);

	uc_vector_clear(&fds);
	free(st);

	return true;
}

/**
 * Sends a message through the socket.
 *
 * Sends a message through the socket handle, supporting complex message
 * structures including multiple data buffers and ancillary data. This function
 * allows for precise control over the message content and delivery behavior.
 *
 * Returns the number of sent bytes.
 *
 * Returns `null` if an error occurred.
 *
 * @function module:socket.socket#sendmsg
 *
 * @param {*} [data]
 * The data to be sent. If a string is provided, it is sent as is. If an array
 * is specified, each item is sent as a separate `struct iovec`. Non-string
 * values are implicitly converted to a string and sent. If omitted, only
 * ancillary data and address are considered.
 *
 * @param {module:socket.socket.ControlMessage[]|string} [ancillaryData]
 * Optional ancillary data to be sent. If an array is provided, each element is
 * converted to a control message. If a string is provided, it is sent as-is
 * without further interpretation. Refer to
 * {@link module:socket.socket#recvmsg|`recvmsg()`} and
 * {@link module:socket.socket.ControlMessage|ControlMessage} for details.
 *
 * @param {module:socket.socket.SocketAddress} [address]
 * The destination address for the message. If provided, it sets or overrides
 * the packet destination address.
 *
 * @param {number} [flags]
 * Optional flags to modify the behavior of the send operation. This should be a
 * bitwise OR-ed combination of `MSG_*` flag values.
 *
 * @returns {?number}
 * Returns the number of bytes sent on success, or `null` if an error occurred.
 *
 * @example
 * // Send file descriptors over domain socket
 * const f1 = fs.open("example.txt", "w");
 * const f2 = fs.popen("date +%s", "r");
 * const sk = socket.connect({ family: socket.AF_UNIX, path: "/tmp/socket" });

 * sk.sendmsg("Hi there, here's some descriptors!", [
 * 	{ level: socket.SOL_SOCKET, type: socket.SCM_RIGHTS, data: [ f1, f2 ] }
 * ]);
 *
 * // Send multiple values in one datagram
 * sk.sendmsg([ "This", "is", "one", "message" ]);
 */
static uc_value_t *
uc_socket_inst_sendmsg(uc_vm_t *vm, size_t nargs)
{
	uc_value_t *data, *ancdata, *addr, *flags;
	struct sockaddr_storage ss = { 0 };
	strbuf_array_t sbarr = { 0 };
	struct msghdr msg = { 0 };
	struct iovec vec = { 0 };
	int flagval, sockfd;
	socklen_t slen;
	ssize_t ret;

	args_get(vm, nargs, &sockfd,
		"data", UC_NULL, true, &data,
		"ancillary data", UC_NULL, true, &ancdata,
		"address", UC_OBJECT, true, &addr,
		"flags", UC_INTEGER, true, &flags);

	flagval = flags ? ucv_int64_get(flags) : 0;

	/* treat string ancdata arguemnt as raw controldata buffer */
	if (ucv_type(ancdata) == UC_STRING) {
		msg.msg_control = ucv_string_get(ancdata);
		msg.msg_controllen = ucv_string_length(ancdata);
	}
	/* encode ancdata passed as array */
	else if (ucv_type(ancdata) == UC_ARRAY) {
		msg.msg_controllen = 0;

		for (size_t i = 0; i < ucv_array_length(ancdata); i++) {
			size_t sz = estimate_cmsg_size(ucv_array_get(ancdata, i));

			if (sz > 0)
				msg.msg_controllen += CMSG_SPACE(sz);
		}

		if (msg.msg_controllen > 0) {
			msg.msg_control = xalloc(msg.msg_controllen);

			struct cmsghdr *cmsg = NULL;

			for (size_t i = 0; i < ucv_array_length(ancdata); i++) {
#ifdef __clang_analyzer__
				/* Clang static analyzer assumes that CMSG_*HDR() returns
				 * allocated heap pointers and not pointers into the
				 * msg.msg_control buffer. Nudge it. */
				cmsg = (struct cmsghdr *)msg.msg_control;
#else
				cmsg = cmsg ? CMSG_NXTHDR(&msg, cmsg) : CMSG_FIRSTHDR(&msg);
#endif

				if (!cmsg) {
					free(msg.msg_control);
					err_return(ENOBUFS, "Not enough CMSG buffer space");
				}

				if (!encode_cmsg(vm, ucv_array_get(ancdata, i), cmsg)) {
					free(msg.msg_control);
					return NULL;
				}
			}

			msg.msg_controllen = (cmsg != NULL)
				? (char *)cmsg - (char *)msg.msg_control + CMSG_SPACE(cmsg->cmsg_len)
				: 0;
		}
	}
	else if (ancdata) {
		err_return(EINVAL, "Ancillary data must be string or array value");
	}

	/* prepare iov array */
	if (ucv_type(data) == UC_ARRAY) {
		msg.msg_iovlen = ucv_array_length(data);
		msg.msg_iov = (msg.msg_iovlen > 1)
			? xalloc(sizeof(vec) * msg.msg_iovlen) : &vec;

		for (size_t i = 0; i < (size_t)msg.msg_iovlen; i++) {
			uc_value_t *item = ucv_array_get(data, i);

			if (ucv_type(item) == UC_STRING) {
				msg.msg_iov[i].iov_base = _ucv_string_get(&((uc_array_t *)data)->entries[i]);
				msg.msg_iov[i].iov_len = ucv_string_length(item);
			}
			else if (item) {
				struct printbuf *pb = xprintbuf_new();
				uc_vector_push(&sbarr, pb);
				ucv_to_stringbuf(vm, pb, item, false);
				msg.msg_iov[i].iov_base = pb->buf;
				msg.msg_iov[i].iov_len = pb->bpos;
			}
		}
	}
	else if (ucv_type(data) == UC_STRING) {
		msg.msg_iovlen = 1;
		msg.msg_iov = &vec;
		vec.iov_base = ucv_string_get(data);
		vec.iov_len = ucv_string_length(data);
	}
	else if (data) {
		struct printbuf *pb = xprintbuf_new();
		uc_vector_push(&sbarr, pb);
		ucv_to_stringbuf(vm, pb, data, false);
		msg.msg_iovlen = 1;
		msg.msg_iov = &vec;
		vec.iov_base = pb->buf;
		vec.iov_len = pb->bpos;
	}

	/* prepare address */
	if (addr && uv_to_sockaddr(addr, &ss, &slen)) {
		msg.msg_name = &ss;
		msg.msg_namelen = slen;
	}

	/* now send actual data */
	do {
		ret = sendmsg(sockfd, &msg, flagval);
	} while (ret == -1 && errno == EINTR);

	while (sbarr.count > 0)
		printbuf_free(sbarr.entries[--sbarr.count]);

	uc_vector_clear(&sbarr);

	if (msg.msg_iov != &vec)
		free(msg.msg_iov);

	free(msg.msg_control);

	if (ret == -1)
		err_return(errno, "sendmsg()");

	ok_return(ucv_int64_new(ret));
}



/**
 * Represents a message object returned by
 * {@link module:socket.socket#recvmsg|`recvmsg()`}.
 *
 * @typedef {Object} module:socket.socket.ReceivedMessage
 * @property {number} flags
 * Integer value containing bitwise OR-ed `MSG_*` result flags returned by the
 * underlying receive call.
 *
 * @property {number} length
 * Integer value containing the number of bytes returned by the `recvmsg()`
 * syscall, which might be larger than the received data in case `MSG_TRUNC`
 * was passed.
 *
 * @property {module:socket.socket.SocketAddress} address
 * The address from which the message was received.
 *
 * @property {string[]|string} data
 * An array of strings, each representing the received message data.
 * Each string corresponds to one buffer size specified in the *sizes* argument.
 * If a single receive size was passed instead of an array of sizes, *data* will
 * hold a string containing the received data.
 *
 * @property {module:socket.socket.ControlMessage[]} [ancillary]
 * An array of received control messages. Only included if a non-zero positive
 * *ancillarySize* was passed to `recvmsg()`.
 */

/**
 * Receives a message from the socket.
 *
 * Receives a message from the socket handle, allowing for more complex data
 * reception compared to `recv()`. This includes the ability to receive
 * ancillary data (such as file descriptors, credentials, etc.), multiple
 * message segments, and optional flags to modify the receive behavior.
 *
 * Returns an object containing the received message data, ancillary data,
 * and the sender's address.
 *
 * Returns `null` if an error occurred during the receive operation.
 *
 * @function module:socket.socket#recvmsg
 *
 * @param {number[]|number} [sizes]
 * Specifies the sizes of the buffers used for receiving the message. If an
 * array of numbers is provided, each number determines the size of an
 * individual buffer segment, creating multiple `struct iovec` for reception.
 * If a single number is provided, a single buffer of that size is used.
 *
 * @param {number} [ancillarySize]
 * The size allocated for the ancillary data buffer. If not provided, ancillary
 * data is not processed.
 *
 * @param {number} [flags]
 * Optional flags to modify the behavior of the receive operation. This should
 * be a bitwise OR-ed combination of flag values.
 *
 * @returns {?module:socket.socket.ReceivedMessage}
 * An object containing the received message data, ancillary data,
 * and the sender's address.
 *
 * @example
 * // Receive file descriptors over domain socket
 * const sk = socket.listen({ family: socket.AF_UNIX, path: "/tmp/socket" });
 * sk.setopt(socket.SOL_SOCKET, socket.SO_PASSCRED, true);
 *
 * const msg = sk.recvmsg(1024, 1024); *
 * for (let cmsg in msg.ancillary)
 *   if (cmsg.level == socket.SOL_SOCKET && cmsg.type == socket.SCM_RIGHTS)
 *     print(`Got some descriptors: ${cmsg.data}!\n`);
 *
 * // Receive message in segments of 10, 128 and 512 bytes
 * const msg = sk.recvmsg([ 10, 128, 512 ]);
 * print(`Message parts: ${msg.data[0]}, ${msg.data[1]}, ${msg.data[2]}\n`);
 *
 * // Peek buffer
 * const msg = sk.recvmsg(0, 0, socket.MSG_PEEK|socket.MSG_TRUNC);
 * print(`Received ${length(msg.data)} bytes, ${msg.length} bytes available\n`);
 */
static uc_value_t *
uc_socket_inst_recvmsg(uc_vm_t *vm, size_t nargs)
{
	uc_value_t *length, *anclength, *flags, *rv;
	struct sockaddr_storage ss = { 0 };
	strbuf_array_t sbarr = { 0 };
	struct msghdr msg = { 0 };
	struct iovec vec = { 0 };
	int flagval, sockfd;
	ssize_t ret;

	args_get(vm, nargs, &sockfd,
		"length", UC_NULL, true, &length,
		"ancillary length", UC_INTEGER, true, &anclength,
		"flags", UC_INTEGER, true, &flags);

	flagval = flags ? ucv_int64_get(flags) : 0;

	/* prepare ancillary data buffer */
	if (anclength) {
		size_t sz = ucv_to_unsigned(anclength);

		if (errno != 0)
			err_return(errno, "Invalid ancillary data length");

		optmem_max(&sz);

		if (sz > 0) {
			msg.msg_controllen = sz;
			msg.msg_control = xalloc(sz);
		}
	}

	/* prepare iov array */
	if (ucv_type(length) == UC_ARRAY) {
		msg.msg_iovlen = ucv_array_length(length);
		msg.msg_iov = (msg.msg_iovlen > 1)
			? xalloc(sizeof(vec) * msg.msg_iovlen) : &vec;

		for (size_t i = 0; i < (size_t)msg.msg_iovlen; i++) {
			size_t sz = ucv_to_unsigned(ucv_array_get(length, i));

			if (errno != 0) {
				while (sbarr.count > 0)
					strbuf_free(sbarr.entries[--sbarr.count]);

				uc_vector_clear(&sbarr);

				if (msg.msg_iov != &vec)
					free(msg.msg_iov);

				free(msg.msg_control);

				err_return(errno, "Invalid length value");
			}

			uc_vector_push(&sbarr, strbuf_alloc(sz));
			msg.msg_iov[i].iov_base = strbuf_data(sbarr.entries[i]);
			msg.msg_iov[i].iov_len = sz;
		}
	}
	else {
		size_t sz = ucv_to_unsigned(length);

		if (errno != 0) {
			free(msg.msg_control);
			err_return(errno, "Invalid length value");
		}

		uc_vector_push(&sbarr, strbuf_alloc(sz));

		msg.msg_iovlen = 1;
		msg.msg_iov = &vec;
		vec.iov_base = strbuf_data(sbarr.entries[0]);
		vec.iov_len = sz;
	}

	/* now receive actual data */
	msg.msg_name = &ss;
	msg.msg_namelen = sizeof(ss);

	do {
		ret = recvmsg(sockfd, &msg, flagval);
	} while (ret == -1 && errno == EINTR);

	if (ret == -1) {
		while (sbarr.count > 0)
			strbuf_free(sbarr.entries[--sbarr.count]);

		uc_vector_clear(&sbarr);

		if (msg.msg_iov != &vec)
			free(msg.msg_iov);

		free(msg.msg_control);

		err_return(errno, "recvmsg()");
	}

	rv = ucv_object_new(vm);

	ucv_object_add(rv, "flags", ucv_int64_new(msg.msg_flags));
	ucv_object_add(rv, "length", ucv_int64_new(ret));

	if (msg.msg_namelen > 0) {
		uc_value_t *addr = ucv_object_new(vm);

		if (sockaddr_to_uv(&ss, addr))
			ucv_object_add(rv, "address", addr);
		else
			ucv_put(addr);
	}

	if (msg.msg_controllen > 0) {
		uc_value_t *ancillary = ucv_array_new(vm);

		for (struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
		     cmsg != NULL;
		     cmsg = CMSG_NXTHDR(&msg, cmsg))
		{
			uc_value_t *c = ucv_object_new(vm);

			ucv_object_add(c, "level", ucv_int64_new(cmsg->cmsg_level));
			ucv_object_add(c, "type", ucv_int64_new(cmsg->cmsg_type));
			ucv_object_add(c, "data", decode_cmsg(vm, cmsg));

			ucv_array_push(ancillary, c);
		}

		ucv_object_add(rv, "ancillary", ancillary);
	}

	if (ret >= 0) {
		if (ucv_type(length) == UC_ARRAY) {
			uc_value_t *data = ucv_array_new_length(vm, msg.msg_iovlen);

			for (size_t i = 0; i < (size_t)msg.msg_iovlen; i++) {
				size_t sz = ret;

				if (sz > msg.msg_iov[i].iov_len)
					sz = msg.msg_iov[i].iov_len;

				ucv_array_push(data, strbuf_finish(&sbarr.entries[i], sz));
				ret -= sz;
			}

			ucv_object_add(rv, "data", data);
		}
		else {
			size_t sz = ret;

			if (sz > msg.msg_iov[0].iov_len)
				sz = msg.msg_iov[0].iov_len;

			ucv_object_add(rv, "data", strbuf_finish(&sbarr.entries[0], sz));
		}
	}

	uc_vector_clear(&sbarr);

	if (msg.msg_iov != &vec)
		free(msg.msg_iov);

	free(msg.msg_control);

	ok_return(rv);
}

/**
 * Binds a socket to a specific address.
 *
 * This function binds the socket to the specified address.
 *
 * Returns `true` if the socket is successfully bound.
 *
 * Returns `null` on error, e.g. when the address is in use.
 *
 * @function module:socket.socket#bind
 *
 * @param {string|module:socket.socket.SocketAddress} address
 * The IP address to bind the socket to.
 *
 * @returns {?boolean}
 *
 * @example
 * const sock = socket.create(…);
 * const success = sock.bind("192.168.0.1:80");
 *
 * if (success)
 *     print(`Socket bound successfully!\n`);
 * else
 *     print(`Failed to bind socket: ${sock.error()}.\n`);
 */
static uc_value_t *
uc_socket_inst_bind(uc_vm_t *vm, size_t nargs)
{
	struct sockaddr_storage ss = { 0 };
	uc_value_t *addr;
	socklen_t slen;
	int sockfd;

	args_get(vm, nargs, &sockfd,
		"address", UC_NULL, true, &addr);

	if (addr) {
		if (!uv_to_sockaddr(addr, &ss, &slen))
			return NULL;

		if (bind(sockfd, (struct sockaddr *)&ss, slen) == -1)
			err_return(errno, "bind()");
	}
	else {
#if defined(__linux__)
		int sval = 0;
		slen = sizeof(sval);

		if (getsockopt(sockfd, SOL_SOCKET, SO_DOMAIN, &sval, &slen) == -1)
			err_return(errno, "getsockopt()");

		switch (sval) {
		case AF_INET6:
			ss.ss_family = AF_INET6;
			slen = sizeof(struct sockaddr_in6);
			break;

		case AF_INET:
			ss.ss_family = AF_INET;
			slen = sizeof(struct sockaddr_in);
			break;

		default:
			err_return(EAFNOSUPPORT, "Unsupported socket address family");
		}

		if (bind(sockfd, (struct sockaddr *)&ss, slen) == -1)
			err_return(errno, "bind()");
#else
		ss.ss_family = AF_INET6;
		slen = sizeof(struct sockaddr_in6);

		if (bind(sockfd, (struct sockaddr *)&ss, slen) == -1) {
			if (errno != EAFNOSUPPORT)
				err_return(errno, "bind()");

			ss.ss_family = AF_INET;
			slen = sizeof(struct sockaddr_in);

			if (bind(sockfd, (struct sockaddr *)&ss, slen) == -1)
				err_return(errno, "bind()");
		}
#endif
	}

	ok_return(ucv_boolean_new(true));
}

/**
 * Listen for connections on a socket.
 *
 * This function marks the socket as a passive socket, that is, as a socket that
 * will be used to accept incoming connection requests using `accept()`.
 *
 * The `backlog` parameter specifies the maximum length to which the queue of
 * pending connections may grow. If a connection request arrives when the queue
 * is full, the client connection might get refused.
 *
 * If `backlog` is not provided, it defaults to 128.
 *
 * Returns `true` if the socket is successfully marked as passive.
 * Returns `null` if an error occurred, e.g. when the requested port is in use.
 *
 * @function module:socket.socket#listen
 *
 * @param {number} [backlog=128]
 * The maximum length of the queue of pending connections.
 *
 * @returns {?boolean}
 *
 * @see {@link module:socket.socket#accept|accept()}
 *
 * @example
 * const sock = socket.create(…);
 * sock.bind(…);
 *
 * const success = sock.listen(10);
 * if (success)
 *     print(`Socket is listening for incoming connections!\n`);
 * else
 *     print(`Failed to listen on socket: ${sock.error()}\n`);
 */
static uc_value_t *
uc_socket_inst_listen(uc_vm_t *vm, size_t nargs)
{
	uc_value_t *backlog;
	int ret, sockfd;

	args_get(vm, nargs, &sockfd,
		"backlog", UC_INTEGER, true, &backlog);

	ret = listen(sockfd, backlog ? ucv_to_unsigned(backlog) : 128);

	if (ret == -1)
		err_return(errno, "listen()");

	ok_return(ucv_boolean_new(true));
}

/**
 * Accept a connection on a socket.
 *
 * This function accepts a connection on the socket. It extracts the first
 * connection request on the queue of pending connections, creates a new
 * connected socket, and returns a new socket handle referring to that socket.
 * The newly created socket is not in listening state and has no backlog.
 *
 * When a optional `address` dictionary is provided, it is populated with the
 * remote address details of the peer socket.
 *
 * The optional `flags` parameter is a bitwise-or-ed number of flags to modify
 * the behavior of accepted peer socket. Possible values are:
 * - `SOCK_CLOEXEC`: Enable close-on-exec semantics for the new socket.
 * - `SOCK_NONBLOCK`: Enable nonblocking mode for the new socket.
 *
 * Returns a socket handle representing the newly created peer socket of the
 * accepted connection.
 *
 * Returns `null` if an error occurred.
 *
 * @function module:socket.socket#accept
 *
 * @param {object} [address]
 * An optional dictionary to receive the address details of the peer socket.
 * See {@link module:socket.socket.SocketAddress|SocketAddress} for details.
 *
 * @param {number} [flags]
 * Optional flags to modify the behavior of the peer socket.
 *
 * @returns {?module:socket.socket}
 *
 * @example
 * const sock = socket.create(…);
 * sock.bind(…);
 * sock.listen();
 *
 * const peerAddress = {};
 * const newSocket = sock.accept(peerAddress, socket.SOCK_CLOEXEC);
 * if (newSocket)
 *     print(`Accepted connection from: ${peerAddress}\n`);
 * else
 *     print(`Failed to accept connection: ${sock.error()}\n`);
 */
static uc_value_t *
uc_socket_inst_accept(uc_vm_t *vm, size_t nargs)
{
	struct sockaddr_storage ss = { 0 };
	int peerfd, sockfd, sockflags;
	uc_value_t *addrobj, *flags;
	socklen_t slen;

	args_get(vm, nargs, &sockfd,
		"address", UC_OBJECT, true, &addrobj,
		"flags", UC_INTEGER, true, &flags);

	slen = sizeof(ss);
	sockflags = flags ? ucv_to_integer(flags) : 0;

#ifdef __APPLE__
	peerfd = accept(sockfd, (struct sockaddr *)&ss, &slen);

	if (peerfd == -1)
		err_return(errno, "accept()");

	if (sockflags & SOCK_CLOEXEC) {
		if (fcntl(peerfd, F_SETFD, FD_CLOEXEC) == -1) {
			close(peerfd);
			err_return(errno, "fcntl(F_SETFD)");
		}
	}

	if (sockflags & SOCK_NONBLOCK) {
		sockflags = fcntl(peerfd, F_GETFL);

		if (sockflags == -1) {
			close(peerfd);
			err_return(errno, "fcntl(F_GETFL)");
		}

		if (fcntl(peerfd, F_SETFL, sockflags | O_NONBLOCK) == -1) {
			close(peerfd);
			err_return(errno, "fcntl(F_SETFL)");
		}
	}
#else
	peerfd = accept4(sockfd, (struct sockaddr *)&ss, &slen, sockflags);

	if (peerfd == -1)
		err_return(errno, "accept4()");
#endif

	if (addrobj)
		sockaddr_to_uv(&ss, addrobj);

	ok_return(ucv_socket_new(vm, peerfd));
}

/**
 * Shutdown part of a full-duplex connection.
 *
 * This function shuts down part of the full-duplex connection associated with
 * the socket handle. The `how` parameter specifies which half of the connection
 * to shut down. It can take one of the following constant values:
 *
 * - `SHUT_RD`: Disables further receive operations.
 * - `SHUT_WR`: Disables further send operations.
 * - `SHUT_RDWR`: Disables further send and receive operations.
 *
 * Returns `true` if the shutdown operation is successful.
 * Returns `null` if an error occurred.
 *
 * @function module:socket.socket#shutdown
 *
 * @param {number} how
 * Specifies which half of the connection to shut down.
 * It can be one of the following constant values: `SHUT_RD`, `SHUT_WR`,
 * or `SHUT_RDWR`.
 *
 * @returns {?boolean}
 *
 * @example
 * const sock = socket.create(…);
 * sock.connect(…);
 * // Perform data exchange…
 *
 * const success = sock.shutdown(socket.SHUT_WR);
 * if (success)
 *     print(`Send operations on socket shut down successfully.\n`);
 * else
 *     print(`Failed to shut down send operations: ${sock.error()}\n`);
 */
static uc_value_t *
uc_socket_inst_shutdown(uc_vm_t *vm, size_t nargs)
{
	uc_value_t *how;
	int sockfd, ret;

	args_get(vm, nargs, &sockfd,
		"how", UC_INTEGER, true, &how);

	ret = shutdown(sockfd, ucv_int64_get(how));

	if (ret == -1)
		err_return(errno, "shutdown()");

	ok_return(ucv_boolean_new(true));
}

/**
 * Represents a credentials information object returned by
 * {@link module:socket.socket#peercred|`peercred()`}.
 *
 * @typedef {Object} module:socket.socket.PeerCredentials
 * @property {number} uid
 * The effective user ID the remote socket endpoint.
 *
 * @property {number} gid
 * The effective group ID the remote socket endpoint.
 *
 * @property {number} pid
 * The ID of the process the remote socket endpoint belongs to.
 */

/**
 * Retrieves the peer credentials.
 *
 * This function retrieves the remote uid, gid and pid of a connected UNIX
 * domain socket.
 *
 * Returns the remote credentials if the operation is successful.
 * Returns `null` on error.
 *
 * @function module:socket.socket#peercred
 *
 * @returns {?module:socket.socket.PeerCredentials}
 *
 * @example
 * const sock = socket.create(socket.AF_UNIX, …);
 * sock.connect(…);
 *
 * const peerCredentials = sock.peercred();
 * if (peerCredentials)
 *     print(`Peer credentials: ${peerCredentials}\n`);
 * else
 *     print(`Failed to retrieve peer credentials: ${sock.error()}\n`);
 */
static uc_value_t *
uc_socket_inst_peercred(uc_vm_t *vm, size_t nargs)
{
	uc_value_t *rv = NULL;
	socklen_t optlen;
	int ret, sockfd;

	args_get(vm, nargs, &sockfd);

#if defined(__linux__)
	struct ucred cred;

	optlen = sizeof(cred);
	ret = getsockopt(sockfd, SOL_SOCKET, SO_PEERCRED, &cred, &optlen);

	if (ret == -1)
		err_return(errno, "getsockopt()");

	if (optlen != sizeof(cred))
		err_return(EINVAL, "Invalid credentials received");

	rv = ucv_object_new(vm);

	ucv_object_add(rv, "uid", ucv_uint64_new(cred.uid));
	ucv_object_add(rv, "gid", ucv_uint64_new(cred.gid));
	ucv_object_add(rv, "pid", ucv_int64_new(cred.pid));
#elif defined(__APPLE__)
	struct xucred cred;
	pid_t pid;

	optlen = sizeof(cred);
	ret = getsockopt(sockfd, SOL_LOCAL, LOCAL_PEERCRED, &cred, &optlen);

	if (ret == -1)
		err_return(errno, "getsockopt(LOCAL_PEERCRED)");

	if (optlen != sizeof(cred) || cred.cr_version != XUCRED_VERSION)
		err_return(EINVAL, "Invalid credentials received");

	rv = ucv_object_new(vm);

	ucv_object_add(rv, "uid", ucv_uint64_new(cred.cr_uid));
	ucv_object_add(rv, "gid", ucv_uint64_new(cred.cr_gid));

	optlen = sizeof(pid);
	ret = getsockopt(sockfd, SOL_LOCAL, LOCAL_PEERPID, &pid, &optlen);

	if (ret == -1) {
		ucv_put(rv);
		err_return(errno, "getsockopt(LOCAL_PEERPID)");
	}

	ucv_object_add(rv, "pid", ucv_int64_new(pid));
#else
	err_return(ENOSYS, "Operation not supported on this system");
#endif

	ok_return(rv);
}

/**
 * Retrieves the remote address.
 *
 * This function retrieves the remote address of a connected socket.
 *
 * Returns the remote address if the operation is successful.
 * Returns `null` on error.
 *
 * @function module:socket.socket#peername
 *
 * @returns {?module:socket.socket.SocketAddress}
 *
 * @see {@link module:socket.socket#sockname|sockname()}
 *
 * @example
 * const sock = socket.create(…);
 * sock.connect(…);
 *
 * const peerAddress = sock.peername();
 * if (peerAddress)
 *     print(`Connected to ${peerAddress}\n`);
 * else
 *     print(`Failed to retrieve peer address: ${sock.error()}\n`);
 */
static uc_value_t *
uc_socket_inst_peername(uc_vm_t *vm, size_t nargs)
{
	struct sockaddr_storage ss = { 0 };
	uc_value_t *addr;
	socklen_t sslen;
	int sockfd, ret;

	args_get(vm, nargs, &sockfd);

	sslen = sizeof(ss);
	ret = getpeername(sockfd, (struct sockaddr *)&ss, &sslen);

	if (ret == -1)
		err_return(errno, "getpeername()");

	addr = ucv_object_new(vm);
	sockaddr_to_uv(&ss, addr);

	ok_return(addr);
}

/**
 * Retrieves the local address.
 *
 * This function retrieves the local address of a bound or connected socket.
 *
 * Returns the local address if the operation is successful.
 * Returns `null` on error.
 *
 * @function module:socket.socket#sockname
 *
 * @returns {?module:socket.socket.SocketAddress}
 *
 * @see {@link module:socket.socket#peername|peername()}
 *
 * @example
 * const sock = socket.create(…);
 * sock.connect(…);
 *
 * const myAddress = sock.sockname();
 * if (myAddress)
 *     print(`My source IP address is ${myAddress}\n`);
 * else
 *     print(`Failed to retrieve peer address: ${sock.error()}\n`);
 */
static uc_value_t *
uc_socket_inst_sockname(uc_vm_t *vm, size_t nargs)
{
	struct sockaddr_storage ss = { 0 };
	uc_value_t *addr;
	socklen_t sslen;
	int sockfd, ret;

	args_get(vm, nargs, &sockfd);

	sslen = sizeof(ss);
	ret = getsockname(sockfd, (struct sockaddr *)&ss, &sslen);

	if (ret == -1)
		err_return(errno, "getsockname()");

	addr = ucv_object_new(vm);
	sockaddr_to_uv(&ss, addr);

	ok_return(addr);
}

/**
 * Closes the socket.
 *
 * This function closes the socket, releasing its resources and terminating its
 * associated connections.
 *
 * Returns `true` if the socket was successfully closed.
 * Returns `null` on error.
 *
 * @function module:socket.socket#close
 *
 * @returns {?boolean}
 *
 * @example
 * const sock = socket.create(…);
 * sock.connect(…);
 * // Perform operations with the socket…
 * sock.close();
 */
static uc_value_t *
uc_socket_inst_close(uc_vm_t *vm, size_t nargs)
{
	int *sockfd = uc_fn_this("socket");

	if (!sockfd || *sockfd == -1)
		err_return(EBADF, "Invalid socket context");

	if (!xclose(sockfd))
		err_return(errno, "close()");

	ok_return(ucv_boolean_new(true));
}

static void
close_socket(void *ud)
{
	int fd = (intptr_t)ud;

	if (fd != -1)
		close(fd);
}

static const uc_function_list_t socket_fns[] = {
	{ "connect",	uc_socket_inst_connect },
	{ "bind",		uc_socket_inst_bind },
	{ "listen",		uc_socket_inst_listen },
	{ "accept",		uc_socket_inst_accept },
	{ "send",		uc_socket_inst_send },
	{ "sendmsg",	uc_socket_inst_sendmsg },
	{ "recv",	    uc_socket_inst_recv },
	{ "recvmsg",	uc_socket_inst_recvmsg },
	{ "setopt",		uc_socket_inst_setopt },
	{ "getopt",		uc_socket_inst_getopt },
	{ "fileno",		uc_socket_inst_fileno },
	{ "shutdown",	uc_socket_inst_shutdown },
	{ "peercred",	uc_socket_inst_peercred },
	{ "peername",	uc_socket_inst_peername },
	{ "sockname",	uc_socket_inst_sockname },
	{ "close",		uc_socket_inst_close },
	{ "error",		uc_socket_error },
};

static const uc_function_list_t global_fns[] = {
	{ "sockaddr",	uc_socket_sockaddr },
	{ "create",		uc_socket_create },
	{ "pair",		uc_socket_pair },
	{ "nameinfo",	uc_socket_nameinfo },
	{ "addrinfo",	uc_socket_addrinfo },
	{ "poll",		uc_socket_poll },
	{ "connect",	uc_socket_connect },
	{ "listen",		uc_socket_listen },
	{ "error",		uc_socket_error },
	{ "strerror",	uc_socket_strerror },
};

void uc_module_init(uc_vm_t *vm, uc_value_t *scope)
{
	uc_function_list_register(scope, global_fns);

#define ADD_CONST(x) ucv_object_add(scope, #x, ucv_int64_new(x))

	/**
	 * @typedef
	 * @name Address Families
	 * @description Constants representing address families and socket domains.
	 * @property {number} AF_UNSPEC - Unspecified address family.
	 * @property {number} AF_UNIX - UNIX domain sockets.
	 * @property {number} AF_INET - IPv4 Internet protocols.
	 * @property {number} AF_INET6 - IPv6 Internet protocols.
	 * @property {number} AF_PACKET - Low-level packet interface.
	 */
	ADD_CONST(AF_UNSPEC);
	ADD_CONST(AF_UNIX);
	ADD_CONST(AF_INET);
	ADD_CONST(AF_INET6);
#if defined(__linux__)
	ADD_CONST(AF_PACKET);
#endif

	/**
	 * @typedef
	 * @name Socket Types
	 * @description
	 * The `SOCK_*` type and flag constants are used by
	 * {@link module:socket#create|create()} to specify the type of socket to
	 * open. The {@link module:socket.socket#accept|accept()} function
	 * recognizes the `SOCK_NONBLOCK` and `SOCK_CLOEXEC` flags and applies them
	 * to accepted peer sockets.
	 * @property {number} SOCK_STREAM - Provides sequenced, reliable, two-way, connection-based byte streams.
	 * @property {number} SOCK_DGRAM - Supports datagrams (connectionless, unreliable messages of a fixed maximum length).
	 * @property {number} SOCK_RAW - Provides raw network protocol access.
	 * @property {number} SOCK_PACKET - Obsolete and should not be used.
	 * @property {number} SOCK_NONBLOCK - Enables non-blocking operation.
	 * @property {number} SOCK_CLOEXEC - Sets the close-on-exec flag on the new file descriptor.
	 */
	ADD_CONST(SOCK_STREAM);
	ADD_CONST(SOCK_DGRAM);
	ADD_CONST(SOCK_RAW);
	ADD_CONST(SOCK_NONBLOCK);
	ADD_CONST(SOCK_CLOEXEC);
#if defined(__linux__)
	ADD_CONST(SOCK_PACKET);
#endif

	/**
	 * @typedef
	 * @name Message Flags
	 * @description
	 * The `MSG_*` flag constants are commonly used in conjunction with the
	 * {@link module:socket.socket#send|send()} and
	 * {@link module:socket.socket#recv|recv()} functions.
	 * @property {number} MSG_CONFIRM - Confirm path validity.
	 * @property {number} MSG_DONTROUTE - Send without using routing tables.
	 * @property {number} MSG_DONTWAIT - Enables non-blocking operation.
	 * @property {number} MSG_EOR - End of record.
	 * @property {number} MSG_MORE - Sender will send more.
	 * @property {number} MSG_NOSIGNAL - Do not generate SIGPIPE.
	 * @property {number} MSG_OOB - Process out-of-band data.
	 * @property {number} MSG_FASTOPEN - Send data in TCP SYN.
	 * @property {number} MSG_CMSG_CLOEXEC - Sets the close-on-exec flag on the received file descriptor.
	 * @property {number} MSG_ERRQUEUE - Receive errors from ICMP.
	 * @property {number} MSG_PEEK - Peeks at incoming messages.
	 * @property {number} MSG_TRUNC - Report if datagram truncation occurred.
	 * @property {number} MSG_WAITALL - Wait for full message.
	 */
	ADD_CONST(MSG_DONTROUTE);
	ADD_CONST(MSG_DONTWAIT);
	ADD_CONST(MSG_EOR);
	ADD_CONST(MSG_NOSIGNAL);
	ADD_CONST(MSG_OOB);
	ADD_CONST(MSG_PEEK);
	ADD_CONST(MSG_TRUNC);
	ADD_CONST(MSG_WAITALL);
#if defined(__linux__)
	ADD_CONST(MSG_CONFIRM);
	ADD_CONST(MSG_MORE);
	ADD_CONST(MSG_FASTOPEN);
	ADD_CONST(MSG_CMSG_CLOEXEC);
	ADD_CONST(MSG_ERRQUEUE);
#endif

	/**
	 * @typedef
	 * @name IP Protocol Constants
	 * @description
	 * The `IPPROTO_IP` constant specifies the IP protocol number and may be
	 * passed as third argument to {@link module:socket#create|create()} as well
	 * as *level* argument value to {@link module:socket.socket#getopt|getopt()}
	 * and {@link module:socket.socket#setopt|setopt()}.
	 *
	 * The `IP_*` constants are option names recognized by
	 * {@link module:socket.socket#getopt|getopt()}
	 * and {@link module:socket.socket#setopt|setopt()}, in conjunction with
	 * the `IPPROTO_IP` socket level.
	 * @property {number} IPPROTO_IP - Dummy protocol for IP.
	 * @property {number} IP_ADD_MEMBERSHIP - Add an IP group membership.
	 * @property {number} IP_ADD_SOURCE_MEMBERSHIP - Add an IP group/source membership.
	 * @property {number} IP_BIND_ADDRESS_NO_PORT - Bind to the device only.
	 * @property {number} IP_BLOCK_SOURCE - Block IP group/source.
	 * @property {number} IP_DROP_MEMBERSHIP - Drop an IP group membership.
	 * @property {number} IP_DROP_SOURCE_MEMBERSHIP - Drop an IP group/source membership.
	 * @property {number} IP_FREEBIND - Allow binding to an IP address not assigned to a network interface.
	 * @property {number} IP_HDRINCL - Header is included with data.
	 * @property {number} IP_MSFILTER - Filter IP multicast source memberships.
	 * @property {number} IP_MTU - Path MTU discovery.
	 * @property {number} IP_MTU_DISCOVER - Control Path MTU discovery.
	 * @property {number} IP_MULTICAST_ALL - Receive all multicast packets.
	 * @property {number} IP_MULTICAST_IF - Set outgoing interface for multicast packets.
	 * @property {number} IP_MULTICAST_LOOP - Control multicast packet looping.
	 * @property {number} IP_MULTICAST_TTL - Set time-to-live for outgoing multicast packets.
	 * @property {number} IP_NODEFRAG - Don't fragment IP packets.
	 * @property {number} IP_OPTIONS - Set/get IP options.
	 * @property {number} IP_PASSSEC - Pass security information.
	 * @property {number} IP_PKTINFO - Receive packet information.
	 * @property {number} IP_RECVERR - Receive all ICMP errors.
	 * @property {number} IP_RECVOPTS - Receive all IP options.
	 * @property {number} IP_RECVORIGDSTADDR - Receive original destination address of the socket.
	 * @property {number} IP_RECVTOS - Receive IP TOS.
	 * @property {number} IP_RECVTTL - Receive IP TTL.
	 * @property {number} IP_RETOPTS - Set/get IP options.
	 * @property {number} IP_ROUTER_ALERT - Receive ICMP msgs generated by router.
	 * @property {number} IP_TOS - IP type of service and precedence.
	 * @property {number} IP_TRANSPARENT - Transparent proxy support.
	 * @property {number} IP_TTL - IP time-to-live.
	 * @property {number} IP_UNBLOCK_SOURCE - Unblock IP group/source.
	 */
	ADD_CONST(IPPROTO_IP);
	ADD_CONST(IP_ADD_MEMBERSHIP);
	ADD_CONST(IP_ADD_SOURCE_MEMBERSHIP);
	ADD_CONST(IP_BLOCK_SOURCE);
	ADD_CONST(IP_DROP_MEMBERSHIP);
	ADD_CONST(IP_DROP_SOURCE_MEMBERSHIP);
	ADD_CONST(IP_HDRINCL);
	ADD_CONST(IP_MSFILTER);
	ADD_CONST(IP_MULTICAST_IF);
	ADD_CONST(IP_MULTICAST_LOOP);
	ADD_CONST(IP_MULTICAST_TTL);
	ADD_CONST(IP_OPTIONS);
	ADD_CONST(IP_PKTINFO);
	ADD_CONST(IP_RECVOPTS);
	ADD_CONST(IP_RECVTOS);
	ADD_CONST(IP_RECVTTL);
	ADD_CONST(IP_RETOPTS);
	ADD_CONST(IP_TOS);
	ADD_CONST(IP_TTL);
	ADD_CONST(IP_UNBLOCK_SOURCE);
#if defined(__linux__)
	ADD_CONST(IP_BIND_ADDRESS_NO_PORT);
	ADD_CONST(IP_FREEBIND);
	ADD_CONST(IP_MTU);
	ADD_CONST(IP_MTU_DISCOVER);
	ADD_CONST(IP_MULTICAST_ALL);
	ADD_CONST(IP_NODEFRAG);
	ADD_CONST(IP_PASSSEC);
	ADD_CONST(IP_RECVERR);
	ADD_CONST(IP_RECVORIGDSTADDR);
	ADD_CONST(IP_ROUTER_ALERT);
	ADD_CONST(IP_TRANSPARENT);
#endif

	/**
	 * @typedef {Object} IPv6 Protocol Constants
	 * @description
	 * The `IPPROTO_IPV6` constant specifies the IPv6 protocol number and may be
	 * passed as third argument to {@link module:socket#create|create()} as well
	 * as *level* argument value to {@link module:socket.socket#getopt|getopt()}
	 * and {@link module:socket.socket#setopt|setopt()}.
	 *
	 * The `IPV6_*` constants are option names recognized by
	 * {@link module:socket.socket#getopt|getopt()}
	 * and {@link module:socket.socket#setopt|setopt()}, in conjunction with
	 * the `IPPROTO_IPV6` socket level.
	 * @property {number} IPPROTO_IPV6 - The IPv6 protocol.
	 * @property {number} IPV6_ADDRFORM - Turn an AF_INET6 socket into a socket of a different address family. Only AF_INET is supported.
	 * @property {number} IPV6_ADDR_PREFERENCES - Specify preferences for address selection.
	 * @property {number} IPV6_ADD_MEMBERSHIP - Add an IPv6 group membership.
	 * @property {number} IPV6_AUTHHDR - Set delivery of the authentication header control message for incoming datagrams.
	 * @property {number} IPV6_AUTOFLOWLABEL - Enable or disable automatic flow labels.
	 * @property {number} IPV6_DONTFRAG - Control whether the socket allows IPv6 fragmentation.
	 * @property {number} IPV6_DROP_MEMBERSHIP - Drop an IPv6 group membership.
	 * @property {number} IPV6_DSTOPTS - Set delivery of the destination options control message for incoming datagrams.
	 * @property {number} IPV6_FLOWINFO_SEND - Control whether flow information is sent.
	 * @property {number} IPV6_FLOWINFO - Set delivery of the flow ID control message for incoming datagrams.
	 * @property {number} IPV6_FLOWLABEL_MGR - Manage flow labels.
	 * @property {number} IPV6_FREEBIND - Allow binding to an IP address not assigned to a network interface.
	 * @property {number} IPV6_HOPLIMIT - Set delivery of the hop limit control message for incoming datagrams.
	 * @property {number} IPV6_HOPOPTS - Set delivery of the hop options control message for incoming datagrams.
	 * @property {number} IPV6_JOIN_ANYCAST - Join an anycast group.
	 * @property {number} IPV6_LEAVE_ANYCAST - Leave an anycast group.
	 * @property {number} IPV6_MINHOPCOUNT - Set the minimum hop count.
	 * @property {number} IPV6_MTU - Retrieve or set the MTU to be used for the socket.
	 * @property {number} IPV6_MTU_DISCOVER - Control path-MTU discovery on the socket.
	 * @property {number} IPV6_MULTICAST_ALL - Control whether the socket receives all multicast packets.
	 * @property {number} IPV6_MULTICAST_HOPS - Set the multicast hop limit for the socket.
	 * @property {number} IPV6_MULTICAST_IF - Set the device for outgoing multicast packets on the socket.
	 * @property {number} IPV6_MULTICAST_LOOP - Control whether the socket sees multicast packets that it has sent itself.
	 * @property {number} IPV6_PKTINFO - Set delivery of the IPV6_PKTINFO control message on incoming datagrams.
	 * @property {number} IPV6_RECVDSTOPTS - Control receiving of the destination options control message.
	 * @property {number} IPV6_RECVERR - Control receiving of asynchronous error options.
	 * @property {number} IPV6_RECVFRAGSIZE - Control receiving of fragment size.
	 * @property {number} IPV6_RECVHOPLIMIT - Control receiving of hop limit.
	 * @property {number} IPV6_RECVHOPOPTS - Control receiving of hop options.
	 * @property {number} IPV6_RECVORIGDSTADDR - Control receiving of the original destination address.
	 * @property {number} IPV6_RECVPATHMTU - Control receiving of path MTU.
	 * @property {number} IPV6_RECVPKTINFO - Control receiving of packet information.
	 * @property {number} IPV6_RECVRTHDR - Control receiving of routing header.
	 * @property {number} IPV6_RECVTCLASS - Control receiving of traffic class.
	 * @property {number} IPV6_ROUTER_ALERT_ISOLATE - Control isolation of router alert messages.
	 * @property {number} IPV6_ROUTER_ALERT - Pass forwarded packets containing a router alert hop-by-hop option to this socket.
	 * @property {number} IPV6_RTHDR - Set delivery of the routing header control message for incoming datagrams.
	 * @property {number} IPV6_RTHDRDSTOPTS - Set delivery of the routing header destination options control message.
	 * @property {number} IPV6_TCLASS - Set the traffic class.
	 * @property {number} IPV6_TRANSPARENT - Enable transparent proxy support.
	 * @property {number} IPV6_UNICAST_HOPS - Set the unicast hop limit for the socket.
	 * @property {number} IPV6_UNICAST_IF - Set the interface for outgoing unicast packets.
	 * @property {number} IPV6_V6ONLY - Restrict the socket to sending and receiving IPv6 packets only.
	 */
	ADD_CONST(IPPROTO_IPV6);
	ADD_CONST(IPV6_FLOWINFO_SEND);
	ADD_CONST(IPV6_FLOWINFO);
	ADD_CONST(IPV6_FLOWLABEL_MGR);
	ADD_CONST(IPV6_MULTICAST_HOPS);
	ADD_CONST(IPV6_MULTICAST_IF);
	ADD_CONST(IPV6_MULTICAST_LOOP);
	ADD_CONST(IPV6_RECVTCLASS);
	ADD_CONST(IPV6_TCLASS);
	ADD_CONST(IPV6_UNICAST_HOPS);
	ADD_CONST(IPV6_V6ONLY);
#if defined(__linux__)
	ADD_CONST(IPV6_ADD_MEMBERSHIP);
	ADD_CONST(IPV6_ADDR_PREFERENCES);
	ADD_CONST(IPV6_ADDRFORM);
	ADD_CONST(IPV6_AUTHHDR);
	ADD_CONST(IPV6_AUTOFLOWLABEL);
	ADD_CONST(IPV6_DONTFRAG);
	ADD_CONST(IPV6_DROP_MEMBERSHIP);
	ADD_CONST(IPV6_DSTOPTS);
	ADD_CONST(IPV6_FREEBIND);
	ADD_CONST(IPV6_HOPLIMIT);
	ADD_CONST(IPV6_HOPOPTS);
	ADD_CONST(IPV6_JOIN_ANYCAST);
	ADD_CONST(IPV6_LEAVE_ANYCAST);
	ADD_CONST(IPV6_MINHOPCOUNT);
	ADD_CONST(IPV6_MTU_DISCOVER);
	ADD_CONST(IPV6_MTU);
	ADD_CONST(IPV6_MULTICAST_ALL);
	ADD_CONST(IPV6_PKTINFO);
	ADD_CONST(IPV6_RECVDSTOPTS);
	ADD_CONST(IPV6_RECVERR);
	ADD_CONST(IPV6_RECVFRAGSIZE);
	ADD_CONST(IPV6_RECVHOPLIMIT);
	ADD_CONST(IPV6_RECVHOPOPTS);
	ADD_CONST(IPV6_RECVORIGDSTADDR);
	ADD_CONST(IPV6_RECVPATHMTU);
	ADD_CONST(IPV6_RECVPKTINFO);
	ADD_CONST(IPV6_RECVRTHDR);
	ADD_CONST(IPV6_ROUTER_ALERT_ISOLATE);
	ADD_CONST(IPV6_ROUTER_ALERT);
	ADD_CONST(IPV6_RTHDR);
	ADD_CONST(IPV6_RTHDRDSTOPTS);
	ADD_CONST(IPV6_TRANSPARENT);
	ADD_CONST(IPV6_UNICAST_IF);
#endif

	/**
	 * @typedef
	 * @name Socket Option Constants
	 * @description
	 * The `SOL_SOCKET` constant is passed as *level* argument to the
	 * {@link module:socket.socket#getopt|getopt()} and
	 * {@link module:socket.socket#setopt|setopt()} functions in order to set
	 * or retrieve generic socket option values.
	 *
	 * The `SO_*` constants are passed as *option* argument in conjunction with
	 * the `SOL_SOCKET` level to specify the specific option to get or set on
	 * the socket.
	 * @property {number} SOL_SOCKET - Socket options at the socket API level.
	 * @property {number} SO_ACCEPTCONN - Reports whether socket listening is enabled.
	 * @property {number} SO_ATTACH_BPF - Attach BPF program to socket.
	 * @property {number} SO_ATTACH_FILTER - Attach a socket filter.
	 * @property {number} SO_ATTACH_REUSEPORT_CBPF - Attach BPF program for cgroup and skb program reuseport hook.
	 * @property {number} SO_ATTACH_REUSEPORT_EBPF - Attach eBPF program for cgroup and skb program reuseport hook.
	 * @property {number} SO_BINDTODEVICE - Bind socket to a specific interface.
	 * @property {number} SO_BROADCAST - Allow transmission of broadcast messages.
	 * @property {number} SO_BUSY_POLL - Enable busy polling.
	 * @property {number} SO_DEBUG - Enable socket debugging.
	 * @property {number} SO_DETACH_BPF - Detach BPF program from socket.
	 * @property {number} SO_DETACH_FILTER - Detach a socket filter.
	 * @property {number} SO_DOMAIN - Retrieves the domain of the socket.
	 * @property {number} SO_DONTROUTE - Send packets directly without routing.
	 * @property {number} SO_ERROR - Retrieves and clears the error status for the socket.
	 * @property {number} SO_INCOMING_CPU - Retrieves the CPU number on which the last packet was received.
	 * @property {number} SO_INCOMING_NAPI_ID - Retrieves the NAPI ID of the device.
	 * @property {number} SO_KEEPALIVE - Enable keep-alive packets.
	 * @property {number} SO_LINGER - Set linger on close.
	 * @property {number} SO_LOCK_FILTER - Set or get the socket filter lock state.
	 * @property {number} SO_MARK - Set the mark for packets sent through the socket.
	 * @property {number} SO_OOBINLINE - Enables out-of-band data to be received in the normal data stream.
	 * @property {number} SO_PASSCRED - Enable the receiving of SCM_CREDENTIALS control messages.
	 * @property {number} SO_PASSSEC - Enable the receiving of security context.
	 * @property {number} SO_PEEK_OFF - Returns the number of bytes in the receive buffer without removing them.
	 * @property {number} SO_PEERCRED - Retrieves the credentials of the foreign peer.
	 * @property {number} SO_PEERSEC - Retrieves the security context of the foreign peer.
	 * @property {number} SO_PRIORITY - Set the protocol-defined priority for all packets.
	 * @property {number} SO_PROTOCOL - Retrieves the protocol number.
	 * @property {number} SO_RCVBUF - Set the receive buffer size.
	 * @property {number} SO_RCVBUFFORCE - Set the receive buffer size forcefully.
	 * @property {number} SO_RCVLOWAT - Set the minimum number of bytes to process for input operations.
	 * @property {number} SO_RCVTIMEO - Set the timeout for receiving data.
	 * @property {number} SO_REUSEADDR - Allow the socket to be bound to an address that is already in use.
	 * @property {number} SO_REUSEPORT - Enable duplicate address and port bindings.
	 * @property {number} SO_RXQ_OVFL - Reports if the receive queue has overflown.
	 * @property {number} SO_SNDBUF - Set the send buffer size.
	 * @property {number} SO_SNDBUFFORCE - Set the send buffer size forcefully.
	 * @property {number} SO_SNDLOWAT - Set the minimum number of bytes to process for output operations.
	 * @property {number} SO_SNDTIMEO - Set the timeout for sending data.
	 * @property {number} SO_TIMESTAMP - Enable receiving of timestamps.
	 * @property {number} SO_TIMESTAMPNS - Enable receiving of nanosecond timestamps.
	 * @property {number} SO_TYPE - Retrieves the type of the socket (e.g., SOCK_STREAM).
	 */
	ADD_CONST(SOL_SOCKET);
	ADD_CONST(SO_ACCEPTCONN);
	ADD_CONST(SO_BROADCAST);
	ADD_CONST(SO_DEBUG);
	ADD_CONST(SO_DONTROUTE);
	ADD_CONST(SO_ERROR);
	ADD_CONST(SO_KEEPALIVE);
	ADD_CONST(SO_LINGER);
	ADD_CONST(SO_OOBINLINE);
	ADD_CONST(SO_RCVBUF);
	ADD_CONST(SO_RCVLOWAT);
	ADD_CONST(SO_RCVTIMEO);
	ADD_CONST(SO_REUSEADDR);
	ADD_CONST(SO_REUSEPORT);
	ADD_CONST(SO_SNDBUF);
	ADD_CONST(SO_SNDLOWAT);
	ADD_CONST(SO_SNDTIMEO);
	ADD_CONST(SO_TIMESTAMP);
	ADD_CONST(SO_TYPE);
#if defined(__linux__)
	ADD_CONST(SO_ATTACH_BPF);
	ADD_CONST(SO_ATTACH_FILTER);
	ADD_CONST(SO_ATTACH_REUSEPORT_CBPF);
	ADD_CONST(SO_ATTACH_REUSEPORT_EBPF);
	ADD_CONST(SO_BINDTODEVICE);
	ADD_CONST(SO_BUSY_POLL);
	ADD_CONST(SO_DETACH_BPF);
	ADD_CONST(SO_DETACH_FILTER);
	ADD_CONST(SO_DOMAIN);
	ADD_CONST(SO_INCOMING_CPU);
	ADD_CONST(SO_INCOMING_NAPI_ID);
	ADD_CONST(SO_LOCK_FILTER);
	ADD_CONST(SO_MARK);
	ADD_CONST(SO_PASSCRED);
	ADD_CONST(SO_PASSSEC);
	ADD_CONST(SO_PEEK_OFF);
	ADD_CONST(SO_PEERCRED);
	ADD_CONST(SO_PEERSEC);
	ADD_CONST(SO_PRIORITY);
	ADD_CONST(SO_PROTOCOL);
	ADD_CONST(SO_RCVBUFFORCE);
	ADD_CONST(SO_RXQ_OVFL);
	ADD_CONST(SO_SNDBUFFORCE);
	ADD_CONST(SO_TIMESTAMPNS);

	ADD_CONST(SCM_CREDENTIALS);
	ADD_CONST(SCM_RIGHTS);
#endif

	/**
	 * @typedef
	 * @name TCP Protocol Constants
	 * @description
	 * The `IPPROTO_TCP` constant specifies the TCP protocol number and may be
	 * passed as third argument to {@link module:socket#create|create()} as well
	 * as *level* argument value to {@link module:socket.socket#getopt|getopt()}
	 * and {@link module:socket.socket#setopt|setopt()}.
	 *
	 * The `TCP_*` constants are *option* argument values recognized by
	 * {@link module:socket.socket#getopt|getopt()}
	 * and {@link module:socket.socket#setopt|setopt()}, in conjunction with
	 * the `IPPROTO_TCP` socket level.
	 * @property {number} IPPROTO_TCP - TCP protocol.
	 * @property {number} TCP_CONGESTION - Set the congestion control algorithm.
	 * @property {number} TCP_CORK - Delay packet transmission until full-sized packets are available.
	 * @property {number} TCP_DEFER_ACCEPT - Delay accepting incoming connections until data arrives.
	 * @property {number} TCP_FASTOPEN - Enable TCP Fast Open.
	 * @property {number} TCP_FASTOPEN_CONNECT - Perform TFO connect.
	 * @property {number} TCP_INFO - Retrieve TCP statistics.
	 * @property {number} TCP_KEEPCNT - Number of keepalive probes.
	 * @property {number} TCP_KEEPIDLE - Time before keepalive probes begin.
	 * @property {number} TCP_KEEPINTVL - Interval between keepalive probes.
	 * @property {number} TCP_LINGER2 - Lifetime of orphaned FIN_WAIT2 state sockets.
	 * @property {number} TCP_MAXSEG - Maximum segment size.
	 * @property {number} TCP_NODELAY - Disable Nagle's algorithm.
	 * @property {number} TCP_QUICKACK - Enable quick ACKs.
	 * @property {number} TCP_SYNCNT - Number of SYN retransmits.
	 * @property {number} TCP_USER_TIMEOUT - Set the user timeout.
	 * @property {number} TCP_WINDOW_CLAMP - Set the maximum window.
	 */
	ADD_CONST(IPPROTO_TCP);
	ADD_CONST(TCP_FASTOPEN);
	ADD_CONST(TCP_KEEPCNT);
	ADD_CONST(TCP_KEEPINTVL);
	ADD_CONST(TCP_MAXSEG);
	ADD_CONST(TCP_NODELAY);
#if defined(__linux__)
	ADD_CONST(TCP_CONGESTION);
	ADD_CONST(TCP_CORK);
	ADD_CONST(TCP_DEFER_ACCEPT);
	ADD_CONST(TCP_FASTOPEN_CONNECT);
	ADD_CONST(TCP_INFO);
	ADD_CONST(TCP_KEEPIDLE);
	ADD_CONST(TCP_LINGER2);
	ADD_CONST(TCP_QUICKACK);
	ADD_CONST(TCP_SYNCNT);
	ADD_CONST(TCP_USER_TIMEOUT);
	ADD_CONST(TCP_WINDOW_CLAMP);
#endif

	/**
	 * @typedef
	 * @name Packet Socket Constants
	 * @description
	 * The `SOL_PACKET` constant specifies the packet socket level and may be
	 * passed as *level* argument value to
	 * {@link module:socket.socket#getopt|getopt()} and
	 * {@link module:socket.socket#setopt|setopt()}.
	 *
	 * Most `PACKET_*` constants are *option* argument values recognized by
	 * {@link module:socket.socket#getopt|getopt()}
	 * and {@link module:socket.socket#setopt|setopt()}, in conjunction with
	 * the `SOL_PACKET` socket level.
	 *
	 * The constants `PACKET_MR_PROMISC`, `PACKET_MR_MULTICAST` and
	 * `PACKET_MR_ALLMULTI` are used in conjunction with the
	 * `PACKET_ADD_MEMBERSHIP` and `PACKET_DROP_MEMBERSHIP` options to specify
	 * the packet socket receive mode.
	 *
	 * The constants `PACKET_HOST`, `PACKET_BROADCAST`, `PACKET_MULTICAST`,
	 * `PACKET_OTHERHOST` and `PACKET_OUTGOING` may be used as *packet_type*
	 * value in {@link module:socket.socket.SocketAddress|socket address}
	 * structures.
	 * @property {number} SOL_PACKET - Socket options at the packet API level.
	 * @property {number} PACKET_ADD_MEMBERSHIP - Add a multicast group membership.
	 * @property {number} PACKET_DROP_MEMBERSHIP - Drop a multicast group membership.
	 * @property {number} PACKET_AUXDATA - Receive auxiliary data (packet info).
	 * @property {number} PACKET_FANOUT - Configure packet fanout.
	 * @property {number} PACKET_LOSS - Retrieve the current packet loss statistics.
	 * @property {number} PACKET_RESERVE - Reserve space for packet headers.
	 * @property {number} PACKET_RX_RING - Configure a receive ring buffer.
	 * @property {number} PACKET_STATISTICS - Retrieve packet statistics.
	 * @property {number} PACKET_TIMESTAMP - Retrieve packet timestamps.
	 * @property {number} PACKET_TX_RING - Configure a transmit ring buffer.
	 * @property {number} PACKET_VERSION - Set the packet protocol version.
	 * @property {number} PACKET_QDISC_BYPASS - Bypass queuing discipline for outgoing packets.
	 *
	 * @property {number} PACKET_MR_PROMISC - Enable promiscuous mode.
	 * @property {number} PACKET_MR_MULTICAST - Receive multicast packets.
	 * @property {number} PACKET_MR_ALLMULTI - Receive all multicast packets.
	 *
	 * @property {number} PACKET_HOST - Receive packets destined for this host.
	 * @property {number} PACKET_BROADCAST - Receive broadcast packets.
	 * @property {number} PACKET_MULTICAST - Receive multicast packets.
	 * @property {number} PACKET_OTHERHOST - Receive packets destined for other hosts.
	 * @property {number} PACKET_OUTGOING - Transmit packets.
	 */
#if defined(__linux__)
	ADD_CONST(SOL_PACKET);
	ADD_CONST(PACKET_ADD_MEMBERSHIP);
	ADD_CONST(PACKET_DROP_MEMBERSHIP);
	ADD_CONST(PACKET_AUXDATA);
	ADD_CONST(PACKET_FANOUT);
	ADD_CONST(PACKET_LOSS);
	ADD_CONST(PACKET_RESERVE);
	ADD_CONST(PACKET_RX_RING);
	ADD_CONST(PACKET_STATISTICS);
	ADD_CONST(PACKET_TIMESTAMP);
	ADD_CONST(PACKET_TX_RING);
	ADD_CONST(PACKET_VERSION);
	ADD_CONST(PACKET_QDISC_BYPASS);

	ADD_CONST(PACKET_MR_PROMISC);
	ADD_CONST(PACKET_MR_MULTICAST);
	ADD_CONST(PACKET_MR_ALLMULTI);

	ADD_CONST(PACKET_HOST);
	ADD_CONST(PACKET_BROADCAST);
	ADD_CONST(PACKET_MULTICAST);
	ADD_CONST(PACKET_OTHERHOST);
	ADD_CONST(PACKET_OUTGOING);
#endif

	/**
	 * @typedef
	 * @name UDP Protocol Constants
	 * @description
	 * The `IPPROTO_UDP` constant specifies the UDP protocol number and may be
	 * passed as third argument to {@link module:socket#create|create()} as well
	 * as *level* argument value to {@link module:socket.socket#getopt|getopt()}
	 * and {@link module:socket.socket#setopt|setopt()}.
	 *
	 * The `UDP_*` constants are *option* argument values recognized by
	 * {@link module:socket.socket#getopt|getopt()}
	 * and {@link module:socket.socket#setopt|setopt()}, in conjunction with
	 * the `IPPROTO_UDP` socket level.
	 * @property {number} IPPROTO_UDP - UDP protocol.
	 * @property {number} UDP_CORK - Cork data until flush.
	 */
	ADD_CONST(IPPROTO_UDP);
#if defined(__linux__)
	ADD_CONST(UDP_CORK);
#endif

	/**
	 * @typedef
	 * @name Shutdown Constants
	 * @description
	 * The `SHUT_*` constants are passed as argument to the
	 * {@link module:socket.socket#shutdown|shutdown()} function to specify
	 * which direction of a full duplex connection to shut down.
	 * @property {number} SHUT_RD - Disallow further receptions.
	 * @property {number} SHUT_WR - Disallow further transmissions.
	 * @property {number} SHUT_RDWR - Disallow further receptions and transmissions.
	 */
	ADD_CONST(SHUT_RD);
	ADD_CONST(SHUT_WR);
	ADD_CONST(SHUT_RDWR);

	/**
	 * @typedef
	 * @name Address Info Flags
	 * @description
	 * The `AI_*` flags may be passed as bitwise OR-ed number in the *flags*
	 * property of the *hints* dictionary argument of
	 * {@link module:socket#addrinfo|addrinfo()}.
	 * @property {number} AI_ADDRCONFIG - Address configuration flag.
	 * @property {number} AI_ALL - Return IPv4 and IPv6 socket addresses.
	 * @property {number} AI_CANONIDN - Canonicalize using the IDNA standard.
	 * @property {number} AI_CANONNAME - Fill in the canonical name field.
	 * @property {number} AI_IDN - Enable IDN encoding.
	 * @property {number} AI_NUMERICHOST - Prevent hostname resolution.
	 * @property {number} AI_NUMERICSERV - Prevent service name resolution.
	 * @property {number} AI_PASSIVE - Use passive socket.
	 * @property {number} AI_V4MAPPED - Map IPv6 addresses to IPv4-mapped format.
	 */
	ADD_CONST(AI_ADDRCONFIG);
	ADD_CONST(AI_ALL);
	ADD_CONST(AI_CANONIDN);
	ADD_CONST(AI_CANONNAME);
	ADD_CONST(AI_IDN);
	ADD_CONST(AI_NUMERICHOST);
	ADD_CONST(AI_NUMERICSERV);
	ADD_CONST(AI_PASSIVE);
	ADD_CONST(AI_V4MAPPED);

	/**
	 * @typedef
	 * @name Name Info Constants
	 * @description
	 * The `NI_*` flags may be passed as bitwise OR-ed number via the *flags*
	 * argument of {@link module:socket#nameinfo|nameinfo()}.
	 * @property {number} NI_DGRAM - Datagram socket type.
	 * @property {number} NI_IDN - Enable IDN encoding.
	 * @property {number} NI_NAMEREQD - Hostname resolution required.
	 * @property {number} NI_NOFQDN - Do not force fully qualified domain name.
	 * @property {number} NI_NUMERICHOST - Return numeric form of the hostname.
	 * @property {number} NI_NUMERICSERV - Return numeric form of the service name.
	 */
	ADD_CONST(NI_DGRAM);
	ADD_CONST(NI_IDN);
	ADD_CONST(NI_MAXHOST);
	ADD_CONST(NI_MAXSERV);
	ADD_CONST(NI_NAMEREQD);
	ADD_CONST(NI_NOFQDN);
	ADD_CONST(NI_NUMERICHOST);
	ADD_CONST(NI_NUMERICSERV);

	/**
	 * @typedef
	 * @name Poll Event Constants
	 * @description
	 * The following constants represent event types for polling operations and
	 * are set or returned as part of a
	 * {@link module:socket.PollSpec|PollSpec} tuple by the
	 * {@link module:socket#poll|poll()} function. When passed via an argument
	 * PollSpec to `poll()`, they specify the I/O events to watch for on the
	 * corresponding handle. When appearing in a PollSpec returned by `poll()`,
	 * they specify the I/O events that occurred on a watched handle.
	 * @property {number} POLLIN - Data available to read.
	 * @property {number} POLLPRI - Priority data available to read.
	 * @property {number} POLLOUT - Writable data available.
	 * @property {number} POLLERR - Error condition.
	 * @property {number} POLLHUP - Hang up.
	 * @property {number} POLLNVAL - Invalid request.
	 * @property {number} POLLRDHUP - Peer closed or shutdown writing.
	 */
	ADD_CONST(POLLIN);
	ADD_CONST(POLLPRI);
	ADD_CONST(POLLOUT);
	ADD_CONST(POLLERR);
	ADD_CONST(POLLHUP);
	ADD_CONST(POLLNVAL);
#if defined(__linux__)
	ADD_CONST(POLLRDHUP);
#endif

	uc_type_declare(vm, "socket", socket_fns, close_socket);
}
