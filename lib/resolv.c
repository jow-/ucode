/*
 * nslookup_lede - musl compatible replacement for busybox nslookup
 *
 * Copyright (C) 2017 Jo-Philipp Wich <jo@mein.io>
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

#include <stdio.h>
#include <resolv.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <poll.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <netdb.h>
#include <fcntl.h>

#include "ucode/module.h"

#define for_each_item(arr, item) \
	for (uc_value_t *_idx = NULL, *item = (ucv_type(arr) == UC_ARRAY) ? ucv_array_get(arr, 0) : arr; \
	     (uintptr_t)_idx < (ucv_type(arr) == UC_ARRAY ? ucv_array_length(arr) : (arr != NULL)); \
	     _idx = (void *)((uintptr_t)_idx + 1), item = ucv_array_get(arr, (uintptr_t)_idx))

#define err_return(code, ...) do { set_error(code, __VA_ARGS__); return NULL; } while(0)

static struct {
	int code;
	char *msg;
} last_error;

__attribute__((format(printf, 2, 3))) static void
set_error(int errcode, const char *fmt, ...) {
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

typedef struct {
	socklen_t len;
	union {
		struct sockaddr sa;
		struct sockaddr_in sin;
		struct sockaddr_in6 sin6;
	} u;
} addr_t;

typedef struct {
	const char *name;
	addr_t addr;
} ns_t;

typedef struct {
	char *name;
	size_t qlen, rlen;
	unsigned char query[512];
	int rcode;
} query_t;

typedef struct __attribute__((packed)) {
	uint8_t root_domain;
	uint16_t type;
	uint16_t edns_maxsize;
	uint8_t extended_rcode;
	uint8_t edns_version;
	uint16_t z;
	uint16_t data_length;
} opt_rr_t;

typedef struct {
	uint32_t qtypes;
	size_t n_ns;
	ns_t *ns;
	size_t n_queries;
	query_t *queries;
	uint32_t retries;
	uint32_t timeout;
	uint16_t edns_maxsize;
}  resolve_ctx_t;


static struct {
	int type;
	const char *name;
} qtypes[] = {
	{ ns_t_soa,   "SOA"   },
	{ ns_t_ns,    "NS"    },
	{ ns_t_a,     "A"     },
	{ ns_t_aaaa,  "AAAA"  },
	{ ns_t_cname, "CNAME" },
	{ ns_t_mx,    "MX"    },
	{ ns_t_txt,   "TXT"   },
	{ ns_t_srv,   "SRV"   },
	{ ns_t_ptr,   "PTR"   },
	{ ns_t_any,   "ANY"   },
	{ }
};

static const char *rcodes[] = {
	"NOERROR",
	"FORMERR",
	"SERVFAIL",
	"NXDOMAIN",
	"NOTIMP",
	"REFUSED",
	"YXDOMAIN",
	"YXRRSET",
	"NXRRSET",
	"NOTAUTH",
	"NOTZONE",
	"RESERVED11",
	"RESERVED12",
	"RESERVED13",
	"RESERVED14",
	"RESERVED15",
	"BADVERS"
};

static unsigned int default_port = 53;


static uc_value_t *
init_obj(uc_vm_t *vm, uc_value_t *obj, const char *key, uc_type_t type)
{
	uc_value_t *existing;

	existing = ucv_object_get(obj, key, NULL);

	if (existing == NULL) {
		switch (type) {
		case UC_ARRAY:
			existing = ucv_array_new(vm);
			break;

		case UC_OBJECT:
			existing = ucv_object_new(vm);
			break;

		default:
			return NULL;
		}

		ucv_object_add(obj, key, existing);
	}

	return existing;
}

static int
parse_reply(uc_vm_t *vm, uc_value_t *res_obj, const unsigned char *msg, size_t len)
{
	ns_msg handle;
	ns_rr rr;
	int i, n, rdlen;
	const char *key = NULL;
	char astr[INET6_ADDRSTRLEN], dname[MAXDNAME];
	const unsigned char *cp;
	uc_value_t *name_obj, *type_arr, *item;

	if (ns_initparse(msg, len, &handle) != 0) {
		set_error(errno, "Unable to parse reply packet");

		return -1;
	}

	for (i = 0; i < ns_msg_count(handle, ns_s_an); i++) {
		if (ns_parserr(&handle, ns_s_an, i, &rr) != 0) {
			set_error(errno, "Unable to parse resource record");

			return -1;
		}

		name_obj = init_obj(vm, res_obj, ns_rr_name(rr), UC_OBJECT);

		rdlen = ns_rr_rdlen(rr);

		switch (ns_rr_type(rr))
		{
		case ns_t_a:
			if (rdlen != 4) {
				set_error(EBADMSG, "Invalid A record length");

				return -1;
			}

			type_arr = init_obj(vm, name_obj, "A", UC_ARRAY);

			inet_ntop(AF_INET, ns_rr_rdata(rr), astr, sizeof(astr));
			ucv_array_push(type_arr, ucv_string_new(astr));
			break;

		case ns_t_aaaa:
			if (rdlen != 16) {
				set_error(EBADMSG, "Invalid AAAA record length");

				return -1;
			}

			type_arr = init_obj(vm, name_obj, "AAAA", UC_ARRAY);

			inet_ntop(AF_INET6, ns_rr_rdata(rr), astr, sizeof(astr));
			ucv_array_push(type_arr, ucv_string_new(astr));
			break;

		case ns_t_ns:
			if (!key)
				key = "NS";
			/* fall through */

		case ns_t_cname:
			if (!key)
				key = "CNAME";
			/* fall through */

		case ns_t_ptr:
			if (!key)
				key = "PTR";

			if (ns_name_uncompress(ns_msg_base(handle), ns_msg_end(handle),
				ns_rr_rdata(rr), dname, sizeof(dname)) < 0) {
				set_error(errno, "Unable to uncompress domain name");

				return -1;
			}

			type_arr = init_obj(vm, name_obj, key, UC_ARRAY);
			n = ucv_array_length(type_arr);
			item = n ? ucv_array_get(type_arr, n - 1) : NULL;

			if (!n || strcmp(ucv_string_get(item), dname))
				ucv_array_push(type_arr, ucv_string_new(dname));

			break;

		case ns_t_mx:
			if (rdlen < 2) {
				set_error(EBADMSG, "MX record too short");

				return -1;
			}

			n = ns_get16(ns_rr_rdata(rr));

			if (ns_name_uncompress(ns_msg_base(handle), ns_msg_end(handle),
				ns_rr_rdata(rr) + 2, dname, sizeof(dname)) < 0) {
				set_error(errno, "Unable to uncompress MX domain");

				return -1;
			}

			type_arr = init_obj(vm, name_obj, "MX", UC_ARRAY);
			item = ucv_array_new_length(vm, 2);
			ucv_array_push(item, ucv_int64_new(n));
			ucv_array_push(item, ucv_string_new(dname));
			ucv_array_push(type_arr, item);
			break;

		case ns_t_txt:
			if (rdlen < 1) {
				set_error(EBADMSG, "TXT record too short");

				return -1;
			}

			n = *(unsigned char *)ns_rr_rdata(rr);

			if (n > 0) {
				memset(dname, 0, sizeof(dname));
				memcpy(dname, ns_rr_rdata(rr) + 1, n);

				type_arr = init_obj(vm, name_obj, "TXT", UC_ARRAY);
				ucv_array_push(type_arr, ucv_string_new(dname));
			}
			break;

		case ns_t_srv:
			if (rdlen < 6) {
				set_error(EBADMSG, "SRV record too short");

				return -1;
			}

			cp = ns_rr_rdata(rr);
			n = ns_name_uncompress(ns_msg_base(handle), ns_msg_end(handle),
			                       cp + 6, dname, sizeof(dname));

			if (n < 0) {
				set_error(errno, "Unable to uncompress domain name");

				return -1;
			}

			type_arr = init_obj(vm, name_obj, "SRV", UC_ARRAY);
			item = ucv_array_new_length(vm, 4);
			ucv_array_push(item, ucv_int64_new(ns_get16(cp)));
			ucv_array_push(item, ucv_int64_new(ns_get16(cp + 2)));
			ucv_array_push(item, ucv_int64_new(ns_get16(cp + 4)));
			ucv_array_push(item, ucv_string_new(dname));
			ucv_array_push(type_arr, item);
			break;

		case ns_t_soa:
			if (rdlen < 20) {
				set_error(EBADMSG, "SOA record too short");

				return -1;
			}

			type_arr = init_obj(vm, name_obj, "SOA", UC_ARRAY);
			item = ucv_array_new_length(vm, 7);

			cp = ns_rr_rdata(rr);
			n = ns_name_uncompress(ns_msg_base(handle), ns_msg_end(handle),
			                       cp, dname, sizeof(dname));

			if (n < 0) {
				set_error(errno, "Unable to uncompress domain name");
				ucv_put(item);

				return -1;
			}

			ucv_array_push(item, ucv_string_new(dname)); /* origin */
			cp += n;

			n = ns_name_uncompress(ns_msg_base(handle), ns_msg_end(handle),
			                       cp, dname, sizeof(dname));

			if (n < 0) {
				set_error(errno, "Unable to uncompress domain name");
				ucv_put(item);

				return -1;
			}

			ucv_array_push(item, ucv_string_new(dname)); /* mail addr */
			cp += n;

			ucv_array_push(item, ucv_int64_new(ns_get32(cp))); /* serial */
			cp += 4;

			ucv_array_push(item, ucv_int64_new(ns_get32(cp))); /* refresh */
			cp += 4;

			ucv_array_push(item, ucv_int64_new(ns_get32(cp))); /* retry */
			cp += 4;

			ucv_array_push(item, ucv_int64_new(ns_get32(cp))); /* expire */
			cp += 4;

			ucv_array_push(item, ucv_int64_new(ns_get32(cp))); /* minimum */

			ucv_array_push(type_arr, item);
			break;

		default:
			break;
		}
	}

	return i;
}

static int
parse_nsaddr(const char *addrstr, addr_t *lsa)
{
	char *eptr, *hash, ifname[IFNAMSIZ];
	unsigned int port = default_port;
	unsigned int scope = 0;

	hash = strchr(addrstr, '#');

	if (hash) {
		*hash++ = '\0';
		port = strtoul(hash, &eptr, 10);

		if (eptr == hash || *eptr != '\0' || port > 65535) {
			errno = EINVAL;
			return -1;
		}
	}

	hash = strchr(addrstr, '%');

	if (hash) {
		for (eptr = ++hash; *eptr != '\0' && *eptr != '#'; eptr++) {
			if ((eptr - hash) >= IFNAMSIZ) {
				errno = ENODEV;
				return -1;
			}

			ifname[eptr - hash] = *eptr;
		}

		ifname[eptr - hash] = '\0';
		scope = if_nametoindex(ifname);

		if (scope == 0) {
			errno = ENODEV;
			return -1;
		}
	}

	if (inet_pton(AF_INET6, addrstr, &lsa->u.sin6.sin6_addr)) {
		lsa->u.sin6.sin6_family = AF_INET6;
		lsa->u.sin6.sin6_port = htons(port);
		lsa->u.sin6.sin6_scope_id = scope;
		lsa->len = sizeof(lsa->u.sin6);
		return 0;
	}

	if (!scope && inet_pton(AF_INET, addrstr, &lsa->u.sin.sin_addr)) {
		lsa->u.sin.sin_family = AF_INET;
		lsa->u.sin.sin_port = htons(port);
		lsa->len = sizeof(lsa->u.sin);
		return 0;
	}

	errno = EINVAL;
	return -1;
}

static char *
make_ptr(const char *addrstr)
{
	const char *hexdigit = "0123456789abcdef";
	static char ptrstr[73];
	unsigned char addr[16];
	char *ptr = ptrstr;
	int i;

	if (inet_pton(AF_INET6, addrstr, addr)) {
		if (memcmp(addr, "\0\0\0\0\0\0\0\0\0\0\xff\xff", 12) != 0) {
			for (i = 0; i < 16; i++) {
				*ptr++ = hexdigit[(unsigned char)addr[15 - i] & 0xf];
				*ptr++ = '.';
				*ptr++ = hexdigit[(unsigned char)addr[15 - i] >> 4];
				*ptr++ = '.';
			}
			strcpy(ptr, "ip6.arpa");
		}
		else {
			sprintf(ptr, "%u.%u.%u.%u.in-addr.arpa",
			        addr[15], addr[14], addr[13], addr[12]);
		}

		return ptrstr;
	}

	if (inet_pton(AF_INET, addrstr, addr)) {
		sprintf(ptr, "%u.%u.%u.%u.in-addr.arpa",
		        addr[3], addr[2], addr[1], addr[0]);
		return ptrstr;
	}

	return NULL;
}

static unsigned long
mtime(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_REALTIME, &ts);

	return (unsigned long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static void
to_v4_mapped(addr_t *a)
{
	if (a->u.sa.sa_family != AF_INET)
		return;

	memcpy(a->u.sin6.sin6_addr.s6_addr + 12,
	       &a->u.sin.sin_addr, 4);

	memcpy(a->u.sin6.sin6_addr.s6_addr,
	       "\0\0\0\0\0\0\0\0\0\0\xff\xff", 12);

	a->u.sin6.sin6_family = AF_INET6;
	a->u.sin6.sin6_flowinfo = 0;
	a->u.sin6.sin6_scope_id = 0;
	a->len = sizeof(a->u.sin6);
}

static void
add_status(uc_vm_t *vm, uc_value_t *res_obj, const char *name, const char *rcode)
{
	uc_value_t *name_obj = init_obj(vm, res_obj, name, UC_OBJECT);

	ucv_object_add(name_obj, "rcode", ucv_string_new(rcode));
}

/*
 * Function logic borrowed & modified from musl libc, res_msend.c
 */

static int
send_queries(resolve_ctx_t *ctx, uc_vm_t *vm, uc_value_t *res_obj)
{
	int fd, flags;
	int servfail_retry = 0;
	addr_t from = { };
	int one = 1;
	int recvlen = 0;
	int n_replies = 0;
	struct pollfd pfd;
	unsigned long t0, t1, t2, timeout = ctx->timeout, retry_interval;
	unsigned int nn, qn, next_query = 0;
	struct { unsigned char *buf; size_t len; } reply_buf = { 0 };

	from.u.sa.sa_family = AF_INET;
	from.len = sizeof(from.u.sin);

	for (nn = 0; nn < ctx->n_ns; nn++) {
		if (ctx->ns[nn].addr.u.sa.sa_family == AF_INET6) {
			from.u.sa.sa_family = AF_INET6;
			from.len = sizeof(from.u.sin6);
			break;
		}
	}

#ifdef __APPLE__
	flags = SOCK_DGRAM;
#else
	flags = SOCK_DGRAM|SOCK_CLOEXEC|SOCK_NONBLOCK;
#endif

	/* Get local address and open/bind a socket */
	fd = socket(from.u.sa.sa_family, flags, 0);

	/* Handle case where system lacks IPv6 support */
	if (fd < 0 && from.u.sa.sa_family == AF_INET6 && errno == EAFNOSUPPORT) {
		fd = socket(AF_INET, flags, 0);
		from.u.sa.sa_family = AF_INET;
	}

	if (fd < 0) {
		set_error(errno, "Unable to open UDP socket");

		return -1;
	}

#ifdef __APPLE__
	flags = fcntl(fd, F_GETFD);

	if (flags < 0) {
		set_error(errno, "Unable to acquire socket descriptor flags");
		close(fd);

		return -1;
	}

	if (fcntl(fd, F_SETFD, flags|O_CLOEXEC|O_NONBLOCK) < 0) {
		set_error(errno, "Unable to set socket descriptor flags");
		close(fd);

		return -1;
	}
#endif

	if (bind(fd, &from.u.sa, from.len) < 0) {
		set_error(errno, "Unable to bind UDP socket");
		close(fd);

		return -1;
	}

	/* Convert any IPv4 addresses in a mixed environment to v4-mapped */
	if (from.u.sa.sa_family == AF_INET6) {
		setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &one, sizeof(one));

		for (nn = 0; nn < ctx->n_ns; nn++)
			to_v4_mapped(&ctx->ns[nn].addr);
	}

	pfd.fd = fd;
	pfd.events = POLLIN;
	retry_interval = timeout / ctx->retries;
	t0 = t2 = mtime();
	t1 = t2 - retry_interval;

	for (; t2 - t0 < timeout; t2 = mtime()) {
		if (t2 - t1 >= retry_interval) {
			for (qn = 0; qn < ctx->n_queries; qn++) {
				if (ctx->queries[qn].rcode == 0 || ctx->queries[qn].rcode == 3)
					continue;

				for (nn = 0; nn < ctx->n_ns; nn++) {
					sendto(fd, ctx->queries[qn].query, ctx->queries[qn].qlen,
					       MSG_NOSIGNAL, &ctx->ns[nn].addr.u.sa, ctx->ns[nn].addr.len);
				}
			}

			t1 = t2;
			servfail_retry = 2 * ctx->n_queries;
		}

		/* Wait for a response, or until time to retry */
		switch (poll(&pfd, 1, t1+retry_interval-t2)) {
		case 0:
			/* timeout */
			for (qn = 0; qn < ctx->n_queries; qn++) {
				if (ctx->queries[qn].rcode != -1)
					continue;

				for (nn = 0; nn < ctx->n_ns; nn++)
					add_status(vm, res_obj, ctx->queries[qn].name, "TIMEOUT");
			}

			continue;

		case -1:
			/* error */
			continue;
		}

		while (1) {
			recvlen = recvfrom(fd, NULL, 0, MSG_PEEK|MSG_TRUNC, &from.u.sa, &from.len);

			/* read error */
			if (recvlen < 0)
				break;

			if ((size_t)recvlen > reply_buf.len) {
				reply_buf.buf = xrealloc(reply_buf.buf, recvlen);
				reply_buf.len = recvlen;
			}

			recvlen = recvfrom(fd, reply_buf.buf, recvlen, 0, &from.u.sa, &from.len);

			/* Ignore non-identifiable packets */
			if (recvlen < 4)
				continue;

			/* Ignore replies from addresses we didn't send to */
			for (nn = 0; nn < ctx->n_ns; nn++)
				if (memcmp(&from.u.sa, &ctx->ns[nn].addr.u.sa, from.len) == 0)
					break;

			if (nn >= ctx->n_ns)
				continue;

			/* Find which query this answer goes with, if any */
			for (qn = next_query; qn < ctx->n_queries; qn++)
				if (!memcmp(reply_buf.buf, ctx->queries[qn].query, 2))
					break;

			/* Do not overwrite previous replies from other servers
			 * but allow overwriting preexisting NXDOMAIN reply */
			if (qn >= ctx->n_queries ||
			    ctx->queries[qn].rcode == 0 ||
			    (ctx->queries[qn].rcode == 3 && (reply_buf.buf[3] & 15) != 0))
				continue;

			ctx->queries[qn].rcode = reply_buf.buf[3] & 15;

			switch (ctx->queries[qn].rcode) {
			case 0:
				ucv_object_delete(
					ucv_object_get(res_obj, ctx->queries[qn].name, NULL),
					"rcodes");

				break;

			case 2:
				/* Retry immediately on server failure. */
				if (servfail_retry && servfail_retry--)
					sendto(fd, ctx->queries[qn].query, ctx->queries[qn].qlen,
					       MSG_NOSIGNAL, &ctx->ns[nn].addr.u.sa, ctx->ns[nn].addr.len);

				/* fall through */

			default:
				add_status(vm, res_obj, ctx->queries[qn].name,
				           rcodes[ctx->queries[qn].rcode]);
			}

			/* Store answer */
			n_replies++;

			ctx->queries[qn].rlen = recvlen;

			parse_reply(vm, res_obj, reply_buf.buf, recvlen);

			if (qn == next_query) {
				while (next_query < ctx->n_queries) {
					if (ctx->queries[next_query].rcode == -1)
						break;

					next_query++;
				}
			}

			if (next_query >= ctx->n_queries)
				goto out;
		}
	}

out:
	free(reply_buf.buf);

	return n_replies;
}

static ns_t *
add_ns(resolve_ctx_t *ctx, const char *addr)
{
	char portstr[sizeof("65535")], *p;
	addr_t a = { };
	struct addrinfo *ai, *aip, hints = {
		.ai_flags = AI_NUMERICSERV,
		.ai_socktype = SOCK_DGRAM
	};

	if (parse_nsaddr(addr, &a)) {
		/* Maybe we got a domain name, attempt to resolve it using the standard
		 * resolver routines */

		p = strchr(addr, '#');
		snprintf(portstr, sizeof(portstr), "%hu",
		         (unsigned short)(p ? strtoul(p, NULL, 10) : default_port));

		if (!getaddrinfo(addr, portstr, &hints, &ai)) {
			for (aip = ai; aip; aip = aip->ai_next) {
				if (aip->ai_addr->sa_family != AF_INET &&
				    aip->ai_addr->sa_family != AF_INET6)
					continue;

				ctx->ns = xrealloc(ctx->ns, sizeof(*ctx->ns) * (ctx->n_ns + 1));
				ctx->ns[ctx->n_ns].name = addr;
				ctx->ns[ctx->n_ns].addr.len = aip->ai_addrlen;

				memcpy(&ctx->ns[ctx->n_ns].addr.u.sa, aip->ai_addr, aip->ai_addrlen);

				ctx->n_ns++;
			}

			freeaddrinfo(ai);

			return &ctx->ns[ctx->n_ns];
		}

		return NULL;
	}

	ctx->ns = xrealloc(ctx->ns, sizeof(*ctx->ns) * (ctx->n_ns + 1));
	ctx->ns[ctx->n_ns].addr = a;
	ctx->ns[ctx->n_ns].name = addr;

	return &ctx->ns[ctx->n_ns++];
}

static int
parse_resolvconf(resolve_ctx_t *ctx)
{
	int prev_n_ns = ctx->n_ns;
	char line[128], *p;
	FILE *resolv;
	bool ok;

	if ((resolv = fopen("/etc/resolv.conf", "r")) != NULL) {
		while (fgets(line, sizeof(line), resolv)) {
			p = strtok(line, " \t\n");

			if (!p || strcmp(p, "nameserver"))
				continue;

			p = strtok(NULL, " \t\n");

			if (!p)
				continue;

			p = xstrdup(p);
			ok = add_ns(ctx, p);

			free(p);

			if (!ok)
				break;
		}

		fclose(resolv);
	}

	return ctx->n_ns - prev_n_ns;
}

static query_t *
add_query(resolve_ctx_t *ctx, int type, const char *dname)
{
	opt_rr_t *opt;
	ssize_t qlen;

	ctx->queries = xrealloc(ctx->queries, sizeof(*ctx->queries) * (ctx->n_queries + 1));

	memset(&ctx->queries[ctx->n_queries], 0, sizeof(*ctx->queries));

	qlen = res_mkquery(QUERY, dname, C_IN, type, NULL, 0, NULL,
	                   ctx->queries[ctx->n_queries].query,
	                   sizeof(ctx->queries[ctx->n_queries].query));

	/* add OPT record */
	if (ctx->edns_maxsize != 0 && qlen + sizeof(opt_rr_t) <= sizeof(ctx->queries[ctx->n_queries].query)) {
		ctx->queries[ctx->n_queries].query[11] = 1;

		opt = (opt_rr_t *)&ctx->queries[ctx->n_queries].query[qlen];
		opt->root_domain = 0;
		opt->type = htons(41);
		opt->edns_maxsize = htons(ctx->edns_maxsize);
		opt->extended_rcode = 0;
		opt->edns_version = 0;
		opt->z = htons(0);
		opt->data_length = htons(0);

		qlen += sizeof(opt_rr_t);
	}

	ctx->queries[ctx->n_queries].qlen = qlen;
	ctx->queries[ctx->n_queries].name = xstrdup(dname);
	ctx->queries[ctx->n_queries].rcode = -1;

	return &ctx->queries[ctx->n_queries++];
}

static bool
check_types(uc_value_t *typenames, uint32_t *types)
{
	size_t i;

	*types = 0;

	for_each_item(typenames, typename) {
		if (ucv_type(typename) != UC_STRING)
			err_return(EINVAL, "Query type value not a string");

		for (i = 0; qtypes[i].name; i++) {
			if (!strcasecmp(ucv_string_get(typename), qtypes[i].name)) {
				*types |= (1 << i);
				break;
			}
		}

		if (!qtypes[i].name)
			err_return(EINVAL, "Unrecognized query type '%s'",
			           ucv_string_get(typename));
	}

	return true;
}

static void
add_queries(resolve_ctx_t *ctx, uc_value_t *name)
{
	char *s = ucv_string_get(name);
	char *ptr;
	size_t i;

	if (ctx->qtypes == 0) {
		ptr = make_ptr(s);

		if (ptr) {
			add_query(ctx, ns_t_ptr, ptr);
		}
		else {
			add_query(ctx, ns_t_a, s);
			add_query(ctx, ns_t_aaaa, s);
		}
	}
	else {
		for (i = 0; qtypes[i].name; i++) {
			if (ctx->qtypes & (1 << i)) {
				if (qtypes[i].type == ns_t_ptr) {
					ptr = make_ptr(s);
					add_query(ctx, ns_t_ptr, ptr ? ptr : s);
				}
				else {
					add_query(ctx, qtypes[i].type, s);
				}
			}
		}
	}
}

static bool
parse_options(resolve_ctx_t *ctx, uc_value_t *opts)
{
	uc_value_t *v;

	if (!check_types(ucv_object_get(opts, "type", NULL), &ctx->qtypes))
		return false;

	for_each_item(ucv_object_get(opts, "nameserver", NULL), server) {
		if (ucv_type(server) != UC_STRING)
			err_return(EINVAL, "Nameserver value not a string");

		if (!add_ns(ctx, ucv_string_get(server)))
			err_return(EINVAL, "Unable to resolve nameserver address '%s'",
			           ucv_string_get(server));
	}

	/* Find NS servers in resolv.conf if none provided */
	if (ctx->n_ns == 0)
		parse_resolvconf(ctx);

	/* Fall back to localhost if we could not find NS in resolv.conf */
	if (ctx->n_ns == 0)
		add_ns(ctx, "127.0.0.1");

	v = ucv_object_get(opts, "retries", NULL);

	if (ucv_type(v) == UC_INTEGER)
		ctx->retries = ucv_uint64_get(v);
	else if (v)
		err_return(EINVAL, "Retries value not an integer");

	v = ucv_object_get(opts, "timeout", NULL);

	if (ucv_type(v) == UC_INTEGER)
		ctx->timeout = ucv_uint64_get(v);
	else if (v)
		err_return(EINVAL, "Timeout value not an integer");

	v = ucv_object_get(opts, "edns_maxsize", NULL);

	if (ucv_type(v) == UC_INTEGER)
		ctx->edns_maxsize = ucv_uint64_get(v);
	else if (v)
		err_return(EINVAL, "EDNS max size not an integer");

	return true;
}

static uc_value_t *
uc_resolv_query(uc_vm_t *vm, size_t nargs)
{
	resolve_ctx_t ctx = { .retries = 2, .timeout = 5000, .edns_maxsize = 4096 };
	uc_value_t *names = uc_fn_arg(0);
	uc_value_t *opts = uc_fn_arg(1);
	uc_value_t *res_obj = NULL;

	if (!parse_options(&ctx, opts))
		goto err;

	for_each_item(names, name) {
		if (ucv_type(name) != UC_STRING) {
			set_error(EINVAL, "Domain name value not a string");
			goto err;
		}

		add_queries(&ctx, name);
	}

	res_obj = ucv_object_new(vm);

	if (send_queries(&ctx, vm, res_obj) == 0)
		set_error(ETIMEDOUT, "Server did not respond");

err:
	while (ctx.n_queries)
		free(ctx.queries[--ctx.n_queries].name);

	free(ctx.queries);
	free(ctx.ns);

	return res_obj;
}

static uc_value_t *
uc_resolv_error(uc_vm_t *vm, size_t nargs)
{
	uc_stringbuf_t *buf;
	const char *s;

	if (last_error.code == 0)
		return NULL;

	buf = ucv_stringbuf_new();

	s = strerror(last_error.code);

	ucv_stringbuf_addstr(buf, s, strlen(s));

	if (last_error.msg)
		ucv_stringbuf_printf(buf, ": %s", last_error.msg);

	set_error(0, NULL);

	return ucv_stringbuf_finish(buf);
}


static const uc_function_list_t resolv_fns[] = {
	{ "query",	uc_resolv_query },
	{ "error",	uc_resolv_error },
};

void uc_module_init(uc_vm_t *vm, uc_value_t *scope)
{
	uc_function_list_register(scope, resolv_fns);
}
