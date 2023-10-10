/*
 * Copyright (C) 2023 Jo-Philipp Wich <jo@mein.io>
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
 * # System logging functions
 *
 * The `log` module provides bindings to the POSIX syslog functions `openlog()`,
 * `syslog()` and `closelog()` as well as - when available - the OpenWrt
 * specific ulog library functions.
 *
 * Functions can be individually imported and directly accessed using the
 * {@link https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Statements/import#named_import named import}
 * syntax:
 *
 *   ```
 *   import { openlog, syslog, LOG_PID, LOG_USER, LOG_ERR } from 'log';
 *
 *   openlog("my-log-ident", LOG_PID, LOG_USER);
 *   syslog(LOG_ERR, "An error occurred!");
 *
 *   // OpenWrt specific ulog functions
 *   import { ulog_open, ulog, ULOG_SYSLOG, LOG_DAEMON, LOG_INFO } from 'log';
 *
 *   ulog_open(ULOG_SYSLOG, LOG_DAEMON, "my-log-ident");
 *   ulog(LOG_INFO, "The current epoch is %d", time());
 *   ```
 *
 * Alternatively, the module namespace can be imported
 * using a wildcard import statement:
 *
 *   ```
 *   import * as log from 'log';
 *
 *   log.openlog("my-log-ident", log.LOG_PID, log.LOG_USER);
 *   log.syslog(log.LOG_ERR, "An error occurred!");
 *
 *   // OpenWrt specific ulog functions
 *   log.ulog_open(log.ULOG_SYSLOG, log.LOG_DAEMON, "my-log-ident");
 *   log.ulog(log.LOG_INFO, "The current epoch is %d", time());
 *   ```
 *
 * Additionally, the log module namespace may also be imported by invoking the
 * `ucode` interpreter with the `-llog` switch.
 *
 * ## Constants
 *
 * The `log` module declares a number of numeric constants to specify logging
 * facility, priority and option values, as well as ulog specific channels.
 *
 * ### Syslog Options
 *
 * | Constant Name | Description                                             |
 * |---------------|---------------------------------------------------------|
 * | `LOG_PID`     | Include PID with each message.                          |
 * | `LOG_CONS`    | Log to console if error occurs while sending to syslog. |
 * | `LOG_NDELAY`  | Open the connection to the logger immediately.          |
 * | `LOG_ODELAY`  | Delay open until the first message is logged.           |
 * | `LOG_NOWAIT`  | Do not wait for child processes created during logging. |
 *
 * ### Syslog Facilities
 *
 * | Constant Name  | Description                                      |
 * |----------------|--------------------------------------------------|
 * | `LOG_AUTH`     | Authentication/authorization messages.           |
 * | `LOG_AUTHPRIV` | Private authentication messages.                 |
 * | `LOG_CRON`     | Clock daemon (cron and at commands).             |
 * | `LOG_DAEMON`   | System daemons without separate facility values. |
 * | `LOG_FTP`      | FTP server daemon.                               |
 * | `LOG_KERN`     | Kernel messages.                                 |
 * | `LOG_LPR`      | Line printer subsystem.                          |
 * | `LOG_MAIL`     | Mail system.                                     |
 * | `LOG_NEWS`     | Network news subsystem.                          |
 * | `LOG_SYSLOG`   | Messages generated internally by syslogd.        |
 * | `LOG_USER`     | Generic user-level messages.                     |
 * | `LOG_UUCP`     | UUCP subsystem.                                  |
 * | `LOG_LOCAL0`   | Local use 0 (custom facility).                   |
 * | `LOG_LOCAL1`   | Local use 1 (custom facility).                   |
 * | `LOG_LOCAL2`   | Local use 2 (custom facility).                   |
 * | `LOG_LOCAL3`   | Local use 3 (custom facility).                   |
 * | `LOG_LOCAL4`   | Local use 4 (custom facility).                   |
 * | `LOG_LOCAL5`   | Local use 5 (custom facility).                   |
 * | `LOG_LOCAL6`   | Local use 6 (custom facility).                   |
 * | `LOG_LOCAL7`   | Local use 7 (custom facility).                   |
 *
 * ### Syslog Priorities
 *
 * | Constant Name | Description                         |
 * |---------------|-------------------------------------|
 * | `LOG_EMERG`   | System is unusable.                 |
 * | `LOG_ALERT`   | Action must be taken immediately.   |
 * | `LOG_CRIT`    | Critical conditions.                |
 * | `LOG_ERR`     | Error conditions.                   |
 * | `LOG_WARNING` | Warning conditions.                 |
 * | `LOG_NOTICE`  | Normal, but significant, condition. |
 * | `LOG_INFO`    | Informational message.              |
 * | `LOG_DEBUG`   | Debug-level message.                |
 *
 * ### Ulog channels
 *
 * | Constant Name | Description                          |
 * |---------------|--------------------------------------|
 * | `ULOG_KMSG`   | Log messages to `/dev/kmsg` (dmesg). |
 * | `ULOG_STDIO`  | Log messages to stdout.              |
 * | `ULOG_SYSLOG` | Log messages to syslog.              |
 *
 * @module log
 */

#include <syslog.h>
#include <errno.h>

#ifdef HAVE_ULOG
#include <libubox/ulog.h>
#endif

#include "ucode/module.h"


static char log_ident[32];

/**
 * The following log option strings are recognized:
 *
 * | Log Option | Description                                                |
 * |------------|------------------------------------------------------------|
 * | `"pid"`    | Include PID with each message.                             |
 * | `"cons"`   | Log to console if an error occurs while sending to syslog. |
 * | `"ndelay"` | Open the connection to the logger immediately.             |
 * | `"odelay"` | Delay open until the first message is logged.              |
 * | `"nowait"` | Do not wait for child processes created during logging.    |
 *
 * @typedef {string} module:log.LogOption
 * @enum {module:log.LogOption}
 *
 */
static const struct { const char *name; int value; } log_options[] = {
	{ "pid", LOG_PID },
	{ "cons", LOG_CONS },
	{ "ndelay", LOG_NDELAY },
	{ "odelay", LOG_ODELAY },
	{ "nowait", LOG_NOWAIT },
};

/**
 * The following log facility strings are recognized:
 *
 * | Facility     | Description                                      |
 * |--------------|--------------------------------------------------|
 * | `"auth"`     | Authentication/authorization messages.           |
 * | `"authpriv"` | Private authentication messages.                 |
 * | `"cron"`     | Clock daemon (cron and at commands).             |
 * | `"daemon"`   | System daemons without separate facility values. |
 * | `"ftp"`      | FTP server daemon.                               |
 * | `"kern"`     | Kernel messages.                                 |
 * | `"lpr"`      | Line printer subsystem.                          |
 * | `"mail"`     | Mail system.                                     |
 * | `"news"`     | Network news subsystem.                          |
 * | `"syslog"`   | Messages generated internally by syslogd.        |
 * | `"user"`     | Generic user-level messages.                     |
 * | `"uucp"`     | UUCP subsystem.                                  |
 * | `"local0"`   | Local use 0 (custom facility).                   |
 * | `"local1"`   | Local use 1 (custom facility).                   |
 * | `"local2"`   | Local use 2 (custom facility).                   |
 * | `"local3"`   | Local use 3 (custom facility).                   |
 * | `"local4"`   | Local use 4 (custom facility).                   |
 * | `"local5"`   | Local use 5 (custom facility).                   |
 * | `"local6"`   | Local use 6 (custom facility).                   |
 * | `"local7"`   | Local use 7 (custom facility).                   |
 *
 * @typedef {string} module:log.LogFacility
 * @enum {module:log.LogFacility}
 */
static const struct { const char *name; int value; } log_facilities[] = {
	{ "auth", LOG_AUTH },
#ifdef LOG_AUTHPRIV
	{ "authpriv", LOG_AUTHPRIV },
#endif
	{ "cron", LOG_CRON },
	{ "daemon", LOG_DAEMON },
#ifdef LOG_FTP
	{ "ftp", LOG_FTP },
#endif
	{ "kern", LOG_KERN },
	{ "lpr", LOG_LPR },
	{ "mail", LOG_MAIL },
	{ "news", LOG_NEWS },
	{ "syslog", LOG_SYSLOG },
	{ "user", LOG_USER },
	{ "uucp", LOG_UUCP },
	{ "local0", LOG_LOCAL0 },
	{ "local1", LOG_LOCAL1 },
	{ "local2", LOG_LOCAL2 },
	{ "local3", LOG_LOCAL3 },
	{ "local4", LOG_LOCAL4 },
	{ "local5", LOG_LOCAL5 },
	{ "local6", LOG_LOCAL6 },
	{ "local7", LOG_LOCAL7 },
};

/**
 * The following log priority strings are recognized:
 *
 * | Priority    | Description                         |
 * |-------------|-------------------------------------|
 * | `"emerg"`   | System is unusable.                 |
 * | `"alert"`   | Action must be taken immediately.   |
 * | `"crit"`    | Critical conditions.                |
 * | `"err"`     | Error conditions.                   |
 * | `"warning"` | Warning conditions.                 |
 * | `"notice"`  | Normal, but significant, condition. |
 * | `"info"`    | Informational message.              |
 * | `"debug"`   | Debug-level message.                |
 *
 * @typedef {string} module:log.LogPriority
 * @enum {module:log.LogPriority}
 */
static const struct { const char *name; int value; } log_priorities[] = {
	{ "emerg", LOG_EMERG },
	{ "alert", LOG_ALERT },
	{ "crit", LOG_CRIT },
	{ "err", LOG_ERR },
	{ "warning", LOG_WARNING },
	{ "notice", LOG_NOTICE },
	{ "info", LOG_INFO },
	{ "debug", LOG_DEBUG },
};


static int
parse_facility(uc_value_t *facility)
{
	char *s;
	int rv;

	switch (ucv_type(facility)) {
	case UC_STRING:
		s = ucv_string_get(facility);

		for (size_t i = 0; i < ARRAY_SIZE(log_facilities); i++)
			if (s && !strcasecmp(s, log_facilities[i].name))
				return log_facilities[i].value;

		return -1;

	case UC_INTEGER:
		rv = ucv_int64_get(facility);

		if (errno == ERANGE || rv < 0)
			return -1;

		return rv;

	case UC_NULL:
		return 0;

	default:
		return -1;
	}
}

static int
parse_options(uc_value_t *option)
{
	char *s;
	int rv;

	switch (ucv_type(option)) {
	case UC_ARRAY:
		rv = 0;

		for (size_t i = 0; i < ucv_array_length(option); i++) {
			uc_value_t *opt = ucv_array_get(option, i);
			char *s = ucv_string_get(opt);

			for (size_t j = 0; j < ARRAY_SIZE(log_options); j++) {
				if (s && !strcasecmp(log_options[j].name, s))
					rv |= log_options[j].value;
				else
					return -1;
			}
		}

		return rv;

	case UC_STRING:
		s = ucv_string_get(option);

		for (size_t i = 0; i < ARRAY_SIZE(log_options); i++)
			if (s && !strcasecmp(s, log_options[i].name))
				return log_options[i].value;

		return -1;

	case UC_INTEGER:
		rv = ucv_int64_get(option);

		if (errno == ERANGE || rv < 0)
			return -1;

		return rv;

	case UC_NULL:
		return 0;

	default:
		return -1;
	}
}

static int
parse_priority(uc_value_t *priority)
{
	char *s;
	int rv;

	switch (ucv_type(priority)) {
	case UC_STRING:
		s = ucv_string_get(priority);

		for (size_t i = 0; i < ARRAY_SIZE(log_priorities); i++)
			if (s && !strcasecmp(s, log_priorities[i].name))
				return log_priorities[i].value;

		return -1;

	case UC_INTEGER:
		rv = ucv_int64_get(priority);

		if (errno == ERANGE || rv < 0)
			return -1;

		return rv;

	case UC_NULL:
		return LOG_INFO;

	default:
		return -1;
	}
}

static char *
parse_ident(uc_vm_t *vm, uc_value_t *ident)
{
	if (!ident)
		return NULL;

	char *s = ucv_to_string(vm, ident);

	snprintf(log_ident, sizeof(log_ident), "%s", s ? s : "");
	free(s);

	return log_ident[0] ? log_ident : NULL;
}

/**
 * Open connection to system logger.
 *
 * The `openlog()` function instructs the program to establish a connection to
 * the system log service and configures the default facility and identification
 * for use in subsequent log operations. It may be omitted, in which case the
 * first call to `syslog()` will implicitly call `openlog()` with a default
 * ident value representing the program name and a default `LOG_USER` facility.
 *
 * The log option argument may be either a single string value containing an
 * option name, an array of option name strings or a numeric value representing
 * a bitmask of `LOG_*` option constants.
 *
 * The facility argument may be either a single string value containing a
 * facility name or one of the numeric `LOG_*` facility constants in the module
 * namespace.
 *
 * Returns `true` if the system `openlog()` function was invoked.
 *
 * Returns `false` if an invalid argument, such as an unrecognized option or
 * facility name, was provided.
 *
 * @function module:log#openlog
 *
 * @param {string} [ident]
 * A string identifying the program name. If omitted, the name of the calling
 * process is used by default.
 *
 * @param {number|module:log.LogOption|module:log.LogOption[]} [options]
 * Logging options to use.
 *
 * See {@link module:log.LogOption|LogOption} for recognized option names.
 *
 * @param {number|module:log.LogFacility} [facility="user"]
 * The facility to use for log messages generated by subsequent syslog calls.
 *
 * See {@link module:log.LogFacility|LogFacility} for recognized facility names.
 *
 * @returns {boolean}
 *
 * @example
 * // Example usage of openlog function
 * openlog("myapp", LOG_PID | LOG_NDELAY, LOG_LOCAL0);
 *
 * // Using option names instead of bitmask and LOG_USER facility
 * openlog("myapp", [ "pid", "ndelay" ], "user");
 */
static uc_value_t *
uc_openlog(uc_vm_t *vm, size_t nargs)
{
	char *ident = parse_ident(vm, uc_fn_arg(0));
	int options = parse_options(uc_fn_arg(1));
	int facility = parse_facility(uc_fn_arg(2));

	if (options == -1 || facility == -1)
		return ucv_boolean_new(false);

	openlog(ident, options, facility);

	return ucv_boolean_new(true);
}

/**
 * Log a message to the system logger.
 *
 * This function logs a message to the system logger. The function behaves in a
 * sprintf-like manner, allowing the use of format strings and associated
 * arguments to construct log messages.
 *
 * If the `openlog` function has not been called explicitly before, `syslog()`
 * implicitly calls `openlog()`, using a default ident and `LOG_USER` facility
 * value before logging the message.
 *
 * If the `format` argument is not a string and not `null`, it will be
 * implicitly converted to a string and logged as-is, without further format
 * string processing.
 *
 * Returns `true` if a message was passed to the system `syslog()` function.
 *
 * Returns `false` if an invalid priority value or an empty message was given.
 *
 * @function module:log#syslog
 *
 * @param {number|module:log.LogPriority} priority
 * Log message priority. May be either a number value (potentially bitwise OR-ed
 * with a log facility constant) which is passed as-is to the system `syslog()`
 * function or a priority name string.
 *
 * See {@link module:log.LogPriority|LogPriority} for recognized priority names.
 *
 * @param {*} format
 * The sprintf-like format string for the log message, or any other, non-null,
 * non-string value type which will be implicitly stringified and logged as-is.
 *
 * @param {...*} [args]
 * In case a format string value was provided in the previous argument, then
 * all subsequent arguments are used to replace the placeholders in the format
 * string.
 *
 * @returns {boolean}
 *
 * @example
 * // Example usage of syslog function with format string and arguments
 * const username = "user123";
 * const errorCode = 404;
 * syslog(LOG_ERR, "User %s encountered error: %d", username, errorCode);
 *
 * // If openlog has not been called explicitly, it is implicitly called with defaults:
 * syslog(LOG_INFO, "This message will be logged with default settings.");
 *
 * // Selectively override used facility by OR-ing numeric constant
 * const password =" secret";
 * syslog(LOG_DEBUG|LOG_AUTHPRIV, "The password %s has been wrong", secret);
 *
 * // Using priority names for logging
 * syslog("emerg", "System shutdown imminent!");
 *
 * // Implicit stringification
 * syslog("debug", { foo: 1, bar: true, baz: [1, 2, 3] });
 */
static uc_value_t *
uc_syslog(uc_vm_t *vm, size_t nargs)
{
	int priority = parse_priority(uc_fn_arg(0));

	if (priority == -1 || nargs < 2)
		return ucv_boolean_new(false);

	uc_value_t *fmt = uc_fn_arg(1), *msg;
	uc_cfn_ptr_t fmtfn;
	char *s;

	switch (ucv_type(fmt)) {
	case UC_STRING:
		fmtfn = uc_stdlib_function("sprintf");
		msg = fmtfn(vm, nargs - 1);

		if (msg) {
			syslog(priority, "%s", ucv_string_get(msg));
			ucv_put(msg);

			return ucv_boolean_new(true);
		}

		break;

	case UC_NULL:
		break;

	default:
		s = ucv_to_string(vm, fmt);

		if (s) {
			syslog(priority, "%s", s);
			free(s);

			return ucv_boolean_new(true);
		}

		break;
	}

	return ucv_boolean_new(false);
}

/**
 * Close connection to system logger.
 *
 * The usage of this function is optional, and usually an explicit log
 * connection tear down is not required.
 *
 * @function module:log#closelog
 */
static uc_value_t *
uc_closelog(uc_vm_t *vm, size_t nargs)
{
	closelog();

	return NULL;
}


#ifdef HAVE_ULOG
/**
 * The following ulog channel strings are recognized:
 *
 * | Channel    | Description                                       |
 * |------------|---------------------------------------------------|
 * | `"kmsg"`   | Log to `/dev/kmsg`, log messages appear in dmesg. |
 * | `"syslog"` | Use standard `syslog()` mechanism.                |
 * | `"stdio"`  | Use stderr for log output.                        |
 *
 * @typedef {string} module:log.UlogChannel
 * @enum {module:log.UlogChannel}
 */
static const struct { const char *name; int value; } ulog_channels[] = {
	{ "kmsg", ULOG_KMSG },
	{ "syslog", ULOG_SYSLOG },
	{ "stdio", ULOG_STDIO },
};

static int
parse_channels(uc_value_t *channels)
{
	char *s;
	int rv;

	switch (ucv_type(channels)) {
	case UC_ARRAY:
		rv = 0;

		for (size_t i = 0; i < ucv_array_length(channels); i++) {
			uc_value_t *channel = ucv_array_get(channels, i);
			char *s = ucv_string_get(channel);

			for (size_t j = 0; j < ARRAY_SIZE(ulog_channels); j++) {
				if (s && !strcasecmp(s, ulog_channels[j].name))
					rv |= ulog_channels[j].value;
				else
					return -1;
			}
		}

		return rv;

	case UC_STRING:
		s = ucv_string_get(channels);

		for (size_t i = 0; i < ARRAY_SIZE(ulog_channels); i++)
			if (s && !strcasecmp(s, ulog_channels[i].name))
				return ulog_channels[i].value;

		return -1;

	case UC_INTEGER:
		rv = ucv_uint64_get(channels);

		if (errno == ERANGE)
			return -1;

		return rv & (ULOG_KMSG|ULOG_STDIO|ULOG_SYSLOG);

	case UC_NULL:
		return 0;

	default:
		return -1;
	}
}

/**
 * Configure ulog logger.
 *
 * This functions configures the ulog mechanism and is analogeous to using the
 * `openlog()` function in conjuncton with `syslog()`.
 *
 * The `ulog_open()` function is OpenWrt specific and may not be present on
 * other systems. Use `openlog()` and `syslog()` instead for portability to
 * non-OpenWrt environments.
 *
 * A program may use multiple channels to simultaneously output messages using
 * different means. The channel argument may either be a single string value
 * containing a channel name, an array of channel names or a numeric value
 * representing a bitmask of `ULOG_*` channel constants.
 *
 * The facility argument may be either a single string value containing a
 * facility name or one of the numeric `LOG_*` facility constants in the module
 * namespace.
 *
 * The default facility value varies, depending on the execution context of the
 * program. In OpenWrt's preinit boot phase, or when stdout is not connected to
 * an interactive terminal, the facility defaults to `"daemon"` (`LOG_DAEMON`),
 * otherwise to `"user"` (`LOG_USER`).
 *
 * Likewise, the default channel is selected depending on the context. During
 * OpenWrt's preinit boot phase, the `"kmsg"` channel is used, for interactive
 * terminals the `"stdio"` one and for all other cases the `"syslog"` channel
 * is selected.
 *
 * Returns `true` if ulog was configured.
 *
 * Returns `false` if an invalid argument, such as an unrecognized channel or
 * facility name, was provided.
 *
 * @function module:log#ulog_open
 *
 * @param {number|module:log.UlogChannel|module:log.UlogChannel[]} [channel]
 * Specifies the log channels to use.
 *
 * See {@link module:log.UlogChannel|UlogChannel} for recognized channel names.
 *
 * @param {number|module:log.LogFacility} [facility]
 * The facility to use for log messages generated by subsequent `ulog()` calls.
 *
 * See {@link module:log.LogFacility|LogFacility} for recognized facility names.
 *
 * @param {string} [ident]
 * A string identifying the program name. If omitted, the name of the calling
 * process is used by default.
 *
 * @returns {boolean}
 *
 * @example
 * // Log to dmesg and stderr
 * ulog_open(["stdio", "kmsg"], "daemon", "my-program");
 *
 * // Use numeric constants and use implicit default ident
 * ulog_open(ULOG_SYSLOG, LOG_LOCAL0);
 */
static uc_value_t *
uc_ulog_open(uc_vm_t *vm, size_t nargs)
{
	int channels = parse_channels(uc_fn_arg(0));
	int facility = parse_facility(uc_fn_arg(1));
	char *ident = parse_ident(vm, uc_fn_arg(2));

	if (channels == -1 || facility == -1)
		return ucv_boolean_new(false);

	ulog_open(channels, facility, ident);

	return ucv_boolean_new(true);
}

static uc_value_t *
uc_ulog_log_common(uc_vm_t *vm, size_t nargs, int priority)
{
	uc_value_t *fmt = uc_fn_arg(0), *msg;
	uc_cfn_ptr_t fmtfn;
	char *s;

	switch (ucv_type(fmt)) {
	case UC_STRING:
		fmtfn = uc_stdlib_function("sprintf");
		msg = fmtfn(vm, nargs);

		if (msg) {
			ulog(priority, "%s", ucv_string_get(msg));
			ucv_put(msg);

			return ucv_boolean_new(true);
		}

		break;

	case UC_NULL:
		break;

	default:
		s = ucv_to_string(vm, fmt);

		if (s) {
			ulog(priority, "%s", s);
			free(s);

			return ucv_boolean_new(true);
		}

		break;
	}

	return ucv_boolean_new(false);
}

/**
 * Log a message via the ulog mechanism.
 *
 * The `ulog()` function outputs the given log message to all configured ulog
 * channels unless the given priority level exceeds the globally configured ulog
 * priority threshold. See {@link module:log#ulog_threshold|ulog_threshold()}
 * for details.
 *
 * The `ulog()` function is OpenWrt specific and may not be present on other
 * systems. Use `syslog()` instead for portability to non-OpenWrt environments.
 *
 * Like `syslog()`, the function behaves in a sprintf-like manner, allowing the
 * use of format strings and associated arguments to construct log messages.
 *
 * If the `ulog_open()` function has not been called explicitly before, `ulog()`
 * implicitly configures certain defaults, see
 * {@link module:log#ulog_open|ulog_open()} for a detailled description.
 *
 * If the `format` argument is not a string and not `null`, it will be
 * implicitly converted to a string and logged as-is, without further format
 * string processing.
 *
 * Returns `true` if a message was passed to the underlying `ulog()` function.
 *
 * Returns `false` if an invalid priority value or an empty message was given.
 *
 * @function module:log#ulog
 *
 * @param {number|module:log.LogPriority} priority
 * Log message priority. May be either a number value or a priority name string.
 *
 * See {@link module:log.LogPriority|LogPriority} for recognized priority names.
 *
 * @param {*} format
 * The sprintf-like format string for the log message, or any other, non-null,
 * non-string value type which will be implicitly stringified and logged as-is.
 *
 * @param {...*} [args]
 * In case a format string value was provided in the previous argument, then
 * all subsequent arguments are used to replace the placeholders in the format
 * string.
 *
 * @returns {boolean}
 *
 * @example
 * // Example usage of ulog function with format string and arguments
 * const username = "user123";
 * const errorCode = 404;
 * ulog(LOG_ERR, "User %s encountered error: %d", username, errorCode);
 *
 * // Using priority names for logging
 * ulog("err", "General error encountered");
 *
 * // Implicit stringification
 * ulog("debug", { foo: 1, bar: true, baz: [1, 2, 3] });
 *
 * @see module:log#ulog_open
 * @see module:log#ulog_threshold
 * @see module:log#syslog
 */
static uc_value_t *
uc_ulog_log(uc_vm_t *vm, size_t nargs)
{
	int priority = parse_priority(uc_fn_arg(0));

	if (priority == -1 || nargs < 2)
		return ucv_boolean_new(false);

	return uc_ulog_log_common(vm, nargs - 1, priority);
}

/**
 * Close ulog logger.
 *
 * Resets the ulog channels, the default facility and the log ident value to
 * defaults.
 *
 * In case the `"syslog"` channel has been configured, the underlying
 * `closelog()` function will be invoked.
 *
 * The usage of this function is optional, and usually an explicit ulog teardown
 * is not required.
 *
 * The `ulog_close()` function is OpenWrt specific and may not be present on
 * other systems. Use `closelog()` in conjunction with `syslog()` instead for
 * portability to non-OpenWrt environments.
 *
 * @function module:log#ulog_close
 *
 * @see module:log#closelog
 */
static uc_value_t *
uc_ulog_close(uc_vm_t *vm, size_t nargs)
{
	ulog_close();

	return NULL;
}

/**
 * Set ulog priority threshold.
 *
 * This function configures the application wide log message threshold for log
 * messages emitted with `ulog()`. Any message with a priority higher (= less
 * severe) than the threshold priority will be discarded. This is useful to
 * implement application wide verbosity settings without having to wrap `ulog()`
 * invocations into a helper function or guarding code.
 *
 * When no explicit threshold has been set, `LOG_DEBUG` is used by default,
 * allowing log messages with all known priorities.
 *
 * The `ulog_threshold()` function is OpenWrt specific and may not be present on
 * other systems. There is no syslog equivalent to this ulog specific threshold
 * mechanism.
 *
 * The priority argument may be either a string value containing a priority name
 * or one of the numeric `LOG_*` priority constants in the module namespace.
 *
 * Returns `true` if a threshold was set.
 *
 * Returns `false` if an invalid priority value was given.
 *
 * @function module:log#ulog_threshold
 *
 * @param {number|module:log.LogPriority} [priority]
 * The priority threshold to configure.
 *
 * See {@link module:log.LogPriority|LogPriority} for recognized priority names.
 *
 * @returns {boolean}
 *
 * @example
 * // Set threshold to "warning" or more severe
 * ulog_threshold(LOG_WARNING);
 *
 * // This message will be supressed
 * ulog(LOG_DEBUG, "Testing thresholds");
 *
 * // Using priority name
 * ulog_threshold("debug");
 */
static uc_value_t *
uc_ulog_threshold(uc_vm_t *vm, size_t nargs)
{
	int priority = parse_priority(uc_fn_arg(0));

	if (priority == -1)
		return ucv_boolean_new(false);

	ulog_threshold(priority);

	return ucv_boolean_new(true);
}

/**
 * Invoke ulog with LOG_INFO.
 *
 * This function is convenience wrapper for `ulog(LOG_INFO, ...)`.
 *
 * See {@link module:log#ulog|ulog()} for details.
 *
 * @function module:log#INFO
 *
 * @param {*} format
 * The sprintf-like format string for the log message, or any other, non-null,
 * non-string value type which will be implicitly stringified and logged as-is.
 *
 * @param {...*} [args]
 * In case a format string value was provided in the previous argument, then
 * all subsequent arguments are used to replace the placeholders in the format
 * string.
 *
 * @returns {boolean}
 *
 * @example
 * INFO("This is an info log message");
 */
static uc_value_t *
uc_ulog_INFO(uc_vm_t *vm, size_t nargs)
{
	return uc_ulog_log_common(vm, nargs, LOG_INFO);
}

/**
 * Invoke ulog with LOG_NOTICE.
 *
 * This function is convenience wrapper for `ulog(LOG_NOTICE, ...)`.
 *
 * See {@link module:log#ulog|ulog()} for details.
 *
 * @function module:log#NOTE
 *
 * @param {*} format
 * The sprintf-like format string for the log message, or any other, non-null,
 * non-string value type which will be implicitly stringified and logged as-is.
 *
 * @param {...*} [args]
 * In case a format string value was provided in the previous argument, then
 * all subsequent arguments are used to replace the placeholders in the format
 * string.
 *
 * @returns {boolean}
 *
 * @example
 * NOTE("This is a notification log message");
 */
static uc_value_t *
uc_ulog_NOTE(uc_vm_t *vm, size_t nargs)
{
	return uc_ulog_log_common(vm, nargs, LOG_NOTICE);
}

/**
 * Invoke ulog with LOG_WARNING.
 *
 * This function is convenience wrapper for `ulog(LOG_WARNING, ...)`.
 *
 * See {@link module:log#ulog|ulog()} for details.
 *
 * @function module:log#WARN
 *
 * @param {*} format
 * The sprintf-like format string for the log message, or any other, non-null,
 * non-string value type which will be implicitly stringified and logged as-is.
 *
 * @param {...*} [args]
 * In case a format string value was provided in the previous argument, then
 * all subsequent arguments are used to replace the placeholders in the format
 * string.
 *
 * @returns {boolean}
 *
 * @example
 * WARN("This is a warning");
 */
static uc_value_t *
uc_ulog_WARN(uc_vm_t *vm, size_t nargs)
{
	return uc_ulog_log_common(vm, nargs, LOG_WARNING);
}

/**
 * Invoke ulog with LOG_ERR.
 *
 * This function is convenience wrapper for `ulog(LOG_ERR, ...)`.
 *
 * See {@link module:log#ulog|ulog()} for details.
 *
 * @function module:log#ERR
 *
 * @param {*} format
 * The sprintf-like format string for the log message, or any other, non-null,
 * non-string value type which will be implicitly stringified and logged as-is.
 *
 * @param {...*} [args]
 * In case a format string value was provided in the previous argument, then
 * all subsequent arguments are used to replace the placeholders in the format
 * string.
 *
 * @returns {boolean}
 *
 * @example
 * ERR("This is an error!");
 */
static uc_value_t *
uc_ulog_ERR(uc_vm_t *vm, size_t nargs)
{
	return uc_ulog_log_common(vm, nargs, LOG_ERR);
}
#endif


static const uc_function_list_t global_fns[] = {
	{ "openlog",		uc_openlog },
	{ "syslog",			uc_syslog },
	{ "closelog",		uc_closelog },

#ifdef HAVE_ULOG
	{ "ulog_open",		uc_ulog_open },
	{ "ulog",			uc_ulog_log },
	{ "ulog_close",		uc_ulog_close },
	{ "ulog_threshold",	uc_ulog_threshold },
	{ "INFO",			uc_ulog_INFO },
	{ "NOTE",			uc_ulog_NOTE },
	{ "WARN",			uc_ulog_WARN },
	{ "ERR",			uc_ulog_ERR },
#endif
};


void uc_module_init(uc_vm_t *vm, uc_value_t *scope)
{
	uc_function_list_register(scope, global_fns);

#define ADD_CONST(x) ucv_object_add(scope, #x, ucv_int64_new(x))

	ADD_CONST(LOG_PID);
	ADD_CONST(LOG_CONS);
	ADD_CONST(LOG_NDELAY);
	ADD_CONST(LOG_ODELAY);
	ADD_CONST(LOG_NOWAIT);

	ADD_CONST(LOG_AUTH);
#ifdef LOG_AUTHPRIV
	ADD_CONST(LOG_AUTHPRIV);
#endif
	ADD_CONST(LOG_CRON);
	ADD_CONST(LOG_DAEMON);
#ifdef LOG_FTP
	ADD_CONST(LOG_FTP);
#endif
	ADD_CONST(LOG_KERN);
	ADD_CONST(LOG_LPR);
	ADD_CONST(LOG_MAIL);
	ADD_CONST(LOG_NEWS);
	ADD_CONST(LOG_SYSLOG);
	ADD_CONST(LOG_USER);
	ADD_CONST(LOG_UUCP);
	ADD_CONST(LOG_LOCAL0);
	ADD_CONST(LOG_LOCAL1);
	ADD_CONST(LOG_LOCAL2);
	ADD_CONST(LOG_LOCAL3);
	ADD_CONST(LOG_LOCAL4);
	ADD_CONST(LOG_LOCAL5);
	ADD_CONST(LOG_LOCAL6);
	ADD_CONST(LOG_LOCAL7);

	ADD_CONST(LOG_EMERG);
	ADD_CONST(LOG_ALERT);
	ADD_CONST(LOG_CRIT);
	ADD_CONST(LOG_ERR);
	ADD_CONST(LOG_WARNING);
	ADD_CONST(LOG_NOTICE);
	ADD_CONST(LOG_INFO);
	ADD_CONST(LOG_DEBUG);

#ifdef HAVE_ULOG
	ADD_CONST(ULOG_KMSG);
	ADD_CONST(ULOG_SYSLOG);
	ADD_CONST(ULOG_STDIO);
#endif
}
