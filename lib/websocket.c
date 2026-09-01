/*
 * Copyright (C) 2026 ucode contributors
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
 * # WebSocket Module
 *
 * The `websocket` module provides functions for interacting with WebSocket
 * (RFC 6455) servers using an event driven, uloop based API.
 *
 * Functions can be individually imported and directly accessed using the
 * {@link https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Statements/import#named_import named import}
 * syntax:
 *
 *   ```javascript
 *   import { connect } from 'websocket';
 *
 *   let ws = connect('ws://10.0.0.1:8080/path');
 *   ```
 *
 * Alternatively, the module namespace can be imported
 * using a wildcard import statement:
 *
 *   ```javascript
 *   import * as websocket from 'websocket';
 *
 *   let ws = websocket.connect('ws://10.0.0.1:8080/path');
 *   ```
 *
 * Additionally, the websocket module namespace may also be imported by
 * invoking the `ucode` interpreter with the `-lwebsocket` switch.
 *
 * @module websocket
 */

#include "ucode/module.h"

#include <wslay/wslay.h>

/**
 * Initiate a WebSocket connection to the given URL.
 *
 * @function module:websocket#connect
 *
 * @param {string} url
 * The WebSocket URL to connect to, e.g. `ws://host:port/path`.
 *
 * @param {Object} [options]
 * Connection options such as custom headers, maximum frame size or
 * handshake timeout.
 *
 * @returns {?WebSocketConnection}
 * Returns the connection resource or `null` on error.
 */
static uc_value_t *
uc_connect(uc_vm_t *vm, size_t nargs)
{
	uc_vm_raise_exception(vm, EXCEPTION_TYPE,
		"websocket.connect() is not implemented yet");

	return NULL;
}

static const uc_function_list_t websocket_fns[] = {
	{ "connect",		uc_connect },
};

void uc_module_init(uc_vm_t *vm, uc_value_t *scope)
{
	uc_function_list_register(scope, websocket_fns);
}
