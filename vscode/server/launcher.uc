import { stdin, stdout, open, stat } from 'fs';
import { poll, POLLIN, POLLHUP, POLLERR } from 'socket';

const server_path = `${sourcepath(0, true)}/server.uc`;

let server, prev_mtime;
let opened = {};

unshift(REQUIRE_SEARCH_PATH, `${sourcepath(0, true)}/*.uc`);

function check_update() {
	let curr_mtime = stat(server_path)?.mtime ?? 0;

	if (curr_mtime != prev_mtime) {
		warn(`Reloading ${server_path}...\n`);

		try {
			for (let mod in global.modules)
				delete global.modules[mod];

			require('server');

			if (global.modules.server)
				server = global.modules.server;

			for (let uri, msg in opened)
				server.handle(msg);
		}
		catch (e) {
			warn(`Unable to reload server: ${e}\n`);
		}

		prev_mtime = curr_mtime;
	}
}

function recvmsg() {
	let clen, ctype = 'application/vscode-jsonrpc; charset=utf-8';

	while (true) {
		let header = rtrim(stdin.read('line'), '\r\n');

		if (header == null) {
			warn("EOF while reading message header\n");
			exit(1);
		}

		if (!length(header))
			break;

		let kv = split(header, ':', 2);

		switch (kv[0]) {
		case 'Content-Length':
			clen = +kv[1];
			break;

		case 'Content-Type':
			ctype = trim(kv[1]);
			break;
		}
	}

	if (clen == null || clen == 0) {
		warn(`Invalid Content-Length in request\n`);
		return null;
	}

	if (ctype != 'application/vscode-jsonrpc; charset=utf-8') {
		warn(`Unexpected Content-Type '${ctype ?? '?'}' in request\n`);
		return null;
	}

	let payload = stdin.read(clen);
	let message;

	try {
		message = json(payload);
	}
	catch (e) {
		warn(`Invalid request payload '${payload}: ${e}\n`);
		return null;
	}

	let msgstr = `${message}`;

	if (length(msgstr) > 127)
		msgstr = `${substr(msgstr, 0, 127)}...`;

	warn(`[RX] ${msgstr}\n`);

	return message;
}

function reply(id, payload) {
	let message = sprintf('%J', ('jsonrpc' in payload) ? payload : {
		jsonrpc: '2.0',
		id,
		result: payload
	});

	let header = sprintf('Content-Length: %d\r\n\r\n', length(message));

	let msgstr = `${message}`;

	if (length(msgstr) > 127)
		msgstr = `${substr(msgstr, 0, 127)}...`;

	warn(`[TX] ${msgstr}\n`);

	stdout.write(header);
	stdout.write(message);
	stdout.flush();
}

while (true) {
	const events = poll(250, stdin);

	check_update();

	if (events[0][1] & (POLLHUP|POLLERR)) {
		warn(`Peer closed connection, shutting down.\n`);
		break;
	}
	else if (events[0][1] & POLLIN) {
		let rpc = recvmsg();

		if (rpc.method in [ "textDocument/didOpen", "textDocument/didChange" ])
			opened[rpc.params.textDocument.uri] = rpc;

		try {
			let out = server.handle(rpc);
			reply(rpc.id, out);
		}
		catch (e) {
			warn(`Error handling '${rpc.method}': ${e}\n${e.stacktrace[0].context}\n`);
			reply(rpc.id, null);
		}
	}
	else {
		try {
			let out = server.idle();

			if (type(out) == 'array')
				for (let msg in out)
					reply(null, msg);
			else if (out)
				reply(null, out);
		}
		catch (e) {
			warn(`Error invoking idle method: ${e}\n${e.stacktrace[0].context}\n`);
		}
	}
}
