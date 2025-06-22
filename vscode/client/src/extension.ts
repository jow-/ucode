import * as path from 'path';
import { window, workspace, ExtensionContext } from 'vscode';
import {
	Executable,
	LanguageClient,
	LanguageClientOptions,
	ServerOptions,
	TransportKind,
	RevealOutputChannelOn
} from 'vscode-languageclient/node';

let client: LanguageClient;

function sendSettings(client: LanguageClient) {
	const settings = workspace.getConfiguration('ucodeLanguageServer');

	client.sendNotification('custom/updateSettings', {
		moduleSearchPath: settings.get('moduleSearchPath')
	});
}

export function activate(context: ExtensionContext) {
	const ucodeInterp: string = workspace.getConfiguration('ucodeLanguageServer').get('interpreterPath') || 'ucode';
	const serverScript: string = context.asAbsolutePath(path.join('server', 'launcher.uc'));
	const serverSpec: Executable = {
		command: ucodeInterp,
		args: [serverScript, '--'],
		transport: TransportKind.stdio
	};
	const serverOptions: ServerOptions = { run: serverSpec, debug: serverSpec };

	const clientOptions: LanguageClientOptions = {
		documentSelector: [{ scheme: 'file', language: 'ucode' }],
		synchronize: {
			fileEvents: workspace.createFileSystemWatcher('**/.clientrc')
		},
		outputChannel: window.createOutputChannel('ucode Language Server'),
		revealOutputChannelOn: RevealOutputChannelOn.Debug
	};

	client = new LanguageClient(
		'ucodeLanguageServer',
		'ucode Language Server',
		serverOptions,
		clientOptions
	);

	sendSettings(client);

	context.subscriptions.push(
		workspace.onDidChangeConfiguration(event => {
			if (event.affectsConfiguration('ucodeLanguageServer.valgrindDebugging') ||
			    event.affectsConfiguration('ucodeLanguageServer.interpreterPath')) {

				const ucodeInterp: string = workspace.getConfiguration('ucodeLanguageServer').get('interpreterPath') || 'ucode';
				const useValgrind: boolean = workspace.getConfiguration('ucodeLanguageServer').get('valgrindDebugging');

				if (useValgrind) {
					serverSpec.command = 'valgrind';
					serverSpec.args = ['--num-callers=100', '--leak-check=full', ucodeInterp, serverScript, '--'];
				}
				else {
					serverSpec.command = ucodeInterp;
					serverSpec.args = [serverScript, '--'];
				}

				client.restart();
			}

			sendSettings(client);
		})
	);

	client.start();
}

export function deactivate(): Thenable<void> | undefined {
	if (!client) {
		return undefined;
	}
	return client.stop();
}
