# ucode Language Server Extension for Visual Studio Code

## Overview

This extension provides language server support for ucode in Visual Studio Code. It offers syntax highlighting, code completion, and error diagnostics for ucode development.

## Features

- Syntax highlighting for ucode files
- Code completion suggestions
- Basic compile time error diagnostics
- Go to definition and find all references
- Configurable ucode interpreter path
- Custom module search paths

## Requirements

- Visual Studio Code version 1.60.0 or higher
- ucode interpreter
- Valgrind (optional, for debugging)

## Installation

1. Open Visual Studio Code
2. Go to the Extensions view (Ctrl+Shift+X or Cmd+Shift+X on macOS)
3. Search for "ucode Language Server"
4. Click Install

Alternatively, the VSIX file can be downloaded from the [VS Code Marketplace](https://marketplace.visualstudio.com) and installed manually.

## Configuration

This extension contributes the following settings:

- `ucodeLanguageServer.valgrindDebugging`: Enable/disable running the language server process in Valgrind.
  - Type: `boolean`
  - Default: `false`
  - Scope: Resource

- `ucodeLanguageServer.interpreterPath`: Override the path to the ucode interpreter executable.
  - Type: `string`
  - Default: `"ucode"`
  - Scope: Resource

- `ucodeLanguageServer.moduleSearchPath`: Specify a list of module search path patterns for the ucode runtime.
  - Type: `array`
  - Default: `[]`
  - Scope: Resource

These settings can be modified in the `settings.json` file or through the Settings UI in VS Code.

Example configuration in `settings.json`:

```json
{
  "ucodeLanguageServer.valgrindDebugging": false,
  "ucodeLanguageServer.interpreterPath": "/usr/local/bin/ucode",
  "ucodeLanguageServer.moduleSearchPath": [
    "/path/to/your/ucode/modules",
    "${workspaceFolder}/ucode_modules"
  ]
}
```

Note: The `${workspaceFolder}` variable can be used in the `moduleSearchPath` to refer to the root of the current workspace.

## Known Issues

**Note:** This is an early development version of the ucode Language Server Extension. It may be unstable and contain bugs.

Current limitations:

- The extension is in active development and may change significantly.
- Some features may be incomplete or behave unexpectedly.
- Performance optimizations are ongoing.
- Error reporting and diagnostics may be incomplete or inaccurate.
- Limited testing across platforms and ucode project configurations.

Bugs and unexpected behavior can be reported by [opening an issue](https://github.com/your-repo/issues) on the GitHub repository.

Contributions are welcome.

It is recommended to use the latest version of the extension, as improvements and bug fixes are released regularly.

## Release Notes

### 0.0.20240924

Initial release of ucode Language Server Extension

- Basic syntax highlighting
- Code completion for function calls and property accesses
- Error diagnostics for cucode compile time errors

## License

This extension is licensed under the [MIT License](LICENSE.md).

## Contact

Questions, issues, or suggestions can be submitted by [opening an issue](https://github.com/jow-/ucode/issues) on the GitHub repository.
