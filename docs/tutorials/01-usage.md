The `ucode` command line utility provides a set of options and arguments for
executing and compiling ucode programs. Here is a detailed explanation of each
option and its usage:

- `-h`:
  Display the help message, which provides an overview of the available
  options and their usage.

- `-e "expression"`:
  Execute the given expression as a ucode program. This option allows you to
  provide a single-line ucode expression for immediate execution.

- `-p "expression"`:
  Execute the given expression as a ucode program and print the result after
  execution.

- `-c [-s] [-o output.uc] input.uc [input2.uc ...]`:
  Compile the specified source file(s) to bytecode instead of executing them.
  By default, the compiled bytecode is written to `./uc.out`. The `-s` option
  omits debug information, reducing the size of the compiled bytecode. The `-o`
  option allows specifying the output file path for the compiled bytecode.

- `-t`:
  Enable VM (Virtual Machine) execution tracing. This option enables tracing of
  the ucode program's execution, providing detailed information for debugging
  purposes.

- `-g interval`:
  Perform periodic garbage collection at regular intervals defined by the
  `interval` parameter. Garbage collection is a memory management process that
  frees up memory occupied by objects that are no longer in use.

- `-S`:
  Enable strict mode, which enforces strict adherence to ucode language rules
  and prevents the use of certain potentially error-prone or unsafe language
  features.

- `-R`:
  Process source file(s) as raw script code. This is the default mode of
  operation, where the ucode interpreter treats the source files as direct ucode
  script code.

- `-T[flag,flag,...]`:
  Process the source file(s) as templates instead of raw script code. This
  option enables the usage of Jinja-like templates with embedded ECMAScript 6
  code. The flags provide additional control over template processing, such as
  preserving leading whitespace or trailing newlines.

- `-D [name=]value`:
  Define a global variable in the ucode program. If the `name` parameter is
  omitted, a JSON dictionary is expected as the `value`, where each property
  becomes a global variable with its corresponding value. If `name` is
  specified, it defines a global variable with the provided `value`, parsed as
  JSON or as a literal string if JSON parsing fails.

- `-F [name=]path`:
  Similar to the `-D` option, but reads the value from a file specified by the
  `path` parameter. The file must contain a single, well-formed JSON dictionary.

- `-U name`:
  Undefine the given global variable `name`. This option removes the specified
  global variable from the ucode program's scope.

- `-l [name=]library`:
  Preload the specified `library` for use in the ucode program. Optionally, the
  library can be aliased to a different `name` within the program.

- `-L pattern`:
  Prepend the provided `pattern` to the default library search paths. This
  option allows specifying custom paths for loading libraries. If the `pattern`
  does not contain an asterisk (`*`), it is added twice, once with `/*.so` and
  once with `/*.uc` appended to it.


## Examples

Here are some examples showcasing the invocation of the `ucode` program with
different options:

1. Execute a ucode expression:
   ```
   ucode -e "print('Hello, World!\n');"
   ```

2. Execute a ucode expression and print the result:
   ```
   ucode -p "2 ** 3"
   ```

3. Execute a ucode program from a source file:
   ```
   ucode program.uc
   ```

4. Compile a ucode program to bytecode:
   ```
   ucode -c program.uc
   ```

5. Compile a ucode program to bytecode with a specified output file:
   ```
   ucode -c -o compiled.uc program.uc
   ```
