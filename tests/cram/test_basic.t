setup common environment:

  $ [ -n "$BUILD_BIN_DIR" ] && export PATH="$BUILD_BIN_DIR:$PATH"
  $ alias ucode="$UCODE_BIN"

  $ for m in $BUILD_BIN_DIR/*.so; do
  >   ln -s "$m" "$(pwd)/$(basename $m)"; \
  > done

check that ucode provides exepected help:

  $ ucode | sed 's/ucode-san/ucode/'
  Usage
  
    # ucode [-t] [-l] [-r] [-S] [-R] [-x function [-x ...]] [-e '[prefix=]{"var": ...}'] [-E [prefix=]env.json] {-i <file> | -s "ucode script..."}
    -h, --help\tPrint this help (esc)
    -i file\tExecute the given ucode script file (esc)
    -s "ucode script..."\tExecute the given string as ucode script (esc)
    -t Enable VM execution tracing
    -l Do not strip leading block whitespace
    -r Do not trim trailing block newlines
    -S Enable strict mode
    -R Enable raw code mode
    -e Set global variables from given JSON object
    -E Set global variables from given JSON file
    -x Disable given function
    -m Preload given module

check that ucode prints greetings:

  $ ucode -s "{% print('hello world') %}"
  hello world (no-eol)

check that ucode provides proper error messages:

  $ ucode -m foo
  One of -i or -s is required
  [1]

  $ ucode -m foo -s ' '
  Runtime error: No module named 'foo' could be found
  
  [254]

  $ touch moo; ucode -m foo -i moo
  Runtime error: No module named 'foo' could be found
  
  [254]

check that ucode can load fs module:

  $ ucode -m fs
  One of -i or -s is required
  [1]

  $ ucode -m fs -s ' '
    (no-eol)

  $ touch moo; ucode -m fs -i moo
