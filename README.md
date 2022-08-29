# ABOUT

The ucode language is a tiny general purpose scripting language featuring a
syntax closely resembling ECMAScript. It can be used in a stand-alone manner
by using the ucode command line interpreter or embedded into host applications
by linking libucode and utilizing its C language API. Additionally, ucode can
be invoked in template mode where control flow and expression logic statements
are embedded in Jinja-like markup blocks.

Besides aiming for small size, the major design goals of ucode are the ability
to trivially read and write JSON data, good embeddability into C applications,
template capabilities for output formatting, extensiblity through loadable
native extension modules and a straightforward set of built-in functions
mimicking those found in the Perl 5 language.

## HISTORY AND MOTIVATION

In spring 2021 it has been decided to rewrite the OpenWrt firewall framework on
top of nftables with the goal to replace the then current C application with a
kind of preprocessor generating nftables rulesets using a set of templates
instead of relying on built-in hardcoded rules like its predecessor.

That decision spurred the development of *ucode*, initially meant to be a
simple template processor solely for the OpenWrt nftables firewall but quickly
evolving into a general purpose scripting language suitable for a wider range
of system scripting tasks.

Despite OpenWrt predominantly relying on POSIX shell and Lua as system
scripting languages already, a new solution was needed to accomodate the needs
of the new firewall implementation; mainly the ability to efficiently deal with
JSON data and complex data structures such as arrays and dictionaries and the
ability to closely interface with OpenWrt's *ubus* message bus system.

Throughout the design process of the new firewall and its template processor,
the following design goals were defined for the *ucode* scripting language:

 - Ability to embed code logic fragments such as control flow statements,
   function calls or arithmetic expressions into plain text templates, using
   a block syntax and functionality roughly inspired by Jinja templates
 - Built-in support for JSON data parsing and serialization, without the need
   for external libraries
 - Distinct array and object types (compared to Lua's single table datatype)
 - Distinct integer and float types and guaranteed 64bit integer range
 - Built-in support for bit operations
 - Built-in support for (POSIX) regular expressions
 - A comprehensive set of built-in standard functions, inspired by the core
   functions found in the Perl 5 interpreter
 - Staying as close to ECMAScript syntax as possible due to higher developer
   familiarity and to be able to reuse existing tooling such as editor syntax
   highlighting
 - Bindings for all relevant Linux and OpenWrt APIs, such as *ubus*, *uci*,
   *uloop*, *netlink* etc.
 - Procedural, synchronous programming flow
 - Very small executable size (the interpreter and runtime is currently around
   64KB on ARM Cortex A9)
 - Embeddability into C host applications

Summarized, *ucode* can be described as synchronous ECMAScript without the
object oriented standard library.


# INSTALLATION

## OpenWrt

In OpenWrt 22.03 and later, *ucode* should already be preinstalled. If not,
it can be installed via the package manager, using the `opkg install ucode`
command.

## MacOS

To build on MacOS, first install *cmake* and *json-c* via
[Homebrew](https://brew.sh/), then clone the ucode repository and execute
*cmake* followed by *make*:

    $ brew install cmake json-c
    $ git clone https://github.com/jow-/ucode.git
    $ cd ucode/
    $ cmake -DUBUS_SUPPORT=OFF -DUCI_SUPPORT=OFF -DULOOP_SUPPORT=OFF .
    $ make
    $ sudo make install

## Debian

The ucode repository contains build recipes for Debian packages, to build .deb
packages for local installation, first install required development packages,
then clone the repository and invoke *dpkg-buildpackage* to produce the binary
package files:

    $ sudo apt-get install build-essential devscripts debhelper libjson-c-dev
    $ git clone https://github.com/jow-/ucode.git
    $ cd ucode/
    $ dpkg-buildpackage -b -us -uc
    $ sudo dpkg -i ../ucode*.deb ../libucode*.deb

## Other Linux systems

To install ucode from source on other systems, ensure that the json-c library
and associated development headers are installed, then clone and compile the
ucode repository:

    $ git clone https://github.com/jow-/ucode.git
    $ cd ucode/
    $ cmake -DUBUS_SUPPORT=OFF -DUCI_SUPPORT=OFF -DULOOP_SUPPORT=OFF .
    $ make
    $ sudo make install


# SYNTAX

## Template mode

By default, *ucode* is executed in *raw mode*, means it expects a given source
file to only contain script code. By invoking the ucode interpreter with the
`-T` flag or by using the `utpl` alias, the *ucode* interpreter is switched
into *template mode* where the source file is expected to be a plaintext file
containing *template blocks* containing ucode script expressions or comments.

### Block types

There are three kinds of blocks; *expression blocks*, *statement blocks* and
*comment blocks*. The former two embed code logic using ucode's JavaScript-like
syntax while the latter comment block type is simply discarded during
processing.


#### 1. Statement block

Statement blocks are enclosed in an opening `{%` and a closing `%}` tag and
may contain any number of script code statements, even entire programs.

It is allowed to omit the closing `%}` of a statement block to parse the
entire remaining source text after the opening tag as ucode script.

By default, statement blocks produce no output and the entire block is
reduced to an empty string during template evaluation but contained script
code might invoke functions such as `print()` to explicitly output contents.

For example the following template would result in `The epoch is odd` or
`The epoch is even`, depending on the current epoch value:

`The epoch is {% if (time() % 2): %}odd{% else %}even{% endif %}!`


#### 2. Expression block

Expression blocks are enclosed in an opening `{{` and a closing `}}` tag and
may only contain a single expression statement (multiple expressions may be
chained with comma). The implicit result of the rightmost evaluated expression
is used as output when processing the block.

For example the template `Hello world, {{ getenv("USER") }}!` would result in
the output "Hello world, user!" where `user` would correspond to the name of
the current user executing the ucode interpreter.


#### 3. Comment block

Comment blocks, which are denoted with an opening `{#` and a closing `#}` tag
may contain arbitrary text except the closing `#}` tag itself. Comments blocks
are completely stripped during processing and are replaced with an empty string.

The following example template would result in the output "Hello world":

`Hello {# mad #}word`


### Whitespace handling

Each block start tag may be suffixed with a dash to strip any whitespace
before the block and likewise any block end tag may be prefixed with a dash
to strip any whitespace following the block.

Without using whitespace stripping, the following example:

```
This is a first line
{% for (x in [1, 2, 3]): %}
This is item {{ x }}.
{% endfor %}
This is the last line
```

Would result in the following output:

```
This is a first line

This is item 1.
This is item 2.
This is item 3.

This is the last line
```

By adding a trailing dash to apply whitespace stripping after the block, the
empty lines can be eliminated:

```
This is a first line
{% for (x in [1, 2, 3]): -%}
This is item {{ x }}.
{% endfor -%}
This is the last line
```

Output:

```
This is a first line
This is item 1.
This is item 2.
This is item 3.
This is the last line
```

By applying whitespace stripping before the block, all lines can be joined
into a single output line:

```
This is a first line
{%- for (x in [1, 2, 3]): -%}
This is item {{ x }}.
{%- endfor -%}
This is the last line
```

Output:

```
This is a first lineThis is item 1.This is item 2.This is item 3.This is the last line
```

## Script syntax

The ucode script language - used either within statement and expression blocks
or throughout the entire file in *raw mode*, uses untyped variables and employs
a simplified JavaScript like syntax.

The language implements function scoping and differentiates between local and
global variables. Each function has its own private scope while executing and
local variables declared inside a function are not accessible in the outer
calling scope.

### 1. Data types

Ucode supports seven different basic types as well as two additional special
types; function values and ressource values. The supported types are:

 - Boolean values (`true` or `false`)
 - Integer values (`-9223372036854775808` to `+9223372036854775807`)
 - Double values (`-1.7e308` to `+1.7e308`)
 - String values (e.g. `'Hello world!'` or `"Sunshine \u2600!"`)
 - Array values (e.g. `[1, false, "foo"]`)
 - Object values (e.g. `{ foo: true, "bar": 123 }`)
 - Null value (`null`)

Ucode utilizes reference counting to manage memory used for variables and values
and frees data automatically as soon as values go out of scope.

Numeric values are either stored as signed 64bit integers or as IEEE 756 double
value. Conversion between integer and double values can happen implicitly, e.g.
through numeric operations, or explicitely, e.g. by invoking functions such as
`int()`.

### 2. Variables

Variable names must start with a letter or an underscore and may only contain
the characters `A`..`Z`, `a`..`z`, `0`..`9` or `_`. By prefixing a variable
name with the keyword `let`, it is declared in the local block scope only
and not visible outside anymore.

Variables may also be declared using the `const` keyword. Such variables follow
the same scoping rules as `let` declared ones but they cannot be modified after
they have been declared. Any attempt to do so will result in a syntax error
during compilation.

```javascript
{%

  a = 1;  // global variable assignment

  function test() {
    let b = 2;  // declare `b` as local variable
    a = 2;        // overwrite global a
  }

  test();

  print(a, "\n");  // outputs "2"
  print(b, "\n");  // outputs nothing

  const c = 3;
  print(c, "\n");  // outputs "3"

  c = 4;           // raises syntax error
  c++;             // raises syntax error

  const d;         // raises syntax error, const variables must
                   // be initialized at declaration time

%}
```

### 3. Control statements

Similar to JavaScript, ucode supports `if`, `for` and `while` statements to
control execution flow.

#### 3.1. Conditional statement

If/else blocks can be used execute statements depending on a condition.

```javascript
{%

  user = getenv("USER");

  if (user == "alice") {
      print("Hello Alice!\n");
  }
  else if (user == "bob") {
      print("Hello Bob!\n");
  }
  else {
      print("Hello guest!\n");
  }

%}
```

If only a single statement is wrapped by an if or else branch, the enclosing
curly braces may be omitted:

```javascript
{%

  if (rand() == 3)
      print("This is quite unlikely\n");

%}
```

#### 3.2. Loop statements

Ucode script supports three different flavors of loop control statements; a
`while` loop that executes enclosed statements as long as the loop condition is
fulfilled, a `for in` loop that iterates keys of objects or items of arrays and
a counting `for` loop that is a variation of the `while` loop.

```javascript
{%

  i = 0;
  arr = [1, 2, 3];
  obj = { Alice: 32, Bob: 54 };

  // execute as long as condition is true
  while (i < length(arr)) {
      print(arr[i], "\n");
      i++;
  }

  // execute for each item in arr
  for (n in arr) {
      print(n, "\n");
  }

  // execute for each key in obj
  for (person in obj) {
      print(person, " is ", obj[person], " years old.\n");
  }

  // execute initialization statement (j = 0) once
  // execute as long as condition (j < length(arr)) is true
  // execute step statement (j++) after each iteration
  for (j = 0; j < length(arr); j++) {
      print(arr[j], "\n");
  }

%}
```

#### 3.3. Alternative syntax

Since conditional statements and loops are often used for template formatting
purposes, e.g. to repeat a specific markup for each item of a list, ucode
supports an alternative syntax that does not require curly braces to group
statements but that uses explicit end keywords to denote the end of the control
statement body for better readability instead.

The following two examples first illustrate the normal syntax, followed by the
alternative syntax that is more suitable for statement blocks:

```
Printing a list:
{% for (n in [1, 2, 3]) { -%}
  - Item #{{ n }}
{% } %}
```

The alternative syntax replaces the opening curly brace (`{`) with a colon
(`:`) and the closing curly brace (`}`) with an explicit `endfor` keyword:

```
Printing a list:
{% for (n in [1, 2, 3]): -%}
  - Item #{{ n }}
{% endfor %}
```

For each control statement type, a corresponding alternative end keyword is defined:

  - `if (...): ... endif`
  - `for (...): ... endfor`
  - `while (...): ... endwhile`


### 4. Functions

Ucode scripts may define functions to group repeating operations into reusable
operations. Functions can be both declared with a name, in which case they're
automatically registered in the current scope, or anonymously which allows
assigning the resulting value to a variable, e.g. to build arrays or objects of
functions:

```javascript
{%

  function duplicate(n) {
       return n * 2;
  }

  let utilities = {
      concat: function(a, b) {
          return "" + a + b;
      },
      greeting: function() {
          return "Hello, " + getenv("USER") + "!";
      }
  };

-%}

The duplicate of 2 is {{ duplicate(2) }}.
The concatenation of 'abc' and 123 is {{ utilities.concat("abc", 123) }}.
Your personal greeting is: {{ utilities.greeting() }}.
```

#### 4.1. Alternative syntax

Function declarations support the same kind of alternative syntax as defined
for control statements (3.3.)

The alternative syntax replaces the opening curly brace (`{`) with a colon
(`:`) and the closing curly brace (`}`) with an explicit `endfunction`
keyword:

```
{% function printgreeting(name): -%}
  Hallo {{ name }}, nice to meet you.
{% endfunction -%}

<h1>{{ printgreeting("Alice") }}</h1>
```


### 5. Operators

Similar to JavaScript and C, ucode scripts support a range of different
operators to manipulate values and variables.

#### 5.1. Arithmetic operations

The operators `+`, `-`, `*`, `/`, `%`, `++` and `--` allow to perform
additions, substractions, multiplications, divisions, modulo, increment or
decrement operations respectively where the result depends on the type of
involved values.

The `++` and `--` operators are unary, means that they only apply to one
operand. The `+` and `-` operators may be used in unary context to either
convert a given value to a numeric value or to negate a given value.

If either operand of the `+` operator is a string, the other one is converted
to a string value as well and a concatenated string is returned.

All other arithmetic operators coerce their operands into numeric values.
Fractional values are converted to doubles, other numeric values to integers.

If either operand is a double, the other one is converted to a double value as
well and a double result is returned.

Divisions by zero result in the special double value `Infinity`. If an operand
cannot be converted to a numeric value, the result of the operation is the
special double value `NaN`.

```javascript
{%
  a = 2;
  b = 5.2;
  s1 = "125";
  s2 = "Hello world";

  print(+s1);      // 125
  print(+s2);      // NaN
  print(-s1);      // -125
  print(-s2);      // NaN
  print(-a);       // -2

  print(a++);      // 2 (Return value of a, then increment by 1)
  print(++a);      // 4 (Increment by 1, then return value of a)

  print(b--);      // 5.2 (Return value of b, then decrement by 1)
  print(--b);      // 3.2 (Decrement by 1, then return value of b)

  print(4 + 8);    // 12
  print(7 - 4);    // 3
  print(3 * 3);    // 9

  print(10 / 4);   // 2 (Integer division)
  print(10 / 4.0); // 2.5 (Double division)
  print(10 / 0);   // Infinity

  print(10 % 7);   // 3
  print(10 % 7.0); // NaN (Modulo is undefined for non-integers)
%}
```

#### 5.2. Bitwise operations

The operators `&`, `|`, `^`, `<<`, `>>` and `~` allow to perform bitwise and,
or, xor, left shift, right shift and complement operations respectively.

The `~` operator is unary, means that is only applies to one operand.

```javascript
{%
  print(0 & 0, 0 & 1, 1 & 1);  // 001
  print(0 | 0, 0 | 1, 1 | 1);  // 011
  print(0 ^ 0, 0 ^ 1, 1 ^ 1);  // 010
  print(10 << 2);              // 40
  print(10 >> 2);              // 2
  print(~15);                  // -16 (0xFFFFFFFFFFFFFFF0)
%}
```

An important property of bitwise operators is that they're coercing their
operand values to whole integers:

```javascript
{%
  print(12.34 >> 0);   // 12
  print(~(~12.34));    // 12
%}
```

#### 5.3. Relational operations

The operators `==`, `!=`, `<`, `<=`, `>` and `>=` test whether their operands
are equal, inequal, lower than, lower than/equal to, higher than or higher
than/equal to each other respectively.

If both operands are strings, their respective byte values are compared, if
both are objects or arrays, their underlying memory addresses are compared.

In all other cases, both operands are coerced into numeric values and the
resulting values are compared with each other.

This means that comparing values of different types will coerce them both to
numbers.

The result of the relational operation is a boolean indicating truishness.

```javascript
{%
  print(123 == 123);     // true
  print(123 == "123");   // true!
  print(123 < 456);      // true
  print(123 > 456);      // false
  print(123 != 456);     // true
  print(123 != "123");   // false!
  print({} == {});       // false (two different anonymous objects)
  a = {}; print(a == a); // true (same object)
%}
```

#### 5.4. Logical operations

The operators `&&`, `||` and `!` test whether their operands are all true,
partially true or false respectively.

In the case of `&&` the rightmost value is returned while `||` results in the
first truish value.

The unary `!` operator will result in `true` if the operand is not treish,
otherwise it will result in `false`.

Operands are evaluated from left to right while testing truishness, which means
that expressions with side effects, such as function calls, are only executed
if the preceeding condition was satisifed.

```javascript
{%
  print(1 && 2 && 3);    // 3
  print(1 || 2 || 3);    // 1
  print(2 > 1 && 3 < 4); // true
  print(!false);         // true
  print(!true);          // false

  res = test1() && test2();  // test2() is only called if test1() returns true
%}
```

#### 5.5. Assignment operations

In addition to the basic assignment operator `=`, most other operators have a
corresponding shortcut assignment operator which reads the specified variable,
applies the operation and operand to it, and writes it back.

The result of assignment expressions is the assigned value.

```javascript
{%
  a = 1;     // assign 1 to variable a
  a += 2;    // a = a + 2;
  a -= 3;    // a = a - 3;
  a *= 4;    // a = a * 4;
  a /= 5;    // a = a / 5;
  a %= 6;    // a = a % 6;
  a &= 7;    // a = a & 7;
  a |= 8;    // a = a | 8;
  a ^= 9;    // a = a ^ 9;
  a <<= 10;  // a = a << 10;
  a >>= 11;  // a = a >> 11;

  print(a = 2);  // 2
%}
```

#### 5.6. Miscellaneous operators

Besides the operators described so far, ucode script also supports a `delete`
operator which removes a property from an object value.

```javascript
{%
  a = { test: true };

  delete a.test;         // true
  delete a.notexisting;  // false

  print(a);              // { }
%}
```

### 6. Functions

Ucode scripts may call a number of built-in functions to manipulate values or
to output information.

#### 6.1. `abs(x)`

Returns the absolute value of the given operand. Results in `NaN` if operand is
not convertible to number.

```javascript
abs(1);        // 1
abs(-2);       // 2
abs(-3.5);     // 3.5
abs("0x123");  // 291
abs("-0x123"); // NaN
abs([]);       // NaN
```

#### 6.2. `atan2(x, y)`

Calculates the principal value of the arc tangent of x/y, using the signs of
the two arguments to determine the quadrant of the result.

#### 6.3. `chr(n1, ...)`

Converts each given numeric value to a byte and return the resulting string.
Invalid numeric values or values < 0 result in `\0` bytes, values larger than
255 are truncated to 255.

```javascript
chr(65, 98, 99);  // "Abc"
chr(-1, 300);     // string consisting of an `0x0` and a `0xff` byte
```

#### 6.4. `cos(x)`

Return the cosine of x, where x is given in radians.

#### 6.5. `die(msg)`

Raise an exception with the given message and abort execution.

#### 6.6. `exists(obj, key)`

Return `true` if the given key is present within the object passed as first
argument, otherwise `false`.

#### 6.7. `exit(n)`

Terminate the interpreter with the given exit code.

#### 6.8. `exp(n)`

Return the value of e (the base of natural logarithms) raised to the power
of n.

#### 6.9. `filter(arr, fn)`

Filter the array passed as first argument by invoking the function specified
in the second argument for each array item.

If the invoked function returns a truish result, the item is retained,
otherwise it is dropped. The filter function is invoked with three arguments:

 1. The array value
 2. The current index
 3. The array being filtered

Returns the filtered array.

```javascript
// filter out any empty string:
a = filter(["foo", "", "bar", "", "baz"], length)
// a = ["foo", "bar", "baz"]

// filter out any non-number type:
a = filter(["foo", 1, true, null, 2.2], function(v) {
    return (type(v) == "int" || type(v) == "double");
});
// a = [1, 2.2]
```

#### 6.10. `getenv([name])`

Return the value of the given environment variable. If the variable name is
omitted, returns a dictionary containing all environment variables.

#### 6.11. `hex(x)`

Convert the given hexadecimal string into a number.

#### 6.12. `index(arr_or_str, needle)`

Find the given value passed as second argument within the array or string
specified in the first argument.

Returns the first matching array index or first matching string offset or `-1`
if the value was not found.

Returns `null` if the first argument was neither an array, nor a string.

#### 6.13. `int(x)`

Convert the given value to an integer. Returns `NaN` if the value is not
convertible.

#### 6.14. `join(sep, arr)`

Join the array passed as 2nd argument into a string, using the separator passed
in the first argument as glue. Returns `null` if the second argument is not an
array.

#### 6.15. `keys(obj)`

Return an array of all key names present in the passed object. Returns `null`
if the given argument is no object.

#### 6.16. `lc(s)`

Convert the given string to lowercase and return the resulting string.
Returns `null` if the given argument could not be converted to a string.

#### 6.17. `length(x)`

Return the length of the given object, array or string. Returns `null` if
the given argument is neither an object, array, nor a string.

For objects, the length is defined as the number of keys within the object,
for arrays the length specifies the amount of contained items and for strings
it represents the number of contained bytes.

```javascript
length("test")                             // 4
length([true, false, null, 123, "test"])   // 5
length({foo: true, bar: 123, baz: "test"}) // 3
length({})                                 // 0
length(true)                               // null
length(10.0)                               // null
```

#### 6.18. `log(x)`

Return the natural logarithm of x.

#### 6.19. `ltrim(s, c)`

Trim any of the specified characters in `c` from the start of `str`.
If the second argument is omitted, trims the characters, ` ` (space), `\t`,
`\r` and `\n`.

```javascript
ltrim("  foo  \n")     // "foo  \n"
ltrim("--bar--", "-")  // "bar--"
```

#### 6.20. `map(arr, fn)`

Transform the array passed as first argument by invoking the function specified
in the second argument for each array item.

The result of the invoked function is put into the resulting array.
The map function is invoked with three arguments:

 1. The array value
 2. The current index
 3. The array being filtered

Returns the transformed array.

```javascript
// turn into array of string lengths:
a = map(["Apple", "Banana", "Bean"], length)
// a = [5, 6, 4]

// map to type names:
a = map(["foo", 1, true, null, 2.2], type);
// a = ["string", "int", "bool", null, "double"]
```

#### 6.21. `ord(s [, offset])`

Without further arguments, this function returns the byte value of the first
character in the given string.

If an offset argument is supplied, the byte value of the character at this
position is returned. If an invalid index is supplied, the function will
return `null`. Negative index entries are counted towards the end of the
string, e.g. `-2` will return the value of the second last character.

```javascript
ord("Abc");         // 65
ord("Abc", 0);      // 65
ord("Abc", 1);      // 98
ord("Abc", 2);      // 99
ord("Abc", 10);     // null
ord("Abc", -10);    // null
ord("Abc", "nan");  // null
```

#### 6.22. `pop(arr)`

Pops the last item from the given array and returns it. Returns `null` if the
array was empty or if a non-array argument was passed.

#### 6.23. `print(x, ...)`

Print any of the given values to stdout. Arrays and objects are converted to
their JSON representation.

Returns the amount of bytes printed.

#### 6.24. `push(arr, v1, ...)`

Push the given argument(s) to the given array. Returns the last pushed value.

#### 6.25. `rand()`

Returns a random number. If `srand()` has not been called already, it is
automatically invoked passing the current time as seed.

#### 6.26. `reverse(arr_or_str)`

If an array is passed, returns the array in reverse order. If a string is
passed, returns the string with the sequence of the characters reversed.

Returns `null` if neither an array nor a string were passed.

#### 6.27. `rindex(arr_or_str, needle)`

Find the given value passed as second argument within the array or string
specified in the first argument.

Returns the last matching array index or last matching string offset or `-1`
if the value was not found.

Returns `null` if the first argument was neither an array, nor a string.

#### 6.28. `rtrim(str, c)`

Trim any of the specified characters in `c` from the end of `str`.
If the second argument is omitted, trims the characters, ` ` (space), `\t`,
`\r` and `\n`.

```javascript
rtrim("  foo  \n")     // "  foo"
rtrim("--bar--", "-")  // "--bar"
```

#### 6.29. `shift(arr)`

Pops the first item from the given array and returns it. Returns `null` if the
array was empty or if a non-array argument was passed.

#### 6.30. `sin(x)`

Return the sine of x, where x is given in radians.

#### 6.31. `sort(arr, fn)`

Sort the given array according to the given sort function. If no sort
function is provided, a default ascending sort order is applied.

```javascript
sort([8, 1, 5, 9]) // [1, 5, 8, 9]
sort(["Bean", "Orange", "Apple"], function(a, b) {
    return length(a) < length(b);
}) // ["Bean", "Apple", "Orange"]
```

#### 6.32. `splice(arr, off, len, ...)`

Removes the elements designated by `off` and `len` from  the given an array,
and replaces them with the additional arguments passed, if any. Returns the
last element removed, or `null` if no elements are removed. The array grows or shrinks as necessary.

If `off` is negative then it starts that far from the end of the array. If
`len` is omitted, removes everything from `off` onward. If `len` is negative,
removes the elements from `off` onward except for `-len` elements at the end of
the array. If both `off` and `len` are omitted, removes everything.

#### 6.33. `split(str, sep)`

Split the given string using the separator passed as second argument and return
an array containing the resulting pieces.

The separator may either be a plain string or a regular expression.

```javascript
split("foo,bar,baz", ",")     // ["foo", "bar", "baz"]
split("foobar", "")           // ["f", "o", "o", "b", "a", "r"]
split("foo,bar,baz", /[ao]/)  // ["f", "", ",b", "r,b", "z"]
```

#### 6.34. `sqrt(x)`

Return the nonnegative square root of x.

#### 6.35. `srand(n)`

Seed the PRNG using the given number.

#### 6.36. `substr(str, off, len)`

Extracts a substring out of `str` and returns it. First character is at offset
zero. If `off` is negative, starts that far back from the end of the string.
If `len` is omitted, returns everything through the end of the string. If `len`
is negative, leaves that many characters off the end of the string.

```javascript
s = "The black cat climbed the green tree";

substr(s, 4, 5);      // black
substr(s, 4, -11);    // black cat climbed the
substr(s, 14);        // climbed the green tree
substr(s, -4);        // tree
substr(s, -4, 2);     // tr
```

#### 6.37. `time()`

Returns the current UNIX epoch.

```javascript
time();     // 1598043054
```

#### 6.38. `trim()`

Trim any of the specified characters in `c` from the start and end of `str`.
If the second argument is omitted, trims the characters, ` ` (space), `\t`,
`\r` and `\n`.

```javascript
ltrim("  foo  \n")     // "foo"
ltrim("--bar--", "-")  // "bar"
```

#### 6.39. `type(x)`

Returns the type of the given value as string which might be one of
`"function"`, `"object"`, `"array"`, `"double"`, `"int"` or `"bool"`.

Returns `null` when no value or `null` is passed.

#### 6.40. `uchr(n1, ...)`

Converts each given numeric value to an utf8 escape sequence and returns the
resulting string. Invalid numeric values or values outside the range `0` ..
`0x10FFFF` are represented by the unicode replacement character `0xFFFD`.

```javascript
uchr(0x2600, 0x26C6, 0x2601);  // "☀⛆☁"
uchr(-1, 0x20ffff, "foo");     // "���"
```

#### 6.41. `uc(str)`

Converts the given string to uppercase and return the resulting string.
Returns `null` if the given argument could not be converted to a string.

#### 6.42. `unshift(arr, v1, ...)`

Add the given values to the beginning of the array passed as first argument.
Returns the last value added to the array.

#### 6.43. `values(obj)`

Returns an array containing all values of the given object. Returns `null` if
no object was passed.

```javascript
values({ foo: true, bar: false });   // [true, false]
```

#### 6.44. `printf(fmt, ...)`

Formats the given arguments according to the given format string and outputs the
result to stdout.

Ucode supports a restricted subset of the formats allowed by the underlying
libc's `printf()` implementation, namely it allows the `d`, `i`, `o`, `u`, `x`,
`X`, `e`, `E`, `f`, `F`, `g`, `G`, `c` and `s` conversions.

Additionally, an ucode specific `J` format is implemented, which causes the
corresponding value to be formatted as JSON string. By prefixing the `J` format
letter with a precision specifier, the resulting JSON output will be pretty
printed. A precision of `0` will use tabs for indentation, any other positive
precision will use that many spaces for indentation while a negative or omitted
precision specifier will turn off pretty printing.

Other format specifiers such as `n` or `z` are not accepted and returned
verbatim. Format specifiers including `*` and `$` directives are rejected as
well.

```javascript
{%
  printf("Hello %s\n", "world");  // Hello world
  printf("%08x\n", 123);          // 0000007b
  printf("%c%c%c\n", 65, 98, 99); // Abc
  printf("%g\n", 10 / 3.0);       // 3.33333
  printf("%J", [1,2,3]);          // [ 1, 2, 3 ]

  printf("%.J", [1,2,3]);
  // [
  //         1,
  //         2,
  //         3
  // ]

  printf("%.2J", [1,2,3]);
  // [
  //   1,
  //   2,
  //   3
  // ]
%}
```

#### 6.45. `sprintf(fmt, ...)`

Formats the given arguments according to the given format string and returns the
resulting string.

See `printf()` for details.

#### 6.46. `match(str, /pattern/)`

Match the given string against the regular expression pattern specified as
second argument.

If the passed regular expression uses the `g` flag, the return value will be an
array of arrays describing all found occurences within the string.

Without the `g` modifier, an array describing the first match is returned.
Returns `null` if the pattern was not found within the given string.

```javascript
match("foobarbaz", /b.(.)/)   // ["bar", "r"]
match("foobarbaz", /b.(.)/g)  // [["bar", "r"], ["baz", "z"]]
```

#### 6.47. `replace(str, /pattern/, replace)`

Replace occurences of the specified pattern in the string passed as first
argument. The pattern value may be either a regular expression or a plain
string. The replace value may be a function which is invoked for each found
pattern or any other value which is converted into a plain string and used as
replacement.

If the pattern is a regular expression and not using the `g` flag, then only the
first occurence in the string is replaced, if the `g` flag is used or if the
pattern is not a regular expression, all occurrences are replaced.

If the replace value is a callback function, it is invoked with the found
substring as first and any capture group values as subsequent parameters.

If the replace value is a string, the following special substrings are
substituted before it is inserted into the result:

 - `$$` - replaced by a literal `$`
 - ``$` `` - replaced by the text before the match
 - `$'` - replaced by the text after the match
 - `$&` - replaced by the matched substring
 - `$1`..`$9` - replaced by the value of the corresponding capture group, if the capture group is not defined, it is not substituted

```javascript
replace("barfoobaz", /(f)(o+)/g, "[$$|$`|$&|$'|$1|$2|$3]")  // bar[$|bar|foo|baz|f|oo|$3]baz
replace("barfoobaz", /(f)(o+)/g, uc)                        // barFOObaz
replace("barfoobaz", "a", "X")                              // bXrfoobXz
replace("barfoobaz", /(.)(.)(.)/g, function(m, c1, c2, c3) {
    return c3 + c2 + c1;
})                                                          // raboofzab
```

#### 6.48. `json(str)`

Parse the given string as JSON and return the resulting value. Throws an
exception on parse errors, trailing garbage or premature EOF.

```javascript
json('{"a":true, "b":123}')   // { "a": true, "b": 123 }
json('[1,2,')                 // Throws exception
```

#### 6.49. `include(path[, scope])`

Evaluate and include the file at the given path and optionally override the
execution scope with the given scope object.

By default, the file is executed within the same scope as the calling
`include()` but by passing an object as second argument, it is possible to
extend the scope available to the included file. This is useful to supply
additional properties as global variables to the included code.

To sandbox included code, that is giving it only access to explicitely
provided properties, the `proto()` function can be used to create a scope
object with an empty prototype. See the examples below for details.

If the given path argument is not absolute, it is interpreted relative to the
directory of the current template file, that is the file that is invoking the
`include()` function.

If the ucode interpreter executes program code from stdin, the given path is
interpreted relative to the current working directory of the process.

```javascript
// Load and execute "foo.uc" immediately
include("./foo.uc")

// Execute the "supplemental.ucode" in an extended scope and make the "foo" and
// "bar" properties available as global variables
include("./supplemental.uc", {
  foo: true,
  bar: 123
})

// Execute the "untrusted.ucode" in a sandboxed scope and make the "foo" and
// "bar" variables as well as the "print" function available to it. By assigning
// an empty prototype object to the scope, included code has no access to
// other global values anymore
include("./untrusted.uc", proto({
  foo: true,
  bar: 123,
  print: print
}, {}))
```

#### 6.50. `warn(x, ...)`

Print any of the given values to stderr. Arrays and objects are converted to
their JSON representation.

Returns the amount of bytes printed.

#### 6.51. `system(command, timeout)`

Executes the given command, waits for completion and returns the resulting
exit code.

The command argument may be either a string, in which case it is passed to
`/bin/sh -c`, or an array, which is directly converted into an `execv()`
argument vector.

If the program terminated normally, a positive integer holding the programs
`exit()` code is returned. If the program was terminated by an uncatched
signal, a negative signal number is returned, e.g. `-9` when the program was
terminated by `SIGKILL`.

If the optional timeout argument is specified, the program is terminated by
`SIGKILL` after that many milliseconds when it didn't complete within the timeout.

Omitting the timeout argument, or passing `0` disables the command timeout.

```javascript
// Execute through `/bin/sh`
system("echo 'Hello world' && exit 3");    // prints "Hello world" to stdout and returns 3

// Execute argument vector
system(["/usr/bin/date", "+%s"]);          // prints the UNIX timestamp to stdout and returns 0

// Apply a timeout
system("sleep 3 && echo 'Success'", 1000); // returns -9
```

#### 6.52. `trace(level)`

Enables or disables VM opcode tracing. When invoked with a positive non-zero
level, opcode tracing is enabled and debug information is printed to stderr
as the program is executed.

Invoking `trace()` with zero as argument will turn off opcode tracing.

Right now, any positive non-zero value will enable tracing while future
implementation might provide different different verbosity levels or treat
the level argument as bit mask to enable or disable individual debug
elements.

#### 6.53. `proto(val[, proto])`

Get or set the prototype of the array or object value `val`.

When invoked without a second argument, the function returns the current
prototype of the value in `val` or `null` if there is no prototype or if
the given value is neither an object, nor an array.

When invoked with a second prototype argument, the given `proto` value is
set as prototype on the array or object in `val`.

Throws an exception if the given prototype value is not an object.

#### 6.54. `sleep(milliseconds)`

Pause execution for the given amount of milliseconds. Returns `false` if
an invalid value was passed, otherwise `true`.

#### 6.55. `assert(cond[, message])`

Raise an exception with the given `message` parameter if the value in `cond`
is not truish. When `message` is omitted, the default value is `Assertion failed`.

#### 6.56. `render(path[, scope])`

Like `include()` but capture output of included file as string and return it.

See `include()` for details on scoping.

#### 6.57. `regexp(source[, flags])`

Construct a regular expression instance from the given `source` pattern string
and any flags optionally specified by the `flags` argument.

Throws a type error exception if `flags` is not a string or if the string in
`flags` contains unrecognized regular expression flag characters.

Throws a syntax error when the pattern in `source` cannot be compiled into a
valid regular expression by the underlying C runtimes `regcomp(3)` function.

Returns the compiled regular expression value.

```javascript
regexp('foo.*bar', 'is');   // equivalent to /foo.*bar/is
regexp('foo.*bar', 'x');    // throws "Type error: Unrecognized flag character 'x'"
regexp('foo.*(');           // throws "Syntax error: Unmatched ( or \("
```

#### 6.58. `wildcard(subject, pattern[, nocase])`

Match the given subject against the supplied wildcard (file glob) pattern.

If a truish value is supplied as 3rd argument, case insensitive matching is
performed. If a non-string value is supplied as subject, it is converted into
a string before being matched.

Returns `true` when the subject matches the pattern or `false` when not.

#### 6.59. `sourcepath([depth [, dironly]])`

Determine the path of the source file currently being executed by ucode.

The optional `depth` parameter allows walking up the call stack to determine
the path of the parent sources including or requiring the current source file.
If unspecified, the `depth` defaults to `0`, that is the currently executed
file.

If a truish value is passed in `dironly`, only the directory portion of the
source file path is returned.

If the ucode interpreter executes code from stdin or a code fragment passed
via `-s` switch, the function returns `null` since there is no associated
file path.

If `depth` exceeds the size of the call stack, the function returns `null`
as well.

#### 6.60. `min([val1 [, val2 [, ...]]])`

Return the smallest value among all parameters passed to the function.
The function does a `val1 < val2` comparison internally, which means that
the same value coercion rules as for relational operators apply. If both
strings and numbers are passed to `min()`, then any string values will be
effectively ignored since both `1 < "abc"` and `1 > "abc"` comparisons
yield false results.

```javascript
min(5, 2.1, 3, "abc", 0.3);   // 0.3
min(1, "abc");                // 1
min("1", "abc");              // "1"
min("def", "abc", "ghi");     // "abc"
min(true, false);             // false
```

#### 6.61. `max([val1 [, val2 [, ...]]])`

Return the largest value among all parameters passed to the function.
The function does a `val1 > val2` comparison internally, which means that
the same value coercion rules as for relational operators apply. If both
strings and numbers are passed to `min()`, then any string values will be
effectively ignored since both `1 < "abc"` and `1 > "abc"` comparisons
yield false results.

```javascript
max(5, 2.1, 3, "abc", 0.3);   // 5
max(1, "abc");                // 1 (!)
max("1", "abc");              // "abc"
max("def", "abc", "ghi");     // "ghi"
max(true, false);             // true
```

#### 6.62. `b64dec(str)`

Decodes the given base64 encoded string and returns the decoded result, any
whitespace in the input string is ignored.

If non-whitespace, non-base64 characters are encountered, if invalid padding
or trailing garbage is found, the function returns `null`.

If a non-string argument is given, the function returns `null`.

```javascript
b64dec("VGhpcyBpcyBhIHRlc3Q=");   // "This is a test"
b64dec(123);                      // null
b64dec("XXX");                    // null
```

#### 6.63. `b64enc(str)`

Encodes the given string into base64 and returns the resulting encoded
string.

If a non-string argument is given, the function returns `null`.

```javascript
b64enc("This is a test");         // "VGhpcyBpcyBhIHRlc3Q="
b64enc(123);                      // null
```

#### 6.64. `uniq(array)`

Returns a new array containing all unique values of the given input
array. The order is preserved, that is subsequent duplicate values
are simply skipped.

If a non-array argument is given, the function returns `null`.

```javascript
uniq([ 1, true, "foo", 2, true, "bar", "foo" ]); // [ 1, true, "foo", 2, "bar" ]
uniq("test");                                    // null
```

#### 6.65. `localtime([epoch])`

Return the given epoch timestamp (or now, if omitted) as a dictionary
containing broken-down date and time information according to the local
system timezone.

The resulting dictionary contains the following fields:

 - `sec`    Seconds (0-60)
 - `min`    Minutes (0-59)
 - `hour`   Hours (0-23)
 - `mday`   Day of month (1-31)
 - `mon`    Month (1-12)
 - `year`   Year (>= 1900)
 - `wday`   Day of the week (1-7, Sunday = 7)
 - `yday`   Day of the year (1-366, Jan 1st = 1)
 - `isdst`  Daylight saving time in effect (yes = 1)

Note that in contrast to the underlying `localtime(3)` C library function,
the values for `mon`, `wday` and `yday` are 1-based and the `year` is
1900-based.

```javascript
localtime(1647953502);
// {
//         "sec": 42,
//         "min": 51,
//         "hour": 13,
//         "mday": 22,
//         "mon": 3,
//         "year": 2022,
//         "wday": 2,
//         "yday": 81,
//         "isdst": 0
// }
```

#### 6.66. `gmtime([epoch])`

Like `localtime()` but interpreting the given epoch value as UTC time.

See `localtime()` for details on the return value.

#### 6.67. `timelocal(datetimespec)`

Performs the inverse operation of `localtime()` by taking a broken-down
date and time dictionary and transforming it into an epoch value according
to the local system timezone.

The `wday` and `yday` fields of the given date time specification are
ignored. Field values outside of their valid range are internally normalized,
e.g. October 40th is interpreted as November 9th.

Returns the resulting epoch value or null if the input date time dictionary
was invalid or if the date time specification cannot be represented as
epoch value.

```javascript
timelocal({ "sec": 42, "min": 51, "hour": 13, "mday": 22, "mon": 3, "year": 2022, "isdst": 0 })
// 1647953502
```

#### 6.68. `timegm(datetimespec)`

Like `timelocal()` but interpreting the given date time specification as
UTC time.

See `timelocal()` for details.

#### 6.69. `clock([monotonic])`

Reads the current second and microsecond value of the system clock.

By default, the realtime clock is queried which might skew forwards
or backwards due to NTP changes, system sleep modes etc.

If a truish value is passed as argument, the monotonic system clock
is queried instead, which will return the monotonically increasing
time since some arbitrary point in the past (usually the system boot
time).

Returns a two element array containing the full seconds as first and
the nanosecond fraction as second element.

Returns `null` if a monotonic clock value is requested and the system
does not implement this clock type.

```javascript
clock();        // [ 1647954926, 798269464 ]
clock(true);    // [ 474751, 527959975 ]
```

#### 6.70. `hexdec(hexstring[, skipchars])`

The `hexdec()` function decodes the given hexadecimal digit string into
a byte string, optionally skipping specified characters.

If the characters to skip are not specified, a default of `" \t\n"` is
used.

Returns null if the input string contains invalid characters or an uneven
amount of hex digits.

Returns the decoded byte string on success.

```javascript
hexdec("48656c6c6f20776f726c64210a");  // "Hello world!\n"
hexdec("44:55:66:77:33:44", ":");      // "DUfw3D"
```

#### 6.71. `hexenc(val)`

The `hexenc()` function encodes the given byte string into a hexadecimal
digit string, converting the input value to a string if needed.

Returns the encoded hexadecimal digit string.

```javascript
hexenc("Hello world!\n");   // "48656c6c6f20776f726c64210a"
```

#### 6.72. `gc([operation[, argument]])`

The `gc()` function allows interaction with the mark and sweep garbage
collector of the running ucode virtual machine.

Depending on the given `operation` string argument, the meaning of
`argument` and the function return value differs.

The following operations are defined:

 - `collect` - Perform a complete garbage collection cycle, returns `true`.
 - `start` - (Re-)start periodic garbage collection, `argument` is an optional
             integer in the range 1..65535 specifying the interval. Defaults
             to `1000` if omitted. Returns `true` if the periodic GC was
             previously stopped and is now started or if the interval changed.
             Returns `false` otherwise.
 - `stop` - Stop periodic garbage collection. Returns `true` if the periodic GC
            was previously started and is now stopped, `false` otherwise.
 - `count` - Count the amount of active complex object references in the VM
             context, returns the counted amount.

If the `operation` argument is omitted, the default is `collect`.

Returns `null` if a non-string `operation` value is given.

#### 6.73. `loadstring(code[, options])`

Compiles the given code string into a ucode program and returns the resulting
program entry function. The optinal `options` dictionary allows overriding
parse and compile options.

If a non-string `code` argument is given, it is implicitly converted to a
string value first.

If `options` is omitted or a non-object value, the compile options of the
running ucode program are reused.

The following keys in the `options` dictionary are recognized:

| Key                   | Type  | Description                                              |
|-----------------------|-------|----------------------------------------------------------|
| `lstrip_blocks`       | bool  | Strip leading whitespace before statement template blocks|
| `trim_blocks`         | bool  | Strip newline after statement template blocks            |
| `strict_declarations` | bool  | Treat access to undefined variables as fatal error       |
| `raw_mode`            | bool  | Compile source in script mode, don't treat it as template|
| `module_search_path`  | array | Override compile time module search path                 |
| `force_dynlink_list`  | array | List of module names to treat as dynamic extensions      |

Unrecognized keys are ignored, unspecified options default to those of the
running program.

Returns the compiled program entry function.

Throws an exception on compilation errors.

```javascript
let fn1 = loadstring("Hello, {{ name }}", { raw_mode: false });

global.name = "Alice";
fn1(); // prints `Hello, Alice`


let fn2 = loadstring("return 1 + 2;", { raw_mode: true });
fn2(); // 3
```

#### 6.74. `loadfile(path[, options])`

Compiles the given file into a ucode program and returns the resulting program
entry function.

See `loadfile()` for details.

Returns the compiled program entry function.

Throws an exception on compilation or file i/o errors.

```javascript
loadfile("./templates/example.uc");  // function main() { ... }
```

#### 6.75. `call(fn[, ctx[, scope[, arg1[, ...]]]])`

Calls the given function value with a modified environment. The given `ctx`
argument is used as `this` context for the invoked function and the given
`scope` value as global environment. Any further arguments are passed to the
invoked function as-is.

When `ctx` is omitted or `null`, the function will get invoked with `this`
being `null`.

When `scope` is omitted or `null`, the function will get executed with the
current global environment of the running program. When `scope` is set to a
dictionary, the dictionary is used as global function environment.

When the `scope` dictionary has no prototype, the current global environment
will be set as prototype, means the scope will inherit from it. When a scope
prototype is set, it is kept. This allows passing an isolated (sandboxed)
function scope without access to the global environment.

Any further argument is forwarded as-is to the invoked function as function
call argument.

Returns `null` if the given function value `fn` is not callable.

Returns the return value of the invoked function in all other cases.

Forwards exceptions thrown by the invoked function.

```javascript
// Override this context
call(function() { printf("%J\n", this) });            // null
call(function() { printf("%J\n", this) }, null);      // null
call(function() { printf("%J\n", this) }, { x: 1 });  // { "x": 1 }
call(function() { printf("%J\n", this) }, { x: 2 });  // { "x": 2 }

// Run with default scope
global.a = 1;
call(function() { printf("%J\n", a) });                  // 1

// Override scope, inherit from current global scope (implicit)
call(function() { printf("%J\n", a) }, null, { a: 2 });  // 2

// Override scope, inherit from current global scope (explicit)
call(function() { printf("%J\n", a) }, null,
        proto({ a: 2 }, global));                        // 2

// Override scope, don't inherit (pass `printf()` but not `a`)
call(function() { printf("%J\n", a) }, null,
        proto({}, { printf }));                          // null

// Forward arguments
x = call((x, y, z) => x * y * z, null, null, 2, 3, 4);   // x = 24
```
