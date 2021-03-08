## ABOUT

An ucode template consists of arbitrary plain text which is outputted as-is
while control flow or expression logic is embedded in blocks that may appear
anywhere throughout the template.


## BLOCKS

There are three kinds of blocks; expression blocks, statement blocks and
comment blocks. The former two embed code logic using a JavaScript-like syntax
while the latter comment block type is simply discarded during processing.


### 1. STATEMENT BLOCKS

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


### 2. EXPRESSION BLOCKS

Expression blocks are enclosed in an opening `{{` and a closing `}}` tag and
may only contain a single expression statement (multiple expressions may be
chained with comma). The implicit result of the rightmost evaluated expression
is used as output when processing the block.

For example the template `Hello world, {{ getenv("USER") }}!` would result in
the output "Hello world, user!" where `user` would correspond to the name of
the current user executing the ucode interpreter.


### 3. COMMENT BLOCKS

Comment blocks, which are denoted with an opening `{#` and a closing `#}` tag
may contain arbitrary text except the closing `#}` tag itself. Comments blocks
are completely stripped during processing and are replaced with an empty string.

The following example template would result in the output "Hello world":

`Hello {# mad #}word`


### WHITESPACE

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

## SCRIPT LANGUAGE

The ucode script language used within statement and expression blocks uses
untyped variables and employs a simplified JavaScript like syntax.

Ucode script implements function scoping and differentiates between local and
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
name with the keyword `let`, it is declared in the local function scope only
and not visible outside anymore.

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

### 6. Functions

Ucode scripts may call a number of builtin functions to manipulate values or
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

#### 6.5. `delete(obj, key1, ...)`

Delete the given key(s) from the object passed as first argument. Returns the
corresponding value of the last removed key, if any.

#### 6.6. `die(msg)`

Raise an exception with the given message and abort execution.

#### 6.7. `exists(obj, key)`

Return `true` if the given key is present within the object passed as first
argument, otherwise `false`.

#### 6.8. `exit(n)`

Terminate the interpreter with the given exit code.

#### 6.9. `exp(n)`

Return the value of e (the base of natural logarithms) raised to the power
of n.

#### 6.10. `filter(arr, fn)`

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

#### 6.11. `getenv(name)`

Return the value of the given environment variable.

#### 6.12. `hex(x)`

Convert the given hexadecimal string into a number.

#### 6.13. `index(arr_or_str, needle)`

Find the given value passed as second argument within the array or string
specified in the first argument.

Returns the first matching array index or first matching string offset or `-1`
if the value was not found.

Returns `null` if the first argument was neither an array, nor a string.

#### 6.14. `int(x)`

Convert the given value to an integer. Returns `NaN` if the value is not
convertible.

#### 6.15. `join(sep, arr)`

Join the array passed as 2nd argument into a string, using the separator passed
in the first argument as glue. Returns `null` if the second argument is not an
array.

#### 6.16. `keys(obj)`

Return an array of all key names present in the passed object. Returns `null`
if the given argument is no object.

#### 6.17. `lc(s)`

Convert the given string to lowercase and return the resulting string.
Returns `null` if the given argument could not be converted to a string.

#### 6.18. `length(x)`

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

#### 6.19. `log(x)`

Return the natural logarithm of x.

#### 6.20. `ltrim(s, c)`

Trim any of the specified characters in `c` from the start of `str`.
If the second argument is omitted, trims the characters, ` ` (space), `\t`,
`\r` and `\n`.

```javascript
ltrim("  foo  \n")     // "foo  \n"
ltrim("--bar--", "-")  // "bar--"
```

#### 6.21. `map(arr, fn)`

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

#### 6.22. `ord(s, ...)`

Without further arguments, this function returns the byte value of the first
character in the given string.

If one or more index arguments are supplied, an array containing the byte
values at each given index is returned. If an invalid index is supplied, the
corresponding array entry will be `null`. Negative index entries are counted
towards the end of the string, e.g. `-2` will return the value of the second
last character.

```javascript
ord("Abc");                 // 65
ord("Abc", 0);              // [ 65 ]
ord("Abc", 1, -1);          // [ 98, 99 ]
ord("Abc", 2, 1, 0);        // [ 99, 98, 65 ]
ord("Abc", 10, -10, "nan"); // [ null, null, null ]
```

#### 6.23. `pop(arr)`

Pops the last item from the given array and returns it. Returns `null` if the
array was empty or if a non-array argument was passed.

#### 6.24. `print(x, ...)`

Print any of the given values to stdout. Arrays and objects are converted to
their JSON representation.

Returns the amount of bytes printed.

#### 6.25. `push(arr, v1, ...)`

Push the given argument(s) to the given array. Returns the last pushed value.

#### 6.26. `rand()`

Returns a random number. If `srand()` has not been called already, it is
automatically invoked passing the current time as seed.

#### 6.27. `reverse(arr_or_str)`

If an array is passed, returns the array in reverse order. If a string is
passed, returns the string with the sequence of the characters reversed.

Returns `null` if neither an array nor a string were passed.

#### 6.28. `rindex(arr_or_str, needle)`

Find the given value passed as second argument within the array or string
specified in the first argument.

Returns the last matching array index or last matching string offset or `-1`
if the value was not found.

Returns `null` if the first argument was neither an array, nor a string.

#### 6.29. `rtrim(str, c)`

Trim any of the specified characters in `c` from the end of `str`.
If the second argument is omitted, trims the characters, ` ` (space), `\t`,
`\r` and `\n`.

```javascript
rtrim("  foo  \n")     // "  foo"
rtrim("--bar--", "-")  // "--bar"
```

#### 6.30. `shift(arr)`

Pops the first item from the given array and returns it. Returns `null` if the
array was empty or if a non-array argument was passed.

#### 6.31. `sin(x)`

Return the sine of x, where x is given in radians.

#### 6.32. `sort(arr, fn)`

Sort the given array according to the given sort function. If no sort
function is provided, a default ascending sort order is applied.

```javascript
sort([8, 1, 5, 9]) // [1, 5, 8, 9]
sort(["Bean", "Orange", "Apple"], function(a, b) {
    return length(a) < length(b);
}) // ["Bean", "Apple", "Orange"]
```

#### 6.33. `splice(arr, off, len, ...)`

Removes the elements designated by `off` and `len` from  the given an array,
and replaces them with the additional arguments passed, if any. Returns the
last element removed, or `null` if no elements are removed. The array grows or shrinks as necessary.

If `off` is negative then it starts that far from the end of the array. If
`len` is omitted, removes everything from `off` onward. If `len` is negative,
removes the elements from `off` onward except for `-len` elements at the end of
the array. If both `off` and `len` are omitted, removes everything.

#### 6.34. `split(str, sep)`

Split the given string using the separator passed as second argument and return
an array containing the resulting pieces.

The separator may either be a plain string or a regular expression.

```javascript
split("foo,bar,baz", ",")     // ["foo", "bar", "baz"]
split("foobar", "")           // ["f", "o", "o", "b", "a", "r"]
split("foo,bar,baz", /[ao]/)  // ["f", "", ",b", "r,b", "z"]
```

#### 6.35. `sqrt(x)`

Return the nonnegative square root of x.

#### 6.36. `srand(n)`

Seed the PRNG using the given number.

#### 6.37. `substr(str, off, len)`

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

#### 6.38. `time()`

Returns the current UNIX epoch.

```javascript
time();     // 1598043054
```

#### 6.39. `trim()`

Trim any of the specified characters in `c` from the start and end of `str`.
If the second argument is omitted, trims the characters, ` ` (space), `\t`,
`\r` and `\n`.

```javascript
ltrim("  foo  \n")     // "foo"
ltrim("--bar--", "-")  // "bar"
```

#### 6.40. `type(x)`

Returns the type of the given value as string which might be one of
`"function"`, `"object"`, `"array"`, `"double"`, `"int"` or `"bool"`.

Returns `null` when no value or `null` is passed.

#### 6.41. `uchr(n1, ...)`

Converts each given numeric value to an utf8 escape sequence and returns the
resulting string. Invalid numeric values or values outside the range `0` ..
`0x10FFFF` are represented by the unicode replacement character `0xFFFD`.

```javascript
uchr(0x2600, 0x26C6, 0x2601);  // "☀⛆☁"
uchr(-1, 0x20ffff, "foo");     // "���"
```

#### 6.42. `uc(str)`

Converts the given string to uppercase and return the resulting string.
Returns `null` if the given argument could not be converted to a string.

#### 6.43. `unshift(arr, v1, ...)`

Add the given values to the beginning of the array passed as first argument.
Returns the last value added to the array.

#### 6.44. `values(obj)`

Returns an array containing all values of the given object. Returns `null` if
no object was passed.

```javascript
values({ foo: true, bar: false });   // [true, false]
```

#### 6.45. `printf(fmt, ...)`

Formats the given arguments according to the given format string and outputs the
result to stdout.

Ucode supports a restricted subset of the formats allowed by the underlying
libc's `printf()` implementation, namely it allows the `d`, `i`, `o`, `u`, `x`,
`X`, `e`, `E`, `f`, `F`, `g`, `G`, `c` and `s` conversions.

Additionally, an ucode specific `J` format is implemented, which causes the
corresponding value to be formatted as JSON string.

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
%}
```

#### 6.46. `sprintf(fmt, ...)`

Formats the given arguments according to the given format string and returns the
resulting string.

See `printf()` for details.

#### 6.47. `match(str, /pattern/)`

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

#### 6.48. `replace(str, /pattern/, replace)`

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

#### 6.49. `json(str)`

Parse the given string as JSON and return the resulting value. Throws an
exception on parse errors, trailing garbage or premature EOF.

```javascript
json('{"a":true, "b":123}')   // { "a": true, "b": 123 }
json('[1,2,')                 // Throws exception
```

#### 6.50. `include(path, scope)`

Evaluate and include the file at the given path and optionally override the
execution scope with the given scope object.

By default, the file is executed within the same scope as the calling
`include()` but by passing an object as second argument, it is possible to
override the scope available to the included file. This is useful to sandbox the
included code and only grant it access to explicitely passed values and
functions.

If the given path argument is not absolute, it is interpreted relative to the
directory of the current template file, that is the file that is invoking the
`include()` function.

If the ucode interpreter executes program code from stdin, the given path is
interpreted relative to the current working directory of the process.

```javascript
// Load and execute "foo.uc" immediately
include("./foo.uc")

// Execute the "untrusted.ucode" in a sandboxed scope and make the "foo" and
// "bar" variables as well as the "print" function available to it
include("./untrusted.uc", {
  foo: true,
  bar: 123,
  print: print
})
```

#### 6.51. `warn(x, ...)`

Print any of the given values to stderr. Arrays and objects are converted to
their JSON representation.

Returns the amount of bytes printed.

#### 6.52. `system(command, timeout)`

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

#### 6.53. `trace(level)`

Enables or disables VM opcode tracing. When invoked with a positive non-zero
level, opcode tracing is enabled and debug information is printed to stderr
as the program is executed.

Invoking `trace()` with zero as argument will turn off opcode tracing.

Right now, any positive non-zero value will enable tracing while future
implementation might provide different different verbosity levels or treat
the level argument as bit mask to enable or disable individual debug
elements.
