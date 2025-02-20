Arrays in ucode are ordered collections that can store any ucode value. Unlike
many other scripting languages where arrays are implemented as hash tables or
linked lists, ucode arrays are true arrays in memory. This implementation detail
provides several distinctive characteristics that developers should understand
when working with arrays in ucode.

## Key Characteristics of Ucode Arrays

### True Memory Arrays

Ucode arrays are implemented as true arrays in memory, which means:
- They offer fast random access to elements by index
- They are stored contiguously in memory
- Memory allocation expands as needed to accommodate the highest used index

### Sparse Array Behavior

Because ucode arrays are true arrays in memory:
- Memory is always allocated contiguously up to the highest used index
- All positions (including unused ones) consume memory
- "Empty" or unused positions contain `null` values
- There is no special optimization for sparse arrays

### Negative Index Support

Ucode arrays provide convenient negative indexing:
- `-1` refers to the last element
- `-2` refers to the second-last element
- And so on, allowing easy access to elements from the end of the array

### Type Flexibility

Arrays in ucode can hold any ucode value type:
- Booleans, numbers (integers and doubles), strings
- Objects and arrays (allowing nested arrays)
- Functions and null values
- No type restrictions between elements (unlike typed arrays in some languages)

## Core Array Functions

### Array Information Functions

#### {@link module:core#length|length(x)} → {number}

Returns the number of elements in an array. This is one of the most fundamental
array operations in ucode.

```
let fruits = ["apple", "banana", "orange"];
length(fruits); // 3

let sparse = [];
sparse[10] = "value";
length(sparse); // 11 (includes empty slots)
```

For arrays, `length()` returns the highest index plus one, which means it
includes empty slots in sparse arrays. If the input is not an array, string, or
object, `length()` returns null.

#### {@link module:core#index|index(arr_or_str, needle)} → {number}

Searches for a value in an array and returns the index of the first matching occurrence.

```
let colors = ["red", "green", "blue", "green"];
index(colors, "green"); // 1 (returns first match)
index(colors, "yellow"); // -1 (not found)
```

Unlike many other languages where array search functions return -1 or null for
non-matching items, `index()` in ucode specifically returns -1 when the value
isn't found. It returns null only if the first argument is neither an array nor
a string.

#### {@link module:core#rindex|rindex(arr_or_str, needle)} → {number}

Similar to `index()`, but searches backward from the end of the array:

```
let colors = ["red", "green", "blue", "green"];
rindex(colors, "green"); // 3 (last occurrence)
```

#### Checking if a Value is an Array

To determine if a value is an array, use the `type()` function:

```
function isArray(value) {
    return type(value) == "array";
}

isArray([1, 2, 3]); // true
isArray("string"); // false
isArray({key: "value"}); // false
isArray(null); // false
```

The `type()` function is extremely useful for defensive programming, especially
in ucode where functions often need to determine the type of their arguments to
process them correctly.

### Manipulation Functions

#### {@link module:core#push|push(arr, ...values)} → {*}

Adds one or more elements to the end of an array and returns the last pushed
value.

```
let x = [1, 2, 3];
push(x, 4, 5, 6); // 6
print(x); // [1, 2, 3, 4, 5, 6]
```

Returns null if the array was empty or if a non-array argument was passed.

#### {@link module:core#pop|pop(arr)} → {*}

Removes the last element from an array and returns it.

```
let x = [1, 2, 3];
let lastItem = pop(x); // 3
print(x); // [1, 2]
```

Returns null if the array was empty or if a non-array argument was passed.

#### {@link module:core#unshift|unshift(arr, ...values)} → {*}

Adds one or more elements to the beginning of an array and returns the last
value added.

```
let x = [3, 4, 5];
unshift(x, 1, 2); // 2
print(x); // [1, 2, 3, 4, 5]
```

#### {@link module:core#shift|shift(arr)} → {*}

Removes the first element from an array and returns it.

```
let x = [1, 2, 3];
let firstItem = shift(x); // 1
print(x); // [2, 3]
```

Returns null if the array was empty or if a non-array argument was passed.

### Transformation Functions

#### {@link module:core#map|map(arr, fn)} → {Array}

Creates a new array populated with the results of calling a provided function on
every element in the calling array.

```
let numbers = [1, 2, 3, 4];
let squares = map(numbers, x => x * x); // [1, 4, 9, 16]
```

Note: The callback function receives three arguments:
1. The current element value
2. The current index
3. The array being processed

```
let values = map(["foo", "bar", "baz"], function(value, index, array) {
  return `${index}: ${value} (from array of length ${length(array)})`;
});
```

##### Important Pitfall with Built-in Functions

A common mistake when using `map()` is passing a built-in function directly as
the callback. Consider this example attempting to convert an array of strings to
integers:

```
// ⚠️ INCORRECT: This will not work as expected!
let strings = ["10", "32", "13"];
let nums = map(strings, int);  // Results will be unpredictable!
```

This fails because the `map()` function calls the callback with three arguments:
1. The current value (`"10"`, `"32"`, etc.)
2. The current index (`0`, `1`, `2`)
3. The original array (`["10", "32", "13"]`)

So what actually happens is equivalent to:
```
int("10", 0, ["10", "32", "13"])  // Interprets 0 as base parameter!
int("32", 1, ["10", "32", "13"])  // Interprets 1 as base parameter!
int("13", 2, ["10", "32", "13"])  // Interprets 2 as base parameter!
```

The second argument to `int()` is interpreted as the numeric base, causing
unexpected conversion results:

- `"10"` in base 0 is interpreted as decimal 10 (base 0 is a special case that auto-detects the base)
- `"32"` in base 1 produces `NaN` because base 1 is invalid (a numeral system needs at least 2 distinct digits)
- `"13"` in base 2 produces `1` because in binary only `0` and `1` are valid digits - it converts `"1"` successfully and stops at the invalid character `"3"`

The actual result would be `[10, NaN, 1]`, which is certainly not what you'd
expect when trying to convert string numbers to integers!

To fix this, wrap the function call in an arrow function or a regular function
that controls the number of arguments:

```
// ✓ CORRECT: Using arrow function to control arguments
let strings = ["10", "32", "13"];
let nums = map(strings, x => int(x));  // [10, 32, 13]

// Alternative approach using a named function
function toInt(str) {
  return int(str);
}
let nums2 = map(strings, toInt);  // [10, 32, 13]
```

This pattern applies to many other built-in functions like `length()`, `trim()`,
`b64enc()`, etc. Always wrap built-in functions when using them with `map()` to
ensure they receive only the intended arguments.

#### {@link module:core#filter|filter(arr, fn)} → {Array}

Creates a new array with all elements that pass the test implemented by the
provided function.

```
let numbers = [1, 2, 3, 4, 5, 6];
let evens = filter(numbers, x => x % 2 == 0); // [2, 4, 6]
```

The callback function receives the same three arguments as in `map()`.

#### {@link module:core#sort|sort(arr, fn)} → {Array}

Sorts the elements of an array in place and returns the sorted array, optionally
using a custom compare function.

```
let numbers = [3, 1, 4, 2];
sort(numbers); // [1, 2, 3, 4]
```

With a custom compare function:

```
let people = [
  { name: "Alice", age: 25 },
  { name: "Bob", age: 30 },
  { name: "Charlie", age: 20 }
];

sort(people, (a, b) => a.age - b.age);
// [{ name: "Charlie", age: 20 }, { name: "Alice", age: 25 }, { name: "Bob", age: 30 }]
```

#### {@link module:core#reverse|reverse(arr)} → {Array}

Returns a new array with the order of all elements reversed.

```
let arr = [1, 2, 3];
reverse(arr); // [3, 2, 1]
```

This function also works on strings:

```
reverse("hello"); // "olleh"
```

Returns null if the argument is neither an array nor a string.

#### {@link module:core#uniq|uniq(array)} → {Array}

Creates a new array with all duplicate elements removed.

```
let array = [1, 2, 2, 3, 1, 4, 5, 4];
uniq(array); // [1, 2, 3, 4, 5]
```

Returns null if a non-array argument is given.

### Helper Functions and Recipes

The ucode standard library provides essential array functions, but many common
operations must be implemented manually. Below, you'll find example
implementations for frequently needed array operations that aren't built into
the core library.

These recipes demonstrate how to leverage ucode's existing functions to build
more complex array utilities.

#### Array Intersection

Returns a new array containing elements present in all provided arrays.

```
function intersect(...arrays) {
  if (!length(arrays))
    return [];

  let result = arrays[0];

  for (let i = 1; i < length(arrays); i++) {
    result = filter(result, item => item in arrays[i]);
  }

  return uniq(result);
}

// Example usage:
let a = [1, 2, 3, 4];
let b = [2, 3, 5];
let c = [2, 3, 6];
intersect(a, b, c); // [2, 3]
```

This implementation takes advantage of ucode's `in` operator, which checks if a
value exists in an array using strict equality comparison. This makes the code
more concise than using `index()` and checking if the result is not -1.

#### Array Merge/Concatenation

Combines multiple arrays into a new array. Taking advantage of ucode's variadic
`push()` function with the spread operator provides an elegant solution:

```
function merge(...arrays) {
  let result = [];

  for (arr in arrays) {
    push(result, ...arr);  // Spreads all elements from the array directly into push
  }

  return result;
}

// Example usage:
let a = [1, 2];
let b = [3, 4];
let c = [5, 6];
merge(a, b, c); // [1, 2, 3, 4, 5, 6]
```

This implementation leverages the variadic nature of `push()`, which accepts any
number of arguments. The spread operator (`...`) unpacks each array, passing all
its elements as individual arguments to `push()`. This is both more efficient
and more readable than nested loops.

For processing very large arrays, you might want to use a batching approach to
avoid potential call stack limitations:

```
function mergeWithBatching(...arrays) {
  let result = [];
  const BATCH_SIZE = 1000;

  for (arr in arrays) {
    // Handle array in batches to avoid excessive function arguments
    for (let i = 0; i < length(arr); i += BATCH_SIZE) {
      let batch = slice(arr, i, i + BATCH_SIZE);
      push(result, ...batch);
    }
  }

  return result;
}
```

#### Array Difference

Returns elements in the first array not present in subsequent arrays.

```
function difference(array, ...others) {
  return filter(array, item => {
    for (other in others) {
      if (item in other)
        return false;
    }
    return true;
  });
}

// Example usage:
let a = [1, 2, 3, 4, 5];
let b = [2, 3];
let c = [4];
difference(a, b, c); // [1, 5]
```

This implementation uses the `in` operator for concise and efficient membership
testing, filtering out any elements from the first array that appear in any of
the subsequent arrays.

#### Array Chunk

Splits an array into chunks of specified size.

```
function chunk(array, size) {
  if (size <= 0)
    return [];

  let result = [];

  for (let i = 0; i < length(array); i += size) {
    push(result, slice(array, i, i + size));
  }

  return result;
}

// Example usage:
let nums = [1, 2, 3, 4, 5, 6, 7, 8];
chunk(nums, 3); // [[1, 2, 3], [4, 5, 6], [7, 8]]
```

This implementation uses a counting `for` loop combined with `slice()`, which is
both more idiomatic and more efficient. The approach:

1. Iterates through the array in steps of `size`
2. Uses `slice()` to extract chunks of the appropriate size
3. Automatically handles the last chunk being smaller if the array length isn't divisible by the chunk size

This pattern leverages ucode's built-in functions for cleaner, more maintainable
code. No temporary variables are needed to track the current chunk or count,
making the implementation more straightforward.

#### Array Sum

Calculates the sum of all numeric elements in an array.

```
function sum(array) {
  let result = 0;

  for (item in array) {
    if (type(item) == "int" || type(item) == "double")
      result += item;
  }

  return result;
}

// Example usage:
let nums = [1, 2, 3, 4, 5];
sum(nums); // 15
```

#### Array Flatten

Flattens a nested array structure.

```
function flatten(array, depth) {
  if (depth === undefined)
    depth = 1;

  let result = [];

  for (item in array) {
    if (type(item) == "array" && depth > 0) {
      let flattened = flatten(item, depth - 1);
      for (subItem in flattened) {
        push(result, subItem);
      }
    } else {
      push(result, item);
    }
  }

  return result;
}

// Example usage:
let nested = [1, [2, [3, 4], 5], 6];
flatten(nested);     // [1, 2, [3, 4], 5, 6]
flatten(nested, 2);  // [1, 2, 3, 4, 5, 6]
```

## Advanced Array Techniques and Considerations

### Memory Management

When working with arrays in ucode, you should understand several important
memory characteristics that affect performance and resource usage:

#### Sparse Array Memory Implications

Since ucode arrays are true arrays in memory, array memory consumption scales
linearly with the highest index used, regardless of how many elements are
actually stored:

```
let arr = [];
arr[1000000] = "value"; // Allocates memory for 1,000,001 pointers
```

Important technical details about ucode array memory usage:
- Each array element consumes pointer-sized memory (4 bytes on 32-bit systems, 8 bytes on 64-bit systems)
- No optimizations exist for sparse arrays - every position up to the highest index is allocated
- When an array grows beyond its capacity, it's reallocated with a growth factor of 1.5
- Memory is allocated even for "empty" slots (which contain the `null` value)

For example, on a 64-bit system, creating an array with a single element at
index 1,000,000 would consume approximately 8MB of memory (1,000,001 * 8 bytes),
even though only one actual value is stored.

```
// Demonstrates memory consumption
let smallArray = [];
for (let i = 0; i < 10; i++)
  smallArray[i] = i;

let sparseArray = [];
sparseArray[1000000] = "far away";

print(`Small array has ${length(smallArray)} elements\n`);
print(`Sparse array has ${length(sparseArray)} elements\n`);
// Even though only one value is actually set, memory is allocated for all positions
```

This behavior makes ucode arrays efficient for random access but potentially
wasteful for very sparse data structures. For data with large gaps or when
working on memory-constrained systems, consider alternative approaches like
objects with numeric string keys.

#### Negative Index Implementation

While negative indices provide convenient access to elements from the end of an
array, they involve an internal conversion process:

```
let arr = [1, 2, 3, 4, 5];
arr[-1]; // Internally converted to arr[length(arr) - 1], or arr[4]
arr[-3]; // Internally converted to arr[length(arr) - 3], or arr[2]
```

This conversion adds a small computational overhead compared to direct positive
indexing. For performance-critical code processing large arrays, consider using
positive indices when possible.

#### Mixed-Type Arrays and Sorting

Arrays in ucode can contain mixed types, offering great flexibility but
requiring careful handling, especially with operations like `sort()`:

```
let mixed = ["apple", 10, true, {name: "object"}, [1, 2]];

// Sort behaves differently with mixed types
// Numbers come first, then arrays, then strings, then booleans, then objects
sort(mixed); // [10, [1, 2], "apple", true, {name: "object"}]
```

When sorting mixed-type arrays, consider implementing a custom comparison
function to define the sorting behavior explicitly:

```
function mixedTypeSort(a, b) {
    // Sort by type first, then by value
    let typeA = type(a);
    let typeB = type(b);

    if (typeA != typeB) {
        // Define a type precedence order
        let typePrecedence = {
            "int": 1,
            "double": 2,
            "string": 3,
            "bool": 4,
            "array": 5,
            "object": 6
        };
        return typePrecedence[typeA] - typePrecedence[typeB];
    }

    // If same type, compare values appropriately
    if (typeA == "string" || typeA == "array")
        return length(a) - length(b);
    return a - b;
}

// Now sorting is more predictable
sort(mixed, mixedTypeSort);
```

### Performance Optimization

When working with large arrays, consider these optimization techniques:

1. **Pre-allocation**: Where possible, create arrays with known capacity rather than growing incrementally
2. **Batch operations**: Minimize individual push/pop/shift/unshift calls by processing in batches
3. **Avoid unnecessary copies**: Use in-place operations when possible
4. **Filter early**: Filter arrays early in processing pipelines to reduce subsequent operation sizes

### Array Deep Copying

Since arrays are reference types, creating true copies requires special handling:

```
function deepCopy(arr) {
    if (type(arr) != "array")
        return arr;

    let result = [];
    for (item in arr) {
        if (type(item) == "array")
            push(result, deepCopy(item));
        else if (type(item) == "object")
            push(result, deepCopyObject(item));
        else
            push(result, item);
    }
    return result;
}

function deepCopyObject(obj) {
    if (type(obj) != "object")
        return obj;

    let result = {};
    for (key in keys(obj)) {
        if (type(obj[key]) == "array")
            result[key] = deepCopy(obj[key]);
        else if (type(obj[key]) == "object")
            result[key] = deepCopyObject(obj[key]);
        else
            result[key] = obj[key];
    }
    return result;
}
```

This approach ensures all nested arrays and objects are properly copied rather
than referenced.
