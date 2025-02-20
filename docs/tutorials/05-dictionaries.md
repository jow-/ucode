Dictionaries in ucode (also referred to as objects) are key-value collections
that provide efficient lookups by key. Unlike arrays which use numeric indices,
dictionaries use string keys to access values. Understanding how dictionaries
are implemented in ucode and their distinctive characteristics will help you
write more efficient and effective code.

## Key Characteristics of Ucode Dictionaries

### Hash Table Implementation with Ordered Keys

Ucode dictionaries are implemented as ordered hash tables, which means:
- They offer fast O(1) average-case lookups by key
- Keys are hashed to determine storage location
- Memory allocation is dynamic and grows as needed
- Unlike arrays, memory is not allocated contiguously
- Key order is preserved based on declaration or assignment sequence
- Keys can be reordered using `sort()`

### String-Only Keys with Important Limitations

One important limitation of ucode dictionaries:
- All keys must be strings
- Non-string keys are implicitly converted to strings
- Numeric keys become string representations (e.g., `5` becomes `"5"`)
- This differs from JavaScript where objects can use Symbols as keys

#### Warning: Null Byte Truncation in Keys

A critical implementation detail to be aware of is that dictionary keys
containing null bytes (`\0`) will be silently truncated at the first null byte:

```
let dict = {"foo\0bar": 123};
print(dict.foo);  // 123
print(exists(dict, "foo\0bar"));  // false
print(exists(dict, "foo"));  // true
```

This happens because the underlying hash table implementation treats keys as
C-style null-terminated strings. While this behavior may change in future
versions of ucode, you should currently:

- Never use keys containing null bytes
- Sanitize any untrusted external input used as dictionary keys
- Be especially careful when using binary data or user input as keys

This issue can lead to subtle bugs and potential security vulnerabilities if
malicious users craft input with embedded null bytes to manipulate key lookups.

### Type Flexibility for Values

Like arrays, dictionary values in ucode can be of any type:
- Booleans, numbers (integers and doubles), strings
- Objects and arrays (allowing nested structures)
- Functions and null values
- Different keys can store different value types

### Reference Semantics

Dictionaries are reference types in ucode:
- Assigning a dictionary to a new variable creates a reference, not a copy
- Modifying a dictionary through any reference affects all references
- Equality comparisons test reference identity, not structural equality

## Core Dictionary Functions

### Dictionary Information Functions

#### {@link module:core#length|length(x)} → {number}

Returns the number of keys in a dictionary.

```
let user = {name: "Alice", age: 30, role: "Admin"};
length(user); // 3

let empty = {};
length(empty); // 0
```

For dictionaries, `length()` returns the count of keys. If the input is not an
array, string, or object, `length()` returns null.

#### {@link module:core#keys|keys(obj)} → {Array}

Returns an array containing all keys in the dictionary.

```
let config = {debug: true, timeout: 500, retries: 3};
keys(config); // ["debug", "timeout", "retries"]
```

Unlike many other languages, ucode maintains key ordering based on declaration
or assignment order. Keys are returned in the same order they were defined or
assigned.

#### {@link module:core#values|values(obj)} → {Array}

Returns an array containing all values in the dictionary.

```
let counts = {apples: 5, oranges: 10, bananas: 7};
values(counts); // [5, 10, 7]
```

The returned values correspond to the declaration/assignment order of keys in
the dictionary, matching the order that would be returned by `keys()`.

#### {@link module:core#exists|exists(obj, key)} → {boolean}

Checks whether a key exists in a dictionary.

```
let settings = {theme: "dark", fontSize: 16};
exists(settings, "theme"); // true
exists(settings, "language"); // false
```

This function offers a straightforward way to check for key existence without
accessing the value.

#### Checking if a Value is a Dictionary

To determine if a value is a dictionary (object), use the `type()` function:

```
function isObject(value) {
    return type(value) == "object";
}

isObject({key: "value"}); // true
isObject([1, 2, 3]); // false
isObject("string"); // false
isObject(null); // false
```

### Manipulation Functions

In ucode, dictionary manipulation is performed primarily through direct property
access using dot notation or bracket notation.

#### Adding or Updating Properties

```
let user = {name: "Bob"};

// Adding new properties
user.age = 25;
user["email"] = "bob@example.com";

// Updating existing properties
user.name = "Robert";
user["age"] += 1;

print(user); // {name: "Robert", age: 26, email: "bob@example.com"}
```

#### Removing Properties

Properties can be removed using the `delete` operator:

```
let product = {id: "p123", name: "Laptop", price: 999, discontinued: false};

delete product.discontinued;
print(product); // {id: "p123", name: "Laptop", price: 999}

delete product["price"];
print(product); // {id: "p123", name: "Laptop"}
```

#### Merging Dictionaries

Ucode supports using spread expressions to merge dictionaries elegantly:

```
let defaults = {theme: "light", fontSize: 12, notifications: true};
let userSettings = {theme: "dark"};

// Merge dictionaries with spread syntax
let merged = {...defaults, ...userSettings};
print(merged); // {theme: "dark", fontSize: 12, notifications: true}
```

When merging with spread syntax, properties from later objects overwrite those
from earlier objects if the keys are the same. This provides a clean way to
implement default options with overrides:

```
// Apply user preferences with fallbacks
let config = {
    ...systemDefaults,
    ...globalSettings,
    ...userPreferences
};
```

For situations requiring more complex merging logic, you can implement a custom
function:

```
function merge(target, ...sources) {
    for (source in sources) {
        for (key in keys(source)) {
            target[key] = source[key];
        }
    }
    return target;
}

let defaults = {theme: "light", fontSize: 12, notifications: true};
let userSettings = {theme: "dark"};
let merged = merge({}, defaults, userSettings);
print(merged); // {theme: "dark", fontSize: 12, notifications: true}
```

Note that this performs a shallow merge. For nested objects, a deep merge would
be needed:

```
function deepMerge(target, ...sources) {
    if (!sources.length) return target;

    for (source in sources) {
        if (type(source) !== "object") continue;

        for (key in keys(source)) {
            if (type(source[key]) == "object" && type(target[key]) == "object") {
                // Recursively merge nested objects
                target[key] = deepMerge({...target[key]}, source[key]);
            } else {
                // For primitive values or when target key doesn't exist/isn't an object
                target[key] = source[key];
            }
        }
    }

    return target;
}

let userProfile = {
    name: "Alice",
    preferences: {
        theme: "light",
        sidebar: {
            visible: true,
            width: 250
        }
    }
};

let updates = {
    preferences: {
        theme: "dark",
        sidebar: {
            width: 300
        }
    }
};

let merged = deepMerge({}, userProfile, updates);
/* Result:
{
    name: "Alice",
    preferences: {
        theme: "dark",
        sidebar: {
            visible: true,
            width: 300
        }
    }
}
*/
```

### Iteration Techniques

#### Iterating with for-in

The most common way to iterate through a dictionary is using `for-in`:

```
let metrics = {visits: 1024, conversions: 85, bounceRate: 0.35};

for (key in metrics) {
    printf("%s: %J\n", key, metrics[key]);
}
// Output:
// visits: 1024
// conversions: 85
// bounceRate: 0.35
```

#### Iterating over Entries (Key-Value Pairs)

A more advanced iteration technique gives access to both keys and values:

```
let product = {name: "Widget", price: 19.99, inStock: true};

for (key in keys(product)) {
    let value = product[key];
    printf("%s: %J\n", key, value);
}
```

#### Enhanced for-in Loop

Ucode provides an enhanced for-in loop that can destructure keys and values:

```
let inventory = {apples: 50, oranges: 25, bananas: 30};

for (item, quantity in inventory) {
    printf("We have %d %s in stock\n", quantity, item);
}
// Output:
// We have 50 apples in stock
// We have 25 oranges in stock
// We have 30 bananas in stock
```

This syntax offers a more elegant way to work with both keys and values
simultaneously.

## Key Ordering and Sorting

One distinctive feature of ucode dictionaries is their predictable key ordering.
Unlike many other languages where hash-based dictionaries have arbitrary or
implementation-dependent key ordering, ucode maintains key order based on
declaration or assignment sequence.

### Predictable Iteration Order

When iterating through a dictionary, keys are always processed in their
insertion order:

```
let scores = {};
scores.alice = 95;
scores.bob = 87;
scores.charlie = 92;

// Keys will be iterated in the exact order they were added
for (name in scores) {
    printf("%s: %d\n", name, scores[name]);
}
// Output will consistently be:
// alice: 95
// bob: 87
// charlie: 92
```

This predictable ordering applies to all dictionary operations: for-in loops,
`keys()`, and `values()`.

### Sorting Dictionary Keys

You can explicitly reorder dictionary keys using the `sort()` function:

```
let stats = {
    average: 72.5,
    median: 68,
    mode: 65,
    range: 45
};

// Sort keys alphabetically
sort(stats);

// Now keys will be iterated in alphabetical order
for (metric in stats) {
    printf("%s: %J\n", metric, stats[metric]);
}
// Output:
// average: 72.5
// median: 68
// mode: 65
// range: 45
```

Custom sorting is also supported:

```
let inventory = {
    apples: 45,
    bananas: 25,
    oranges: 30,
    grapes: 60
};

// Sort by value (quantity) in descending order
sort(inventory, (k1, k2, v1, v2) => v2 - v1);

// Keys will now be ordered by their associated values
for (fruit, quantity in inventory) {
    printf("%s: %d\n", fruit, quantity);
}
// Output:
// grapes: 60
// apples: 45
// oranges: 30
// bananas: 25
```

This ability to maintain and manipulate key order makes ucode dictionaries
particularly useful for:
- Configuration objects where property order matters
- UI element definitions that should be processed in a specific sequence
- Data structures that need to maintain insertion chronology

## Advanced Dictionary Techniques

### Nested Dictionaries

Dictionaries can contain other dictionaries, allowing for complex data
structures:

```
let company = {
    name: "Acme Corp",
    founded: 1985,
    address: {
        street: "123 Main St",
        city: "Metropolis",
        zipCode: "12345"
    },
    departments: {
        engineering: {
            headCount: 50,
            projects: ["Alpha", "Beta", "Gamma"]
        },
        sales: {
            headCount: 30,
            regions: ["North", "South", "East", "West"]
        }
    }
};

// Accessing nested properties
printf("Engineering headcount: %d\n", company.departments.engineering.headCount);
```

### Dictionary as a Cache

Dictionaries are excellent for implementing caches or memoization:

```
function memoizedFibonacci() {
    let cache = {};

    // Return the actual fibonacci function with closure over cache
    return function fib(n) {
        // Check if result exists in cache
        if (exists(cache, n)) {
            return cache[n];
        }

        // Calculate result for new inputs
        let result;
        if (n <= 1) {
            result = n;
        } else {
            result = fib(n-1) + fib(n-2);
        }

        // Store result in cache
        cache[n] = result;
        return result;
    };
}

let fibonacci = memoizedFibonacci();
printf("Fibonacci 40: %d\n", fibonacci(40)); // Fast computation due to caching
```

### Using Dictionaries for Lookups

Dictionaries excel at lookup tables and can replace complex conditional logic:

```
// Instead of:
function getStatusMessage(code) {
    if (code == 200) return "OK";
    else if (code == 404) return "Not Found";
    else if (code == 500) return "Server Error";
    // ...and so on
    return "Unknown Status";
}

// Use a dictionary:
let statusMessages = {
    "200": "OK",
    "404": "Not Found",
    "500": "Server Error"
};

function getStatusMessage(code) {
    return statusMessages[code] ?? "Unknown Status";
}
```

### Dictionary Patterns and Recipes

#### Deep Clone

Creating a deep copy of a dictionary with nested objects:

```
function deepClone(obj) {
    if (type(obj) != "object") {
        return obj;
    }

    let clone = {};
    for (key in keys(obj)) {
        if (type(obj[key]) == "object") {
            clone[key] = deepClone(obj[key]);
        } else if (type(obj[key]) == "array") {
            clone[key] = deepCloneArray(obj[key]);
        } else {
            clone[key] = obj[key];
        }
    }
    return clone;
}

function deepCloneArray(arr) {
    let result = [];
    for (item in arr) {
        if (type(item) == "object") {
            push(result, deepClone(item));
        } else if (type(item) == "array") {
            push(result, deepCloneArray(item));
        } else {
            push(result, item);
        }
    }
    return result;
}
```

#### Dictionary Filtering

Creating a new dictionary with only desired key-value pairs:

```
function filterObject(obj, filterFn) {
    let result = {};
    for (key in keys(obj)) {
        if (filterFn(key, obj[key])) {
            result[key] = obj[key];
        }
    }
    return result;
}

// Example: Keep only numeric values
let mixed = {a: 1, b: "string", c: 3, d: true, e: 4.5};
let numbersOnly = filterObject(mixed, (key, value) =>
    type(value) == "int" || type(value) == "double"
);
print(numbersOnly); // {a: 1, c: 3, e: 4.5}
```

#### Object Mapping

Transforming values in a dictionary while keeping the same keys:

```
function mapObject(obj, mapFn) {
    let result = {};
    for (key in keys(obj)) {
        result[key] = mapFn(key, obj[key]);
    }
    return result;
}

// Example: Double all numeric values
let prices = {apple: 1.25, banana: 0.75, cherry: 2.50};
let discountedPrices = mapObject(prices, (fruit, price) => price * 0.8);
print(discountedPrices); // {apple: 1, banana: 0.6, cherry: 2}
```

#### Dictionary Equality

Comparing dictionaries by value instead of by reference:

```
function objectEquals(obj1, obj2) {
    // Check if both are objects
    if (type(obj1) != "object" || type(obj2) != "object") {
        return obj1 === obj2;
    }

    // Check key count
    let keys1 = keys(obj1);
    let keys2 = keys(obj2);
    if (length(keys1) != length(keys2)) {
        return false;
    }

    // Check each key-value pair
    for (key in keys1) {
        if (!exists(obj2, key)) {
            return false;
        }

        if (type(obj1[key]) == "object" && type(obj2[key]) == "object") {
            // Recursively check nested objects
            if (!objectEquals(obj1[key], obj2[key])) {
                return false;
            }
        } else if (type(obj1[key]) == "array" && type(obj2[key]) == "array") {
            // For arrays, we would need array equality check
            if (!arrayEquals(obj1[key], obj2[key])) {
                return false;
            }
        } else if (obj1[key] !== obj2[key]) {
            return false;
        }
    }
    return true;
}

function arrayEquals(arr1, arr2) {
    if (length(arr1) != length(arr2)) {
        return false;
    }

    for (let i = 0; i < length(arr1); i++) {
        if (type(arr1[i]) == "object" && type(arr2[i]) == "object") {
            if (!objectEquals(arr1[i], arr2[i])) {
                return false;
            }
        } else if (type(arr1[i]) == "array" && type(arr2[i]) == "array") {
            if (!arrayEquals(arr1[i], arr2[i])) {
                return false;
            }
        } else if (arr1[i] !== arr2[i]) {
            return false;
        }
    }
    return true;
}
```

## Performance Considerations and Best Practices

### Hash Collision Impacts

Since ucode dictionaries use hash tables:
- Hash collisions can occur (different keys hash to same value)
- Hash collision resolution affects performance
- As dictionaries grow large, performance degradation may occur
- Performance is generally consistent but can have occasional spikes due to rehashing

### Key Naming Considerations

String keys have important implications:
- Choose short, descriptive keys to minimize memory usage
- Be consistent with key naming conventions
- Remember that property access via dot notation (`obj.prop`) and bracket notation (`obj["prop"]`) are equivalent
- Keys containing special characters or reserved words must use bracket notation: `obj["special-key"]`

### Memory Usage Optimization

To optimize dictionary memory usage:
- Delete unused keys to prevent memory leaks
- Use shallow structures when possible
- Consider serialization for large dictionaries not actively used
- Be aware that circular references delay garbage collection until mark-sweep GC runs

```
// Circular reference example
let obj1 = {};
let obj2 = {ref: obj1};
obj1.ref = obj2; // Creates a circular reference

// While reference counting won't collect these immediately,
// a mark-sweep GC run will eventually reclaim this memory
// when the objects become unreachable from the root scope
```

### Performance Patterns

#### Property Access Optimization

When repeatedly accessing the same property in loops, consider caching:

```
// Less efficient - repeated property access
for (let i = 0; i < 1000; i++) {
    processValue(config.complexComputedValue);
}

// More efficient - cache the property
let cachedValue = config.complexComputedValue;
for (let i = 0; i < 1000; i++) {
    processValue(cachedValue);
}
```

#### Key Existence Check Performance

Different methods for checking key existence have varying performance
implications:

```
// Option 1: Using exists() - most explicit and readable
if (exists(user, "email")) {
    sendEmail(user.email);
}

// Option 2: Direct property access with null check
if (user.email != null) {
    sendEmail(user.email);
}

// Option 3: Using in operator with keys
if ("email" in keys(user)) {
    sendEmail(user.email);
}
```

Option 1 is typically the most performant as it's specifically designed for
this purpose.

### Dictionary Implementation Details

Understanding internal implementation details can help write more efficient code:

1. **Initial Capacity**: Dictionaries start with a small capacity and grow as needed
2. **Load Factor**: When dictionaries reach a certain fullness threshold, they're resized
3. **Hash Function**: Keys are hashed using a specialized string hashing function
4. **Collision Resolution**: Ucode typically uses open addressing with linear probing
5. **Deletion**: When keys are deleted, they're marked as deleted but space isn't reclaimed until rehashing
6. **Order Preservation**: Unlike many hash table implementations, ucode tracks and maintains insertion order

These implementation details explain why:
- Iterating over a dictionary with many deleted keys might be slower
- Adding many keys may trigger occasional performance pauses for rehashing
- Key order is consistent and predictable, matching declaration/assignment order
- Dictionaries can be deliberately reordered using `sort()`

## Conclusion

Dictionaries in ucode provide a powerful and flexible way to organize data by
key-value relationships. By understanding their implementation characteristics
and following best practices, you can effectively leverage dictionaries for
everything from simple configuration storage to complex nested data structures.

Remember that dictionaries excel at:
- Fast lookups by string key
- Dynamic property addition and removal
- Representing structured data
- Implementing caches and lookup tables

When working with large dictionaries or performance-critical code, consider the
memory usage patterns and optimization techniques described in this article to
ensure your code remains efficient and maintainable.
