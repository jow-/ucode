The ucode scripting language utilizes a reference count-based garbage collector
as its primary method of memory management. When assigning an array or object
value, the reference count is incremented. When a local variable holding a
reference goes out of scope, the reference count is decremented. If the
reference count reaches zero, a recursive traversal is performed to decrease the
reference count of any nested references. Once the traversal is complete, the
top-level array or object structure is freed.

Example 1:
```javascript
x = [ { a: 1 }, { b: 2 }, { c: 3 } ];
// `x` holds a reference to `[...]` (refcount 1)
// `x[0]` holds a reference to `{ a: 1 }` (refcount 1)
// `x[1]` holds a reference to `{ b: 2 }` (refcount 1)
// `x[2]` holds a reference to `{ c: 3 }` (refcount 1)

x = null;
// refcount of `[...]` drops to 0; refcount decreasing cascades
// down, `{ a: 1 }`, `{ b: 2 }` and { c: 3 }` refcounts reach
// zero as well; `{ a: 1 }`, `{ b: 2 }`, `{ c: 3 }` and `[ ... ]`
// are freed
```

Example 2:
```javascript
x = [ { a: 1 }, { b: 2 }, { c: 3 } ];
y = x[1];
// `x` holds a reference to `[...]` (refcount 1)
// `x[0]` holds a reference to `{ a: 1 }` (refcount 1)
// `x[1]` and `y` hold a reference to `{ b: 2 }` (refcount 2)
// `x[2]` holds a reference to `{ c: 3 }` (refcount 1)

x = null;
// refcount of `[...]` drops to 0, refcount decreasing cascades
// down, `{ a: 1 }` and `{ c: 3 }` refcounts reach zero while
// `{ b: 2 }` refcount is down to one.
// `{ a: 1 }`, `{ c: 3 }` and `[ ... ]` are freed
// `{ b: 2 }` is still alive with refcount 1, pointed to by `y`
```

Although the reference count-based garbage collector efficiently manages memory,
it cannot handle cyclic structures, leading to memory leaks.

Example 1:
```javascript
o = { }; o.x = o;
// `o` holds a reference to itself (refcount 1)

```

Example 2:
```javascript
a = [ ]; a[0] = a;
// `a` holds a reference to itself (refcount 1)
```

Example 3:
```javascript
x = { y: { z: [ ] } }; x.y.z = x;
// `x` holds a reference to itself through `x.y.z` (refcount 1)
```

In these examples, cyclic references are created where objects or arrays point
back to themselves or create a circular chain. Since each element within the
cycle maintains a reference, the reference count for each object or array never
reaches zero, resulting in a memory leak. The reference count-based garbage
collector cannot automatically reclaim memory in such cases.

To address cyclic structures and avoid memory leaks, ucode provides a secondary
mark-and-sweep garbage collector. This collector can be enabled by passing the
`-g` flag to the ucode interpreter or manually triggered using the
[`gc()`](/module-core.html#gc) function during runtime. The mark-and-sweep
collector identifies and frees unreachable objects, including those involved in
cyclic references.
