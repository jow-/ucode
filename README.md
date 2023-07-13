# The ucode Scripting Language

The ucode language is a small, general-purpose scripting language that resembles
ECMAScript syntax. It can be used as a standalone interpreter or embedded into
host applications. Ucode supports template mode with control flow and expression
logic statements embedded in Jinja-like markup blocks.

The development of ucode was motivated by the need to rewrite the OpenWrt
firewall framework using nftables. Initially intended as a template processor,
ucode evolved into a versatile scripting language for various system scripting
tasks. Its design goals include easy integration with C applications, efficient
handling of JSON data and complex data structures, support for OpenWrt's ubus
message bus system, and a comprehensive set of built-in functions inspired by
Perl 5.

Ucode provides the ability to embed code logic into plain text templates,
supports JSON parsing and serialization, has distinct array and object types,
includes built-in support for bit operations and regular expressions, and offers
bindings for relevant Linux and OpenWrt APIs. It follows ECMAScript syntax for
familiarity and reusability of existing tooling, emphasizes synchronous
programming flow, aims for a small executable size, and can be embedded into C
host applications.

In summary, ucode is a synchronous scripting language resembling ECMAScript,
designed for template processing, system scripting tasks, and integration into C
applications, with features such as JSON support, comprehensive built-in
functions, and bindings for relevant APIs.

## Installation

The *ucode* package should be already preinstalled on modern OpenWrt releases.

To learn how to install it on other systems, refer to the
[Installation Section](https://ucode.mein.io/#installation) in the
documentation.

## Documentation

The most up-to-date documentation is hosted at the
[ucode documentation portal](https://ucode.mein.io/).

You can build the documentation yourself by running `npm install` followed by
`npm run doc` in the cloned repository. The generated documentation will be
placed in the `docs/` directory.

## Examples

Examples for embedding ucode into C applications can be found in the
[`examples/` directory](https://github.com/jow-/ucode/tree/master/examples).

Notable OpenWrt programs *embedding* ucode are the
[OpenWrt ubus rpc daemon](https://github.com/openwrt/rpcd) and the
[Tiny uhttpd web server](https://github.com/openwrt/uhttpd).

Some ucode scripting examples can be found in the ucode
[testcase sources](https://github.com/jow-/ucode/tree/master/tests/custom).

Projects using ucode scripting include the
[OpenWrt LuCI web interface](https://github.com/openwrt/luci) and the
[OpenWrt firewall4 framework](https://github.com/openwrt/firewall4).
