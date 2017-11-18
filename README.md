# Secret-Handshake

Rust wrapper around [shs1-c](https://github.com/AljoschaMeyer/shs1-c).

[API documentation](https://docs.rs/secret_handshake)

The `examples` folder contains executables for use with the [shs1-testsuite](https://github.com/AljoschaMeyer/shs1-testsuite). Run `cargo build --example client` or `cargo build --example server` to compile them.

### Building

This module depends on [libsodium](https://github.com/jedisct1/libsodium).

This also contains [shs1-c](https://github.com/AljoschaMeyer/shs1-c) as a git submodule, so be sure to perform the right git magic when cloning, updating etc.
