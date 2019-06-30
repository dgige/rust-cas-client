# CAS Client in Rust

Allow user connection with [CAS server](https://www.apereo.org/projects/cas "Apereo CAS Homepage").

Tested with:
- [Actix](https://actix.rs/ "Actix framework homepage")

## Actix example

```bash
cargo run --features "actix-framework" --example actix-web-example
# OR
cd examples/actix-web-example && cargo run
```

## Run tests
```bash
cargo test --all
# OR
cargo test -p cas-client-core
```

## TODO
- Tests
- Documentation
- Refactoring
- and more...
