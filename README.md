# vlmcsd-rs

Rust 2024 KMS V4/V5/V6 emulator and test client, with async and blocking library
APIs and Tokio CLIs. Small, bounded protocol
and crypto operations execute synchronously. Async socket I/O uses Tokio;
blocking socket I/O uses the standard library.

```sh
cargo run --locked -p vlmcsd -- --listen 127.0.0.1:1688
RUST_LOG=vlmcsd=debug cargo run --locked -p vlmcsd -- --listen 127.0.0.1:1688
cargo run --locked -p vlmcsd -- --help
```

The default listener is loopback. Use `--listen 0.0.0.0:1688` or an explicit LAN
address for remote clients; IPv6 literals use `[::1]:1688`. The process stays in
the foreground, making it suitable for a service manager. Ctrl-C and Unix
SIGTERM stop accepting, drain connections for `--shutdown-grace` seconds, then
abort and join remaining tasks.

`--max-connections` bounds the task set (default 256); at capacity, acceptance
pauses. `--timeout` bounds each entire RPC exchange, including header, fragmented
body and response write (default 30 seconds). `--max-exchanges` bounds persistent
connection lifetime in exchanges, including bind (default 1024). Parsing caps PDUs
and assembled requests at 4096 bytes, contexts at 32, and request fragments at 16.

The implementation validates RPC headers, presentation contexts, transfer syntax
versions, operation numbers, NDR lengths, exact KMS sizes, UTF-16 workstation
names, V4 MACs, V5/V6 padding, and inner/outer version consistency. It supports
NDR32/NDR64 negotiation, alter-context, repeated calls, and request fragmentation.
Invalid context IDs and operation numbers receive RPC faults; malformed packets
close the offending connection. All crate code forbids unsafe Rust.

Configure the stable host identity with `--epid` and `--hardware-id`. Configure
response policy with `--client-count`, `--activation-interval` and
`--renewal-interval` (intervals in minutes). The default reported count is 50.
This is **emulation**: count is configured, not measured; the server does not
activate a Microsoft CSVLK or maintain a persistent client database. One ePID
is used for all products. Product catalogs, per-product identities, DNS SRV
publication, RPC authentication, fragmented binds, interleaved fragmented calls,
and BTFN security features are not implemented. Unsupported BTFN proposals are
rejected; the C reference client warns when NDR64 is available without BTFN.

V5 uses RustCrypto's `aes::Aes128`. V4 uses RustCrypto's low-level AES round
functions with its protocol-specific 160-bit key expansion and eleven rounds.
V6 retains the custom Rijndael implementation with modified round keys. The
remaining custom code is isolated in a private module of `vlmcsd-protocol`,
adapted from the upstream Rust port. SHA-256 and HMAC also use RustCrypto, and salts use the OS random
source. Protocol keys are public constants; this module is not a general-purpose
secret-key cryptography library.


## Workspace and client

- `crates/vlmcsd`: async/blocking server library and `vlmcsd` binary.
- `crates/vlmcs`: async/blocking client library and `vlmcs` binary.
- `crates/vlmcsd-protocol`: shared KMS codecs, types and crypto.

The former `vlmcsd-rs` Cargo package and `vlmcsd_rs` library are now named
`vlmcsd`. Both binaries build with `cargo build --locked --workspace`.

```sh
cargo run --locked -p vlmcs -- 127.0.0.1:1688
cargo run --locked -p vlmcs -- -4 -n 2 127.0.0.1:1688
cargo run --locked -p vlmcs -- -6 --ndr64 -v '[::1]:1688'
cargo run --locked -p vlmcs -- --help
```

The client defaults to V6, NDR32, one request and a Windows Professional product
identity. Use `-4`, `-5`, or `-6`, `-n` for repeated requests, `-w` for the
workstation name, and `-t` for the deadline in seconds. Hostnames and bare IPs
use port 1688. Explicit IPv6 ports require brackets. Product GUIDs can be set
with `--application-id`, `--activation-id`, and `--kms-id`; `--required-count`
sets the requested threshold. An embedded product catalog and DNS SRV discovery
are not implemented.

Connect and bind share a deadline; each complete request has its own deadline.
The client validates RPC call IDs, context and syntax, NDR lengths, KMS versions,
CMID, timestamp, UTF-16 ePID, padding, V4 MAC, V5 salt/hash, and V6 salt/hash/HMAC.
It accepts bounded fragmented responses. A transport, integrity or server-status
failure returns an error and makes the CLI exit unsuccessfully. After a canceled
or failed network exchange, library callers must reconnect.

## Async and blocking APIs

Both network crates have additive `std`, `async`, `blocking`, and `cli` features.
Defaults enable `async`, `blocking`, and `cli`, which imply `std`. `async` enables Tokio networking; `blocking` uses
standard-library sockets without a Tokio dependency; `cli` enables the existing
async executable and its command-line dependencies. The protocol codecs and RPC
state machines are shared between both transport implementations and embedded
`no_std` sessions.

Select the library mode in your Cargo manifest:

```toml
[dependencies]
vlmcs = { path = "crates/vlmcs", default-features = false, features = ["blocking"] }
vlmcsd = { path = "crates/vlmcsd", default-features = false, features = ["blocking"] }
```

Use `features = ["async"]` for async-only libraries, or `["async", "blocking"]`
for both. Library users supply the runtime for async calls. The libraries never
create a Tokio runtime internally.

```rust,no_run
use vlmcs::{ActivationRequest, ClientConfig};

// Product IDs, CMID and timestamp use the shared protocol's wire conventions.
let request = ActivationRequest::new([0; 16], [0; 16], [0; 16], [0; 16], 0);
let mut client = vlmcs::blocking::Client::connect("127.0.0.1:1688", ClientConfig::default())?;
let response = client.activate(&request)?;
# Ok::<(), vlmcs::Error>(())
```

The async equivalent is `vlmcs::Client::connect(...).await?` followed by
`client.activate(&request).await?`. Blocking DNS resolution happens before the
socket deadline; supply a `SocketAddr` when a predictable connect deadline is
required. Blocking deadlines cover all reads and writes in an exchange,
including fragmented or slowly delivered messages.

The async server uses `vlmcsd::serve` with a Tokio listener and shutdown future.
The blocking server uses a standard-library listener and an atomic shutdown flag:

```rust,no_run
use std::{net::TcpListener, sync::atomic::AtomicBool};

let listener = TcpListener::bind("127.0.0.1:1688")?;
let shutdown = AtomicBool::new(false);
// Another thread sets shutdown to true when termination is requested.
vlmcsd::blocking::serve(listener, vlmcsd::ServerConfig::default(), &shutdown)?;
# Ok::<(), vlmcsd::Error>(())
```

The blocking server creates at most `max_connections` worker threads. It pauses
accepting at capacity, uses a 10 ms shutdown polling interval, drains for `shutdown_grace`,
then interrupts remaining sockets and joins every worker. Errors also clean up
all workers. `blocking::serve_connection` is available when an embedding
application already owns the listener, threads, or shutdown policy.

Blocking APIs belong on ordinary threads. When calling them from Tokio, use
[`spawn_blocking`](https://tokio.rs/tokio/topics/bridging) so blocking socket
operations do not stall runtime workers. Prefer the async APIs for high connection
counts. The bounded codecs run inline because their work is small and synchronous.

## `no_std` protocol library

`vlmcsd-protocol` is unconditionally `#![no_std]` and requires `alloc` (a heap
allocator). Its dependency graph contains no Tokio, OS randomness or clock APIs.
The client and server networking features require `std`. With default features
disabled, both `vlmcs` and `vlmcsd` also compile as `no_std` libraries and expose
runtime-independent RPC sessions. Crypto contexts are constructed locally without global lazy locks.

Callers supply Windows-wire-order GUIDs and a FILETIME timestamp to
`ActivationRequest::new`, and a fresh cryptographically random 16-byte salt to
`encode`. `EncodedRequest::verify_response` validates the resulting response.
Server integrations supply two fresh random blocks to `respond_into`.
Do not reuse fixed test salts in production integrations.


For an embedded client/server application, disable defaults on both dependencies:

```toml
[dependencies]
vlmcs = { path = "crates/vlmcs", default-features = false }
vlmcsd = { path = "crates/vlmcsd", default-features = false }
```

Use `vlmcs::ClientSession` and `vlmcsd::ServerSession` to drive RPC without OS
sockets or a runtime. These are synchronous byte-processing state machines that
can sit underneath either a sync or async embedded transport:

1. The client calls `start_bind`, sends the returned frame, then passes its reply
   to `finish_bind`.
2. The client calls `start_request(request, fresh_salt)` and sends its frame.
3. The server calls `receive(frame, prepared_host, fresh_random, fresh_iv)` for
   each complete frame. `None` means more request fragments are needed; `Some`
   contains the response frame to send.
4. The client calls `receive_response` for each complete response frame. `Some`
   contains an integrity-checked activation response; `None` means more fragments
   are needed. The association is ready for another request when complete.

Read 16 bytes of RPC header, call `vlmcsd_protocol::rpc::frame_len` to validate the
bounded frame size, and read exactly the remaining bytes before passing a frame
to a session. Frames and assembled calls are bounded; interleaved calls are
rejected. Malformed peer data invalidates the session. Call `close` after a
transport failure, cancellation, or timeout, then start a new session for a new
connection. Transport I/O, DNS, deadlines, and server connection limits belong to
the embedding application. Errors are available as `vlmcs::ProtocolError` and
`vlmcsd::ProtocolError`.

These APIs require an allocator; an allocation-free version is not implemented.
No standard-library, Tokio, OS-randomness or clock dependency is enabled in the
normal `no_std` client/server dependency graph.

Check all three libraries on an installed bare-metal target:

```sh
cargo check --locked -p vlmcsd-protocol --no-default-features --target thumbv7em-none-eabi
cargo check --locked -p vlmcs --no-default-features --target thumbv7em-none-eabi
cargo check --locked -p vlmcsd --no-default-features --target thumbv7em-none-eabi
```

## Validation

```sh
cargo test --locked --workspace
cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
cargo test --locked -p vlmcs --no-default-features --features blocking
cargo test --locked -p vlmcsd --no-default-features --features blocking
```

Tests adapt the upstream Rust port's eight crypto tests and V4/V5/V6 network
roundtrips. Network tests use ephemeral ports, async I/O and explicit shutdown.
Client tests also compare generated requests and verified V4/V5/V6 responses
against independent py-kms fixtures, and exercise response fragmentation,
corruption, replay, RPC faults, deadlines, cancellation, and CLI validation.
Server tests additionally cover faults, malformed packets, fragmentation, connection
limits, exchange deadlines, request budgets and shutdown. Checked-in py-kms
fixtures allow ordinary Rust tests to run without external repositories.

For independent validation, obtain the source revisions in
[THIRD-PARTY-NOTICES](THIRD-PARTY-NOTICES), build the C `vlmcs` client with `make
vlmcs`, and run:

```sh
PYKMS_SOURCE=/path/to/py-kms VLMC_CLIENT=/path/to/vlmcsd/bin/vlmcs \
  cargo test --locked -p vlmcsd --test async_server -- --ignored
```

The Python harness calls upstream `generateRequest`, `decryptResponse`, V4 hash,
V6 MAC-key derivation, and AES routines directly. It validates 24 responses:
V4/V5/V6 × NDR32/NDR64 × fragmented/unfragmented × two calls per connection.
It checks complete response base bytes, CMID, timestamp, host identity, count,
intervals, V4 MAC, V5 IV/hash, and V6 salt/hash/HWID/HMAC. The C client independently
checks two requests for each version/transfer-syntax combination (12 responses).
Its diagnostics are checked as well as its exit code.

Regenerate the deterministic fixtures from the repository root:

```sh
python3 scripts/pykms_interop.py --source /path/to/py-kms \
  --fixtures tests/fixtures
```

The fixture provenance file records the source commit and SHA-256 values.
The Python checkout has no comprehensive protocol unit-test suite to transplant;
we reuse its protocol implementations as an independent oracle instead.
This validation establishes interoperability with these references on Linux.
Native Windows client activation, Windows service integration and cross-platform
runtime behavior remain untested.

## Benchmarks and fuzzing

Run the dependency-free protocol microbenchmarks in release mode:

```sh
cargo bench --locked -p vlmcsd-protocol --bench protocol
```

Each V4/V5/V6 encode, respond and verify operation gets a warmup and a
one-second measurement. Results report mean nanoseconds per operation; response
generation reuses its output allocation. Host preparation, randomness, sockets
and RPC transport are excluded. These are local timing estimates, not statistical
regression tests. Compare runs on the same idle machine and toolchain.

The separate `fuzz` package uses cargo-fuzz and libFuzzer with AddressSanitizer.
Install cargo-fuzz and a nightly toolchain, then seed it with the independent
protocol fixtures and run a bounded campaign from the repository root:

```sh
cargo install cargo-fuzz --locked
rustup toolchain install nightly
mkdir -p fuzz/corpus/protocol
cp tests/fixtures/*request.bin tests/fixtures/*response.bin fuzz/corpus/protocol/
cargo +nightly fuzz run protocol -- -max_total_time=60 -max_len=4096
```

The target exercises raw KMS request processing and response verification for
all three versions, RPC headers, bind acknowledgements, and bound/unbound
NDR32/NDR64 sessions. It also mutates valid RPC requests and responses to reach
parsers beyond initial header checks. Fixed salts are for this offline harness.
Crashes are saved under `fuzz/artifacts/protocol`; replay one with
`cargo +nightly fuzz run protocol fuzz/artifacts/protocol/<artifact>`.
Corpus and artifacts are ignored by Git; the fuzz dependency lockfile is tracked.
A short successful campaign is a smoke test, not proof of correctness.

## Releases

GitHub Actions checks Linux, Windows and macOS builds, feature configurations,
formatting, Clippy, and bare-metal `no_std` compilation on pushes to `main` and
pull requests.

To release, update the workspace version and the local dependency version
requirements together, commit the changes, then push a matching `v<version>`
tag (currently `v0.1.0`). The release workflow reruns CI, verifies the tag,
packages all three crates and a source snapshot with its commit ID, and builds
and tests both CLIs for Linux x86-64, Windows x86-64 and macOS ARM64. The GitHub release contains `.crate` packages,
a source archive, binary archives with license notices, and `SHA256SUMS`.
Tags containing a hyphen create prereleases. This workflow does not publish to crates.io.

Each crate includes copies of the root `LICENSE` and `THIRD-PARTY-NOTICES`;
keep these copies synchronized when changing the originals. CI checks them.
