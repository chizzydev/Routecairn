# Protocol semantics operation

## Execution and policy

The protocol manifest compiles exact, same-origin cases. Scope, DNS pinning, scan and protocol budgets, response limits, identity checks and target authorization apply before transmission. Streaming state changes require disposable resources, fresh authorization and cleanup; cleanup capacity is separate from the ordinary scan budget.

WebTransport uses native Extended CONNECT and QUIC datagrams. Include `CONNECT` explicitly in the scope and any target authorization request rules. Authentication is an explicit secret-backed application datagram, not an injected HTTP header. Every outgoing datagram is at most 1,200 bytes; at most 16 are sent. Received bytes are bounded across the session, not per datagram. Missing replies are inconclusive. CONNECT 401/403 is a classified denial, and JSON-path expectations verify application receipts.

`transport.trustedCaPem` accepts only public CA certificates. It applies to the HTTP pool, cleanup, raw H1 probes, TLS WebSocket/gRPC/H2 and native H3/WebTransport. Certificate validation remains enabled. QUICO is pinned to 0.4.0: its WebTransport wrapper does not forward TLS options, so the isolated worker uses an explicit pinned socket adapter. Its TLS dependency does not build the platform trust chain automatically. For default public trust, RouteCairn authenticates the same pinned TCP/TLS origin with Node's PKI verifier before QUIC and uses the verified issuer for QUIC. This sends no HTTP request or credentials. A QUIC-only private service must supply its CA. No fallback to H1/H2 application transport is permitted.

gRPC success requires the expected HTTP status, a valid final gRPC status and complete bounded message framing. Malformed flags, trailing fragments, excessive messages and unsupported message compression are inconclusive, rather than accepted prefixes.

Incremental delivery requires complete MIME framing, valid object parts, final completion and the declared paths. Oversized, malformed or truncated delivery is inconclusive. Query contracts reject mixed mutation/subscription documents, including mutations hidden after hash-containing strings. Identity comparison requires a real selected identity in every leg; absent paths cannot agree as `undefined`.

## Reproduce and retain evidence

Supply approved local Caddy and nginx executables. The runner starts isolated loopback listeners and processes, generates ephemeral private TLS fixtures, and removes all fixture state. It never installs binaries, modifies system trust or terminates unrelated processes.

```powershell
$env:ROUTECAIRN_CADDY_BINARY = 'C:\tools\caddy.exe'
$env:ROUTECAIRN_NGINX_BINARY = 'C:\tools\nginx.exe'
npm run acceptance:protocol-semantics -- --output acceptance/protocols/FRESH_RUN
```

The output directory must be new. `protocol-semantics-lab-result.json` commits to source, dependency runtime and executable hashes, test counts and redacted runtime evidence. Missing native binaries, skipped cases, runtime errors, incomplete evidence or changed sources fail the run. `SHA256SUMS` verifies the retained files. Evidence contains outcomes, counts and fingerprints; credentials, identity values, request payloads and TLS private keys are omitted.

The module exercise covers live gRPC client/bidirectional streaming, incremental GraphQL, persisted registration/hash retrieval, federation entity resolution, modern/legacy subscription reconnect authorization, WebSocket login/read/logout/denial, real interrupted uploads and restoration, gzip/deflate/Brotli bounds, H1/H2/H3 identity parity, missing/mismatched identities, WebTransport application receipts and CONNECT denial. Negative TLS and aggregate datagram-limit controls run against real listeners.

Two native intermediary deployments exercise H1/H2/H3 ingress through Caddy, then H1 or H2 to nginx, then H1 to the application. Each framing cell requires a fresh challenge, matching deployment digest and ordered hop trace. Backend state is bound to the challenge. H2/H3 length rejection and clean sentinel execution are retained; H1 ambiguity without observed backend misrouting remains inconclusive. Neither accepted pipelining nor a timeout alone establishes desynchronization.

The packaged `routecairn validate-protocol-fixtures --output FRESH_PARENT` acceptance command additionally executes seven transport lanes, including authenticated TLS/native WebTransport. Package smoke runs the installed command and checks its retained lane evidence.

## Evidence boundaries

These are self-maintained, real local runtime and intermediary deployments. They do not assert independent operation, public deployment, external application acceptance, H3 upstream forwarding or every possible intermediary combination. Subscription reauthorization is reconnect-based; continuous revocation of an already active subscription needs a separate application contract. A compression expansion-limit PASS establishes that the scanner bounded its decoder; it does not establish the application's decompression safety. Secure results apply only to the exercised case.

Native datagrams follow [RFC 9297](https://www.rfc-editor.org/rfc/rfc9297.html). Runtime compatibility is tied to the reviewed [QUICO implementation](https://github.com/colocohen/quico).
