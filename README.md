# Quincy
[![Crates.io](https://img.shields.io/crates/v/quincy.svg)](https://crates.io/crates/quincy)
[![Documentation](https://docs.rs/quincy/badge.svg)](https://docs.rs/quincy/)
[![Build status](https://github.com/M0dEx/quincy/workflows/CI/badge.svg)](https://github.com/M0dEx/quincy/actions?query=workflow%3ACI)
[![codecov](https://codecov.io/gh/M0dEx/quincy/graph/badge.svg?token=YRKG8VIGWQ)](https://codecov.io/gh/M0dEx/quincy)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENCE)
[![Matrix](https://img.shields.io/badge/chat-%23quincy:matrix.org-%2346BC99?logo=matrix)](https://matrix.to/#/#quincy:matrix.org)

Quincy is a VPN client and server implementation using the [QUIC](https://en.wikipedia.org/wiki/QUIC) protocol.

## Design
Quincy uses the QUIC protocol implemented by [`quinn`](https://github.com/quinn-rs/quinn) to create an encrypted tunnel between clients and the server.

This tunnel serves two purposes:
- authentication using a reliable bi-directional stream
- data transfer using unreliable datagrams (for lower latency and avoidance of multiple reliability layers)

After a connection is established and the client is authenticated, a TUN interface is spawned using an IP address provided by the server.

When all is set up, a connection task is spawned, which handles IO on the TUN interface and the QUIC connection, effectively relaying packets between them.

The [`tokio`](https://github.com/tokio-rs/tokio) runtime is used to provide an efficient and scalable implementation.

## Supported platforms
- [X] Windows (x86_64), using [Wintun](https://www.wintun.net/)
- [X] Linux (x86_64, aarch64)
- [X] FreeBSD (x86_64, aarch64)
- [X] MacOS (aarch64)

## Installation
Binaries are currently available for Windows, Linux (x86_64) and macOS (aarch64) for every official release.

### Cargo
Using cargo, installation of any published version can be done with a simple command:
```bash
cargo install quincy
```

### Docker
Docker images are available on [Docker Hub](https://hub.docker.com/r/m0dex/quincy) in different flavours:
- `m0dex/quincy:latest`: The latest version of Quincy with pre-quantum cryptography
- `m0dex/quincy:latest-quantum`: The latest version of Quincy with post-quantum cryptography
- `m0dex/quincy:<version>`: A specific version of Quincy with pre-quantum cryptography
- `m0dex/quincy:<version>-quantum`: A specific version of Quincy with post-quantum cryptography

To run the client/server, you need to add a volume with the configuration files and add needed capabilities:
```bash
docker run
  --rm # remove the container after it stops
  --cap-add=NET_ADMIN # needed for creating the TUN interface
  --device=/dev/net/tun # needed for creating the TUN interface
  -p "55555:55555" # server port-forwarding
  -v <configuration directory>:/etc/quincy # directory with the configuration files 
  m0dex/quincy:latest # or any of the other tags
  quincy-server --config-path /etc/quincy/server.toml
```

To add or remove a user to the `users` file, you can run the following command:
```bash
docker run
  --rm # remove the container after it stops
  -it # interactive mode
  -v <configuration directory>:/etc/quincy # directory with the configuration files 
  m0dex/quincy:latest # or any of the other tags
  quincy-users --add /etc/quincy/users
  # quincy-users --delete /etc/quincy/users
```

## Building from sources
As Quincy does not rely upon any non-Rust libraries, the build process is incredibly simple:
```bash
cargo build
```
If you additionally want to build Quincy in release mode with optimizations, add the `--release` switch:
```bash
cargo build --release
```
The resulting binaries can be found in the `target/debug` and `target/release` directories.

## Build features
- `jemalloc`: Uses the jemalloc memory allocator on UNIX systems for improved performance [default: **disabled**]
- `crypto-standard`: Uses the `ring` crate for pre-quantum cryptographic operations [default: **enabled**]
- `crypto-quantum`: Uses post-quantum cryptography for key exchange (`X25519Kyber768Draft00`) [default: **disabled**]
  - requires the `aws-lc-rs` crypto backend, which requires some build dependencies to be installed (Clang/GCC and CMake)
  - the algorithm has not been standardized yet and is not recommended for production use
  - both the client and server have to be compiled with this feature enabled, otherwise the connection will not be established

### Jemalloc
Quincy can optionally use the [jemalloc](https://jemalloc.net/) memory allocator for slightly improved performance.
To enable it, add the `--features jemalloc` switch to the `build`/`install` command:
```bash
cargo build --release --features jemalloc
```

### Post-quantum key-exchange
Quincy can optionally use post-quantum cryptography for key exchange.
To enable it, add the `--features crypto-quantum` switch to the `build`/`install` command:
```bash
cargo build --release --no-default-features --features crypto-quantum
```

## Usage
Quincy is split into 3 binaries:
- `quincy-client`: The VPN client
- `quincy-server`: The VPN server
- `quincy-users`: A utility binary meant for managing the `users` file

### Client
The Quincy client requires a separate configuration file, an example of which can be found in [`examples/client.toml`](examples/client.toml).
The documentation for the client configuration file fields can be found [here](https://docs.rs/quincy/latest/quincy/config/struct.ClientConfig.html).

With the configuration file in place, the client can be started using the following command:
```bash
quincy-client --config-path examples/client.toml
```

Routes are set by default to the address and netmask received from the server.
Any additional routes now have to be set up manually.

### Server
The Quincy server requires a separate configuration file, an example of which can be found in [`examples/server.toml`](examples/server.toml).
The documentation for the server configuration file fields can be found [here](https://docs.rs/quincy/latest/quincy/config/struct.ServerConfig.html).

With the configuration file in place, the client can be started using the following command:
```bash
quincy-server --config-path examples/server.toml
```

**Please keep in mind that the pre-generated certificate in [`examples/cert/server_cert.pem`](examples/cert/server_cert.pem)
is self-signed and uses the hostname `quincy`. It should be replaced with a proper certificate, 
which can be generated using the instructions in the [Certificate management](#certificate-management) section.**

### Users
The users utility can be used to manage entries in the `users` file.
The `users` file contains usernames and password hashes in a format similar to `/etc/shadow` (example can be found in [`examples/users`](examples/users)).

The following command can be used to add users to this file:
```bash
quincy-users --add examples/users
```

The prompts will look something like this:
```
Enter the username: test
Enter password for user 'test':
Confirm password for user 'test':
```

A similar command can be used to remove users from the file:
```bash
quincy-users --remove examples/users
```

The prompt will again look something like this:
```
Enter the username: test
```

## Certificate management
There are a couple of options when it comes to setting up the certificates used by Quincy.

### Certificate signed by a trusted CA
This is the *proper* way to manage certificates with Quincy.

You can either request/pay for a certificate from a service with a globally trusted CA (Let's Encrypt, GoDaddy, ...) or generate your own certificate authority and then sign an end-point certificate.

If you have a certificate signed by a globally trusted CA, you can simply add it to the server configuration file and run Quincy. The client will trust the certificate, as the signing certificate is most likely in the system's trusted root certificate store.

If you have a certificate signed by your own (self-signed) CA, follow the steps above and additionally add your CA certificate to the client configuration file.

You can use [mkcert](https://github.com/FiloSottile/mkcert) for generating your own CA certificate and using it to sign an end-point certificate.

### Self-signed certificate
This is an easier set up that might be used by home-lab administrators or for local testing.

The steps to generate a self-signed certificate that can be used with Quincy:
1) Generate a private key (I use ECC for my certificates, but RSA is fine)
```
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:secp384r1 -out <your_certificate_key_file>
```

2) Generate a certificate request
```bash
openssl req -new -key <your_certificate_key_file> -out <your_certificate_request_file>
```
```
You are about to be asked to enter information that will be incorporated
into your certificate request.
What you are about to enter is what is called a Distinguished Name or a DN.
There are quite a few fields but you can leave some blank
For some fields there will be a default value,
If you enter '.', the field will be left blank.
-----
Country Name (2 letter code) [AU]:XX
State or Province Name (full name) [Some-State]:.
Locality Name (eg, city) []:.
Organization Name (eg, company) [Internet Widgits Pty Ltd]:.
Organizational Unit Name (eg, section) []:.
Common Name (e.g. server FQDN or YOUR name) []:quincy
Email Address []:

Please enter the following 'extra' attributes
to be sent with your certificate request
A challenge password []:
An optional company name []:
```

3) Create a v3 extensions configuration file with the following content (fill out the `subjectAltName` field with the hostname/IP the clients will be connecting to)
```
subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid:always,issuer:always
basicConstraints       = CA:FALSE
keyUsage               = digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment, keyAgreement, keyCertSign
subjectAltName         = DNS:quincy
issuerAltName          = issuer:copy
```

4) Sign your certificate
```bash
openssl x509 -req -in cert.csr -signkey <your_certificate_key_file> -out <your_certificate_file> -days 365 -sha256 -extfile <your_v3_ext_file>
```

5) Add the certificate to both your server and client configuration files.

**Server**
```toml
# Path to the certificate used for TLS
certificate_file = "server_cert.pem"
# Path to the certificate key used for TLS
certificate_key_file = "server_key.pem"
```

**Client**
```toml
[authentication]
# A list of trusted certificates the server can use or have its certificate signed by
trusted_certificates = ["server_cert.pem"]
```
