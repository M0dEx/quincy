# Quincy
[![Crates.io](https://img.shields.io/crates/v/quincy.svg)](https://crates.io/crates/quincy)
[![Documentation](https://docs.rs/quincy/badge.svg)](https://docs.rs/quincy/)
[![Build status](https://github.com/M0dEx/quincy/workflows/CI/badge.svg)](https://github.com/M0dEx/quincy/actions?query=workflow%3ACI)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENCE)
[![Matrix](https://img.shields.io/badge/chat-%23quincy:matrix.org-%2346BC99?logo=matrix)](https://matrix.to/#/#quincy:matrix.org)

Quincy is a VPN client and server implementation using the [QUIC](https://en.wikipedia.org/wiki/QUIC) protocol.

## Design
Quincy uses the QUIC protocol implemented by [`quinn`](https://github.com/quinn-rs/quinn) to create an encrypted tunnnel between clients and the server.

This tunnel serves two purposes:
- authentication using a reliable bidirectional stream
- data transfer using unreliable datagrams (for lower latency and avoidance of multiple reliability layers)

After a connection is established and the client is authenticated, a TUN interface is spawned using an IP address provided by the server.

When all is set up, multiple tasks are spawned (on both the client and the server), with 2 of them being the most important:
- authentication task - responsible for sending the session token in the specified interval
- connection task - responsible for relaying packets between the TUN interface and the QUIC tunnel

These tasks run in parallel using the [`tokio`](https://github.com/tokio-rs/tokio) runtime for added efficiency and throughput.

## Supported platforms
- [ ] Windows
- [X] Linux
- [X] MacOS

## Installation
Using cargo, installation of published version can be done with a simple command:
```bash
$ cargo install quincy
```

## Building from sources
As Quincy does not rely upon any non-Rust libraries, the build process is incredibly simple:
```bash
$ cargo build
```
If you additionally want to build Quincy in release mode with optimizations, add the `--release` switch:
```bash
$ cargo build --release
```
The resulting binaries can be found in the `target/debug` and `target/release` directories.

## Usage
Quincy is split into 3 binaries: 
- `client`: The VPN client
- `server`: The VPN server
- `users`: A utility binary meant for managing the `users` file

### Client
The Quincy client requires a separate configuration file, an example of which can be found in `examples/client.toml`:
```toml
# The address and port the Quincy server is available at
connection_string = "quincy:55555"

[authentication]
# The username used for authentication
username = "test"
# The password used for authentication
password = "test"
# A list of trusted certificates the server can use or have its certificate signed by
trusted_certificates = ["examples/cert/ca_cert.pem"]

[connection]
# The MTU used by the QUIC tunnel and the spawned TUN interface
mtu = 1400

[log]
# The log level
level = "info"
```

With the configuration file in place, the client can be started using the following command:
```bash
$ quincy-client --config-path examples/client.toml
```

Routes are set up by default on some systems (Linux) and not set-up at all on others (MacOS).

### Server
The Quincy server requires a separate configuration file, an example of which can be found in `examples/server.toml`:
```toml
# Section representing tunnel configuration
[tunnels.tun0]
# Name of the tunnel (currently not used as the name of the interface)
name = "tun0"
# Path to the certificate used for TLS
certificate_file = "examples/cert/server_cert.pem"
# Path to the certificate key used for TLS
certificate_key_file = "examples/cert/server_key.pem"
# The address of the tunnel endpoint and base address of the address pool available to clients
address_tunnel = "10.0.0.1"
# Netmask used to generate the address pool available to clients
address_mask = "255.255.255.0"
# Path to the file containing user credentials
users_file = "examples/users"

[connection]
# The MTU used by the QUIC tunnel and the spawned TUN interface
mtu = 1400

[log]
# The log level
level = "info"
```

With the configuration file in place, the client can be started using the following command:
```bash
$ quincy-server --config-path examples/server.toml
```

### Users
The users utility can be used to manage entries in the `users` file. 
The `users` file contains usernames and password hashes in the following format (`examples/users`):
```
test:$argon2id$v=19$m=19456,t=2,p=1$S9rMLOcz/dnYN4cnyc/TJg$ES0p+DErLfcWoUJ2tvZlxZSSIGYNUEe0ZpKBDz7MOj0
```

The following command can be used to add users to this file:
```bash
$ quincy-users --add examples/users
```

The prompts will look something like this:
```
Enter the username: test 
Enter password for user 'test': 
Confirm password for user 'test': 
```

A similar command can be used to remove users from the file:
```bash
$ quincy-users --remove examples/users
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
$ openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:secp384r1 -out <your_certificate_key_file>
```

2) Generate a certificate request (you can fill out the fields with whatever information you want)
```
$ openssl req -new -key <your_certificate_key_file> -out <your_certificate_request_file>       
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
```
$ openssl x509 -req -in cert.csr -signkey <your_certificate_key_file> -out <your_certificate_file> -days 365 -sha256 -extfile <your_v3_ext_file>
```

You then have to add the certificate to both you server and your client configuration files.

### Configuration reference
**Server**
```toml
[tunnels.<tunnel_name>]
# Path to the certificate used for TLS
certificate_file = "server_cert.pem"
# Path to the certificate key used for TLS
certificate_key_file = "server_key.pem"
```


**Client**
```toml
[authentication]
# A list of trusted certificates the server can use or have its certificate signed by
trusted_certificates = ["ca_cert.pem"]
```
