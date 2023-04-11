# Quincy
[![Crates.io](https://img.shields.io/crates/v/quincy.svg)](https://crates.io/crates/quincy)
[![Documentation](https://docs.rs/quincy/badge.svg)](https://docs.rs/quincy/)
[![Build status](https://github.com/M0dEx/quincy/workflows/CI/badge.svg)](https://github.com/M0dEx/quincy/actions?query=workflow%3ACI)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENCE)

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
$ client --config-path examples/client.toml
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
$ server --config-path examples/server.toml
```

### Users
The users utility can be used to manage entries the `users` file. 
The `users` file contains usernames and password hashes in the following format (`examples/users`):
```
test:$argon2id$v=19$m=19456,t=2,p=1$S9rMLOcz/dnYN4cnyc/TJg$ES0p+DErLfcWoUJ2tvZlxZSSIGYNUEe0ZpKBDz7MOj0
```

The following command can be used to add users to this file:
```bash
$ users --add examples/users
```

The prompts will look something like this:
```
Enter the username: test 
Enter password for user 'test': 
Confirm password for user 'test': 
```

A similar command can be used to remove users from the file:
```bash
$ users --remove examples/users
```

The prompt will again look something like this:
```
Enter the username: test 
```
