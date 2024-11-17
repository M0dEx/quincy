FROM rust:alpine3.20 AS builder

# Install pre-requisites
RUN apk add build-base gcompat jemalloc-dev

# Create a new directory for our application
WORKDIR /tmp/quincy-build

# Copy the source code into the container
COPY src ./src
COPY Cargo.toml Cargo.lock ./

# Build the application
ARG FEATURES="crypto-standard,jemalloc"
RUN cargo build --release --no-default-features --features "${FEATURES}"

FROM alpine:3.20

# Create needed directories
RUN mkdir -p /etc/quincy

# Install glibc
RUN apk add gcompat jemalloc libcap-setcap

# Copy the binary from the builder stage
COPY --from=builder /tmp/quincy-build/target/release/quincy-client /tmp/quincy-build/target/release/quincy-server /tmp/quincy-build/target/release/quincy-users /usr/local/bin/

# Add required capability to executable
RUN setcap \
    'cap_net_admin=+ep cap_net_bind_service=+ep' /usr/local/bin/quincy-client \
    'cap_net_admin=+ep cap_net_bind_service=+ep' /usr/local/bin/quincy-server

# Run under a non-root account
RUN addgroup -S quincy && adduser -S quincy -G quincy
USER quincy

# Set the working directory
WORKDIR /usr/srv/quincy
