use anyhow::{anyhow, Context, Result};
use ipnet::IpNet;
use std::net::IpAddr;
use std::process::Command;

#[cfg(target_os = "linux")]
const ROUTE_ADD_COMMAND: &str = "route add -net {network} netmask {netmask} gw {gateway}";
#[cfg(target_os = "windows")]
const ROUTE_ADD_COMMAND: &str = "route add {network} mask {netmask} {gateway}";
#[cfg(target_os = "macos")]
const ROUTE_ADD_COMMAND: &str = "route -n add -net {network} -netmask {netmask} {gateway}";
#[cfg(target_os = "freebsd")]
const ROUTE_ADD_COMMAND: &str = "route add -net {network} -netmask {netmask} {gateway}";

/// Adds a route to the routing table.
///
/// ### Arguments
/// - `network` - the network to add the route for
/// - `gateway` - the gateway to use for the route
pub fn add_route(network: &IpNet, gateway: &IpAddr) -> Result<()> {
    let route_add_command = ROUTE_ADD_COMMAND
        .replace("{network}", &network.addr().to_string())
        .replace("{netmask}", &network.netmask().to_string())
        .replace("{gateway}", &gateway.to_string());

    let route_command_split = route_add_command.split(" ").collect::<Vec<_>>();

    let route_program = route_command_split[0];
    let route_args = &route_command_split[1..];

    let output = Command::new(route_program)
        .args(route_args)
        .output()
        .context("failed to execute route command")?;

    if !output.status.success() {
        return Err(anyhow!(
            "failed to add route: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }

    Ok(())
}
