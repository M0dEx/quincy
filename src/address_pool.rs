use anyhow::Result;
use dashmap::DashSet;
use ipnet::{Ipv4AddrRange, Ipv4Net};
use std::net::Ipv4Addr;

pub struct AddressPool {
    network: Ipv4Net,
    used_addresses: DashSet<Ipv4Addr>,
}

impl AddressPool {
    pub fn new(address_server: Ipv4Addr, address_mask: Ipv4Addr) -> Result<Self> {
        let network = Ipv4Net::with_netmask(address_server, address_mask)?;
        let used = DashSet::from_iter(vec![network.network(), network.broadcast()]);

        Ok(Self {
            network,
            used_addresses: used,
        })
    }

    pub fn next_available_address(&self) -> Option<Ipv4Addr> {
        let range = Ipv4AddrRange::new(self.network.network(), self.network.broadcast());

        range
            .take_while(|address| !self.used_addresses.contains(address))
            .next()
            .map(|address| {
                self.used_addresses.insert(address);
                address
            })
    }

    pub fn release_address(&self, address: Ipv4Addr) {
        self.used_addresses.remove(&address);
    }
}
