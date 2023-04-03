use anyhow::Result;
use dashmap::DashSet;
use ipnet::{Ipv4AddrRange, Ipv4Net};
use std::net::Ipv4Addr;

/// Represents a pool of addresses from which addresses can be requested and released.
pub struct AddressPool {
    network: Ipv4Net,
    used_addresses: DashSet<Ipv4Addr>,
}

impl AddressPool {
    /// Creates a new instance of an `AddressPool`.
    ///
    /// ### Arguments
    /// - `address_server` - the base address of this pool
    /// - `address_mask` - the mask defining the subnet contained by this pool
    pub fn new(address_server: Ipv4Addr, address_mask: Ipv4Addr) -> Result<Self> {
        let network = Ipv4Net::with_netmask(address_server, address_mask)?;
        let used = DashSet::from_iter(vec![network.network(), network.addr(), network.broadcast()]);

        Ok(Self {
            network,
            used_addresses: used,
        })
    }

    /// Returns the next available address if such an address exists.
    pub fn next_available_address(&self) -> Option<Ipv4Net> {
        let mut range = Ipv4AddrRange::new(self.network.network(), self.network.broadcast());

        range
            .find(|address| !self.used_addresses.contains(address))
            .map(|address| {
                self.used_addresses.insert(address);
                Ipv4Net::with_netmask(address, self.network.netmask())
                    .expect("Netmask will always be valid")
            })
    }

    /// Releases the specified address so it can be used in further requests.
    ///
    /// ### Arguments
    /// - `address` - the address to release
    pub fn release_address(&self, address: Ipv4Addr) {
        self.used_addresses.remove(&address);
    }
}

#[cfg(test)]
mod tests {
    use crate::address_pool::AddressPool;
    use ipnet::Ipv4Net;
    use std::net::Ipv4Addr;

    #[test]
    fn test_address_pool() {
        let pool = AddressPool::new(
            Ipv4Addr::new(10, 0, 0, 1),
            Ipv4Addr::new(255, 255, 255, 252),
        )
        .unwrap();

        assert_eq!(
            pool.next_available_address().unwrap(),
            Ipv4Net::with_netmask(
                Ipv4Addr::new(10, 0, 0, 2),
                Ipv4Addr::new(255, 255, 255, 252)
            )
            .unwrap()
        );
        assert_eq!(pool.next_available_address(), None);
        pool.release_address(Ipv4Addr::new(10, 0, 0, 2));
        assert_eq!(
            pool.next_available_address().unwrap(),
            Ipv4Net::with_netmask(
                Ipv4Addr::new(10, 0, 0, 2),
                Ipv4Addr::new(255, 255, 255, 252)
            )
            .unwrap()
        );
    }
}
