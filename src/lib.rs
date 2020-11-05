/*! Network Time Protocol (NTP)

# Example
Shows how to use the ntp library to fetch the current time according
to the requested ntp server.

```rust
extern crate chrono;
extern crate ntp;

use chrono::TimeZone;

fn main() {
    let address = "0.pool.ntp.org:123";
    let response = ntp::request(address).unwrap();
    let unix_time = ntp::unix_time::Instant::from(response.transmit_timestamp);
    let local_time = chrono::Local.timestamp(unix_time.secs(), unix_time.subsec_nanos() as _);
    println!("{}", local_time);
}
```
*/

#![recursion_limit = "1024"]

#[macro_use]
extern crate custom_derive;
#[macro_use]
extern crate conv;
#[macro_use]
extern crate log;
extern crate byteorder;

use protocol::{ReadBytes, ConstPackedSizeBytes, WriteBytes};
use std::{io, net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr}};
use std::net::{ToSocketAddrs, UdpSocket};
use std::time::Duration;

pub mod protocol;
pub mod unix_time;

/// Send a blocking request to an ntp server with a hardcoded 5 second timeout.
///
///   `addr` can be any valid socket address
///
/// Returns an error if the server cannot be reached or the response is invalid.
///
/// If `addr` resolves to multiple IP addresses, they are tried in order until
/// a request succeeds.
/// If all requests fail, the last error is returned.
pub fn request<A: ToSocketAddrs>(addr: A) -> io::Result<protocol::Packet> {
    let mut last_err = None;

    for addr in addr.to_socket_addrs()? {
        let bind_addr = match addr {
            SocketAddr::V4(_) => Ipv4Addr::UNSPECIFIED.into(),
            SocketAddr::V6(_) => Ipv6Addr::UNSPECIFIED.into(),
        };

        match request_with_bind_addr(addr, bind_addr) {
            Ok(packet) => return Ok(packet),
            Err(err) => last_err = Some(err),
        }
    }

    match last_err {
        Some(err) => Err(err),
        None => Err(io::Error::new(io::ErrorKind::NotFound, format!("Address resolved to empty")))
    }
}

/// Send a blocking request to an ntp server with a hardcoded 5 second timeout.
///
///   `addr` can be any valid socket address
///   `bind_addr` specifies the client IP to send packets from
///
/// Returns an error if the server cannot be reached or the response is invalid.
/// This will also fail when `addr` and `bind_addr` are not of the same IP version.
// **TODO**: remove hardcoded timeout
pub fn request_with_bind_addr(addr: SocketAddr, bind_addr: IpAddr) -> io::Result<protocol::Packet> {
    // Create a packet for requesting from an NTP server as a client.
    let mut packet = {
        let leap_indicator = protocol::LeapIndicator::default();
        let version = protocol::Version::V4;
        let mode = protocol::Mode::Client;
        let poll = 0;
        let precision = 0;
        let root_delay = protocol::ShortFormat::default();
        let root_dispersion = protocol::ShortFormat::default();
        let transmit_timestamp = unix_time::Instant::now().into();
        let stratum = protocol::Stratum::UNSPECIFIED;
        let src = protocol::PrimarySource::Null;
        let reference_id = protocol::ReferenceIdentifier::PrimarySource(src);
        let reference_timestamp = protocol::TimestampFormat::default();
        let receive_timestamp = protocol::TimestampFormat::default();
        let origin_timestamp = protocol::TimestampFormat::default();
        protocol::Packet {
            leap_indicator,
            version,
            mode,
            stratum,
            poll,
            precision,
            root_delay,
            root_dispersion,
            reference_id,
            reference_timestamp,
            origin_timestamp,
            receive_timestamp,
            transmit_timestamp,
        }
    };

    // Write the packet to a slice of bytes.
    let mut bytes = [0u8; protocol::Packet::PACKED_SIZE_BYTES];
    (&mut bytes[..]).write_bytes(&packet)?;

    // Create the socket from which we will send the packet.
    let sock = UdpSocket::bind(SocketAddr::new(bind_addr, 0))?;
    sock.set_read_timeout(Some(Duration::from_secs(5)))?;
    sock.set_write_timeout(Some(Duration::from_secs(5)))?;

    // Send the data.
    let sz = sock.send_to(&bytes, addr)?;
    debug!("{:?}", sock.local_addr());
    debug!("sent: {}", sz);

    // Receive the response.
    let res = sock.recv(&mut bytes[..])?;
    debug!("recv: {:?}", res);
    debug!("{:?}", &bytes[..]);

    // Read the received packet from the response.
    packet = (&bytes[..]).read_bytes()?;
    Ok(packet)
}

#[test]
fn test_request_ntp_org() {
    let res = request("0.pool.ntp.org:123");
    let _ = res.expect("Failed to get a ntp packet from ntp.org");
}

#[test]
fn test_request_google() {
    let res = request("time.google.com:123");
    let _ = res.expect("Failed to get a ntp packet from time.google.com");
}
