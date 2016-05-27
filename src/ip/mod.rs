/*
 * Copyright 2015 Jonathan Anderson
 *
 * Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
 * http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
 * http://opensource.org/licenses/MIT>, at your option. This file may not be
 * copied, modified, or distributed except according to those terms.
 */

//! Dissection of Internet Protocol (IP) packets.
//!
//! This module will eventually contain dissectors for protocols in the IP suite,
//! e.g., `rshark::ip::icmp` and `rshark::ip::tcp`.
//! For now, it only handles IP headers.
//!
//! See [RFC 791](https://tools.ietf.org/html/rfc791).

use {
    Error,
    NamedValue,
    Protocol,
    RawBytes,
    Result,
    Val,
    unsigned,
};

use byteorder::*;


pub struct IPv4;

impl Protocol for IPv4 {
    fn short_name(&self) -> &'static str { "IP" }
    fn full_name(&self) -> &'static str { "Internet Protocol version 4" }

    fn dissect(&self, data : &[u8]) -> Result {
        if data.len() < 20 {
            return Error::underflow(20, data.len(), "IP packet")
        }

        let mut values:Vec<NamedValue> = vec![];

        // IP version (should be "4")
        let version = data[0] >> 4;
        values.push(("Version", Val::base10(version)));

        // Internet Header Length (IHL): number of 32b words in header
        let words = data[0] & 0x0f;
        values.push(("IHL", Val::base10(words)));

        // Differentiated Services Code Point (DSCP): RFC 2474
        let dscp = data[1] >> 2;
        values.push(("DSCP", Val::base16(dscp)));

        // Explicit Congestion Notification (ECN): RFC 3168
        let ecn = data[1] & 0x03;
        values.push(("ECN", Val::base2(ecn)));

        // Total length (including header)
        let length = unsigned::<u16, NetworkEndian>(&data[2..4]);
        values.push(("Length", length.and_then(Val::base10)));

        // Identification (of datagraph fragments): RFC 6864
        values.push(("Identification", Val::base10(data[8])));

        // Protocol number (assigned by IANA)
        let proto_id = data[9] as u64;
        let protocol:Box<Protocol> = match proto_id {
            // TODO: TCP, etc.
            17 => Box::new(udp::UDP),
            _ => RawBytes::unknown_protocol("Unknown IP protocol"),
        };
        values.push(("Protocol", Ok(Val::Enum(proto_id, protocol.short_name()))));

        // Header checksum
        values.push(("Checksum", Ok(Val::Bytes(data[10..12].to_vec()))));

        // Source and destination addresses
        let source = &data[12..16];
        values.push(("Source", Ok(Val::Address {
            bytes: source.to_vec(),
            encoded: source.iter().map(|b| b.to_string()).collect::<Vec<_>>().join("."),
        })));

        let dest = &data[16..20];
        values.push(("Destination", Ok(Val::Address {
            bytes: dest.to_vec(),
            encoded: dest.iter().map(|b| b.to_string()).collect::<Vec<_>>().join("."),
        })));

        // Parse the remainder according to the specified protocol.
        let remainder = &data[20..];
        values.push(("Protocol Data", protocol.dissect(remainder)));

        Ok(Val::Subpacket(values))
    }
}

pub mod udp;
