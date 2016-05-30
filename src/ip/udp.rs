/*
 * Copyright 2016 Jonathan Anderson
 *
 * Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
 * http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
 * http://opensource.org/licenses/MIT>, at your option. This file may not be
 * copied, modified, or distributed except according to those terms.
 */

//! Dissection of User Datagram Protocol (UDP) packets.
//!
//! See [RFC 768](https://tools.ietf.org/html/rfc768).

use {
    Protocol,
    RawBytes,
    Result,
    Val,
    unsigned,
};

use byteorder::NetworkEndian;


/// Parser for the User Datagram Protocol (UDP).
pub struct UDP;

impl Protocol for UDP {
    fn short_name(&self) -> &'static str { "UDP" }
    fn full_name(&self) -> &'static str { "User Datagram Protocol" }

    fn dissect(&self, data : &[u8]) -> Result {
        let source = unsigned::<u16, NetworkEndian>(&data[0..2]);
        let dest = unsigned::<u16, NetworkEndian>(&data[2..4]);
        let length = unsigned::<u16, NetworkEndian>(&data[4..6]);
        let checksum = unsigned::<u16, NetworkEndian>(&data[6..8]);

        let protocol:Box<Protocol> = match (&source,&dest) {
            (&Ok(s), &Ok(d)) => protocol(s, d),
            _ => RawBytes::unknown_protocol("UDP error"),
        };

        let values = vec![
                ("Source port", source.and_then(Val::base10)),
                ("Destination port", dest.and_then(Val::base10)),
                ("Length", length.and_then(Val::base10)),
                ("Checksum", checksum.and_then(Val::base16)),
                ("Data", protocol.dissect(&data[8..])),
            ]
            ;

        Ok(Val::Subpacket(values))
    }
}


/// Find the UDP protocol that uses given source and destination ports.
pub fn protocol(source_port: u16, dest_port: u16) -> Box<Protocol> {
    match (source_port, dest_port) {
        (_, _) => RawBytes::boxed("UNKNOWN", "unknown UDP protocol"),
    }
}
