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
    fn short_name(&self) -> &str { "UDP" }
    fn full_name(&self) -> &str { "User Datagram Protocol" }

    fn dissect(&self, data : &[u8]) -> Result {
        let source = unsigned::<u16, NetworkEndian>(&data[0..2]);
        let dest = unsigned::<u16, NetworkEndian>(&data[2..4]);
        let length = unsigned::<u16, NetworkEndian>(&data[4..6]);
        let checksum = unsigned::<u16, NetworkEndian>(&data[6..8]);

        let protocol = match (&source,&dest) {
            (&Ok(s), &Ok(d)) => RawBytes::boxed("UNKNOWN", &format!["UDP: {} -> {}", s, d]),
            _ => RawBytes::unknown_protocol("unknown UDP protocol or UDP error"),
        };

        let values = vec![
                ("Source port", source.and_then(Val::unsigned)),
                ("Destination port", dest.and_then(Val::unsigned)),
                ("Length", length.and_then(Val::unsigned)),
                ("Checksum", checksum.and_then(Val::unsigned)),
                ("Data", protocol.dissect(&data[8..])),
            ]
            .into_iter()
            .map(|(k,v)| (k.to_string(), v))
            .collect()
            ;

        Ok(Val::Subpacket(values))
    }
}
