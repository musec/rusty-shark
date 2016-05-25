/*
 * Copyright 2015 Jonathan Anderson
 *
 * Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
 * http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
 * http://opensource.org/licenses/MIT>, at your option. This file may not be
 * copied, modified, or distributed except according to those terms.
 */

//! Dissection of Ethernet (IEEE 802.3) frames.

use {
    Endianness,
    Error,
    NamedValue,
    Protocol,
    RawBytes,
    Result,
    Val,
    ip,
    promising_future,
    unsigned,
};


/// The IEEE 802.3 Ethernet protocol.
pub struct Ethernet;


/// Parse a six-byte MAC address, which can be encoded as, e.g., ff:ff:ff:ff:ff:ff.
pub fn mac_address(raw: &[u8]) -> Result<Val> {
    if raw.len() != 6 {
        return Err(Error::InvalidData(format!["MAC address should have 6 B, not {}",
                                              raw.len()]));
    }

    let encoded = raw
                  .iter()
                  .map(|b| format!["{:02x}", b])
                  .collect::<Vec<String>>()
                  .join(":")
                  ;


    Ok(Val::Address { bytes: raw.to_vec(), encoded: encoded })
}


impl Protocol for Ethernet {
    fn short_name(&self) -> &str { "Ethernet" }
    fn full_name(&self) -> &str { "IEEE 802.3 Ethernet" }
    fn dissect(&self, data: &[u8]) -> Result {
        if data.len() < 14 {
            return Err(Error::Underflow { expected: 14, have: data.len(),
                message: "An Ethernet frame must be at least 14 B".to_string() })
        }

        // Process fields asynchronously.
        let (future, promise) = promising_future::future_promise();

        // TODO: actually process asynchronously!
        promise.set(dissect_fields(data));

        Ok(Val::Protocol(future))
    }
}


fn dissect_fields(data: &[u8]) -> Vec<NamedValue> {
    let mut values:Vec<NamedValue> = vec![];
    values.push(("Destination".to_string(), mac_address(&data[0..6])));
    values.push(("Source".to_string(), mac_address(&data[6..12])));

    // The type/length field might be either a type or a length.
    let tlen = unsigned(&data[12..14], Endianness::BigEndian);
    let remainder = &data[14..];

    match tlen {
        Ok(i) if i <= 1500 => {
            values.push(("Length".to_string(), Ok(Val::Unsigned(i))));
        },

        Ok(i) => {
            let protocol: Box<Protocol> = match i {
                // TODO: use the simple 'box' syntax once it hits stable
                0x800 => Box::new(ip::IPv4),
                0x806 => RawBytes::boxed("ARP", "Address Resolution Protocol"),
                0x8138 => RawBytes::boxed("IPX", "Internetwork Packet Exchange"),
                0x86dd => RawBytes::boxed("IPv6", "Internet Protocol version 6"),

                _ => Box::new(RawBytes::unknown_protocol(&format!["0x{:x}", i])),
            };

            let protoname = protocol.short_name().to_string();
            let description = protocol.full_name().to_string();

            values.push(("Type".to_string(), Ok(Val::String(protoname))));
            values.push((description, protocol.dissect(remainder)));
        },
        Err(e) => {
            values.push(("Type/length".to_string(), Err(e)));
        },
    };

    values
}


