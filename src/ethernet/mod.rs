/*
 * Copyright 2015-2016 Jonathan Anderson
 *
 * Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
 * http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
 * http://opensource.org/licenses/MIT>, at your option. This file may not be
 * copied, modified, or distributed except according to those terms.
 */

//! Dissection of Ethernet (IEEE 802.3) frames.

use {
    Error,
    NamedValue,
    Protocol,
    RawBytes,
    Result,
    Val,
    ip,
    unsigned,
};

use byteorder::*;


/// The IEEE 802.3 Ethernet protocol.
pub struct Ethernet;


/// Parse a six-byte MAC address, which can be encoded as, e.g., ff:ff:ff:ff:ff:ff.
pub fn mac_address(raw: &[u8]) -> Result<Val> {
    if raw.len() != 6 {
        return Error::inval(format!["MAC address should have 6 B, not {}", raw.len()]);
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
    fn short_name(&self) -> &'static str { "Ethernet" }
    fn full_name(&self) -> &'static str { "IEEE 802.3 Ethernet" }
    fn dissect(&self, data: &[u8]) -> Result {
        if data.len() < 14 {
            return Error::underflow(14, data.len(), "Ethernet frame")
        }

        let mut values:Vec<NamedValue> = vec![];
        values.push(("Destination", mac_address(&data[0..6])));
        values.push(("Source", mac_address(&data[6..12])));

        // The type/length field might be either a type or a length.
        let tlen = unsigned::<u16,NetworkEndian>(&data[12..14]);
        let remainder = &data[14..];

        match tlen {
            Ok(i) if i <= 1500 => {
                values.push(("Length", Val::base10(i)));

                let index = i as usize;
                let packet_data = remainder[..index].to_vec();
                let padding = remainder[index..].to_vec();
                values.push(("Data", Ok(Val::Bytes(packet_data))));
                values.push(("Padding", Ok(Val::Bytes(padding))));
            },

            Ok(i) => {
                let protocol: Box<Protocol> = match i {
                    // TODO: use the simple 'box' syntax once it hits stable
                    0x800 => Box::new(ip::IPv4),
                    0x806 => RawBytes::boxed("ARP", "Address Resolution Protocol"),
                    0x8138 => RawBytes::boxed("IPX", "Internetwork Packet Exchange"),
                    0x86dd => RawBytes::boxed("IPv6", "Internet Protocol version 6"),

                    0x9000 => Box::new(testproto::TestProtocol),

                    _ => RawBytes::unknown_protocol("Unknown Ethertype"),
                };

                values.push(("Type", Ok(Val::Enum(i as u64, protocol.short_name()))));
                values.push((protocol.full_name(), protocol.dissect(remainder)));
            },
            Err(e) => {
                values.push(("Type/length", Err(e)));
            },
        };

        Ok(Val::Subpacket(values))
    }
}

mod testproto;
