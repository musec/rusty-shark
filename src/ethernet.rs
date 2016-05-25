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

                    0x9000 => Box::new(TestProtocol),

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

        Ok(Val::Subpacket(values))
    }
}


/// Testing protocol from the Xerox Blue Book.
///
/// A test packet can contain data to forward to another Ethernet address and/or
/// a reply to a previous test packet. See http://www.mit.edu/~jhawk/ctp.pdf for details.
pub struct TestProtocol;

enum TestMessage<'a> {
    Reply { receipt_number: Result<u64>, data: &'a [u8] },
    ForwardData { dest: Result<Val>, message: Result<Box<TestMessage<'a>>> },
}

impl Protocol for TestProtocol {
    fn short_name(&self) -> &str { "Loopback" }
    fn full_name(&self) -> &str { "Ethernet Configuration Testing Protocol" }
    fn dissect(&self, data: &[u8]) -> Result {
        let mut values:Vec<NamedValue> = vec![];

        let skip_count = unsigned(&data[0..2], Endianness::BigEndian);
        values.push(("Skip count".to_string(), skip_count.map(Val::Unsigned)));

        let top_message =
            TestMessage::parse(&data[2..])
                        .map(TestMessage::as_val)
                        .unwrap_or_else(|e| ("Error".to_string(), Err(e)))
                        ;

        values.push(top_message);

        Ok(Val::Subpacket(values))
    }
}

impl <'a> TestMessage <'a> {
    fn name(&self) -> &str {
        match self {
            &TestMessage::Reply{ .. } => "Reply Message",
            &TestMessage::ForwardData{ .. } => "Forward Data Message",
        }
    }

    fn as_val(self) -> NamedValue {
        let name = self.name().to_string();
        let val = match self {
            TestMessage::Reply{ receipt_number, data } =>
                vec![
                    ("Function Code".to_string(), Ok(Val::Unsigned(1))),
                    ("Receipt Number".to_string(), receipt_number.map(Val::Unsigned)),
                    ("Data".to_string(), Ok(Val::Bytes(data.to_vec()))),
                ],

            TestMessage::ForwardData{ dest, message } => {
                let data = match message.map(|b| (*b).as_val()) {
                    Ok((k,v)) => Ok(Val::Subpacket(vec![(k,v)])),
                    Err(e) => Err(e),
                };

                vec![
                    ("Function Code".to_string(), Ok(Val::Unsigned(2))),
                    ("Forward Address".to_string(), dest),
                    ("Data".to_string(), data),
                ]
            },
        };

        (name, Ok(Val::Subpacket(val)))
    }

    fn parse(data: &[u8]) -> Result<TestMessage> {
        let function_code = unsigned(&data[0..2], Endianness::LittleEndian);
        match function_code {
            Ok(1) => Ok({
                let receipt_number = unsigned(&data[2..4], Endianness::LittleEndian);

                TestMessage::Reply{
                    receipt_number: receipt_number,
                    data: &data[4..],
                }
            }),

            Ok(2) => Ok({
                TestMessage::ForwardData{
                    dest: mac_address(&data[2..8]),
                    message: TestMessage::parse(&data[8..]).map(Box::new),
                }
            }),

            Ok(x) => Err(Error::InvalidData(format!["invalid function code: {}", x])),
            Err(e) => Err(e),
        }
    }
}
