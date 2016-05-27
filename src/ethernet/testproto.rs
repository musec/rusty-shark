/*
 * Copyright 2015-2016 Jonathan Anderson
 *
 * Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
 * http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
 * http://opensource.org/licenses/MIT>, at your option. This file may not be
 * copied, modified, or distributed except according to those terms.
 */

//! Dissection of the test protocol from the Xerox Blue Book (but not IEEE 802.3).

use {
    Error,
    NamedValue,
    Protocol,
    Result,
    Val,
    ethernet,
    unsigned,
};

use byteorder::*;


/// Testing protocol from the Xerox Blue Book.
///
/// A test packet can contain data to forward to another Ethernet address and/or
/// a reply to a previous test packet. See http://www.mit.edu/~jhawk/ctp.pdf for details.
pub struct TestProtocol;

enum TestMessage<'a> {
    Reply { receipt_number: Result<u16>, data: &'a [u8] },
    ForwardData { dest: Result<Val>, message: Result<Box<TestMessage<'a>>> },
}

impl Protocol for TestProtocol {
    fn short_name(&self) -> &'static str { "Loopback" }
    fn full_name(&self) -> &'static str { "Ethernet Configuration Testing Protocol" }
    fn dissect(&self, data: &[u8]) -> Result {
        let mut values:Vec<NamedValue> = vec![];

        let skip_count = unsigned::<u64, NetworkEndian>(&data[0..2]);
        values.push(("Skip count", skip_count.and_then(Val::base10)));

        let top_message =
            TestMessage::parse(&data[2..])
                        .map(TestMessage::as_val)
                        .unwrap_or_else(|e| ("Error", Err(e)))
                        ;

        values.push(top_message);

        Ok(Val::Subpacket(values))
    }
}

impl <'a> TestMessage <'a> {
    fn name(&self) -> &'static str {
        match self {
            &TestMessage::Reply{ .. } => "Reply Message",
            &TestMessage::ForwardData{ .. } => "Forward Data Message",
        }
    }

    fn as_val(self) -> NamedValue {
        let name = self.name();
        let val = match self {
            TestMessage::Reply{ receipt_number, data } =>
                vec![
                    ("Function Code", Ok(Val::Enum(1, "Reply Message"))),
                    ("Receipt Number", receipt_number.and_then(Val::base10)),
                    ("Data", Ok(Val::Bytes(data.to_vec()))),
                ],

            TestMessage::ForwardData{ dest, message } => {
                let data = match message.map(|b| (*b).as_val()) {
                    Ok((k,v)) => Ok(Val::Subpacket(vec![(k,v)])),
                    Err(e) => Err(e),
                };

                vec![
                    ("Function Code", Ok(Val::Enum(2, "Forward Data Message"))),
                    ("Forward Address", dest),
                    ("Data", data),
                ]
            },
        };

        (name, Ok(Val::Subpacket(val)))
    }

    fn parse(data: &[u8]) -> Result<TestMessage> {
        let function_code = unsigned::<u16, LittleEndian>(&data[0..2]);
        match function_code {
            Ok(1) => Ok({
                let receipt_number = unsigned::<u16, LittleEndian>(&data[2..4]);

                TestMessage::Reply{
                    receipt_number: receipt_number,
                    data: &data[4..],
                }
            }),

            Ok(2) => Ok({
                TestMessage::ForwardData{
                    dest: ethernet::mac_address(&data[2..8]),
                    message: TestMessage::parse(&data[8..]).map(Box::new),
                }
            }),

            Ok(x) => Error::inval(format!["invalid function code: {}", x]),
            Err(e) => Err(e),
        }
    }
}
