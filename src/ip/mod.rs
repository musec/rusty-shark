//! Dissection of Internet Protocol (IP) packets.
//!
//! This module will eventually contain dissectors for protocols in the IP suite,
//! e.g., `rshark::ip::icmp` and `rshark::ip::tcp`.
//! For now, it only handles IP headers.
//!
//! See [RFC 791](https://tools.ietf.org/html/rfc791).

use {
    Endianness,
    Error,
    NamedValue,
    Result,
    Val,
    raw,
    unsigned,
};


pub fn dissect(data : &[u8]) -> Result {
    if data.len() < 20 {
        return Err(Error::Underflow { expected: 20, have: data.len(),
            message: "An IP packet must be at least 20 B".to_string() })
    }

    let mut values:Vec<NamedValue> = vec![];

    // IP version (should be "4")
    let version = data[0] >> 4;
    values.push(("Version".to_string(), Ok(Val::Unsigned(version as u64))));

    // Internet Header Length (IHL): number of 32b words in header
    let words = data[0] & 0x0f;
    values.push(("IHL".to_string(), Ok(Val::Unsigned(words as u64))));

    // Differentiated Services Code Point (DSCP): RFC 2474
    let dscp = data[1] >> 2;
    values.push(("DSCP".to_string(), Ok(Val::Unsigned(dscp as u64))));

    // Explicit Congestion Notification (ECN): RFC 3168
    let ecn = data[1] & 0x03;
    values.push(("ECN".to_string(), Ok(Val::Unsigned(ecn as u64))));

    // Total length (including header)
    let length = unsigned(&data[2..4], Endianness::BigEndian);
    values.push(("Length".to_string(), length.map(|v| Val::Unsigned(v))));

    // Identification (of datagraph fragments): RFC 6864
    values.push(("Identification".to_string(), Ok(Val::Unsigned(data[8] as u64))));

    // Protocol number (assigned by IANA)
    let protocol = data[9];
    values.push(("Protocol".to_string(), Ok(Val::Unsigned(protocol as u64))));

    // Header checksum
    values.push(("Checksum".to_string(), Ok(Val::Bytes(data[10..12].to_vec()))));

    // Source and destination addresses
    let source = &data[12..16];
    values.push(("Source".to_string(), Ok(Val::Address {
        bytes: source.to_vec(),
        encoded: source.iter().map(|b| b.to_string()).collect::<Vec<_>>().join("."),
    })));

    let dest = &data[16..20];
    values.push(("Destination".to_string(), Ok(Val::Address {
        bytes: dest.to_vec(),
        encoded: dest.iter().map(|b| b.to_string()).collect::<Vec<_>>().join("."),
    })));

    // Parse the remainder according to the specified protocol.
    let remainder = &data[20..];
    let dissect_pdu = match protocol {
        // TODO: UDP, TCP, etc.
        _ => raw,
    };

    values.push(("Protocol Data".to_string(), dissect_pdu(remainder)));

    Ok(Val::Object(values))
}
