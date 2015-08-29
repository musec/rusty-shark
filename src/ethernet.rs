//! Dissection of Ethernet (IEEE 802.3) frames.

use {
    Dissector,
    Endianness,
    Error,
    NamedValue,
    Result,
    Val,
    ip,
    raw,
    unsigned,
};


pub fn dissect(data : &[u8]) -> Result {
    if data.len() < 14 {
        return Err(Error::Underflow { expected: 14, have: data.len(),
            message: "An Ethernet frame must be at least 14 B".to_string() })
    }

    let mut values:Vec<NamedValue> = vec![];
    values.push(("Destination".to_string(), Ok(Val::Bytes(data[0..6].to_vec()))));
    values.push(("Source".to_string(), Ok(Val::Bytes(data[6..12].to_vec()))));

    // The type/length field might be either a type or a length.
    let tlen = unsigned(&data[12..14], Endianness::BigEndian);
    let remainder = &data[14..];

    match tlen {
        Ok(i) if i <= 1500 => {
            values.push(("Length".to_string(), Ok(Val::Unsigned(i))));
        },

        Ok(i) => {
            let (protocol, dissector): (Result<&str>, Dissector) = match i {
                0x800 => (Ok("IP"), ip::dissect),
                0x806 => (Ok("ARP"), raw),
                0x8138 => (Ok("IPX"), raw),
                0x86dd => (Ok("IPv6"), raw),
                _ => (
                    Err(Error::InvalidData(format!["unknown protocol: {:x}", i])),
                    raw
                ),
            };

            let (ty, subname):(Result,String) = match protocol {
                Ok(name) =>
                    (
                        Ok(Val::String(name.to_string())),
                        format!["{} data", name]
                    ),

                Err(e) => (Err(e), "Unknown protocol data".to_string()),
            };

            values.push(("Type".to_string(), ty));
            values.push((subname, dissector(remainder)));
        },
        Err(e) => {
            values.push(("Type/length".to_string(), Err(e)));
        },
    };

    Ok(Val::Object(values))
}
