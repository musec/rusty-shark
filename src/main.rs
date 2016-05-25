/*
 * Copyright 2015 Jonathan Anderson
 *
 * Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
 * http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
 * http://opensource.org/licenses/MIT>, at your option. This file may not be
 * copied, modified, or distributed except according to those terms.
 */

extern crate docopt;
extern crate rshark;
extern crate rustc_serialize;
extern crate pcap;

use docopt::Docopt;
use rshark::Protocol;


// TODO: use docopt_macros once rust-lang/rust#28089 is resolved
const USAGE: &'static str = "
Usage: rshark [options] <source>
       rshark (--help | --version)

Options:
    -f, --filter         BFP filter (see http://biot.com/capstats/bpf.html)
    -h, --help           Show this message
    -p, --promiscuous    Listen to all packets
    -s, --snaplen=<len>  Bytes to capture from each packet [default: 5000]
    -t, --timeout=<ms>   Packet read timeout, in ms [default: 10]
    -v, --version        Show the version of rshark
";

const VERSION: Option<&'static str> = option_env!("CARGO_PKG_VERSION");


#[derive(RustcDecodable)]
struct Args {
    arg_source: String,
    flag_filter: String,
    flag_snaplen: i32,
    flag_timeout: i32,
    flag_promiscuous: bool,
    flag_version: bool,
}

type PcapResult = Result<pcap::Capture<pcap::Activated>, pcap::Error>;


fn main() {
    let args: Args = Docopt::new(USAGE)
        .and_then(|d| d.argv(std::env::args()).decode())
        .unwrap_or_else(|e| e.exit())
        ;

    if args.flag_version {
        println!["rshark v{}", VERSION.unwrap_or("<unknown>")];
        return;
    }

    let protocol = rshark::ethernet::Ethernet;

    let result = open_capture(&args)
        .map(|mut c| {
            let mut count = 0;

            while let Ok(packet) = c.next() {
                println!("\n\n{}-B packet:", packet.data.len());

                match protocol.dissect(packet.data) {
                    Ok(dissected) => print!["{}", dissected.pretty_print(1)],
                    Err(e) => println!["Error: {}", e],
                }

                count += 1;
            }

            count
        })
        ;


    match result {
        Ok(packet_count) => println!["Processed {} packets", packet_count],
        Err(e) => {
            println!["{}", e];
            std::process::exit(1);
        },
    }
}


fn open_capture(args: &Args) -> PcapResult {
    let device = try![open_device(args)];

    let capture = match device {
        Some(d) => Ok(d),
        None => open_file(&args.arg_source),
    };

    capture.and_then(|mut c| {
        try![c.filter(&args.flag_filter)];
        Ok(c)
    })
}

fn open_device(args: &Args)
        -> Result<Option<pcap::Capture<pcap::Activated>>, pcap::Error> {

    match pcap::Device::list() {
        Ok(devices) => {
            for d in devices {
                if d.name == args.arg_source {
                    return pcap::Capture::from_device(d)
                        .map(|d| d.promisc(args.flag_promiscuous)
                                  .rfmon(args.flag_promiscuous)
                                  .snaplen(args.flag_snaplen)
                                  .timeout(args.flag_timeout))
                        .and_then(|d| d.open())
                        .map(|c| c.into())
                        .map(Some)
                        ;
                }
            };

            Ok(None)
        },
        Err(e) => Err(e),
    }
}

fn open_file(filename: &str) -> PcapResult {
    std::fs::metadata(filename)
        .map_err(|e| pcap::Error::PcapError(format!["{}", e]))
        .and_then(|f|
            if f.is_file() {
                pcap::Capture::from_file(filename)
                    .map(|c| c.into())
            } else {
                Err(pcap::Error::PcapError(
                        format!["{} is not a file or interface", filename]))
            }
        )
}
