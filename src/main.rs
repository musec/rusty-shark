extern crate rshark;
extern crate pcap;

use pcap::Device;


fn process(p: &pcap::Packet) {
    print!("received {}-B packet:", p.data.len());

    match rshark::ethernet::dissect(p.data) {
        Err(e) => println!["Error: {}", e],
        Ok(p) => print!["{}", p.pretty_print(1)],
    }
}

fn main() {
    let dev = Device::lookup().unwrap();
    println!("Device name: {}", dev.name);

    let mut cap = pcap::Capture::from_device(dev).unwrap()
                      .promisc(true)
                      .snaplen(5000)
                      .timeout(10)
                      .open().unwrap();

    loop {
        match cap.next() {
            Some(ref packet) => { process(packet); },
            None => {},
        }
    }

}
