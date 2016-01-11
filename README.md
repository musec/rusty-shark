![Rusty Shark logo](artwork/logo.png)

`rshark`, the Rusty Shark library, is a library for deep inspection
of malicious packets.

[Wireshark](https://www.wireshark.org) is a very useful tool for network
debugging, but it's had its
[fair share of security vulnerabilities](https://www.wireshark.org/security).
`rshark` uses the type safety of Rust to enable the dissection of
malicious packets without worry of buffer overflows or other common memory errors.
That is, Rusty Shark is compartmentalized to minimize the damage that
can be done by a successful adversary. The submarine metaphors write themselves.

Further details are available
[in the Rustdoc](http://musec.github.io/rusty-shark/rshark/).

## License

Licensed under either of

 * Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
 * MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any
additional terms or conditions.
