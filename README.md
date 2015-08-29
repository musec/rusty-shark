![foo](artwork/logo.png)

`rshark`, the Rusty Shark library, is a library for inspecting malicious packets.

# Background

[Wireshark](https://www.wireshark.org) is a very useful tool for network
debugging, but it's had its
[fair share of security vulnerabilities](https://www.wireshark.org/security).
It's generally accepted that, to succeed at Capture the Flag, one should fuzz
Wireshark for awhile before the competition to find a few new vulnerabilities
(don't worry, they're there, you'll find some) and use those offensively to
blind one's opponents.
This speaks to both the indispensability of packet capture/dissection tools
and the fundamental difficulty of ``just making Wireshark secure''.
Wireshark has a *lot* of dissectors, which are written using a
[complex C API](https://www.wireshark.org/docs/wsdg_html_chunked/ChDissectAdd.html)
(although some are now written in Lua).

`rshark` uses the type safety of Rust to enable the dissection of
malicious packets without worry of buffer overflows or other common memory errors.
Rusty Shark dissectors can make mistakes, but those logical errors should only
affect the interpretation of the *current* data, rather than *all* data.
That is to say, Rusty Shark is compartmentalized to minimize the damage that
can be done by a successful adversary. The submarine metaphors write themselves.
