sha2 
[![License](https://img.shields.io/github/license/AntonMeep/sha2.svg?color=blue)](https://github.com/AntonMeep/sha2/blob/master/LICENSE.txt)
[![Alire crate](https://img.shields.io/endpoint?url=https://alire.ada.dev/badges/sha2.json)](https://alire.ada.dev/crates/sha2.html)
[![GitHub release](https://img.shields.io/github/release/AntonMeep/sha2.svg)](https://github.com/AntonMeep/sha2/releases/latest)
[![GitHub Workflow Status](https://img.shields.io/github/workflow/status/AntonMeep/sha2/Default)](https://github.com/AntonMeep/sha2/actions)
=======

Secure Hash Algorithm 2 implemented in Ada, no external dependencies. For the
ease of use, both generic interface and an Ada.Streams-compatible one are
provided. Implementation has been tested against [these](https://www.di-mgt.com.au/sha_testvectors.html)
test vectors.

Purpose of this crate is to provide cryptography functions in a portable way
with sane API, since `GNAT.SHA*` packages are lacking both of these properties.

> PRs are welcome!
