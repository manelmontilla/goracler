# GORACLER 

Goracle is a go library that helps performing [padding
oracle](https://en.wikipedia.org/wiki/Padding_oracle_attack) attacks. The oracle
must use a block cipher working in CBC mode and PKCS5 padding. The library also
supposes the common practice of having the IV in the first block of the
ciphertext.

The library allows to perform both encryption and decryption attacks. It also
allows to speed up the attack by using a configurable number of go routines to
concurrently querying the oracle.
