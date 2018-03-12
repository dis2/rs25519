## 2-way Borromean Ring Signatures (BRS) for ed25519

The BRS algorithm is not compatible with other implementations (there is no
real standard). The code is loosely based on libsecp256-zkp and Chain.

* Signature can store `m_rings*n_sigs*32` bytes of data, it is implicitly
  encrypted by knowledge of the private keys.
* chameleon hash is ran through sha512, decoy PRF is salsa20 keyed with sha512/384
