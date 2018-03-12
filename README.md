## 2-way Borromean Ring Signatures (BRS) for ed25519

The BRS algorithm is not compatible with other implementations (there is no
real standard). The code is loosely based on libsecp256-zkp and Chain.

* Intermediate (decoy) scalars on the ring are fetched with no regard for
  cofactor. Make sure public keys from untrusted sources are torsion-free.
* Signature can store `m_rings*n_sigs*32` bytes of data
* The chamaleon hash we use is sha512, the PRF of the ring salsa20+sha512/384
