# CL-PKE on Arkworks

A Rust implementation of the Certificateless Public-Key Encryption (CL-PKE) 
scheme proposed by Cheng and Comley (2005), built on top of the 
[arkworks-rs](https://github.com/arkworks-rs) ecosystem over the BLS12-381 curve.

>**WARNING**: This is an academic proof-of-concept prototype. It has not 
> received careful code review and is **NOT ready for production use**.

## Overview

Identity-Based Encryption (IBE) allows encrypting to a recipient using their 
identity as a public key, but suffers from a key escrow problem: the Key 
Generation Center (KGC) holds all private keys. Certificateless PKE addresses 
this by splitting the private key into two parts, one issued by the KGC, one 
chosen by the user, such that neither alone is sufficient for decryption.

This implementation covers the five algorithms of the Cheng-Comley CL-PKE 
scheme: `Setup`, `Extract`, `Publish`, `Encrypt`, and `Decrypt`. The scheme 
is originally specified over a Type-1 symmetric pairing. Since BLS12-381 is a 
Type-3 asymmetric curve, we adapt the scheme following standard practice from 
reference IBE implementations on this curve.

## Goals

- **Correctness**: the implementation follows the mathematical specification 
  of the scheme. Each algorithm is tested for functional correctness 
  (encrypt/decrypt roundtrip).
- **Readability**: the code is organized to reflect the structure of the 
  paper, with a correspondence table between mathematical notation and Rust 
  types documented in the accompanying note.
- **Reference for practitioners**: this repo is intended as a starting point 
  for engineers wishing to implement certificateless cryptography on modern 
  pairing-friendly curves using arkworks.

## Paper

The accompanying note describing the implementation, the Type-1 to Type-3 
adaptation, and deployment considerations is available in this repository.

📄 [`cl_pke_note_kg.pdf`](./cl_pke_note_kg.pdf)



## Code Organisation
src/
├── lib.rs       # Core algorithms: Setup, Extract, Publish, Encrypt, Decrypt
└── utils.rs     # Hash functions (H1–H4) and random sampling utilities
## Building and Testing

```bash
cargo build
cargo test
```

## Security Notes

- This implementation is **not audited** and should not be used to encrypt 
  sensitive data.
- The scheme is IND-CCA2 secure under the BDHP assumption in the random 
  oracle model. For full security proofs, refer to the original 
  paper [[1]](#references).
- BLS12-381 does not provide post-quantum security.

## References

- [1] X. Cheng, J. Comley, "An Efficient Certificateless Public Key 
  Encryption Scheme", ePrint 2005/012. 
  https://eprint.iacr.org/2005/012
- [2] S. Al-Riyami, K. Paterson, "Certificateless Public Key Cryptography", 
  ASIACRYPT 2003.
- [3] RFC 9380 — Hashing to Elliptic Curves. 
  https://www.rfc-editor.org/rfc/rfc9380
- [4] arkworks-rs. https://github.com/arkworks-rs

## License

MIT