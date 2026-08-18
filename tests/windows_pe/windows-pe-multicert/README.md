Tests signer (leaf) certificate resolution for the `windows_pe` cert options.
The signed PE's PKCS#7 embeds two certificates with the actual signer
("Real Leaf Signer") deliberately placed second in the certificates SET,
behind a "Decoy Chain Cert". Verifies that matching considers every embedded
certificate (both the leaf and the non-leaf match), while the logged
`executable.cert_subject`/`cert_thumbprint` report the resolved leaf signer
rather than the first certificate in the SET.

The `input.pcap` is a frozen fixture; see the `pe-keyword-validation` bundle's
`common/pcap-generators/gen_multicert.py` for how it is generated.
