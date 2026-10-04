# Pioneer codec

Shared Rust envelope/image code for the offline codec and the flasher's backup
implementation. This crate has no drive I/O, archive discovery, or extraction
pipeline dependency.

`decode_envelope` identifies envelope framing and decodes Kernel images. Its
Normal result is **framing-only**, not verified receiver plaintext. Its metadata
has `receiver_xor_policy: null`.

For encrypted Normal firmware, decode the paired Kernel and call
`decode_envelope_with_kernel(normal_bytes, &kernel)`. The Kernel must contain one
recognized instruction sequence comparing two byte offsets and branching over
the XOR. The policy is extracted from those instructions, not a model lookup.
Missing, ambiguous, unaligned, or duplicate offsets fail. The caller remains
responsible for establishing that the supplied Kernel belongs with the Normal.
`DecodedEnvelope::repack` and `repack_resized_normal` retain this exact policy;
XOR is omitted at its two offsets while rotation is preserved.

The standalone `pioneer-firmware` tool accepts `--kernel KERNEL.enc` for Normal
encode/decode and discovers a Kernel in a supplied package. Explicit
`--unverified-codec` is reserved for framing-only research when no Kernel exists.
This is not proof that a rebuilt envelope is accepted by a drive.

Run unit tests with `cargo test --workspace`. To run the supplied UD04/live KAT,
set `PIONEER_CODEC_KAT_DIR` to a directory containing `kernel.enc`, `normal.enc`,
and `normal.live.bin`. The test pins the known Normal plaintext and envelope
SHA-256 values and requires full-image equality, not just roundtrip symmetry.
