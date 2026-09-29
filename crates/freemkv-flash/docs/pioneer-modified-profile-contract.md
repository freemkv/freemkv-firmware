# Modified Pioneer bundle profile contract

The current Pioneer dry-run Kernel+Normal selector accepts only byte-exact
resources from an audited updater. It binds the bundle to a pinned profile
using source package identity plus both PE resource sizes and SHA-256 hashes.
This supports 38 single-updater packages; four packages with two matching
updater executables fail closed. It never infers a writer from a model or
version string alone.

A modified bundle cannot retain the OEM resource hashes. The future
candidate API should require an **explicit audited base profile**, identified
by its pinned nested-updater SHA-256, together with the modified Kernel and
Normal component bytes. The base updater file itself is not a runtime input.
The input bundle must name exactly one Kernel and one Normal component and
must hash-check both against its own manifest. The selector must then check
both component lengths, Pioneer magic and file types, and pinned base
model/revision/hardware/destination fields. The pair's header identity must
agree. A dual-updater package needs the precise nested-updater SHA-256;
package name or outer hash alone cannot choose ELD versus KAI.

Return a separate `UncertifiedModifiedCandidate` evidence status carrying
the base profile ID and both new component hashes. The offline transcript
may use the base profile's exact control construction and transfer framing,
with an explicit seed for the generated Kernel block. Neither structural
checks nor a reproducible transcript prove the modified envelope's decoding,
integrity, drive acceptance, or safe execution. The live write gate remains
closed until those checks and a proven restorable backup exist. No current
CLI option silently routes modified Kernel+Normal bundles through the exact
OEM registry.
