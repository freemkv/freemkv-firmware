# Test fixtures — third-party firmware

The `*.bin` images in this directory are **OEM optical-drive firmware** (LG /
Hitachi-LG Data Storage, MediaTek MT19xx). They are the property of their
original manufacturers, included **only** as test fixtures for interoperability
and research. They are **NOT** covered by this repository's MIT LICENSE — see
the repository-root `NOTICE`. No ownership is claimed; do not redistribute
except as permitted by their owners.

WH16NS58 1.V9 is the original 2 MiB OEM image from the reported failure, SHA-256
`97b287072e20c9527de6f34f6d564c8edcc6afb3ecf5675c11b8262c11663061`.
It exercises an erased run extending beyond the final active integrity range.

BE14NU40 MT1939 JB7 1.01 is a 2 MiB OEM image from the external read-only
firmware hoard, SHA-256
`7ff91816c192f4c0ba492b507c8119fafb71df7a25118d0e456682bb34e2e567`. It
regresses classic MT1939 CREATE/MODIFY parity when the independent HRL detour
resolves but the RawRead helper does not.

BU40N 1.05 is a 2 MiB OEM image from the read-only hoard, SHA-256
`fbfed0cc2d55bf823012d76cc7ac6d7fa742f059602d9d126b4866bdd8617d2d`.
It regresses exact-size boot-record allocation after all newly resolved hooks.
