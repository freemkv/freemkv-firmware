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
