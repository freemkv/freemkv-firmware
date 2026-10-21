# Firmware utility UI catalogs

These catalogs are embedded in freemkv Flash and freemkv Modify. Both applications
share the language preference; the main freemkv ripping application's catalogs are
independent. UI copy belongs here, including errors, forms, file filters, confirmation
sheets, progress, result labels and analysis controls. Diagnostics remain English.

Keep message IDs stable. Every language must have the same nonempty messages and
named placeholders. Add translations and tests with each new UI function or feature.
Device identities, firmware names, paths, hashes and protocol data remain data.

Messages with arguments remain unresolved until presentation, so changing the UI
language also updates an existing result. English diagnostic rendering is separate
from the selected language. Full source error chains are recorded before customer
guidance is selected; they must never be replaced by the translated UI text.

Tests cover catalog parity, placeholders, saved preferences, language changes,
backup consent and English diagnostics. Native GUI gates check actual widgets.
