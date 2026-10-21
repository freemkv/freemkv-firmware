# Flash GUI catalogs

These catalogs belong to the flash GUI and are embedded in its binary. They are
authored independently of the main freemkv application and its i18n crate.

The current 0.14.0 development snapshot has 36 message IDs in each of 29 languages.
It covers the language picker, common drive controls, task tabs, main result
actions, application name, native menus, and stable operation failure summaries.
Task forms, dynamic statuses, progress, logs, confirmation details, and analysis
results still contain English copy and require further migration. This snapshot
does not provide complete localization.

Message lookup requires a nonempty translation for the selected language. Tests
check catalog key parity, locale codes, main-view language changes, and saved
preferences across app instances. The macOS GUI gate selects every language
through the native menu and verifies actual labels, tabs, and placeholders.

Keep message IDs stable and give new messages translations in every catalog.
Device identities, firmware identifiers, paths, and protocol data remain data.
