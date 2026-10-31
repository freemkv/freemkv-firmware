# UD02 conversion: certified firmware pair and settings

Reports ca053108 and 6f8f61b6 exposed an unnecessary factory-SKU eligibility check: their BDR-UD02FAN identity failed a profile containing only BDR-UD02TBD. Recovery also lacked that factory evidence. Neither attempt wrote firmware.

Matthew explicitly chose the rule: this source firmware is certified to this target firmware with these settings. Factory SKU allowlists and the corresponding preparation/execution requirement are removed. The profile still binds decoded source and target Normal hashes, hardware-family fingerprint, target model, exact replacement bytes, length, checksum and output digest. Required live mechanism word 0x28F = 1 is still checked before settings or firmware writes. Live setting migrations, verification and rollback remain active.

Normal Flash, Recovery and offline decisions now prepare the certified pair without reading factory identity. Native UD04 -> stock UD02 remains excluded because native UD04 is not a registered source for the stock-return profile. Certified converted UD04 -> stock UD02 remains registered. The public library factory-parameters binder remains a no-op for source compatibility; it grants no route.

The diagnostic parameters section in 6f8f61b6 has verified SHA-256 14b91f41e3e4eac2b46cb8c4ab80e5594ba08576f5929f945d2c6890f06e45cf and mechanism word 0x28F = 1. Raw parameters and personal diagnostic data are not committed.

Validation: full library tests and Pioneer app regressions, with the held pair explicitly enabled, verify unchanged converted Normal hash ca09032288c62b8b26bb983431af11b52aaeec8da9bd0e80afcccdf3b07f0815, exact return and native reverse refusal. Physical test remains pending: bench SSH agent refused signing; no hardware writes occurred. Isolated from dev and MT1959 research.
