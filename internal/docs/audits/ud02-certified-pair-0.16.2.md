# UD02 certified-pair regression in 0.16.1

The 265afc13 report repeats the earlier UD02FAN rejection. The prior library fix c1bb01f and application fix 968bb32 remained on fix branches and were not ancestors of the 0.16.1 release. Its pinned library f835d5b still required a factory product-code allowlist.

0.16.2 integrates the conversion fix into the current stage-based execution code and pins Pioneer 1.4.0. Conversion eligibility uses the exact decoded source/target firmware pair, hardware-family fingerprint, target model, expected replacement bytes, length, checksum and output digest. Factory product codes grant no route. The live mechanism requirement (word 0x28f = 1), settings transactions, readback and rollback remain enforced.

Regression coverage includes ordinary Flash authorization, Recovery preparation and offline compatibility. External report fixtures are supplied through PIONEER_UD02_REPORT_FIXTURES; the existing held-image check uses PIONEER_SETTINGS_HOARD. Personal report data and firmware are not committed. The expected adapted Normal SHA-256 remains ca09032288c62b8b26bb983431af11b52aaeec8da9bd0e80afcccdf3b07f0815. Exact converted-to-stock return remains registered; native UD04-to-UD02 remains excluded.

MediaTek remains pinned at 1.2.0 because this fix changes only Pioneer conversion selection. No physical firmware writes were performed for this release validation.
