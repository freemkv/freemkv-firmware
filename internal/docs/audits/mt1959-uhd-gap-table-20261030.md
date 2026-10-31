# MT1959 OEM UHD comparison and gap table

**Definition agreed with the user: OEM UHD = 100% of G01-G06.** G07/G08 are known internal authentication differences only. They do not affect this classification, block conversion or generate patches. Existing freemkv AKE/encryption bypasses remain separate.

**Active scope: 147/147 newer-layout payloads meet all six reviewed media contracts (100%).** They already contain these contracts; no G01-G06 conversion edits are needed for this group. The 24 older-layout MT1959 payloads are deferred alongside MT1939. No physical UHD read or playback success is implied by the six-contract classification.

199 catalogue entries comprise 171 distinct full payloads, 26 incomplete sources and two archive aliases. The full OEM source bucket has 67 images. Source provenance, manufacturer advertising and physical testing are separate from the requested six-contract definition. Incomplete sources remain unresolved.

| Required media contract | Meaning |
| --- | --- |
| G01 | U/5 DI admission and C7/C8 layer state |
| G02 | C7 control-bit selection |
| G03 | C7 control-field selection |
| G04 | C7 forward calculation |
| G05 | C7 reverse calculation and native mode selection |
| G06 | C7 conditional parameter |

The numerical surveys execute native division workers. The reverse alternatives use R7 minus 12 times the quotient in mode zero, and R5 minus 9 times the quotient in nonzero mode. Mode production and calibration remain unresolved for the deferred older layouts. The original DI/consumer receipt assumptions remain recorded in their source JSONs; optical acquisition and sector reads require hardware validation.

## Manufacturer-backed comparison references

These nine stock images anchor the comparison. They are not the only images classified OEM UHD under the revised definition.

| Product | Revision | SHA prefix | Specification |
| --- | --- | --- | --- |
| LG WH16NS60 | 1.01 | `aea98763cad7` | [Specification](https://www.lg.com/us/burners-drives/lg-wh16ns60-internal-blu-ray-dvd-drive) |
| LG WH16NS60 | 1.03 | `f1cd257b8c4b` | [Specification](https://www.lg.com/us/burners-drives/lg-wh16ns60-internal-blu-ray-dvd-drive) |
| HLDS BU40N general retail | 1.02 | `97bee5c51fbe` | [Specification](https://advdownload.advantech.com/productfile/PIS/96SDVR-8X-ST-HL-BB/file/96SDVR-8X-ST-HL-BB_datasheet_2025032820250328133155.pdf) |
| HLDS BU40N general retail | 1.04 | `5c1a47392976` | [Specification](https://advdownload.advantech.com/productfile/PIS/96SDVR-8X-ST-HL-BB/file/96SDVR-8X-ST-HL-BB_datasheet_2025032820250328133155.pdf) |
| LG BP60NB10 | 1.00 | `f60b037fb29e` | [Specification](https://media.us.lg.com/m/23735db0ce507a13/original/BP60NB10-Spec-Sheet.PDF) |
| Buffalo BRUHD-PU3 / BU40N BU11 | BU11 | `08d14869e553` | [Specification](https://www.buffalo.jp/product/detail/bruhd-pu3-bk.html) |
| HLDS BU40N general retail | 1.02 | `1bbeb5351dc0` | [Specification](https://advdownload.advantech.com/productfile/PIS/96SDVR-8X-ST-HL-BB/file/96SDVR-8X-ST-HL-BB_datasheet_2025032820250328133155.pdf) |
| HLDS BU40N general retail | 1.05 | `fbfed0cc2d55` | [Specification](https://advdownload.advantech.com/productfile/PIS/96SDVR-8X-ST-HL-BB/file/96SDVR-8X-ST-HL-BB_datasheet_2025032820250328133155.pdf) |
| Buffalo BRUHD-PU3 / BU40N BU12 | BU12 | `920a89f98b69` | [Specification](https://www.buffalo.jp/product/detail/bruhd-pu3-bk.html) |

## Internal authentication findings (no patches)

G07 records class-3 REPORT/SEND KEY routing differences. G08 records extended response/session/backend differences. In the active 147, 94 have both differences and 53 have neither in the reviewed paths. Neither finding changes the G01-G06 result. Their necessity for freemkv reading with bypasses enabled has not been demonstrated. Do not infer successful native authentication from the media classification.

## All firmware entries

| Source | Hardware / revision / destination | SHA prefix | OEM UHD (G01-G06) | Required media gaps | Internal auth differences |
| --- | --- | --- | --- | --- | --- |
| oem / full source | ASUS BC-12B1ST MT1959 JBC6/JB8 / 3.01 / ASUS | `8961b80b005c` | OEM UHD | none | G07,G08 |
| oem / full source | ASUS BC-12B1ST MT1959 JBC6/JB8 / 3.11 / ASUS | `ae0c03138570` | OEM UHD | none | G07,G08 |
| oem / full source | ASUS BC-12D2HT MT1959 JBC6/JB8 / 3.01 / ASUS | `93ea068da225` | OEM UHD | none | G07,G08 |
| oem / full source | ASUS BC-12D2HT MT1959 JBC6/JB8 / 3.11 / ASUS | `9f5bc0036740` | OEM UHD | none | G07,G08 |
| oem / full source | ASUS BW-16D1H-U MT1959 JB8/JB8 / A203 / ASUS | `e9d8bcddf85a` | OEM UHD | none | G07,G08 |
| oem / full source | ASUS BW-16D1HT MT1959 JB8/JB8 / 3.02 / ASUS | `784e017fbacd` | OEM UHD | none | G07,G08 |
| oem / full source | ASUS BW-16D1HT MT1959 JB8/JB8 / 3.03 / ASUS | `1d57260bf091` | OEM UHD | none | G07,G08 |
| oem / full source | ASUS BW-16D1HT MT1959 JB8/JB8 / 3.10 / ASUS | `37a32bfd708b` | OEM UHD | none | G07,G08 |
| oem / full source | HL-DT-ST BE16NU50 NU50 / 1.02 / GENERAL | `2b3ea41f8776` | OEM UHD | none | G07,G08 |
| oem / full source | HL-DT-ST BE16NU50 NU50 / 1.04 / GENERAL | `7dcc99d27600` | OEM UHD | none | G07,G08 |
| oem / full source | HL-DT-ST BE16NU50 NU50 / INTM / GENERAL | `215488b5ac20` | OEM UHD | none | G07,G08 |
| oem / full source | HL-DT-ST BH14NS50 NS50 / 1.01 / GENERAL | `4ef56002dd39` | OEM UHD | none | G07,G08 |
| oem / full source | HL-DT-ST BH14NS58 NS50 / 1.00 / GENERAL | `53d2cdc32a2a` | OEM UHD | none | G07,G08 |
| oem / full source | HL-DT-ST BH14NS58 NS50 / 1.01 / GENERAL | `eb0e2e727544` | OEM UHD | none | G07,G08 |
| oem / full source | HL-DT-ST BH16NS40 NS50 / 1.02 / GENERAL | `acbe782ebc3c` | OEM UHD | none | G07,G08 |
| oem / full source | HL-DT-ST BH16NS40 NS50 / 1.03 / GENERAL | `a5bb75b8dbec` | OEM UHD | none | G07,G08 |
| oem / full source | HL-DT-ST BH16NS40 NS50 / 1.05 / GENERAL | `dd27dc3901ea` | OEM UHD | none | G07,G08 |
| oem / full source | HL-DT-ST BH16NS40 NS50 / INTM / GENERAL | `c3a18eed1725` | OEM UHD | none | G07,G08 |
| oem / full source | HL-DT-ST BH16NS50 NS50 / 1.01 / GENERAL | `b7a368da0fcb` | OEM UHD | none | G07,G08 |
| oem / full source | HL-DT-ST BH16NS55 NS50 / 1.03 / GENERAL | `0bfdd3009ed1` | OEM UHD | none | G07,G08 |
| oem / full source | HL-DT-ST BH16NS55 NS50 / 1.05 / GENERAL | `5f3fa17d6111` | OEM UHD | none | G07,G08 |
| oem / full source | HL-DT-ST BH16NS55 NS50 / 1.05 / GENERAL | `ca7e8db8576a` | OEM UHD | none | G07,G08 |
| oem / full source | HL-DT-ST BH16NS58 NS50 / 1.00 / GENERAL | `6d9fdb2bd658` | OEM UHD | none | G07,G08 |
| oem / full source | HL-DT-ST BH16NS58 NS50 / 1.01 / GENERAL | `ccc97e4f92e4` | OEM UHD | none | G07,G08 |
| oem / full source | HL-DT-ST BH16NS58 NS50 / 1.02 / GENERAL | `4f4e63cd5988` | OEM UHD | none | G07,G08 |
| oem / full source | HL-DT-ST BH16NS60 MT1959 JB8/JB8 / INTM / GENERAL | `1baed51d34e0` | OEM UHD | none | none observed |
| oem / full source | HL-DT-ST BP50NB40 MT1959 BUP1/BU1 / 1.00 / GENERAL | `c88a69013d55` | 1959 non UHD | G01,G02,G03,G04,G05,G06 | G07,G08 |
| oem / full source | HL-DT-ST BP50NB40 NB50 / 1.01 / GENERAL | `961acab180c9` | 1959 non UHD | G01,G02,G04,G05,G06 | G07,G08 |
| oem / full source | HL-DT-ST BP50NB40 NB50 / 1.03 / GENERAL | `3cdbdacace5c` | 1959 non UHD | G01,G02,G04,G05,G06 | G07,G08 |
| oem / full source | HL-DT-ST BP50NB40 NB50 / INTM / GENERAL | `92bb22b2c899` | 1959 non UHD | G01,G02,G04,G05,G06 | G07,G08 |
| oem / full source | HL-DT-ST BP55EB40 NB50 / 1.01 / GENERAL | `e60a4ce02a58` | 1959 non UHD | G01,G02,G04,G05,G06 | G07,G08 |
| oem / full source | HL-DT-ST BP60NB10 NB10 / 1.00 / GENERAL | `f60b037fb29e` | OEM UHD | none | none observed |
| oem / full source | HL-DT-ST BU40N BU40 / 1.02 / GENERAL | `1bbeb5351dc0` | OEM UHD | none | none observed |
| oem / full source | HL-DT-ST BU40N BU40 / 1.02 / GENERAL | `97bee5c51fbe` | OEM UHD | none | none observed |
| oem / full source | HL-DT-ST BU40N BU40 / 1.04 / GENERAL | `5c1a47392976` | OEM UHD | none | none observed |
| oem / full source | HL-DT-ST BU40N BU40 / 1.05 / GENERAL | `fbfed0cc2d55` | OEM UHD | none | none observed |
| oem / full source | HL-DT-ST BU40N MT1959 BU5/BU3 / 1.01 / R? | `103b9da94c91` | OEM UHD | none | none observed |
| oem / full source | HL-DT-ST BU40N MT1959 BU5/BU3 / A103 / D? | `7d7f2465feaf` | OEM UHD | none | none observed |
| oem / full source | HL-DT-ST BU40N MT1959 BU5/BU3 / BN11 / 0? | `5c01c1fda59f` | 1959 non UHD | G01,G02,G04,G05,G06 | none observed |
| oem / full source | HL-DT-ST BU40N MT1959 BU5/BU3 / BN12 / 0? | `3d3badd67d47` | 1959 non UHD | G01,G02,G04,G05,G06 | none observed |
| oem / full source | HL-DT-ST BU40N MT1959 BU5/BU3 / BU11 / BUFFALO | `08d14869e553` | OEM UHD | none | none observed |
| oem / full source | HL-DT-ST BU40N MT1959 BU5/BU3 / BU12 / BUFFALO | `920a89f98b69` | OEM UHD | none | none observed |
| oem / full source | HL-DT-ST BU40N MT1959 BU5/BU3 / CB04 / CB04 | `78f75561d474` | 1959 non UHD | G01,G02,G04,G05,G06 | G07,G08 |
| oem / full source | HL-DT-ST BU40N MT1959 BU5/BU3 / INTM / GENERAL | `29ad30264714` | OEM UHD | none | none observed |
| oem / full source | HL-DT-ST BU40N MT1959 BU5/BU3 / TK03 / X? | `c328b6561228` | OEM UHD | none | none observed |
| oem / full source | HL-DT-ST BU40N MT1959 BU5/BU3 / U101 / U101 | `5f9abd3f7169` | OEM UHD | none | none observed |
| oem / full source | HL-DT-ST BU50N MT1959 BU51/BU3 / 1.00 / GENERAL | `20425a8ade6b` | OEM UHD | none | none observed |
| oem / full source | HL-DT-ST CH12NS40 NS40 / 1.01 / GENERAL | `731bcf7aa48d` | OEM UHD | none | G07,G08 |
| oem / full source | HL-DT-ST CH12NS40 NS40 / INTM / GENERAL | `fc98fda6431f` | OEM UHD | none | G07,G08 |
| oem / full source | HL-DT-ST UH12NS40 NS40 / 1.01 / GENERAL | `fbe641e5e808` | OEM UHD | none | G07,G08 |
| oem / full source | HL-DT-ST UH12NS40 NS40 / 1.03 / GENERAL | `eeb1c948f1ed` | OEM UHD | none | G07,G08 |
| oem / full source | HL-DT-ST WH14NS40 NS50 / 1.03 / GENERAL | `de13d8d0fd56` | OEM UHD | none | G07,G08 |
| oem / full source | HL-DT-ST WH14NS40 NS50 / 1.05 / GENERAL | `38a70ac234a1` | OEM UHD | none | G07,G08 |
| oem / full source | HL-DT-ST WH16NS40 NS50 / 1.03 / GENERAL | `3e3b227e1338` | OEM UHD | none | G07,G08 |
| oem / full source | HL-DT-ST WH16NS40 NS50 / 1.05 / GENERAL | `ffde0e55aed6` | OEM UHD | none | G07,G08 |
| oem / full source | HL-DT-ST WH16NS58 MT1959 JB8/JB8 / 1.V1 / GENERAL | `4041c0f122a9` | OEM UHD | none | G07,G08 |
| oem / full source | HL-DT-ST WH16NS58 MT1959 JB8/JB8 / 1.V2 / GENERAL | `3018997b63cc` | OEM UHD | none | G07,G08 |
| oem / full source | HL-DT-ST WH16NS58 MT1959 JB8/JB8 / 1.V5 / GENERAL | `e24060184915` | OEM UHD | none | G07,G08 |
| oem / full source | HL-DT-ST WH16NS58 MT1959 JB8/JB8 / 1.V7 / GENERAL | `569cea9bb8ad` | OEM UHD | none | G07,G08 |
| oem / full source | HL-DT-ST WH16NS58 MT1959 JB8/JB8 / 1.V9 / GENERAL | `97b287072e20` | OEM UHD | none | G07,G08 |
| oem / full source | HL-DT-ST WH16NS60 NS60 / 1.01 / GENERAL | `aea98763cad7` | OEM UHD | none | none observed |
| oem / full source | HL-DT-ST WH16NS60 NS60 / 1.03 / GENERAL | `f1cd257b8c4b` | OEM UHD | none | none observed |
| oem / full source | HL-DT-ST WP50NB40 NB50 / 1.01 / GENERAL | `bea3a823370a` | 1959 non UHD | G01,G02,G04,G05,G06 | G07,G08 |
| oem / full source | HL-DT-ST WP50NB40 NB50 / 1.03 / GENERAL | `263994abefb0` | 1959 non UHD | G01,G02,G04,G05,G06 | G07,G08 |
| oem / full source | hp HLDS BU40N MT1959 BU5/BU3 / BW41 / HP | `3b9dd9b4c9bd` | OEM UHD | none | none observed |
| oem / full source | hp HLDS BU40N MT1959 BU5/BU3 / BW42 / HP | `c68cd76b6ca9` | OEM UHD | none | none observed |
| oem / full source | hp HLDS BU50N MT1959 BU51/BU3 / BW51 / HP | `d1e4d3d704c6` | OEM UHD | none | none observed |
| oem / fragment | ASUS BC-12D2HT MT1959 JBC6/JB8 / 3.12 / ASUS | `e81220df9664` | unresolved | unresolved | unresolved |
| oem / archive duplicate | ASUS BW-16D1HT MT1959 JB8/JB8 / 3.01 / ASUS | `f79ccf0bc90e` | unresolved | unresolved | G07,G08 |
| oem / fragment | ASUS BW-16D1HT MT1959 JB8/JB8 / 3.11 / ASUS | `187259f63ee1` | unresolved | unresolved | unresolved |
| oem / fragment | ASUS BW-16D1HT MT1959 JB8/JB8 / 3.11 / ASUS | `4003430a126a` | unresolved | unresolved | unresolved |
| oem / fragment | ASUS BW-16D1HT MT1959 JB8/JB8 / 3.11 / ASUS | `c8e1b169907f` | unresolved | unresolved | unresolved |
| oem / fragment | ASUS BW-16D1HT MT1959 JB8/JB8 / 3.11 / ASUS | `e4eeb0eccf0d` | unresolved | unresolved | unresolved |
| oem / fragment | ASUS BW-16D1X-U MT1959 JB8/JB8 / A105 / ASUS | `8ed898bf603f` | unresolved | unresolved | unresolved |
| oem / fragment | ASUS SBW-06D2X-U MT1959 BU51/BU3 / A102 / ASUS | `b191765d053e` | unresolved | unresolved | unresolved |
| oem / archive duplicate | HL-DT-ST BE16NU50 NU50 / 1.01 / GENERAL | `7d5aa8bc43f3` | unresolved | unresolved | G07,G08 |
| oem / fragment | HL-DT-ST BH-A10AME MT1959 JB8/JB8 / 1.02 / 7? | `1431278f12f6` | unresolved | unresolved | unresolved |
| oem / fragment | HL-DT-ST BH-A10AME MT1959 JB8/JB8 / 1.03 / 7? | `ae167a4b9bf9` | unresolved | unresolved | unresolved |
| oem / fragment | HL-DT-ST BH-A10AME MT1959 JB8/JB8 / T.24 / 7? | `d426b7308933` | unresolved | unresolved | unresolved |
| oem / fragment | HL-DT-ST BH16NS58 NS50 / 1.02 / GENERAL | `d308d8c30d77` | unresolved | unresolved | unresolved |
| oem / fragment | HL-DT-ST BP50NB40 NB50 / 1.02 / GENERAL | `e983a899ac20` | unresolved | unresolved | unresolved |
| oem / fragment | HL-DT-ST BP55EB40 EB52 / 1.03 / GENERAL | `fb282973bac2` | unresolved | unresolved | unresolved |
| oem / fragment | HL-DT-ST BP60NB10 NB12 / 1.02 / GENERAL | `db5dd30f90a5` | unresolved | unresolved | unresolved |
| oem / fragment | HL-DT-ST BP71N MT1959 BUP5/BU3 / 1.02 / S? | `35831ee2f6bc` | unresolved | unresolved | unresolved |
| oem / fragment | HL-DT-ST BU40N BU40 / 1.05 / GENERAL | `9707dfe2d0e7` | unresolved | unresolved | unresolved |
| oem / fragment | HL-DT-ST BU40N MT1959 BU5/BU3 / BN13 / 0? | `314ed8aca511` | unresolved | unresolved | unresolved |
| oem / fragment | HL-DT-ST BU40N MT1959 BU5/BU3 / BN14 / 0? | `8fe0f07d0ae8` | unresolved | unresolved | unresolved |
| oem / fragment | HL-DT-ST BU40N MT1959 BU5/BU3 / BU14 / BUFFALO | `c4a1d01d1495` | unresolved | unresolved | unresolved |
| oem / fragment | HL-DT-ST BU40N MT1959 BU5/BU3 / CB05 / CB04 | `255a9c307a26` | unresolved | unresolved | unresolved |
| oem / fragment | HL-DT-ST BU40N MT1959 BU5/BU3 / TK03 / X? | `9f1e448caf1e` | unresolved | unresolved | unresolved |
| oem / fragment | HL-DT-ST WH16NS40 NS50 / 1.04 / GENERAL | `6d664bccfa61` | unresolved | unresolved | unresolved |
| oem / fragment | HL-DT-ST WP50NB40 NB52 / 1.03 / GENERAL | `52c257459dc0` | unresolved | unresolved | unresolved |
| oem / fragment | hp HLDS BU40N MT1959 BU5/BU3 / BW43 / HP | `bf7201bec6d9` | unresolved | unresolved | unresolved |
| mk / full source | ASUS BC-12B1ST MT1959 JBC6/JB8 / 3.01 / ASUS | `69e5c2b5f7ca` | OEM UHD | none | G07,G08 |
| mk / full source | ASUS BC-12B1ST MT1959 JBC6/JB8 / 3.11 / ASUS | `11c8657aa75e` | OEM UHD | none | G07,G08 |
| dump / full source | ASUS BC-12D2HT MT1959 JBC6/JB8 / 3.00 / ASUS | `dd03cdae194d` | OEM UHD | none | G07,G08 |
| mk / full source | ASUS BC-12D2HT MT1959 JBC6/JB8 / 3.01 / ASUS | `dc88b3e4d44a` | OEM UHD | none | G07,G08 |
| mk / full source | ASUS BC-12D2HT MT1959 JBC6/JB8 / 3.11 / ASUS | `6c003aa1e751` | OEM UHD | none | G07,G08 |
| mk / full source | ASUS BW-16D1H-U MT1959 JB8/JB8 / A203 / ASUS | `df4452bbbd06` | OEM UHD | none | G07,G08 |
| dump / full source | ASUS BW-16D1H-U MT1959 JB8/JB8 / A204 / ASUS | `223e7e38b85f` | OEM UHD | none | G07,G08 |
| mk / full source | ASUS BW-16D1H-U MT1959 JB8/JB8 / A204 / ASUS | `714faf5c4cea` | OEM UHD | none | G07,G08 |
| dump / full source | ASUS BW-16D1HT MT1959 JB8/JB8 / 3.01 / ASUS | `2e243a167739` | OEM UHD | none | G07,G08 |
| dump / full source | ASUS BW-16D1HT MT1959 JB8/JB8 / 3.01 / ASUS | `40118f8171da` | OEM UHD | none | G07,G08 |
| omni / full source | ASUS BW-16D1HT MT1959 JB8/JB8 / 3.02 / ASUS | `0d085b4c854b` | OEM UHD | none | G07,G08 |
| omni / full source | ASUS BW-16D1HT MT1959 JB8/JB8 / 3.02 / ASUS | `21e1f77e0ea0` | OEM UHD | none | G07,G08 |
| omni / full source | ASUS BW-16D1HT MT1959 JB8/JB8 / 3.02 / ASUS | `663c1b55e479` | OEM UHD | none | G07,G08 |
| dump / full source | ASUS BW-16D1HT MT1959 JB8/JB8 / 3.02 / ASUS | `83ea24bb07b8` | OEM UHD | none | G07,G08 |
| omni / full source | ASUS BW-16D1HT MT1959 JB8/JB8 / 3.02 / ASUS | `afeab3e66cbd` | OEM UHD | none | G07,G08 |
| omni / full source | ASUS BW-16D1HT MT1959 JB8/JB8 / 3.02 / ASUS | `d00191537a8f` | OEM UHD | none | G07,G08 |
| mk / full source | ASUS BW-16D1HT MT1959 JB8/JB8 / 3.03 / ASUS | `48c7b55faf30` | OEM UHD | none | G07,G08 |
| omni / full source | ASUS BW-16D1HT MT1959 JB8/JB8 / 3.10 / ASUS | `66f277bcad34` | OEM UHD | none | G07,G08 |
| mk / full source | ASUS BW-16D1HT MT1959 JB8/JB8 / 3.10 / ASUS | `e04ed8f38ce9` | OEM UHD | none | G07,G08 |
| dump / full source | HL-DT-ST BE16NU50 NU50 / 1.01 / GENERAL | `9c46e6972b79` | OEM UHD | none | G07,G08 |
| dump / full source | HL-DT-ST BE16NU50 NU50 / 1.01 / GENERAL | `d286c5a7ea4a` | OEM UHD | none | G07,G08 |
| mk / full source | HL-DT-ST BE16NU50 NU50 / 1.02 / GENERAL | `f5eb16235209` | OEM UHD | none | G07,G08 |
| mk / full source | HL-DT-ST BE16NU50 NU50 / 1.04 / GENERAL | `d59b5da7424e` | OEM UHD | none | G07,G08 |
| mk / full source | HL-DT-ST BH14NS50 NS50 / 1.01 / GENERAL | `0a12a6ebf0b4` | OEM UHD | none | G07,G08 |
| mk / full source | HL-DT-ST BH14NS50 NS50 / 1.03 / GENERAL | `cfe1f92182b4` | OEM UHD | none | G07,G08 |
| dump / full source | HL-DT-ST BH14NS58 NS50 / 1.00 / GENERAL | `aaeea1ba97d0` | OEM UHD | none | G07,G08 |
| mk / full source | HL-DT-ST BH14NS58 NS50 / 1.01 / GENERAL | `b65c63e53960` | OEM UHD | none | G07,G08 |
| dump / full source | HL-DT-ST BH16NS40 NS50 / 1.02 / GENERAL | `beb8330e79d0` | OEM UHD | none | G07,G08 |
| mk / full source | HL-DT-ST BH16NS40 NS50 / 1.03 / GENERAL | `547cff99467c` | OEM UHD | none | G07,G08 |
| mk / full source | HL-DT-ST BH16NS40 NS50 / 1.04 / GENERAL | `86a46340da93` | OEM UHD | none | G07,G08 |
| dump / full source | HL-DT-ST BH16NS40 NS50 / 1.04 / GENERAL | `bc4e6126b880` | OEM UHD | none | G07,G08 |
| mk / full source | HL-DT-ST BH16NS40 NS50 / 1.05 / GENERAL | `a9127d5bc310` | OEM UHD | none | G07,G08 |
| mk / full source | HL-DT-ST BH16NS50 NS50 / 1.01 / GENERAL | `2de9ddd7b9d6` | OEM UHD | none | G07,G08 |
| mk / full source | HL-DT-ST BH16NS50 NS50 / 1.03 / GENERAL | `e6ae082bba5f` | OEM UHD | none | G07,G08 |
| dump / full source | HL-DT-ST BH16NS55 NS50 / 1.01 / GENERAL | `ce732330b3ca` | OEM UHD | none | G07,G08 |
| dump / full source | HL-DT-ST BH16NS55 NS50 / 1.02 / GENERAL | `64cff02c3db3` | OEM UHD | none | G07,G08 |
| dump / full source | HL-DT-ST BH16NS55 NS50 / 1.02 / GENERAL | `bdfd6f290ba8` | OEM UHD | none | G07,G08 |
| mk / full source | HL-DT-ST BH16NS55 NS50 / 1.03 / GENERAL | `e086fbe75d4c` | OEM UHD | none | G07,G08 |
| mk / full source | HL-DT-ST BH16NS55 NS50 / 1.04 / GENERAL | `06ac3d3a5037` | OEM UHD | none | G07,G08 |
| dump / full source | HL-DT-ST BH16NS55 NS50 / 1.04 / GENERAL | `394e6f8d6319` | OEM UHD | none | G07,G08 |
| mk / full source | HL-DT-ST BH16NS55 NS50 / 1.05 / GENERAL | `8299344e146a` | OEM UHD | none | G07,G08 |
| mk / full source | HL-DT-ST BH16NS58 NS50 / 1.01 / GENERAL | `fccfc7bd4b70` | OEM UHD | none | G07,G08 |
| mk / full source | HL-DT-ST BH16NS58 NS50 / 1.02 / GENERAL | `9ecb2b6bc379` | OEM UHD | none | G07,G08 |
| dump / full source | HL-DT-ST BH16NS60 NS60 / 1.00 / GENERAL | `580d867cee3d` | OEM UHD | none | none observed |
| mk / full source | HL-DT-ST BH16NS60 NS60 / 1.00 / GENERAL | `93868c4ea14b` | OEM UHD | none | none observed |
| mk / full source | HL-DT-ST BH16NS60 NS60 / 1.02 / GENERAL | `dc6579b6880c` | OEM UHD | none | none observed |
| mk / full source | HL-DT-ST BP50NB40 NB50 / 1.01 / GENERAL | `148d89cc6ea4` | 1959 non UHD | G01,G02,G04,G05,G06 | G07,G08 |
| dump / full source | HL-DT-ST BP50NB40 NB50 / 1.02 / GENERAL | `a344e289e0b1` | 1959 non UHD | G01,G02,G04,G05,G06 | G07,G08 |
| mk / full source | HL-DT-ST BP50NB40 NB50 / 1.02 / GENERAL | `cc7182ac0e56` | 1959 non UHD | G01,G02,G04,G05,G06 | G07,G08 |
| mk / full source | HL-DT-ST BP50NB40 NB50 / 1.03 / GENERAL | `e04aaf44157f` | 1959 non UHD | G01,G02,G04,G05,G06 | G07,G08 |
| mk / full source | HL-DT-ST BP55EB40 NB50 / 1.01 / GENERAL | `4ed5cdc974eb` | 1959 non UHD | G01,G02,G04,G05,G06 | G07,G08 |
| mk / full source | HL-DT-ST BP55EB40 NB50 / 1.02 / GENERAL | `88761a31edd5` | 1959 non UHD | G01,G02,G04,G05,G06 | G07,G08 |
| dump / full source | HL-DT-ST BP55EB40 NB50 / 1.02 / GENERAL | `e64c4ca52445` | 1959 non UHD | G01,G02,G04,G05,G06 | G07,G08 |
| mk / full source | HL-DT-ST BP55EB40 NB50 / 1.03 / GENERAL | `0f7b3d34cbf5` | 1959 non UHD | G01,G02,G04,G05,G06 | G07,G08 |
| mk / full source | HL-DT-ST BP60NB10 NB10 / 1.00 / GENERAL | `04f879f0bf67` | OEM UHD | none | none observed |
| mk / full source | HL-DT-ST BP60NB10 NB10 / 1.01 / GENERAL | `a0dcfbe49365` | OEM UHD | none | none observed |
| dump / full source | HL-DT-ST BP60NB10 NB10 / 1.01 / GENERAL | `fb9174aa2615` | OEM UHD | none | none observed |
| mk / full source | HL-DT-ST BP60NB10 NB10 / 1.02 / GENERAL | `cd10fc7396a2` | OEM UHD | none | none observed |
| mk / full source | HL-DT-ST BP60NB10 NB12 / 1.02 / GENERAL | `1227f133eb1c` | OEM UHD | none | none observed |
| omni / full source | HL-DT-ST BU40N BU40 / 1.00 / GENERAL | `0bd77fed4ec9` | OEM UHD | none | none observed |
| dump / full source | HL-DT-ST BU40N BU40 / 1.00 / GENERAL | `221ad35b7edd` | OEM UHD | none | none observed |
| omni / full source | HL-DT-ST BU40N BU40 / 1.00 / GENERAL | `22edcf493f22` | OEM UHD | none | none observed |
| omni / full source | HL-DT-ST BU40N BU40 / 1.00 / GENERAL | `4c2e0b2d87ba` | OEM UHD | none | none observed |
| omni / full source | HL-DT-ST BU40N BU40 / 1.00 / GENERAL | `734ccb11f0b4` | OEM UHD | none | none observed |
| dump / full source | HL-DT-ST BU40N BU40 / 1.00 / GENERAL | `79e8df06c776` | OEM UHD | none | none observed |
| omni / full source | HL-DT-ST BU40N BU40 / 1.00 / GENERAL | `b2139fd99d7c` | OEM UHD | none | none observed |
| mk / full source | HL-DT-ST BU40N BU40 / 1.02 / GENERAL | `6d8b000f7bff` | OEM UHD | none | none observed |
| dump / full source | HL-DT-ST BU40N BU40 / 1.03 / GENERAL | `64688690a287` | OEM UHD | none | none observed |
| mk / full source | HL-DT-ST BU40N BU40 / 1.03 / GENERAL | `64900e8d6921` | OEM UHD | none | none observed |
| mk / full source | HL-DT-ST BU40N BU40 / 1.04 / GENERAL | `d5113bd8ad97` | OEM UHD | none | none observed |
| mk / full source | HL-DT-ST BU40N MT1959 BU5/BU3 / 1.01 / R? | `5846f3daeac5` | OEM UHD | none | none observed |
| mk / full source | HL-DT-ST BU40N MT1959 BU5/BU3 / 1.01 / R? | `ce1c0acf1678` | OEM UHD | none | none observed |
| mk / full source | HL-DT-ST BU40N MT1959 BU5/BU3 / BN11 / 0? | `c0b346b0e2a7` | 1959 non UHD | G01,G02,G04,G05,G06 | none observed |
| mk / full source | HL-DT-ST BU40N MT1959 BU5/BU3 / BN12 / 0? | `3559077e3c03` | 1959 non UHD | G01,G02,G04,G05,G06 | none observed |
| dump / full source | HL-DT-ST BU40N MT1959 BU5/BU3 / BN12 / 0? | `c4d995f031fe` | 1959 non UHD | G01,G02,G04,G05,G06 | none observed |
| dump / full source | HL-DT-ST BU40N MT1959 BU5/BU3 / BU10 / BUFFALO | `14d86e9949d9` | OEM UHD | none | none observed |
| dump / full source | HL-DT-ST BU40N MT1959 BU5/BU3 / BU10 / BUFFALO | `58203b539de0` | OEM UHD | none | none observed |
| mk / full source | HL-DT-ST BU40N MT1959 BU5/BU3 / BU12 / BUFFALO | `f98acee01998` | OEM UHD | none | none observed |
| dump / full source | HL-DT-ST BU40N MT1959 BU5/BU3 / FR07 / LG-DVD | `4af842c0acf4` | OEM UHD | none | none observed |
| mk / full source | HL-DT-ST BU40N MT1959 BU5/BU3 / FR07 / LG-DVD | `71fef6641146` | OEM UHD | none | none observed |
| mk / full source | HL-DT-ST BU40N MT1959 BU5/BU3 / U100 / 3? | `de24b0003fb0` | 1959 non UHD | G01,G02,G04,G05,G06 | none observed |
| mk / full source | HL-DT-ST BU40N MT1959 BU5/BU3 / U101 / U101 | `7bf0db2cee29` | OEM UHD | none | none observed |
| mk / full source | HL-DT-ST BU50N MT1959 BU51/BU3 / 1.00 / GENERAL | `e98152fe2a7b` | OEM UHD | none | none observed |
| mk / full source | HL-DT-ST CH12NS40 NS40 / 1.01 / GENERAL | `2e3433314276` | OEM UHD | none | G07,G08 |
| mk / full source | HL-DT-ST CH12NS40 NS40 / 1.03 / GENERAL | `b3892226d89d` | OEM UHD | none | G07,G08 |
| mk / full source | HL-DT-ST UH12NS40 NS40 / 1.01 / GENERAL | `2bb0b5833c83` | OEM UHD | none | G07,G08 |
| mk / full source | HL-DT-ST UH12NS40 NS40 / 1.03 / GENERAL | `243a7b0bb237` | OEM UHD | none | G07,G08 |
| dump / full source | HL-DT-ST WH14NS40 NS50 / 1.02 / GENERAL | `648a16d024ee` | OEM UHD | none | G07,G08 |
| mk / full source | HL-DT-ST WH14NS40 NS50 / 1.03 / GENERAL | `44945dad6c56` | OEM UHD | none | G07,G08 |
| mk / full source | HL-DT-ST WH14NS40 NS50 / 1.04 / GENERAL | `0e41ef05cf2e` | OEM UHD | none | G07,G08 |
| dump / full source | HL-DT-ST WH14NS40 NS50 / 1.04 / GENERAL | `164e2475aea2` | OEM UHD | none | G07,G08 |
| mk / full source | HL-DT-ST WH14NS40 NS50 / 1.05 / GENERAL | `60a66592d501` | OEM UHD | none | G07,G08 |
| dump / full source | HL-DT-ST WH16NS40 NS50 / 1.02 / GENERAL | `87790f053877` | OEM UHD | none | G07,G08 |
| mk / full source | HL-DT-ST WH16NS40 NS50 / 1.03 / GENERAL | `a5c1ee575135` | OEM UHD | none | G07,G08 |
| mk / full source | HL-DT-ST WH16NS40 NS50 / 1.05 / GENERAL | `f37fc1b8f61c` | OEM UHD | none | G07,G08 |
| mk / full source | HL-DT-ST WH16NS58 MT1959 JB8/JB8 / 1.V5 / GENERAL | `bed2ef00714d` | OEM UHD | none | G07,G08 |
| dump / full source | HL-DT-ST WH16NS60 NS60 / 1.00 / GENERAL | `5e2ec51fb355` | OEM UHD | none | none observed |
| dump / full source | HL-DT-ST WH16NS60 NS60 / 1.00 / GENERAL | `d13389320939` | OEM UHD | none | none observed |
| mk / full source | HL-DT-ST WH16NS60 NS60 / 1.01 / GENERAL | `29b7f24c55f4` | OEM UHD | none | none observed |
| dump / full source | HL-DT-ST WH16NS60 NS60 / 1.02 / GENERAL | `12c4ee6fb88d` | OEM UHD | none | none observed |
| mk / full source | HL-DT-ST WH16NS60 NS60 / 1.02 / GENERAL | `c5e351d25f64` | OEM UHD | none | none observed |
| mk / full source | HL-DT-ST WH16NS60 NS60 / 1.03 / GENERAL | `3d9011427337` | OEM UHD | none | none observed |
| mk / full source | HL-DT-ST WP50NB40 NB50 / 1.01 / GENERAL | `ed8f1c8414fa` | 1959 non UHD | G01,G02,G04,G05,G06 | G07,G08 |
| mk / full source | HL-DT-ST WP50NB40 NB50 / 1.03 / GENERAL | `592e8d22d98a` | 1959 non UHD | G01,G02,G04,G05,G06 | G07,G08 |
| mk / fragment | HL-DT-ST BU40N BU40 / 1.03 / GENERAL | `f367b4d312e7` | unresolved | unresolved | unresolved |
| omni / fragment | hardware-unknown / revision-unknown / GENERAL | `0db02a9cfba9` | unresolved | unresolved | unresolved |

## Evidence and reproduction

The adjacent CSV/JSON retain source hashes, relative hoard paths, manufacturer-reference provenance, stage observations and unresolved physical checks. G01-G06 media requirements are separate from internal G07/G08 observations. The implementation checkpoint records compiler tests, CPU validation and installer behavior.

```sh
python3 scripts/report-mt1959-uhd-gaps.py --scan internal/docs/audits/mt1959-uhd-protocol-receipts-20261030.json --di internal/docs/audits/mt1959-uhd-di-receipts-20261030.json --keys internal/docs/audits/mt1959-uhd-keys-receipts-20261030.json --out internal/docs/audits
```

All 171 full payloads have source-bound DI, consumer, key and mode receipts. Historical authentication receipts remain diagnostic evidence; their presence does not authorize authentication edits.
