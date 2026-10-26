# MT1939 parameter and DI mode validation

Development evidence; standard/public UHD conversion remains gated. No physical UHD-reading claim.

The parameter getter has two positively matched profiles across the 24 held classic images: 18 media-selected getters require routing C7/On to their own native C8 coefficient table; six state-independent getters already use the same table for C7/C8 and require no parameter patch. Native rate selection and calibration values are retained.

Current local execution results (uncommitted library path dependency): 58,752 routing comparisons, 7,680 arithmetic cases, 7,488 full parameter-getter cases, 345,648 native DI cases, 1,332 saved parent returns. All 24 inputs passed. Library all-features unit results: 171 passed, three ignored; integration and documentation tests also passed. Clippy all targets/features passed. These results require reproduction from the final pinned commit before delivery.

Remaining concrete DI initialization difference: modern comparison source 648a16d0 at e079c accepts C8-mask states or explicit C7 for native mode 0x1c (CC selects 0x15), otherwise mode 7. Classic comparison source 40eb760e at 10a0c4 has only the C8-mask condition. The native selection body, common store and subsequent call are structurally equivalent. A strict instruction survey finds exactly one classic pattern and a saved native LR/frame in each of the 24 sources. Runtime selection must use that code grammar and common state binding, not these documentary source addresses.

The DI mode hook is now implemented and passes all 1,024 state/setting cases on BH16NS48. A source-bound read-boundary hook also passes 48 full native reflection cases on that image. Its displaced sequence contains a PC-relative literal load between BICS and BNE; copying that load verbatim into the stub would be wrong. The contract binds the loaded destination and the emitter relocates the load while preserving native flags/registers. Remaining downstream consumers still require classification before a tester BIN is considered ready.
