# MT1939 parameter and DI mode validation

Development evidence; standard/public UHD conversion remains gated. No physical UHD-reading claim.

The parameter getter has two positively matched profiles across the 24 held classic images: 18 media-selected getters require routing C7/On to their own native C8 coefficient table; six state-independent getters already use the same table for C7/C8 and require no parameter patch. Native rate selection and calibration values are retained.

Current local execution results (uncommitted library path dependency): 58,752 routing comparisons, 7,680 arithmetic cases, 7,488 full parameter-getter cases, 345,648 native DI cases, 1,332 saved parent returns. All 24 inputs passed. Library all-features unit results: 171 passed, three ignored; integration and documentation tests also passed. Clippy all targets/features passed. These results require reproduction from the final pinned commit before delivery.

Remaining concrete DI initialization difference: modern comparison source 648a16d0 at e079c accepts C8-mask states or explicit C7 for native mode 0x1c (CC selects 0x15), otherwise mode 7. Classic comparison source 40eb760e at 10a0c4 has only the C8-mask condition. The native selection body, common store and subsequent call are structurally equivalent. A strict instruction survey finds exactly one classic pattern and a saved native LR/frame in each of the 24 sources. Runtime selection must use that code grammar and common state binding, not these documentary source addresses.

The DI mode hook is now implemented and passes all 1,024 state/setting cases on BH16NS48. A source-bound read-boundary hook also passes 48 full native reflection cases on that image. Its displaced sequence contains a PC-relative literal load between BICS and BNE; copying that load verbatim into the stub would be wrong. The contract binds the loaded destination and the emitter relocates the load while preserving native flags/registers. Remaining downstream consumers still require classification before a tester BIN is considered ready.

## Paired native position scaling

Further comparison of modern 648a16d0 d840e..d84b6 with classic 40eb760e fc954..fc9f0 confirms explicit modern C7 inclusion in both the quarter-scale input and doubled-result selectors. The complete classic routine (including polls, native stores and return) matches exactly once in all 24 images when only PC-relative literal displacements vary. The new ClassicPosition contract passed the 195-image optional inventory test; four provenance-bound snippet fixtures include positive and negative tests.

BH16NS48 execution of both emitted selectors passes 69,632 local routing comparisons and 66 saved-parent returns. A separate full-native-routine test passes 192 input/state/setting combinations, comparing C7/On against native C8 and all other cases against their original native behavior. Controller completion is simulated and the programmed input is echoed; this proves the software scaling/control flow, not actual optical controller behavior. Remaining consumers, final pinned CI, signing/placement and tester instructions remain open.

## Startup calibration selection lead

Modern 648a16d0 db262..db27c selects C7's table at native base+0x64; the classic 40eb760e corresponding path 104452..104458 unconditionally uses base+0x58. Classic base+0x64 is unrelated packed data, not another halfword coefficient table. It must not be used by offset analogy.

The classic startup table base+0x58 equals the parameter getter's OEM coefficient table (1a6f16 in the reference). Its speed classifier uses thresholds 3,4,6,8,10 and a sixth fallback, then computes R6=index*2. The native C8 getter table's first six rates share those indices. This provides a candidate source-bound reuse of the native C8 coefficients for the media-selected profile, without copying modern calibration constants. State-independent getter profiles already return their same native coefficients for C7/C8 and should preserve those.

A full startup-routine grammar survey (1042bc..1044a6 in the reference) matches once in all 24 inputs, masking only PC literal and native call displacements. This is a placement lead, not an implemented calibration hook or proof of hardware behavior.

Startup calibration is now implemented as a separate, source-bound lookup detour. The complete startup grammar and getter rate/coefficient relationship bind selection; media-selected profiles reuse their own C8 table, state-independent profiles emit no extra hook. BH16NS48 passes 3,072 lookup cases across all six indices, eight media states, four feature settings and sixteen incoming flag combinations. The test verifies the selected halfword, every other general register, native arithmetic flags and stack balance. The signed internal placement probe now installs 19 components and passes branch/byte, integrity and offline flash-admission checks. It remains explicitly not ready for hardware testing while remaining consumers are audited.
