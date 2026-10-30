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

## Native read-position decoding and ranges

The complete legacy 103668..1037b4 routine matches once in all 24 inputs. A new source-bound contract identifies the decode gate, native first-layer reflection body (0x7fffff), native zero-layer path, both 0x22/0x1c range selectors, shared state/position/layer/cache cells and saved frames. C7/On now selects the first-layer body only when position byte 2 has upper bits 01; other C7 classes clear the layer through the native path. Both range gates include C7. OEM/Off replay the original decode and range conditions.

BH16NS48 passes 77,824 routing cases and 70 parent-return cases with these additions. A full-native comparison executes legacy and modern decoder bodies and compares position word, current-layer byte and range-status bit: 3,072 combinations of high position byte, low word, layer/cache state and feature flag pass. Native logging and the modern controller notification call are intercepted; their arguments do not define those compared outputs. The reference code and literal-pool excerpt is recorded under tests/fixtures/mtk-uhd-read-position-modern.json with source and part SHA-256 hashes. Physical controller/optical behavior remains unproven.

## Native read-controller selection

Modern 648a16d0 dc7ea and classic 40eb760e 106a62 select the same native 0x042080c0 programming body: set bit zero at offsets0x18/0x28 and clear lower nine bits at0x1c/0x2c. Modern includes C7 when its separate calibration flag is zero. The classic C8 body is retained as the baseline policy, without copying the modern flag producer. The new ReadControl contract binds the source state cell, preceding controller-pointer load, BICS/LDR/conditional sequence and native continuations. The displaced register-relative LDR is replayed, not treated as a PC literal. It matches once in all24 inputs. BH16NS48 passes128 native register-state comparisons against its own C8 behavior for C7/On and its original behavior otherwise. The signed internal probe with23 components passes integrity and offline flash admission.

Remaining position-setup counterpart identified: classic fc848..fc954 corresponds to modern d82f0..d840e. The classic input selector atfc85e quarters the working position and table term for C8; modern includes C7 atd8324. The classic command selector atfc8c0 chooses0x14 versus0x0a; modern includes C7 before its0x14 write atd837c. Both need the same source-bound treatment as the already implemented separate position getter, rather than transplanting newer calibration-flag behavior. A complete-routine grammar survey is underway.

## Paired position-setup selectors

The complete legacy fc848..fc954 routine matches once in all24 images. ClassicPositionSetup binds its shared state, working-position cell, native mode/table, hardware controller, polling loops, result correction and both saved frames. C7/On now uses the existing C8 quarter-scale input/table term and existing0x14 command parameter; OEM/Off keep the original selectors. No newer calibration-flag producer or numeric table is transplanted.

BH16NS48 passes360 full-native routine comparisons across six media states, four feature settings, five position inputs and three native modes. The test compares returned value and every controller write at offsets0x10/0x14/0x18 against native C8 for C7/On and native original behavior otherwise. Controller completion is simulated. The signed internal25-component probe passes branch/byte, integrity and offline flash-admission checks. Library all-features unit tests:175 passed, three ignored; integration/doc tests also pass. Full24-image execution and the expanded195-image contract inventory are running.

Previously identified independent mode writer: classic6799a..679b4 corresponds to modern688e6..68908. The classic media-default routine first writes mode7, then replaces it with0x15/0x1c for C8-class states. Modern additionally includes C7 for0x1c. This must be handled separately from the DI-mode selector: otherwise the native defaults routine can overwrite C7's mode with7. The next contract must bind the shared state and both native branches to the common STRB mode store, plus the rejection join after that store, allowing pool movement without model/hash dispatch.


The independent media-default writer is now source-bound and extended for C7/On. Its two native mode-selection branches must reach the same STRB store, and the rejection's unconditional branch chain must join immediately after that store. The source caller's mode-cell load is separately validated. All24 images have one matching grammar. BH16NS48 passes3072 complete mode-store cases covering all256 media states, four settings and three initial modes. C7/On writes0x1c; other inputs preserve native mode selection. The signed internal26-component probe passes integrity and offline flash admission. This closes the mode-overwrite issue; remaining controller/error-recovery/speed-policy consumers are still being classified before hardware-test readiness is claimed.

Speed follow-up: [native speed-policy audit](mtk-speed-policy-20261026.md) closes
speed-policy validation across all 24 classic images and 171 modern comparisons.
Retain the native image-specific limits and requested-rate clamp; no blanket rate
rewrite is justified. This does not close the remaining recovery/controller work
or promote the internal conversion probe to hardware-test readiness.

Completion follow-up: [complete experimental software group](mt1939-complete-uhd-software-20261026.md)
binds the remaining paired controller fields, the separate read-completion
boundary body and native ROM recovery dispatch. The known software-contract gate
is now complete across all 24 inputs; production installation and physical UHD
reading remain separate from the offline evidence.
