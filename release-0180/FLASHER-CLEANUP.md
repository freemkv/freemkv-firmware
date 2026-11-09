Flasher backend cleanup — source frozen for root integration

Behavior and ownership:
- package.rs dispatches recovery selection, member listing and image wrapping through FileFacet. MTK discriminator/member/manifest/CMAC logic is backend-owned; malformed claimed packages retain backend validation errors.
- cmac.rs, probe.rs and mediatek_package.rs are compatibility exports; implementations live in backends/mtk/{cmac,probe,package}. Existing Modify callers remain source-compatible.
- imageid.rs and flashset.rs are compatibility exports; signatures and historical recipes/tests live in backends/catalog. This is informational legacy data, NOT a third protocol backend, and never authorizes writes. Registry owns fallback report/family access; shared engine and inspection contain no vendor family branches.
- Crossflash keeps shared route composition/types. Pioneer owns ProductCode binding, typed refusal classification and fallback platform signatures. MediaTek owns package-stage evaluation. Registry dispatches those operations and unsupported-backup-layout classification.
- Shared discovery retains INQUIRY, arbitration, timeout/rejection behavior and diagnostic aggregation. Vendor probes/parse are in each backend's detection.rs, called through registry in unchanged order.
- Pioneer identity/read command sequences moved to its transport.rs. Shared transport retains SCSI adapters and compatibility exports. Standard MMC remains shared.
- Engine's MTK BackupArtifact import was TEST ONLY; moved into engine_tests.rs, not replaced with a needless new artifact abstraction.

Changed-file groups:
backend/{mod,registry,detection}; backends/{mod,catalog/*,mtk/{mod,cmac,package,package_selection,probe,routing,detection},pioneer/{mod,routing,detection,transport}}; compatibility root modules {cmac,probe,mediatek_package,imageid,flashset}; root {package,crossflash,transport,engine,engine_tests,user_error,inspection/mod}; MTK implementation imports {backup,file_info,fixture_tests,fwdump,inspect,inspect_tests}; Pioneer flash compatibility catalog import.
Original root imageid_tests.rs and flashset_tests.rs moved alongside implementations. Include untracked source files when syncing.
Root's MTK Current files flash.rs, receiver_reference.rs, recovery.rs, stage_tests.rs were not directly edited. cargo fmt --all may format shared working tree.

Validation:
cargo fmt --all passes. Root owns combined clippy/build and targeted tests with external local dependency patch. No build/test suite/device operation/commit/push performed by this worker.
Focused filters (cargo test -p freemkv-flash --lib FILTER):
package::tests::malformed_owned_package_retains_backend_validation_error
package::tests::member_selection_cannot_be_applied_to_an_unowned_input
backends::mtk::package::tests::
recovery_requires_tar_for_standalone_pioneer_components
crossflash:: (small existing shared route/status/input tests)
backends::catalog::imageid::tests:: (moved signature tests)
Existing protocol detection arbitration tests should be included by root's detection filter.

Architectural exceptions preserved intentionally:
Typed vendor Evidence variants remain in backend/detection contract, public legacy module names remain thin exports, and historical catalog reports still describe unsupported formats. No vendor dependency enters production GUI/CLI/workflow/engine decisions.
Final ownership refinement: MTK detection owns BOOT normal-operation eligibility; MTK routing owns the allowed single-stage route and multi-stage evaluation calls it locally. Registry only delegates these policies. Probe let-and-return locals removed before root clippy.

Root integration completed: removed duplicate package parsing, routed compatibility exports through registry, made shared inspection/CLI guidance generic, and preserved source tripwires at relocated helper/probe paths. Focused behavior, discovery, backend boundary, write-grant and adapter tests pass. App delta is net +255 lines including tests/docs; most patch volume relocates existing code. Workspace fmt/clippy/build pass. Details and exact source hashes are in STATUS.json.
