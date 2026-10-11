use super::*;
use crate::backend::Backend;
use crate::backends::pioneer::Pioneer;
use crate::platform::MockScsiDevice;
use pioneer_optical::cdb;

#[test]
fn read_device_refuses_undeclared_data_out() {
    // No declared unlocks: every data-out is refused before it reaches the drive.
    let mut mock = MockScsiDevice::new();
    {
        let mut dev = ReadDevice::new(&mut mock, &[]);
        assert!(dev.command_in(&cdb::inquiry(96), 96).is_ok());
        let error = dev.command_out(&cdb::knock(), &[]).unwrap_err();
        assert!(
            format!("{error:#}").contains("refused data-out"),
            "{error:#}"
        );
        assert!(dev
            .command_out_strict(&cdb::enter_update(), &[0; 256])
            .is_err());
    }
    assert!(mock.writes.is_empty());
    assert_eq!(mock.reads.len(), 1);

    // Pioneer declares only its read-unlock knock.
    let mut mock = MockScsiDevice::new();
    {
        let mut dev = ReadDevice::new(&mut mock, Pioneer::new().allowed_data_out());
        dev.command_out(&cdb::knock(), &[]).unwrap();
        assert!(dev.command_out(&cdb::enter_update(), &[0; 256]).is_err());
        assert!(dev.command_out_strict(&cdb::finish(), &[0; 256]).is_err());
    }
    assert_eq!(mock.writes.len(), 1);
    assert_eq!(mock.writes[0].0, cdb::knock());
}

#[test]
fn read_device_refuses_zero_length_session_commands() {
    // The MediaTek transport sends no-data commands as zero-length data-in, so
    // PREPARE and COMMIT must not slip through a read-only handle that way.
    use crate::backends::mtk::{cdb as mtk, Mtk};
    let mut mock = MockScsiDevice::mtk();
    {
        let mut dev = ReadDevice::new(&mut mock, Mtk.allowed_data_out());
        for refused in [&mtk::enter_update()[..], &mtk::finish()[..], &[][..]] {
            let error = dev.command_in(refused, 0).unwrap_err();
            assert!(
                format!("{error:#}").contains("refused no-data"),
                "{error:#}"
            );
        }
        dev.command_in(&mtk::test_unit_ready(), 0).unwrap();
        dev.command_in(&cdb::test_unit_ready(), 0).unwrap();
        // A data-in with a data phase is not this check's business.
        dev.command_in(&mtk::probe(), mtk::PROBE_LEN).unwrap();
    }
    assert!(mock.writes.is_empty());
    assert_eq!(
        mock.reads,
        [
            mtk::test_unit_ready().to_vec(),
            cdb::test_unit_ready().to_vec(),
            mtk::probe().to_vec()
        ]
    );
}
