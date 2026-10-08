use super::*;

#[test]
fn linear_chunks_preserve_all_bytes_and_encode_final_fragment() {
    for len in [1, 0x7fff, 0x8000, 0x8001, 0x10000, 0x11200] {
        let bytes: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
        let steps = data_out(&[0xA5; 256], &bytes, None).unwrap();
        let writes = &steps[1..steps.len() - 1];
        let joined: Vec<u8> = writes.iter().flat_map(|w| w.data.iter().copied()).collect();
        assert_eq!(joined, bytes);
        let last = writes.last().unwrap();
        let off = (len - 1) / 0x8000 * 0x8000;
        let tail = len - off;
        assert_eq!(
            last.cdb,
            [
                0x3B,
                7,
                0xF0,
                (off >> 16) as u8,
                (off >> 8) as u8,
                off as u8,
                0,
                (tail >> 8) as u8,
                tail as u8,
                0
            ]
        );
        assert_eq!(steps.first().unwrap().data.as_ref(), &[0xA5; 256]);
        assert_eq!(steps.last().unwrap().data.as_ref(), &[0xA5; 256]);
    }
}

#[test]
fn invalid_spans_are_rejected_before_materialization() {
    assert!(data_out(&[0; 256], &[], None).is_err());
    assert!(data_out(&[0; 256], &[1], Some(KernelTransfer::LinearFe(&[]))).is_err());
    let too_large = vec![0; 0x100_0001];
    assert!(data_out(&[0; 256], &too_large, None).is_err());
    assert!(data_out(&[0; 256], &[1], Some(KernelTransfer::LinearFe(&too_large))).is_err());
}

#[test]
fn arbitrary_kernel_bytes_never_select_a_transfer() {
    for size in [0, 0x111ff, 0x11200, 0x11201] {
        assert!(select_kernel(&vec![0; size]).is_err());
    }
}
