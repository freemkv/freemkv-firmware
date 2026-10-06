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
fn same_kernel_size_does_not_select_a_strategy() {
    let kernel: Vec<u8> = (0..0x11200).map(|i| (i % 251) as u8).collect();
    let normal = [0x33; 0x101];
    let linear = data_out(&[0; 256], &normal, Some(KernelTransfer::LinearFe(&kernel))).unwrap();
    let generated = data_out(
        &[0; 256],
        &normal,
        Some(KernelTransfer::PrefixF0GeneratedFe {
            bytes: &kernel,
            seed: 1,
        }),
    )
    .unwrap();
    assert_eq!(linear.len(), 6); // entry, three FE, Normal, finish
    assert_eq!(generated.len(), 8); // entry, F0 prefix, four FE, Normal, finish
    assert_eq!(linear[1].cdb, [0x3B, 7, 0xFE, 0, 0, 0, 0, 0x80, 0, 0]);
    assert_eq!(generated[1].cdb, [0x3B, 7, 0xF0, 0, 0, 0, 0, 0x12, 0, 0]);
    assert_eq!(generated[3].data.as_ref(), &kernel[0x200..0x8200]);
    assert_eq!(generated[5].data.as_ref(), &kernel[0x10200..0x11200]);
    assert_eq!(kernel[0], 0); // input retained, never overwritten with generated data
}

#[test]
fn invalid_spans_are_rejected_before_materialization() {
    assert!(data_out(&[0; 256], &[], None).is_err());
    assert!(data_out(&[0; 256], &[1], Some(KernelTransfer::LinearFe(&[]))).is_err());
    for size in [0, 0x111ff, 0x11201] {
        let kernel = vec![0; size];
        assert!(data_out(
            &[0; 256],
            &[1],
            Some(KernelTransfer::PrefixF0GeneratedFe {
                bytes: &kernel,
                seed: 0,
            })
        )
        .is_err());
    }
    let too_large = vec![0; 0x100_0001];
    assert!(data_out(&[0; 256], &too_large, None).is_err());
    assert!(data_out(&[0; 256], &[1], Some(KernelTransfer::LinearFe(&too_large))).is_err());
}
