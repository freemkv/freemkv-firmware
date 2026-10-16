//! Prepare Normal for the Kernel that will actually receive it. A paired update
//! hands off to its incoming Kernel first; a Normal-only update keeps the
//! installed Kernel. The caller must supply a receiver-decoded source image.
use anyhow::{bail, ensure, Context, Result};
use pioneer_optical::envelope::{
    builder::{encode_normal_for_kernel, NormalKeySource, NormalSignature},
    signature::SigningKey,
    Envelope,
};

/// A complete update receives Normal under the incoming Kernel. Update::load
/// supplies the same pairing, integrity and authentication checks as Flash.
pub(super) fn pair(kernel: &[u8], normal: &[u8]) -> Result<pioneer_optical::envelope::Update> {
    let update = pioneer_optical::envelope::Update::load(kernel, normal)
        .map_err(super::flash::preparation_error)?;
    let bytes = prepare(update.kernel(), update.normal(), normal)?;
    pioneer_optical::envelope::Update::load(kernel, &bytes).map_err(super::flash::preparation_error)
}

pub(super) fn prepare(receiver: &Envelope, source: &Envelope, bytes: &[u8]) -> Result<Vec<u8>> {
    ensure!(
        source.info().kind == pioneer_optical::ComponentKind::Normal,
        "Normal preparation requires a decoded Normal component"
    );
    ensure!(
        source.unrecovered_tail().is_none() && super::flash_plan::be32_sum_zero(&source.image),
        "Normal preparation requires a complete zero-checksum source image"
    );
    if Envelope::load_with_kernel(bytes, receiver)
        .is_ok_and(|decoded| decoded.image == source.image)
    {
        // Preserve the OEM signature and file representation whenever possible.
        return Ok(bytes.to_vec());
    }
    if source.receiver_xor_exceptions().is_none() {
        bail!("cannot re-encode Normal without its original Kernel's decoding policy");
    }
    let seed = source
        .encoding_seed()
        .context("Normal has no recoverable encoding seed")?;
    let signer = SigningKey::random()
        .map_err(|e| anyhow::anyhow!("cannot create Normal signing key: {e}"))?;
    let encoded = encode_normal_for_kernel(
        &receiver.image,
        &source.image,
        bytes
            .get(..super::IMAGE_MIN)
            .context("Normal has no complete header")?,
        NormalKeySource::Seed(seed),
        NormalSignature::Sign(&signer),
    )
    .map_err(|e| anyhow::anyhow!("cannot encode Normal for its receiving Kernel: {e:?}"))?;
    let proof = Envelope::load_with_kernel(&encoded, receiver)
        .context("re-encoded Normal does not decode under its receiving Kernel")?;
    ensure!(
        proof.image == source.image && super::flash_plan::be32_sum_zero(&proof.image),
        "re-encoded Normal differs from the source firmware"
    );
    Ok(encoded)
}
