//! Prepare Normal for the Kernel that will actually receive it. A paired update
//! hands off to its incoming Kernel first; a Normal-only update keeps the
//! installed Kernel. The caller must supply a receiver-decoded source image.
use anyhow::{bail, ensure, Context, Result};
use pioneer_optical::envelope::{
    builder::{
        encode_normal_for_kernel, normal_authentication_from_kernel, normal_authentication_valid,
        NormalAuthentication, NormalKeySource, NormalSignature,
    },
    signature::SigningKey,
    Envelope,
};

/// Explain target authentication failures without treating an unsigned capture
/// as corrupt or discarding the library's typed diagnostic cause.
pub(super) fn load_pair(kernel: &[u8], normal: &[u8]) -> Result<pioneer_optical::envelope::Update> {
    let result = pioneer_optical::envelope::Update::load(kernel, normal);
    // Authentication is the final Update gate: this error means the original
    // pair already passed headers, checksums, exact roundtrip and tail checks.
    if matches!(
        result,
        Err(pioneer_optical::envelope::UpdateError::Authentication)
    ) && unsigned(normal)
    {
        let receiver = Envelope::load(kernel).context("decoding backup Kernel")?;
        let signed = sign_for_receiver(&receiver, normal)?;
        return pioneer_optical::envelope::Update::load(kernel, &signed)
            .map_err(super::flash::preparation_error)
            .context("The backup could not be prepared for this Kernel. Choose a matching Kernel + Normal package. No firmware was written.");
    }
    result.map_err(|error| {
        let authentication = matches!(error, pioneer_optical::envelope::UpdateError::Authentication);
        let error = super::flash::preparation_error(error);
        if !authentication {
            return error;
        }
        let reason =
            "The selected firmware's Normal signature could not be verified against its bundled \
             Kernel's requirements. Choose a matching, signed Kernel + Normal firmware package. \
             A nonzero invalid signature cannot be treated as an unsigned backup. No firmware was written.";
        error.context(reason)
    })
}

fn unsigned(bytes: &[u8]) -> bool {
    bytes
        .get(0x170..0x1c0)
        .is_some_and(|sig| sig.iter().all(|b| *b == 0))
}

/// Sign an owned transfer copy, retaining the original key table/ciphertext.
/// In particular, captures need not have a recoverable encoding seed.
fn sign_for_receiver(receiver: &Envelope, bytes: &[u8]) -> Result<Vec<u8>> {
    let signer = SigningKey::random().context(
        "Could not create a transfer signing key. Retry the operation. No firmware was written.",
    )?;
    let mut signed = bytes.to_vec();
    match normal_authentication_from_kernel(&receiver.image) {
        Some(NormalAuthentication::KeyAndCiphertext) => signer.sign_normal(&mut signed),
        Some(NormalAuthentication::CiphertextOnly) => signer.sign_normal_ciphertext_only(&mut signed),
        _ => bail!("This Kernel's backup authentication format is not supported. Choose a matching firmware package. No firmware was written."),
    }.context("The unsigned backup's transfer format could not be signed for its Kernel. Choose a complete matching firmware package. No firmware was written.")?;
    ensure!(normal_authentication_valid(&signed, &receiver.image),
        "The backup's transfer signature did not satisfy its receiving Kernel. No firmware was written.");
    Ok(signed)
}

/// A complete update receives Normal under the incoming Kernel. Update::load
/// supplies the same pairing, integrity and authentication checks as Flash.
pub(super) fn pair(kernel: &[u8], normal: &[u8]) -> Result<pioneer_optical::envelope::Update> {
    let update = load_pair(kernel, normal)?;
    let bytes = prepare(update.kernel(), update.normal(), update.normal_transfer())?;
    load_pair(kernel, &bytes)
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
    let decodes = Envelope::load_with_kernel(bytes, receiver)
        .is_ok_and(|decoded| decoded.image == source.image);
    if decodes && normal_authentication_valid(bytes, &receiver.image) {
        // Preserve the OEM signature and file representation whenever possible.
        return Ok(bytes.to_vec());
    }
    if decodes && unsigned(bytes) {
        let original = Envelope::load_with_kernel(bytes, receiver)?;
        ensure!(original.unrecovered_tail().is_none()
            && original.repack(&original.image).as_deref() == Some(bytes),
            "The unsigned backup does not rebuild exactly or has missing firmware bytes. Choose a complete backup. No firmware was written.");
        let signed = sign_for_receiver(receiver, bytes)?;
        let proof = Envelope::load_with_kernel(&signed, receiver)?;
        ensure!(
            proof.image == source.image,
            "Signing changed the backup firmware body. No firmware was written."
        );
        return Ok(signed);
    }
    if !unsigned(bytes) {
        use pioneer_optical::envelope::signature::{verify_normal_signature, SignatureCheck};
        ensure!(matches!(verify_normal_signature(bytes),
            SignatureCheck::ValidKeyAndCiphertext | SignatureCheck::ValidCiphertextOnly),
            "The selected firmware has an invalid Normal signature. It is not an unsigned backup. Choose an intact matching firmware package. No firmware was written.");
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
