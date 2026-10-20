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
    #[cfg(test)]
    recorded_transfer_authentication(receiver, &mut signed)?;
    Ok(signed)
}

/// A complete update receives Normal under the incoming Kernel. Update::load
/// supplies the same pairing, integrity and authentication checks as Flash.
pub(super) fn pair(kernel: &[u8], normal: &[u8]) -> Result<pioneer_optical::envelope::Update> {
    let update = load_pair(kernel, normal)?;
    let bytes = prepare(update.kernel(), update.normal(), update.normal_transfer())?;
    if bytes == update.normal_transfer() {
        Ok(update)
    } else {
        load_pair(kernel, &bytes)
    }
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
    #[cfg(test)]
    let encoded = {
        let mut encoded = encoded;
        recorded_transfer_authentication(receiver, &mut encoded)?;
        encoded
    };
    let proof = Envelope::load_with_kernel(&encoded, receiver)
        .context("re-encoded Normal does not decode under its receiving Kernel")?;
    ensure!(
        proof.image == source.image && super::flash_plan::be32_sum_zero(&proof.image),
        "re-encoded Normal differs from the source firmware"
    );
    Ok(encoded)
}

// Exact captured authentication for golden tests only. Every key covers the
// receiver policy and ALL remaining transfer bytes; production still creates
// fresh keys/nonces. Validate the real signer before substituting, then validate
// the recorded signature independently against the receiving Kernel.
#[cfg(test)]
fn recorded_transfer_authentication(receiver: &Envelope, bytes: &mut [u8]) -> Result<()> {
    use sha2::{Digest, Sha256};
    ensure!(
        normal_authentication_valid(bytes, &receiver.image),
        "fresh transfer authentication failed"
    );
    let policy = format!(
        "{:?}",
        normal_authentication_from_kernel(&receiver.image)
            .context("missing receiver authentication policy")?
    );
    let mut hash = Sha256::new();
    hash.update(policy.as_bytes());
    hash.update(bytes.get(..0x170).context("short transfer header")?);
    hash.update(
        bytes
            .get(0x1c0..)
            .context("short transfer authentication")?,
    );
    let key = format!("{:x}", hash.finalize());
    const FIXTURES: &[(&str, &str, &str)] = &[
        // 8301/ID43 BDR-S08 :: flash Normal-only package
        ("CiphertextOnly", "9cbe3765d7bb4ef3f340176cbc5a911deb5e46e3be659456b35890e89da86034", "cc638f6ee39d5d268ca8526b68045666625c6cd6277ce663e2dab211e6ca6e46657231da445528754e3d5e1913913041075bb75440870e4d3e9fd014236d305194fd5927acaab4311023305d404027ea"),
        // 8301/ID58 BDR-208M :: flash Normal-only package
        ("CiphertextOnly", "ac8d18db685cc35be321826a62a79282238977f47e41fdd83d133e36049e2070", "25e2274f4397f620c855e6490f1854f84c1a7b0b1b7ad65581e291c9f9041e122ac10034591068d47325018c5039cdfe23211a5119aaf5571d1d1d8595481e7ef59a460c5cae4846ea3cef34adbf6acf"),
        // 8301/ID60 BDR-208M :: flash Normal-only package
        ("CiphertextOnly", "4c151d94989030a8f7a32775a1d47a9090cb10f74924937994aad2e8dc5d11b9", "8c6c5466c4cca10f7b8bb7cc96483990f3fcbb198ad73928dc9cf6e1b1cee4a1fb79441ac096c037b5b8c864041470112533b3a3becc30925411e1a21717f97daaf1e4321c38252fcac977bb6933c244"),
        // 8301/ID81 BDR-208 :: flash Normal-only package
        ("CiphertextOnly", "a6ecb9fdf31b5efdbe1a501cd994d29fa8c453759ec6e7f37749ba245db99f8e", "2d892a5b1e38d067572155d2d9187ba3475e61174172034c39d5cc94ad3920a9cc7eebaa9d12409c73040782f5d8853efcb893a3c79dd6d6d2ca72e8762dad506ca103d7997973170a86698b08bc354c"),
        // 8600/ID43 BDR-S09 :: flash Normal-only package
        ("CiphertextOnly", "9482af77f3c3b9c2eafc20b9495a03abb68f0d9d10d2ef4f421035f5b6476b93", "c0362510b7c27dea8a5a80c5a0df4c17552fd4e801d599cac8dfa81889db65e1bfa11c343365f484c2a76d68d3c6cc7b9eff53b830212cf8888758e404d09f83d8fbc10e32a9a7d288dfc2e9d97b7196"),
        // 8600/ID58 BDR-209M :: flash Normal-only package
        ("CiphertextOnly", "a1836371a6be022b91fff243b86c6f7b529ece9943f8deb64494b0c76735aae4", "4b1799b93d99aa767227da7e2ccf8f42ed77054fb6f6c0598f37a67f335240485de697f6193fa04290ca3028e20abfe88a0084b15f25d234c9a783c74b99c31ed88e60a64639c0d37bd151e3e33a864e"),
        // 8600/ID60 BDR-209M :: flash Normal-only package
        ("CiphertextOnly", "118b9cb038e159c138d81f6161d0255352356e92aa8e5345511888f3def4d990", "8fd160e681f293542600ff8100ce02f90de008cc25cc497d17846e8101dfcfb69b10195ff90f46360f500b13892ced323023b88cb03a973974bbdedf2e63cdd01c55ef9a6e298c7bb01240c49405a654"),
        // 8600/ID72 BDR-S09JX :: flash Normal-only package
        ("CiphertextOnly", "e6cd5f419900a1ff9f50cc814f525532bdc12494346f81b55d19743fc20b259c", "ab13413f3114f2a9eb86601ac059a59a9e034559104352a0a78f848fbdb1a148d21315c3884e91bdc8557b0126aa5a78159a79f519f270f288f47255a47d10eed29d0abaaac00eebff28a3f0c2f30bb2"),
        // 8600/ID81 BDR-209 :: flash Normal-only package
        ("CiphertextOnly", "4a7e50464cff72bab7781723edba34fdc54b5b92f0584f4fcdc613ce9566650e", "560749781bdd5df526da00b75beb64f8582e4ec4d61f9300d07db74762f2ef0fbcebf0b0fa95185a8313a9cce7b2150bb00747665eb444b9887604a452b1b0090fe900eb9184f24ec954439a600b91ef"),
        // 8601/ID43 BDR-S09 :: flash Normal-only package
        ("CiphertextOnly", "bf49c91db8ea19364148de6f920e64acf1233018b828c4d543a1dd096a956856", "c8c38e79f34e2a8b1399c83514fa9bd451906a05d34689846715ddf3dc009776e3d1076c5364bc25423a72c9082fecc3eee74b6088fba3bf7d596b6f4b52a91acbfb973d8705c070b6ca6cef92162e0c"),
        // 8601/ID60 BDR-209M :: flash Normal-only package
        ("CiphertextOnly", "5093809ed5acdf91032b339c7982922163fc70df7517eea5b091b6772b8fef6c", "1ede9c67cf43c275d30e6fc991677ffa10c79c2cd0c8ec87277f11e1d989b8d6347df09ed0c8402b4eeba86b098a19eec0fb67decda3b2d1e95ee93ec655057040fd407d8c3b26e4ae838077bf6f5484"),
        // 8800/ID43 BDR-S11 :: flash Normal-only package
        ("CiphertextOnly", "12c259bd2166525a3d2205def256739ebf0a5123cb62e7c3ea26878460b0bc5f", "c6f50397c7acce44370ac7256535f46c647ace13bee0867a5937896ae780a633fbfc5e536c4bf7616fda45fde5372fe90014c960ec8be9ea33b5262039bf45a685d4f023cc82e007a6af3db9428a9d26"),
        // 8800/ID58 BDR-211M :: flash Normal-only package
        ("CiphertextOnly", "ed1abbccbb14ee1382db2157c2b092440fc8e3ec2fb8c9a70eeb7986e94af5e0", "80f4ed132e5f0178b88cc809ac8d621c6145afc4b6cf1e02fa0fc999989c4205e3c8e650e38ad0740fcd0725247200d0b259da3d3918200246db8341aba61d6da87f322f23a0f7a233b92746b8506239"),
        // 8800/ID60 BDR-211M :: flash Normal-only package
        ("CiphertextOnly", "95ae244b624d34b24ccae889507eee00ec05349d04fb5a3861f4e9a78a2c392f", "2732f5b762e9e4145f8f4a8225af211fbbb72311b3731f73854c0cdceb55f25b24b51e782c1fc8fd31716309df79a80b27a411c1f765656e1f4925de7be6799245253d8db715b0bc24f3de84b302c36c"),
        // 8800/ID72 BDR-S11JX :: flash Normal-only package
        ("CiphertextOnly", "5573acfe3cab819242caeb4fbfc3ce01fa3fc013bab651e6b2ae8da107f5bfae", "63582c1c8e2e9b6c70dbcc935837fc272dadd84ccacec0aa9f0f68814bdb80368726109b9e34a068af0bb611173af8b59b77c00df3d924756604b2c8ac7dc81d7a2232c6ee6ed24a5ec2e7e570837f2d"),
        // 8801/ID43 BDR-S11 :: flash Normal-only package
        ("CiphertextOnly", "63033dc8f6c373d82d69404fb8064362b70125709e4839941b5ee7c273bd9a5f", "1e992e4d8b7ad5494fbd99037677b6a037074d2a0622af60dadd797a726955794e5b8969732db62d7430d4bed35b275e353167fc495b0405d11aa5cfb36be1bfd0b6033f91a286e44a4b83faadb2068e"),
        // 8801/ID58 BDR-211M :: flash Normal-only package
        ("CiphertextOnly", "eec407f4293d0a6cfdf639bc65a7381ecdcf860867118d0a8fbc48652bb34e17", "4182691f8c7dff1bdca324928a46af2349a60ac505a2c73b0698688e7d73f8d4492577b3b2eb9fbfa730e4a38ec4169e292d660146c86cd32c10464580c4d915fe62a4f65ad4572e15dc92427edb5af6"),
        // 8801/ID60 BDR-211M :: flash Normal-only package
        ("CiphertextOnly", "ecfb3db2ecde0155b12c30c3d8666f98ab6e970d6bbc5d42066ecf3bd31c28a7", "108e102b10e64e52e9a001fbdb31c6795a9da61e262070634d8890133a9457c11ab91978b19be6ea49546465533e50a78b21e3d1ce0ed916e4b42d566c6a0011ec2ac71690d2ed293b749a1ca1a5ef11"),
        // 8801/ID72 BDR-S11JX :: flash Normal-only package
        ("CiphertextOnly", "e0be850c4db2124856c51423b12e228e2a36f42b102dc35d977dd37eac1f219b", "406b3b3ec2335682f18470dde3bb52f4d44781423f09e76a923499fe30d258a3f9f845e0e36abc5416aa4e26ab541edbb27709a4f8c1af6e38b0e188dd8f8cf7de86b8cddf544fb8d82ae2a0c97b7bc7"),
        // 8D30/ID32 BDR-AD07 :: flash Normal-only package
        ("CiphertextOnly", "b154a15701fc6536f627bd7c6c211dd468c37bfe725ec3e5a8e40071e864dc9b", "2dd26cffeeea29ff7431b81f3c22606ccfdfc9dec6b0b21c61ffdc7028c8ab8f0da43fbbe2550a9f2b5685059319cd1d0a04d21e7858d1c4208308bb6cd84ad57e4b4b7586049efd6019b5a0d5591b57"),
        // 8D30/ID35 BDR-XD07 :: flash Normal-only package
        ("CiphertextOnly", "c30e8f0efe3b14154ff8628d53cfafbeeccecc8f9c0591bbe42844622c529961", "52334304165fe4285366e87ab5aa08f410e0dfaf4d0ad101427f2df75d83f1f159c90b6eea39371b8a3f869f954a5ea1d4ede77ddc55a1f965aefd6878714939264c8d25824ad9cec2d491e9bb8ed907"),
        // 8D30/ID36 BDR-XD07 :: flash Normal-only package
        ("CiphertextOnly", "3a27e9c2c0ab3b48e5db1dacbc4f39c5bdf31f9754c01935bce64c853c350897", "1fb3471b500d9cd6a51a65b8dd622034bf72982ad755e2d87c646d0253a72adee3c967e4f17e611710226ad0237c904a8817d29076f2df077fab34251f74d0407433f21db42fa74376c33f72b031e36d"),
        // 8D31/ID69 BDR-XD07U :: flash Normal-only package
        ("CiphertextOnly", "b7fe4078ac692829ba680db85eca58e2886762dc70566503f55eb353cc77c68c", "bd668760bf62887d7352a0fa3f2362c0f15d65ba18c6ff37ec14f27b951ed8a48d8c9071fafd0abb202a86834dc93d6491327896c91d32964e520da5502e8941030ce92c2691f82d9d203e4c344a3c3e"),
        // 9000/ID15 BDR-X12 :: flash Normal-only package
        ("CiphertextOnly", "6d9c44a075b87bd6b9d13341ba4f9839d816780a7fef66324c8393764e3b8692", "24cde25040acf5665c24e226800f4aedf15030418aea03153e951ae663445e875802b1577c60aa9fa79f5664e086e3a20d59b1e72bf659f0ed6507468b07a4ab7e474d9d208e145074468ef9f817f935"),
        // 9001/ID43 BDR-X12U :: flash Normal-only package
        ("CiphertextOnly", "63fd8c7d425292253c630cf365d86a618e7464805543b1b5adb5c63cc6d42867", "39b5815988ff1876a2d5261b61cbe888e3815f6b8c9024a6910525f0830ed9ad252d7fd207eb1ece9f0bcb153df1c43ace084fe36238ab2cb99c32ebd8d43476f8cb31cbcac89faac674dceae658fda6"),
        // 9200/ID56 BDR-213M :: flash Normal-only package
        ("CiphertextOnly", "44349d37d136e7bfb3b644233c3f1a08623758c93c6e2d7113fa041f6119118e", "d0bff0d48c71612114b23080165cae2118ba0b6891056c21f3241eb8d58415def95532db16588fd9665592b3c5f1cf2a9353b053b6f02e4b5d05c8a20fabc59c6452fdc336750d2ad1c44e17d85eb300"),
        // 9330/GENERAL BDR-XD08 :: flash Normal-only package
        ("CiphertextOnly", "af5ef80fe73d243fe4a6059d124c8445670ae4e0a3196c6966b11997b9303931", "d3926d093a9eaf0a952dbd5904087af74ccd2c82e03304ee70fbd2b9ac05e4621d84874d85bcf29714cf02af8f025c2b1057d995d9220214ab2ad97a530d260c165628a6873fa4e66884da95e63e167e"),
        // 9330/ID32 BDR-AD08 :: flash Normal-only package
        ("CiphertextOnly", "466faa248195049b083b2cf1769a436927d61d833e233425092bc0bea7b7219e", "266064e7cd759a097d9a3a7211aec21847fa25dc357db62b2a1c7e2569f6a976d8c44d5b60f0dea411b25a1463c2852b6341315b95b5a300a0c9e37a898577aefe695d1504569a78b53cd3d1eee46357"),
        // 9330/ID35 BDR-XD08 :: flash Normal-only package
        ("CiphertextOnly", "61d4eafaadb2d17605d4caa87593ce66a7a519edef4f61fb898560cd0dfd641a", "b0b9f86d93b2f3a30981f23abd79689a8c4832db0f0f7beafd68cffdca5ba36249ca64dd91951bfd1bc55b5c8c581ff3ed9bebf33545832949cba4956240196c6d2833bdb57d00c94eb0899f77543795"),
        // 9330/ID36 BDR-XD08 :: flash Normal-only package
        ("CiphertextOnly", "f77779319e57ac60fac5a0d18e9cf7b2fb219d5b4b6d1f4e6d838cb502790025", "a2849b501b796d9ce2bea50eb30756726441a49654db770c75f76c3d0e2ff08331eefbbea5a111fcd7db257167f3042ef5cb426ecd4ce281bc9bc445c28d1e46dac47f72d5289006b7434d5a747f6d00"),
        // 9331/ID05 BDR-XD08U :: flash Normal-only package
        ("CiphertextOnly", "ba44b27aaa5a93124531722aba32d0480beff123596350119e4d268c00b70c39", "1f115a9936f4867c312fe98880bff56459462b9a118bbb98e5bf9a21beb4eb609fc7f348ce4161b05b94e0008103daf77ae95f74f3e78dc74467b0c936c32f8dcbe0547fed1a8fe05e5c9956f62359e8"),
        // 9331/ID69 BDR-XD08U :: flash Normal-only package
        ("CiphertextOnly", "2a47756d27bf3ef36c822309663de317ae97819dbaf5af26c04160810760f567", "2c08674d87d91bef2af57ee7e7cbaf38f36b53b2d00b0e021c1b867a335cc98628e0e37326293c0d87728ad8697a30c4aa3c4ffdccb77a708e2c439d23b48e04eba2beffeef3bec262e22d385a2c9a2e"),
        // 9400/ID56 BDR-X13 :: flash Normal-only package
        ("CiphertextOnly", "080b51a2f2aab7708efbe235a63ec5fae85edd286482df6c8ce1c37060cdef24", "7e81cae77e1b0c46db9f6733ba3f049a9978fcb61858096c5ad84e45c566774469fe8f62aae15ec10c0a2d513d3d279e41ea68a4daf10d4fe71ba48412d46ef7f4437a7b82a8eae21042c7a99fc78e02"),
        // 9401/ID29 BDR-X13U :: flash Normal-only package
        ("CiphertextOnly", "c26242caca91b9323f8ab3dd197531d95364524d64fdc19c18855668f58a664f", "7f0efab930610257f56942c8ca3e2163852c3c4674ea851449e53069071d71f3210fa9f2efc12cf116aeea908d8ba19b55970114b940c1b9405756024c4f0cf8a25e93758e7d132d661782b68319d19f"),
    ];
    if let Some((_, _, signature)) = FIXTURES.iter().find(|(p, h, _)| *p == policy && *h == key) {
        ensure!(
            signature.len() == 160,
            "recorded authentication must contain exactly 80 bytes"
        );
        for (i, pair) in signature.as_bytes().as_chunks::<2>().0.iter().enumerate() {
            bytes[0x170 + i] = u8::from_str_radix(std::str::from_utf8(pair)?, 16)?;
        }
        ensure!(
            normal_authentication_valid(bytes, &receiver.image),
            "recorded transfer authentication failed"
        );
    }
    Ok(())
}

#[cfg(test)]
#[path = "normal_prepare_tests.rs"]
mod tests;
