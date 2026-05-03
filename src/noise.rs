use std::sync::OnceLock;

use snow::params::NoiseParams;

const NOISE_PARAMS: &str = "Noise_XX_25519_AESGCM_BLAKE2b";

static NOISE_PARAMS_PARSED: OnceLock<NoiseParams> = OnceLock::new();

pub fn noise_params() -> NoiseParams {
    NOISE_PARAMS_PARSED
        .get_or_init(|| NOISE_PARAMS.parse().unwrap())
        .clone()
}
