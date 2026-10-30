//! Configuration for mapping EIP-8025 proof types to ERE zkVM verifiers.

use crate::{ProofEngine, ProofEngineError, test_utils::MockProofEngine};
use serde::{Deserialize, Deserializer, Serialize, de::Error as _};
use std::{collections::HashSet, str::FromStr};
use types::execution::ProofType;

// Program verification keys registered by eth-act/ere-guests v0.19.0 for use with the ERE
// v0.19.6 verifier pinned by build/ere_verifier.rs. The client and release versions below
// identify the guest binaries that produced the keys.
// Ethrex stateless-validator guests from ethrex v30.0.1.
const DEFAULT_ETHREX_OPENVM_PROGRAM_VK: &str = concat!(
    "008d36200a00e90c730a00b9900134009fb25e6f00836162350054ddfd0700ee924c30008108af2a06030619068000a2",
    "c21b53000a2fee4f0036169c2800aaaa8d6c0087fbce5b00328dc26f009fe7de5a004686562400e77e894500a128f20f",
    "00674f7c2400b38df01800309c530900a487cf0400725bac510051af497500e4abff6e00a58ac939000775b41a001a76",
    "e84100c5e8944400c94e8e1600330e6b39001cacbc5a00ca47cd51001b418e02000fe02a480009a32070002554164500",
    "d7069403007d07bf3000290ccf21008726523b00e5fd1112003d03bd4c001c6831680016a3fe4200ad7ec6300028529e",
    "3c005710de1700349b6a77004b13962f00cff00054001483f65100ab05ce6b0034174b6000bc041c0900a9b5a11a00b2",
    "6f160300615de46100935f922800d39e4a2700596ea87000ca5764770023df7b57000b1ee85e004c456d61000bdad13b",
    "003de28a5f008584cc2a00033ab1020025f59e4a00c3a9f64a00b8ef166500",
);
const DEFAULT_ETHREX_SP1_PROGRAM_VK: &str =
    "00507acac63813288e5be07a21ab6b8d0fbb0393e290b584a2d19bc1e7f4c540";
const DEFAULT_ETHREX_ZISK_PROGRAM_VK: &str =
    "9a9d2e610bbe0d5e9d030a0c558e92446ddf7df5c6378b5bd040353241316076";

// Reth stateless-validator guests from reth v0.1.0-rc.6.
const DEFAULT_RETH_OPENVM_PROGRAM_VK: &str = concat!(
    "00d9e27d020052f71b26001262c4620034ceb12a0056b3015900d7e27b5900b329b52300e3bdc24c06030619068000a2",
    "c21b53000a2fee4f0036169c2800aaaa8d6c0087fbce5b00328dc26f009fe7de5a004686562400e77e894500a128f20f",
    "00674f7c2400b38df01800309c530900a487cf0400725bac510051af497500e4abff6e00a58ac939000775b41a001a76",
    "e84100c5e8944400c94e8e1600330e6b39001cacbc5a00ca47cd51001b418e02000fe02a480009a32070002554164500",
    "d7069403007d07bf3000290ccf21008726523b00e5fd1112003d03bd4c001c6831680016a3fe4200ad7ec6300028529e",
    "3c005710de1700349b6a77004b13962f00cff00054001483f65100ab05ce6b0034174b6000bc041c0900a9b5a11a00b2",
    "6f160300615de46100935f922800d39e4a2700596ea87000ca5764770023df7b57000b1ee85e004c456d61000bdad13b",
    "003de28a5f008584cc2a00033ab1020025f59e4a00c3a9f64a00b8ef166500",
);
const DEFAULT_RETH_SP1_PROGRAM_VK: &str =
    "00cfd2116a638ef1ddf49203a19967fbe2dfc1a0158f1771fad2fc568d5e24fb";
const DEFAULT_RETH_ZISK_PROGRAM_VK: &str =
    "783097a373742236094ead8b832a2cf1e80ec60e7f3b3538b2f6612f9fabc837";

// Nimbus stateless-validator guests from nimbus-zkvm-guests v0.3.1-alpha.
const DEFAULT_NIMBUS_SP1_PROGRAM_VK: &str =
    "007688ef646ad5d5c57904bdc6dc64be64d1ee0a2a3b30d7c375a2975e702609";
const DEFAULT_NIMBUS_ZISK_PROGRAM_VK: &str =
    "27a16d493e4fd453ee6eeb9c993912713ded47f6d8b4b02f6946e5796a4bf00e";

// Nethermind stateless-validator guests from nethermind zkvm-guests-2.3.0-preview+3.
const DEFAULT_NETHERMIND_SP1_PROGRAM_VK: &str =
    "004d9d64976fd3a15057a28245b83229a4cbe0ac6f98923ab935a6a0df09f84b";
const DEFAULT_NETHERMIND_ZISK_PROGRAM_VK: &str =
    "88b9f812a85d8a110877221fb1b4c24500cfd34339b0b258a0c09373e136a61f";

// Zilkworm stateless-validator guest from zilkworm v0.1.0-alpha.7.
const DEFAULT_ZILKWORM_SP1_PROGRAM_VK: &str =
    "004ae5f2938262b0c67f4592246c29be501aac3a305672224f4f058c55d7f51b";

/// Configuration for the in-process EIP-8025 proof engine.
#[derive(Debug, Clone, Serialize)]
pub struct ProofEngineConfig {
    execution_proofs: Vec<ExecutionProofConfig>,
    /// Accept mock proofs of the configured proof types in place of the ERE verifiers.
    /// Devnets only.
    mock_proofs: bool,
    /// Ready-built engine returned by [`Self::build_engine`] instead of the configured
    /// verifiers. Never serialized and only present with the `test-utils` feature, so tests can
    /// inject a mock without an `ere-verifier` build.
    #[cfg(feature = "test-utils")]
    #[serde(skip)]
    engine: Option<ProofEngine>,
}

/// Equality covers the configured verifiers only; an injected test engine is not compared.
impl PartialEq for ProofEngineConfig {
    fn eq(&self, other: &Self) -> bool {
        self.execution_proofs == other.execution_proofs && self.mock_proofs == other.mock_proofs
    }
}

impl Eq for ProofEngineConfig {}

impl ProofEngineConfig {
    /// Validate and construct a non-empty configuration with unique, supported proof types.
    pub fn new(execution_proofs: Vec<ExecutionProofConfig>) -> Result<Self, String> {
        if execution_proofs.is_empty() {
            return Err("`execution_proofs` must contain at least one entry".to_string());
        }

        let mut proof_types = HashSet::with_capacity(execution_proofs.len());

        for config in &execution_proofs {
            if !proof_types.insert(config.proof_type) {
                return Err(format!(
                    "duplicate configuration for proof type `{}`",
                    config.proof_type
                ));
            }
            if config.program_vk.is_empty() {
                return Err(format!(
                    "empty program verification key for proof type `{}`",
                    config.proof_type
                ));
            }
        }

        Ok(Self {
            execution_proofs,
            mock_proofs: false,
            #[cfg(feature = "test-utils")]
            engine: None,
        })
    }

    /// Return the configured proof-type/verifier mappings.
    pub fn execution_proofs(&self) -> &[ExecutionProofConfig] {
        &self.execution_proofs
    }

    /// Accept mock proofs, for devnets without a real prover. See
    /// [`MockProofEngine::accepting_mock_proofs`].
    pub fn with_mock_proofs(mut self) -> Self {
        self.mock_proofs = true;
        self
    }

    /// Whether mock proofs are accepted in place of the ERE verifiers.
    pub fn mock_proofs(&self) -> bool {
        self.mock_proofs
    }

    /// Yield `engine` from [`Self::build_engine`] instead of building the configured verifiers.
    #[cfg(feature = "test-utils")]
    pub fn with_engine(mut self, engine: ProofEngine) -> Self {
        self.engine = Some(engine);
        self
    }

    /// Build the proof engine this configuration describes: an injected test engine if one was
    /// supplied, the mock-proof engine in mock mode, otherwise the ERE verifiers, which
    /// need the `ere-verifier` feature.
    pub fn build_engine(&self) -> Result<ProofEngine, ProofEngineError> {
        #[cfg(feature = "test-utils")]
        if let Some(engine) = &self.engine {
            return Ok(engine.clone());
        }

        if self.mock_proofs {
            return Ok(ProofEngine::new(MockProofEngine::accepting_mock_proofs(
                self.execution_proofs.iter().map(|config| config.proof_type),
            )));
        }

        #[cfg(feature = "ere-verifier")]
        {
            crate::ere::EreProofEngine::new(self.clone()).map(ProofEngine::new)
        }

        #[cfg(not(feature = "ere-verifier"))]
        {
            Err(ProofEngineError::ProofVerifierError {
                message: "Lighthouse was built without `ere-verifier`".to_string(),
                error_type: "proof_verifier_error",
            })
        }
    }
}

impl Default for ProofEngineConfig {
    /// Built-in verifier configuration for every guest registered by `eth-act/ere-guests` at tag
    /// `v0.19.0`, for use with the ERE v0.19.6 verifier pinned by `build/ere_verifier.rs`.
    /// The proof-type assignments are provisional while EIP-8025 is under development.
    fn default() -> Self {
        Self::new(
            ProofType::all()
                .iter()
                .filter_map(|proof_type| {
                    default_program_vk(*proof_type).map(|program_vk| ExecutionProofConfig {
                        proof_type: *proof_type,
                        program_vk,
                    })
                })
                .collect(),
        )
        .expect("built-in proof engine configuration is valid")
    }
}

/// The embedded program verification key for `proof_type`, or `None` when the pinned
/// `eth-act/ere-guests` release registers no guest for it.
///
/// Exhaustive by construction, so a newly assigned proof type cannot be added without a decision.
fn default_program_vk(proof_type: ProofType) -> Option<Vec<u8>> {
    let encoded = match proof_type {
        ProofType::EthrexOpenVM => DEFAULT_ETHREX_OPENVM_PROGRAM_VK,
        ProofType::EthrexSP1 => DEFAULT_ETHREX_SP1_PROGRAM_VK,
        ProofType::EthrexZisk => DEFAULT_ETHREX_ZISK_PROGRAM_VK,
        ProofType::RethOpenVM => DEFAULT_RETH_OPENVM_PROGRAM_VK,
        ProofType::RethSP1 => DEFAULT_RETH_SP1_PROGRAM_VK,
        ProofType::RethZisk => DEFAULT_RETH_ZISK_PROGRAM_VK,
        ProofType::ZesuZisk => return None,
        ProofType::NimbusSP1 => DEFAULT_NIMBUS_SP1_PROGRAM_VK,
        ProofType::NimbusZisk => DEFAULT_NIMBUS_ZISK_PROGRAM_VK,
        ProofType::NethermindSP1 => DEFAULT_NETHERMIND_SP1_PROGRAM_VK,
        ProofType::NethermindZisk => DEFAULT_NETHERMIND_ZISK_PROGRAM_VK,
        ProofType::ZilkwormSP1 => DEFAULT_ZILKWORM_SP1_PROGRAM_VK,
    };
    Some(hex::decode(encoded).expect("embedded program verification key is valid hex"))
}

impl<'de> Deserialize<'de> for ProofEngineConfig {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Config {
            execution_proofs: Vec<ExecutionProofConfig>,
            #[serde(default)]
            mock_proofs: bool,
        }

        let config = Config::deserialize(deserializer)?;
        let proof_engine = Self::new(config.execution_proofs).map_err(D::Error::custom)?;
        Ok(if config.mock_proofs {
            proof_engine.with_mock_proofs()
        } else {
            proof_engine
        })
    }
}

impl FromStr for ProofEngineConfig {
    type Err = serde_json::Error;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        serde_json::from_str(value)
    }
}

/// Configuration for the verifier assigned to an EIP-8025 proof type.
///
/// The zkVM is not configured: it is named by the proof type, via [`ProofType::zkvm`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionProofConfig {
    /// EIP-8025 proof type handled by this verifier.
    pub proof_type: ProofType,
    /// ERE-encoded program verification key.
    #[serde(with = "serde_utils::hex_vec")]
    pub program_vk: Vec<u8>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use types::execution::ZkvmKind;

    #[test]
    fn parses_and_serializes_json_config() {
        let json = format!(
            r#"{{"execution_proofs":[{{"proof_type":5,"program_vk":"0x{}"}}]}}"#,
            DEFAULT_RETH_SP1_PROGRAM_VK
        );
        let config: ProofEngineConfig = json.parse().expect("valid JSON configuration");

        assert_eq!(config.execution_proofs().len(), 1);
        assert_eq!(config.execution_proofs()[0].proof_type, ProofType::RethSP1);
        // The zkVM is named by the proof type, not carried in the JSON.
        assert_eq!(
            config.execution_proofs()[0].proof_type.zkvm(),
            ZkvmKind::Sp1
        );
        assert_eq!(
            config.execution_proofs()[0].program_vk,
            hex::decode(DEFAULT_RETH_SP1_PROGRAM_VK).expect("valid embedded key")
        );
        assert_eq!(
            serde_json::from_str::<ProofEngineConfig>(
                &serde_json::to_string(&config).expect("serialize configuration")
            )
            .expect("deserialize configuration"),
            config
        );
    }

    #[test]
    fn mock_proofs_survive_a_json_round_trip() {
        let config = ProofEngineConfig::default().with_mock_proofs();
        let json = serde_json::to_string(&config).expect("serialize configuration");

        assert_eq!(
            json.parse::<ProofEngineConfig>()
                .expect("deserialize configuration"),
            config
        );
        assert!(
            !format!(r#"{{"execution_proofs":[{{"proof_type":5,"program_vk":"0x{DEFAULT_RETH_SP1_PROGRAM_VK}"}}]}}"#)
                .parse::<ProofEngineConfig>()
                .expect("mock_proofs defaults to false")
                .mock_proofs()
        );
    }

    #[test]
    fn rejects_invalid_json_fields() {
        for json in [
            // Unassigned proof types are rejected by the codec.
            r#"{"execution_proofs":[{"proof_type":0,"program_vk":"0x00"}]}"#,
            r#"{"execution_proofs":[{"proof_type":13,"program_vk":"0x00"}]}"#,
            r#"{"execution_proofs":[{"proof_type":5,"program_vk":"00"}]}"#,
            r#"{"execution_proofs":[{"proof_type":5,"program_vk":"0x0g"}]}"#,
            r#"{"execution_proofs":[{"proof_type":5,"program_vk":"0x"}]}"#,
        ] {
            assert!(
                json.parse::<ProofEngineConfig>().is_err(),
                "accepted {json}"
            );
        }
    }

    #[test]
    fn proof_engine_config_rejects_empty_and_duplicate_proof_types() {
        let empty = ProofEngineConfig::new(vec![]);
        assert_eq!(
            empty.unwrap_err(),
            "`execution_proofs` must contain at least one entry"
        );

        let execution_proof = ProofEngineConfig::default().execution_proofs()[0].clone();
        let duplicate = ProofEngineConfig::new(vec![execution_proof.clone(), execution_proof]);
        assert_eq!(
            duplicate.unwrap_err(),
            "duplicate configuration for proof type `EthrexOpenVM`"
        );
    }

    #[test]
    fn default_config_matches_all_ere_guests_v0_19_0_program_keys() {
        let config = ProofEngineConfig::default();
        let expected = [
            (
                ProofType::EthrexOpenVM,
                ZkvmKind::Openvm,
                DEFAULT_ETHREX_OPENVM_PROGRAM_VK,
            ),
            (
                ProofType::EthrexSP1,
                ZkvmKind::Sp1,
                DEFAULT_ETHREX_SP1_PROGRAM_VK,
            ),
            (
                ProofType::EthrexZisk,
                ZkvmKind::Zisk,
                DEFAULT_ETHREX_ZISK_PROGRAM_VK,
            ),
            (
                ProofType::RethOpenVM,
                ZkvmKind::Openvm,
                DEFAULT_RETH_OPENVM_PROGRAM_VK,
            ),
            (
                ProofType::RethSP1,
                ZkvmKind::Sp1,
                DEFAULT_RETH_SP1_PROGRAM_VK,
            ),
            (
                ProofType::RethZisk,
                ZkvmKind::Zisk,
                DEFAULT_RETH_ZISK_PROGRAM_VK,
            ),
            (
                ProofType::NimbusSP1,
                ZkvmKind::Sp1,
                DEFAULT_NIMBUS_SP1_PROGRAM_VK,
            ),
            (
                ProofType::NimbusZisk,
                ZkvmKind::Zisk,
                DEFAULT_NIMBUS_ZISK_PROGRAM_VK,
            ),
            (
                ProofType::NethermindSP1,
                ZkvmKind::Sp1,
                DEFAULT_NETHERMIND_SP1_PROGRAM_VK,
            ),
            (
                ProofType::NethermindZisk,
                ZkvmKind::Zisk,
                DEFAULT_NETHERMIND_ZISK_PROGRAM_VK,
            ),
            (
                ProofType::ZilkwormSP1,
                ZkvmKind::Sp1,
                DEFAULT_ZILKWORM_SP1_PROGRAM_VK,
            ),
        ];

        assert_eq!(config.execution_proofs().len(), expected.len());
        for (config, (proof_type, zkvm_kind, program_vk)) in
            config.execution_proofs().iter().zip(expected)
        {
            assert_eq!(
                (config.proof_type, config.proof_type.zkvm()),
                (proof_type, zkvm_kind)
            );
            assert_eq!(hex::encode(&config.program_vk), program_vk);
        }
    }

    #[test]
    fn default_config_covers_every_assigned_proof_type_with_a_guest() {
        let config = ProofEngineConfig::default();

        for proof_type in ProofType::all() {
            // eth-act/ere-guests v0.19.0 registers no Zesu guest.
            assert_eq!(
                config
                    .execution_proofs()
                    .iter()
                    .any(|config| config.proof_type == *proof_type),
                *proof_type != ProofType::ZesuZisk,
                "unexpected verifier configuration for {proof_type:?}"
            );
        }
    }
}
