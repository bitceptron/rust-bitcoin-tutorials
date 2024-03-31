use std::{str::FromStr, sync::Arc};

use bitcoin::{ScriptBuf, XOnlyPublicKey};
use getset::Getters;
use miniscript::{descriptor::TapTree, policy::Concrete, Miniscript, Tap};

use super::TaprootUtilsError;
#[derive(Debug, Clone, PartialEq, Eq, Getters)]
#[get = "pub with_prefix"]
pub struct TapPolicyData {
    policy_str: String,
    miniscript: Miniscript<XOnlyPublicKey, Tap>,
    leaf: TapTree<XOnlyPublicKey>,
    script: ScriptBuf,
}

impl TapPolicyData {
    pub fn from_x_only_policy_str(policy_str: &str) -> Result<Self, TaprootUtilsError> {
        let policy_str = policy_str.to_string();
        let miniscript = x_only_policy_str_to_x_only_tap_miniscript(&policy_str)?;
        let leaf = x_only_tap_miniscript_to_tapleaf(&miniscript);
        let script = x_only_tap_miniscript_to_scriptbuf(&miniscript);
        Ok(TapPolicyData {
            policy_str,
            miniscript,
            leaf,
            script,
        })
    }
}

pub fn x_only_policy_str_to_x_only_tap_miniscript(
    policy_str: &str,
) -> Result<Miniscript<XOnlyPublicKey, Tap>, TaprootUtilsError> {
    let policy = Concrete::<XOnlyPublicKey>::from_str(policy_str)?;
    let policy_miniscript = policy.compile::<Tap>()?;
    policy_miniscript.sanity_check()?;
    Ok(policy_miniscript)
}

pub fn x_only_policy_str_to_tapleaf(
    policy_str: &str,
) -> Result<TapTree<XOnlyPublicKey>, TaprootUtilsError> {
    let policy_miniscript = x_only_policy_str_to_x_only_tap_miniscript(policy_str)?;
    let leaf = TapTree::Leaf(Arc::new(policy_miniscript));
    Ok(leaf)
}

pub fn x_only_policy_str_to_scriptbuf(policy_str: &str) -> Result<ScriptBuf, TaprootUtilsError> {
    let policy_miniscript = x_only_policy_str_to_x_only_tap_miniscript(policy_str)?;
    let script = policy_miniscript.encode();
    Ok(script)
}

pub fn x_only_tap_miniscript_to_tapleaf(
    miniscript: &Miniscript<XOnlyPublicKey, Tap>,
) -> TapTree<XOnlyPublicKey> {
    TapTree::Leaf(Arc::new(miniscript.clone()))
}

pub fn x_only_tap_miniscript_to_scriptbuf(
    miniscript: &Miniscript<XOnlyPublicKey, Tap>,
) -> ScriptBuf {
    miniscript.encode()
}
