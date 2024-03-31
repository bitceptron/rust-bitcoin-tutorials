

#[derive(Debug)]
pub enum TaprootUtilsError {
    Secp256k1Error(bitcoin::secp256k1::Error),
    MiniscriptError(miniscript::Error),
    MiniscriptCompileError(miniscript::policy::compiler::CompilerError),
    MiniscriptAnalysisError(miniscript::AnalysisError),
    BitcoinTaprootBuilderError(bitcoin::taproot::TaprootBuilderError),
    MuSig2KeyAggError(musig2::errors::KeyAggError),
}

impl From<bitcoin::secp256k1::Error> for TaprootUtilsError {
    fn from(value: bitcoin::secp256k1::Error) -> Self {
        TaprootUtilsError::Secp256k1Error(value)
    }
}

impl From<miniscript::Error> for TaprootUtilsError {
    fn from(value: miniscript::Error) -> Self {
        TaprootUtilsError::MiniscriptError(value)
    }
}

impl From<miniscript::policy::compiler::CompilerError> for TaprootUtilsError {
    fn from(value: miniscript::policy::compiler::CompilerError) -> Self {
        TaprootUtilsError::MiniscriptCompileError(value)
    }
}

impl From<miniscript::AnalysisError> for TaprootUtilsError {
    fn from(value: miniscript::AnalysisError) -> Self {
        TaprootUtilsError::MiniscriptAnalysisError(value)
    }
}

impl From<bitcoin::taproot::TaprootBuilderError> for TaprootUtilsError {
    fn from(value: bitcoin::taproot::TaprootBuilderError) -> Self {
        TaprootUtilsError::BitcoinTaprootBuilderError(value)
    }
}

impl From<musig2::errors::KeyAggError> for TaprootUtilsError {
    fn from(value: musig2::errors::KeyAggError) -> Self {
        TaprootUtilsError::MuSig2KeyAggError(value)
    }
}