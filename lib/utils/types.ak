use cardano/assets.{AssetName, PolicyId}
use cardano/transaction.{Input, Output}

//Prefix of the reference nft asset id according to CIP-68
pub const reference_prefix = #"000643b0"

//Prefix of the nft asset id according to CIP-68
pub const user_nft_prefix = #"000de140"

//Image of the nft
pub const nft_image = @"ipfs://QmRhTTbUrPYEw3mJGGhQqQST9k86v1DPBiTTWJGKDJsVFw"

//Prefix of the nft asset name
pub const nft_prefix = @"Testing_"

pub type NftIdentifier {
  ReferenceNft
  UserNft
}

pub type Cip68Metadata {
  metadata: List<(ByteArray, ByteArray)>,
  version: Int,
  extra: CollateralDetails,
}

pub type CollateralDetails {
  policy_id: PolicyId,
  asset_name: AssetName,
  collateral_amount: Int,
}

pub type ActionType {
  ClaimAction
  CancelAction
  MintAction
  BurnAction
}

// input index, output indexes
pub type Action {
  input_index: Int,
  output_indexes: OutputIndexes,
  action_type: ActionType,
}

// The redeemer for the withdraw purpose
pub type WithdrawRedeemer =
  List<Action>

// Output indexes in the transaction:
// - A required main output index.
// - An optional fee output index.
pub type OutputIndexes {
  self_output_index: Int,
  return_output_index: Option<Int>,
}

pub type TransactionDetails {
  self_input: Input,
  self_output: Output,
  return_output: Option<Output>,
}
