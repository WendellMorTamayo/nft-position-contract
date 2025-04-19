use cardano/assets.{AssetName, PolicyId}
use cardano/transaction.{Input, Output}

//Prefix of the reference nft asset id according to CIP-68
pub const reference_prefix = #"000643b0"

//Prefix of the nft asset id according to CIP-68
pub const user_nft_prefix = #"000de140"

//Image of the nft
pub const nft_image = @"ipfs://QmX48MTvb863BvBkBSB8BSWoMUBdUAbnT7nQgfuQjadaCa"

//Prefix of the nft asset name
pub const nft_prefix = @"Testing_"

pub type NftIdentifier {
  ReferenceNft
  UserNft
}

pub type CIP68Metadata {
  metadata: Pairs<ByteArray, ByteArray>,
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
  AlwaysTrueAction
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

// The global protocol parameters for the Levvy protocol
// fee: The fee that is charged for all the pool by default
// fee_address: The address that the fee is sent to
// admin: The address that has the ability to update the protocol parameters
// params_policy: The policy id of the policy that is used to mint 
pub type GlobalParamsDetails {
  fee: Rational,
  fee_address: Address,
  admin: MultisigScript,
  pool_params_policy: PolicyId,
  nft_position_prefix: ByteArray,
  nft_image: ByteArray,
  foreclosed_nft_image: ByteArray,
}

// The details of the pool
// principal_asset: The asset that is being lent
// collateral_asset: The asset that is being used as collateral
pub type PoolDetails {
  principal_asset: Subject,
  collateral_asset: Subject,
}

// The pool protocol parameters for the Levvy protocol
// fee: The fee that is charged for the pool
// fee_address: The address that the fee is sent to
// pool_details: The details of the pool
pub type PoolParamsDetails {
  fee: Rational,
  fee_address: Address,
  pool_details: PoolDetails,
}

// Datum shape for the protocol parameters
pub type ProtocolParamsDatum {
  GlobalParams(GlobalParamsDetails)
  PoolParams(PoolParamsDetails)
}

// The types of parameters
pub type UpdateType {
  Global
  Pool
}

// Redeemer shape for updating the protocol parameters
// updated_params_output_index: The index of the output that contains the new protocol parameters
// global_params_input_index: The index of the input that contains the global parameters
// params_type: The type of the parameters that are being updated
pub type ParamsUpdateRedeemer {
  updated_params_output_index: Int,
  global_params_input_index: Option<Int>,
  params_type: UpdateType,
}
