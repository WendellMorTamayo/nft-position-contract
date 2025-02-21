use cardano/assets.{AssetName, PolicyId}

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

pub type NftPosition {
  metadata: List<(ByteArray, ByteArray)>,
  version: Int,
  extra: CollateralDetails,
}

pub type CollateralDetails {
  policy_id: PolicyId,
  asset_name: AssetName,
  collateral_amount: Int,
}

pub type WithdrawRedeemer {
  indexes: List<(Int, Int)>,
}
