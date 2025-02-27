use aiken/cbor
use aiken/collection/list
use aiken/crypto.{Blake2b_256, Hash}
use aiken/primitive/bytearray
use cardano/address.{Script}
use cardano/assets.{AssetName, PolicyId, flatten, flatten_with}
use cardano/transaction.{
  InlineDatum, Input, Output, OutputReference, Transaction, TransactionId,
}
use utils/functions.{
  get_collateral_value, get_transaction_details, try_extract_nft_position,
}
use utils/types.{
  CIP68Metadata, OutputIndexes, TransactionDetails, nft_prefix, reference_prefix,
  user_nft_prefix,
} as util_types

pub fn claim(input_index: Int, output_indexes: OutputIndexes, tx: Transaction) {
  let tx_details =
    get_transaction_details(
      input_index,
      output_indexes.self_output_index,
      output_indexes.return_output_index,
      tx,
    )

  let TransactionDetails { self_input, return_output, .. } = tx_details

  expect InlineDatum(input_data) = self_input.output.datum
  expect nft_position: CIP68Metadata = input_data
  expect Some(return_output) = return_output

  let collateral_amount =
    get_collateral_value(
      nft_position.extra.policy_id,
      nft_position.extra.asset_name,
      return_output.value,
    )

  let is_collateral_equal =
    collateral_amount == nft_position.extra.collateral_amount

  let datum_tag =
    self_input.output_reference
      |> cbor.serialise()
      |> crypto.blake2b_256()

  expect InlineDatum(return_datum) = return_output.datum
  expect return_datum: Hash<Blake2b_256, OutputReference> = return_datum
  let is_datum_tag_correct = return_datum == datum_tag

  expect Script(validator_hash) = self_input.output.address.payment_credential
  let is_mint_valid = burn_token(validator_hash, tx_details, tx)

  and {
    is_mint_valid?,
    is_collateral_equal?,
    is_datum_tag_correct?,
  }
}

pub fn cancel(input_index: Int, output_indexes: OutputIndexes, tx: Transaction) {
  let tx_details =
    get_transaction_details(
      input_index,
      output_indexes.self_output_index,
      output_indexes.return_output_index,
      tx,
    )

  let TransactionDetails { self_input, self_output, .. } = tx_details

  expect InlineDatum(_) = self_output.datum

  expect Script(validator_hash) = self_input.output.address.payment_credential
  burn_token(validator_hash, tx_details, tx)
}

pub fn lock_asset(
  input_index: Int,
  output_indexes: OutputIndexes,
  tx: Transaction,
) {
  let tx_details =
    get_transaction_details(
      input_index,
      output_indexes.self_output_index,
      output_indexes.return_output_index,
      tx,
    )

  let TransactionDetails { self_output, .. } = tx_details
  expect Script(validator_hash) = self_output.address.payment_credential
  mint_token(validator_hash, tx_details, tx)?
}

pub fn burn_asset(
  input_index: Int,
  output_indexes: OutputIndexes,
  tx: Transaction,
) {
  let tx_details =
    get_transaction_details(
      input_index,
      output_indexes.self_output_index,
      output_indexes.return_output_index,
      tx,
    )

  let TransactionDetails { self_input, .. } = tx_details
  expect Script(validator_hash) = self_input.output.address.payment_credential
  expect InlineDatum(_) = self_input.output.datum
  // todo check collateral details
  burn_token(validator_hash, tx_details, tx)?
}

pub fn mint_token(
  validator_hash: ByteArray,
  tx_details: TransactionDetails,
  tx: Transaction,
) {
  let TransactionDetails { self_input, self_output, .. } = tx_details

  let is_nft_position_valid = try_extract_nft_position(self_output.datum)

  let tx_hash = self_input.output_reference.transaction_id
  let index = self_input.output_reference.output_index
  let reference_token_name: AssetName =
    unique_token_name(tx_hash, index, reference_prefix)
  let user_token_name: AssetName =
    unique_token_name(tx_hash, index, user_nft_prefix)

  // check if reference and user tokens are part of the mint of this transaction
  let mint = tx.mint |> flatten()
  let is_token_mint_valid = and {
      mint
        |> list.any(
            fn(y) { exact_value(y, validator_hash, reference_token_name, 1)? },
          ),
      mint
        |> list.any(
            fn(y) { exact_value(y, validator_hash, user_token_name, 1)? },
          ),
    }
  and {
    is_nft_position_valid?,
    is_token_mint_valid?,
  }
}

pub fn burn_token(
  validator_hash: ByteArray,
  tx_details: TransactionDetails,
  tx: Transaction,
) {
  let mint = tx.mint |> flatten()

  let TransactionDetails { self_input, .. } = tx_details

  let reference_nfts_to_burn =
    self_input.output.value
      |> flatten_with(
          fn(c_policy_id, asset_name, amount) {
            if c_policy_id == validator_hash {
              Some((validator_hash, asset_name, amount))
            } else {
              None
            }
          },
        )

  let reference_prefix_length = reference_prefix |> bytearray.length()
  let is_positions_burned =
    reference_nfts_to_burn
      |> list.all(
          fn(x) {
            let (x_policy_id, x_asset_name, x_amount) = x
            // Get the equivalent UserNft of the ReferenceNft being burned
            let user_nft_asset_name =
              user_nft_prefix
                |> bytearray.concat(
                    x_asset_name
                      |> bytearray.drop(reference_prefix_length),
                  )
            and {
              mint
                |> list.any(
                    fn(y) {
                      exact_value(y, x_policy_id, x_asset_name, -x_amount)?
                    },
                  ),
              // Ensure user NFT is burned
              mint
                |> list.any(
                    fn(y) {
                      exact_value(
                        y,
                        x_policy_id,
                        user_nft_asset_name,
                        -x_amount,
                      )?
                    },
                  ),
            }
          },
        )
  is_positions_burned?
}

pub fn unique_token_name(
  txid: TransactionId,
  idx: Int,
  prefix: ByteArray,
) -> AssetName {
  let prepend_index: ByteArray = bytearray.push(txid, idx)
  let trimmed_personal: ByteArray = bytearray.from_string(nft_prefix)
  let prepend_prefix: ByteArray =
    prefix
      |> bytearray.concat(trimmed_personal)
      |> bytearray.concat(prepend_index)
  prepend_prefix |> bytearray.take(32)
}

pub fn exact_value(
  flat: (ByteArray, ByteArray, Int),
  pid: PolicyId,
  tkn: AssetName,
  amt: Int,
) -> Bool {
  let (policy_id, asset_name, amount) = flat
  and {
    pid == policy_id,
    tkn == asset_name,
    amt == amount,
  }
}
