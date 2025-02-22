use aiken/cbor
use aiken/collection/list
use aiken/crypto.{Blake2b_256, Hash}
use aiken/primitive/bytearray
use cardano/assets.{flatten, flatten_with, quantity_of}
use cardano/transaction.{InlineDatum, OutputReference, Transaction}
use utils/functions.{
  get_collateral_value, get_nft_position_ident, get_transaction_details,
  get_unique_ident_from_inputs, ident_to_asset_name, outputs_contains_nft,
  try_extract_nft_position,
}
use utils/types.{
  NftPosition, OutputIndexes, ReferenceNft, TransactionDetails, reference_prefix,
  user_nft_prefix,
} as util_types

pub fn claim(
  validator_hash: ByteArray,
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

  let TransactionDetails { self_input, return_output, .. } = tx_details

  expect InlineDatum(input_data) = self_input.output.datum
  expect nft_position: NftPosition = input_data
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

  let is_mint_valid = mint_and_burn(validator_hash, tx)

  and {
    is_mint_valid?,
    is_collateral_equal?,
    is_datum_tag_correct?,
  }
}

pub fn cancel(
  validator_hash: ByteArray,
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

  let TransactionDetails { self_input, self_output, .. } = tx_details

  expect InlineDatum(input_data) = self_input.output.datum
  expect input_nft_position: NftPosition = input_data

  expect InlineDatum(output_data) = self_output.datum
  expect output_nft_position: NftPosition = output_data

  let is_nft_valid = and {
      input_nft_position.extra.policy_id == output_nft_position.extra.policy_id,
      input_nft_position.extra.asset_name == output_nft_position.extra.asset_name,
    }
  let is_mint_valid = mint_and_burn(validator_hash, tx)
  and {
    is_nft_valid?,
    is_mint_valid?,
  }
}

pub fn mint_and_burn(param: ByteArray, tx: Transaction) {
  let Transaction { inputs, outputs, mint, .. } = tx
  let tx_identifier = get_unique_ident_from_inputs(inputs)

  // We only evaluate inputs coming from our validator
  let resolved_script_inputs =
    inputs
      |> list.foldl([], fn(input, acc) { acc |> list.push(input.output) })
      |> transaction.find_script_outputs(param)

  // From the `resolved_script_inputs` we extract all reference NFTs to burn, if there's any
  let reference_nfts_to_burn =
    resolved_script_inputs
      |> list.flat_map(
          fn(input) {
            input.value
              |> flatten_with(
                  fn(c_policy_id, asset_name, amount) {
                    if c_policy_id == param {
                      Some((param, asset_name, amount))
                    } else {
                      None
                    }
                  },
                )
          },
        )

  // Ensure that for every `resolved_script_inputs` there's a corresponding reference nft attached
  // otherwise, it's an invalid claim potentially coming from a malformed datum
  expect
    (list.length(resolved_script_inputs) == list.length(reference_nfts_to_burn))?

  // Find all outputs sent to the script
  let script_outputs =
    outputs
      |> transaction.find_script_outputs(param)

  // Put index on outputs
  let outputs_with_index =
    script_outputs
      |> list.indexed_map(fn(index, output) { Pair(index, output) })

  let nft_position_outputs =
    outputs_with_index
      |> list.map(
          fn(output_with_index) {
            let Pair(index, output) = output_with_index

            // Just to make sure the datum is correct
            expect Some(linear_params) = try_extract_nft_position(output.datum)

            let position_ident = get_nft_position_ident(tx_identifier, index)
            let position_nft_name =
              ident_to_asset_name(position_ident, ReferenceNft)

            let has_nft =
              (
                output.value
                  |> quantity_of(param, position_nft_name)
              ) == 1

            when has_nft is {
              True -> Some((position_ident, linear_params))
              False -> None
            }
          },
        )

  let nft_position_outputs_count = nft_position_outputs |> list.length()
  let has_nft_position_outputs = nft_position_outputs_count > 0

  let is_positions_correct =
    nft_position_outputs
      |> list.all(
          fn(elem) {
            expect Some((position_ident, _)) = elem
            outputs_contains_nft(
              outputs,
              param,
              ident_to_asset_name(position_ident, ReferenceNft),
            )
          },
        )

  let flattened_mint = mint |> flatten()

  // Check if mint count is accurate
  let is_positions_minted =
    list.length(flattened_mint) - list.length(reference_nfts_to_burn) * 2 == nft_position_outputs_count * 2

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

            // Ensure both reference and user NFTs are burned
            and {
              // Ensure reference NFT is burned
              flattened_mint
                |> list.any(
                    fn(y) {
                      let (y_policy_id, y_asset_name, y_amount) = y
                      x_policy_id == y_policy_id && x_asset_name == y_asset_name && -x_amount == y_amount
                    },
                  ),
              // Ensure user NFT is burned
              flattened_mint
                |> list.any(
                    fn(y) {
                      let (y_policy_id, y_asset_name, y_amount) = y
                      x_policy_id == y_policy_id && user_nft_asset_name == y_asset_name && -x_amount == y_amount
                    },
                  ),
            }
          },
        )

  and {
    has_nft_position_outputs?,
    is_positions_correct?,
    is_positions_minted?,
    is_positions_burned?,
  }
}
