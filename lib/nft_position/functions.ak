use aiken/collection/list
use aiken/primitive/bytearray
use cardano/assets.{flatten, flatten_with, quantity_of}
use cardano/transaction.{Transaction}
use utils/functions.{
  get_nft_position_ident, get_unique_ident_from_inputs, ident_to_asset_name,
  outputs_contains_nft, try_extract_nft_position,
}
use utils/types.{ReferenceNft, reference_prefix, user_nft_prefix}

pub fn claim(validator_hash: ByteArray, tx: Transaction) {
  // Get all inputs being unlocked from the script
  // let script_inputs = find_script_inputs(tx.inputs, validator_hash)

  // let script_outputs =
  //   tx.outputs
  //     |> transaction.find_script_outputs(validator_hash)

  // // Group Inputs by Vesting Parameters
  // let resolved_inputs_by_params =
  //   group_outputs_by_nft_datum(
  //     script_inputs |> list.map(fn(input) { input.output }),
  //   )

  // // Group Outputs by Vesting Parameters
  // let outputs_by_params = group_outputs_by_nft_datum(script_outputs)

  mint_and_burn(validator_hash, tx)?
}

pub fn mint_and_burn(param: ByteArray, tx: Transaction) {
  let inputs = tx.inputs
  let outputs = tx.outputs
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
  // validator_hash has been passed as policy_id here
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

  let flattened_mint = tx.mint |> flatten()

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
