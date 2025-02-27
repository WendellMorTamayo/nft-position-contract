use aiken/collection/dict
use aiken/collection/list
use aiken/collection/pairs
use aiken/option.{is_some}
use aiken/primitive/bytearray
use cardano/address.{Address, Script}
use cardano/assets.{AssetName, PolicyId, Value, tokens}
use cardano/transaction.{
  Datum, InlineDatum, Input, Output, OutputReference, Transaction,
}
use utils/types.{CIP68Metadata, TransactionDetails, nft_image, nft_prefix}

pub fn get_validator_hash(utxo: OutputReference, tx: Transaction) {
  let inputs = tx.inputs
  let self_inputs =
    inputs |> list.filter(fn(input) { input.output_reference == utxo })
  expect Some(self_input) = self_inputs |> list.head()
  expect Script(validator_hash) = self_input.output.address.payment_credential
  validator_hash
}

pub fn try_extract_nft_position(on_chain_datum: Datum) -> Bool {
  expect InlineDatum(inline_datum) = on_chain_datum
  expect cip68_position: CIP68Metadata = inline_datum

  expect Some(name) =
    cip68_position.metadata
      |> pairs.get_first(bytearray.from_string(@"name"))
  expect Some(image) =
    cip68_position.metadata
      |> pairs.get_first(bytearray.from_string(@"image"))

  // Metadata must only include name and image
  expect list.length(cip68_position.metadata) == 2

  // Metadata name must be in correct format
  let nft_prefix_bytearray = bytearray.from_string(nft_prefix)
  expect
    bytearray.take(name, bytearray.length(nft_prefix_bytearray)) == nft_prefix_bytearray

  // Metadata image must be correct
  expect image == bytearray.from_string(nft_image)

  is_some(Some(cip68_position))?
}

pub fn get_collateral_value(
  policy_id: PolicyId,
  asset_name: AssetName,
  val: Value,
) -> Int {
  expect Some(token) =
    tokens(val, policy_id)
      |> dict.to_pairs()
      |> list.filter(fn(Pair(name, _amount)) { asset_name == name })
      |> list.head()
  token.2nd
}

pub fn get_transaction_details(
  input_index: Int,
  output_index: Int,
  return_output_index: Option<Int>,
  tx: Transaction,
) {
  expect Some(self_input) =
    tx.inputs
      |> list.at(input_index)
  expect Some(self_output) =
    tx.outputs
      |> list.at(output_index)
  let return_output =
    when return_output_index is {
      Some(index) -> tx.outputs |> list.at(index)
      None -> None
    }

  TransactionDetails { self_input, self_output, return_output }
}
