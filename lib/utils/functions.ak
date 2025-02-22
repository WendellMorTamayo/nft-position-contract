use aiken/cbor.{serialise}
use aiken/collection/dict.{Dict}
use aiken/collection/list
use aiken/crypto.{blake2b_256}
use aiken/primitive/bytearray
use cardano/address.{Address, PaymentCredential, Script}
use cardano/assets.{AssetName, PolicyId, Value, quantity_of, tokens}
use cardano/transaction.{
  Datum, InlineDatum, Input, Output, OutputReference, Transaction,
}
use utils/types.{
  NftIdentifier, NftPosition, ReferenceNft, TransactionDetails, UserNft,
  nft_image, nft_prefix, reference_prefix, user_nft_prefix,
}

pub fn get_validator_hash(utxo: OutputReference, tx: Transaction) {
  let inputs = tx.inputs
  let self_inputs =
    inputs |> list.filter(fn(input) { input.output_reference == utxo })
  expect Some(self_input) = self_inputs |> list.head()
  expect Script(validator_hash) = self_input.output.address.payment_credential
  validator_hash
}

pub fn get_unique_ident_from_inputs(inputs: List<Input>) -> ByteArray {
  inputs
    |> list.foldl(
        #"",
        fn(input, acc) {
          blake2b_256(bytearray.concat(acc, serialise(input.output_reference)))
        },
      )
}

pub fn get_nft_position_ident(base_ident: ByteArray, index: Int) -> ByteArray {
  blake2b_256(bytearray.concat(base_ident, serialise(index)))
}

pub fn ident_to_asset_name(identifier: ByteArray, t: NftIdentifier) -> ByteArray {
  let prefix =
    when t is {
      ReferenceNft -> reference_prefix
      UserNft -> user_nft_prefix
    }

  let unique_nft_name =
    list.foldr(
      [prefix, bytearray.from_string(nft_prefix), identifier],
      #"",
      fn(a, b) { bytearray.concat(a, b) },
    )
      |> bytearray.take(32)

  unique_nft_name
}

pub fn outputs_contains_nft(
  outputs: List<Output>,
  policy_id: PolicyId,
  nft_name: AssetName,
) -> Bool {
  outputs
    |> list.any(
        fn(output) {
          (
            output.value
              |> quantity_of(policy_id, nft_name)
          ) == 1
        },
      )
}

pub fn signed_with_input(
  tx: Transaction,
  script_credential: PaymentCredential,
) -> Bool {
  list.any(
    tx.inputs,
    fn(input) { input.output.address.payment_credential == script_credential },
  )
}

pub fn find_script_inputs(
  inputs: List<Input>,
  validator_hash: ByteArray,
) -> List<Input> {
  inputs
    |> list.filter(
        fn(input) {
          expect Script(input_credential) =
            input.output.address.payment_credential
          input_credential == validator_hash
        },
      )
}

pub fn group_outputs_by_nft_datum(
  validator_outputs: List<Output>,
) -> Dict<ByteArray, Pair<NftPosition, List<Output>>> {
  validator_outputs
    |> list.foldl(
        dict.empty,
        fn(output, acc) {
          expect Some(position) = try_extract_nft_position(output.datum)
          let vesting_datum_bytes = serialise(position.extra)
          acc
            |> dict.insert_with(
                vesting_datum_bytes,
                Pair(position, [output]),
                fn(_k, a, b) {
                  let Pair(params_a, outputs_a) = a
                  let Pair(_, outputs_b) = b
                  Some(Pair(params_a, outputs_a |> list.concat(outputs_b)))
                },
              )
        },
      )
}

pub fn try_extract_nft_position(on_chain_datum: Datum) -> Option<NftPosition> {
  expect InlineDatum(inline_datum) = on_chain_datum
  expect cip68_position: NftPosition = inline_datum

  expect Some(name) =
    cip68_position.metadata
      |> list.find(
          fn(m) {
            let (k, _) = m
            k == bytearray.from_string(@"name")
          },
        )
  expect Some(image) =
    cip68_position.metadata
      |> list.find(
          fn(m) {
            let (k, _) = m
            k == bytearray.from_string(@"image")
          },
        )

  let (_, name_value) = name
  let (_, image_value) = image

  // Metadata must only include name and image
  expect list.length(cip68_position.metadata) == 2

  // Metadata name must be in correct format
  let nft_prefix_bytearray = bytearray.from_string(nft_prefix)
  expect
    bytearray.take(name_value, bytearray.length(nft_prefix_bytearray)) == nft_prefix_bytearray

  // Metadata image must be correct
  expect image_value == bytearray.from_string(nft_image)

  Some(cip68_position)
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
