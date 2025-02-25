// use aiken/primitive/bytearray
// use aiken/primitive/string
// use cardano/address.{Address, Credential, Script, VerificationKey}
// use cardano/assets.{add, from_lovelace, zero}
// use cardano/transaction.{
//   InlineDatum, Input, NoDatum, Output, OutputReference, Transaction, placeholder,
// }
// use nft_position
// use utils/functions.{
//   get_nft_position_ident, get_unique_ident_from_inputs, ident_to_asset_name,
// }
// use utils/types.{
//   Action, CancelAction, ClaimAction, CollateralDetails, NftPosition,
//   OutputIndexes, ReferenceNft, UserNft, WithdrawRedeemer, nft_image, nft_prefix,
//   reference_prefix, user_nft_prefix,
// }

// test burn_test() {
//   let validator_hash = #"0000"
//   let owner_hash = #"0011"

//   let input =
//     Input {
//       output_reference: OutputReference {
//         transaction_id: #"1234",
//         output_index: 0,
//       },
//       output: Output(
//         Address {
//           payment_credential: Script(validator_hash),
//           stake_credential: None,
//         },
//         from_lovelace(100_000_000)
//           |> add(
//               validator_hash,
//               reference_prefix |> bytearray.concat(#"1111"),
//               1,
//             ),
//         InlineDatum(
//           CollateralDetails {
//             policy_id: #"0000",
//             asset_name: #"0011",
//             collateral_amount: 2_000_000,
//           },
//         ),
//         None,
//       ),
//     }

//   let ident = get_unique_ident_from_inputs([input])

//   let output1 =
//     Output(
//       Address {
//         payment_credential: Script(validator_hash),
//         stake_credential: None,
//       },
//       from_lovelace(300_000_000)
//         |> add(
//             validator_hash,
//             get_nft_position_ident(ident, 0)
//               |> ident_to_asset_name(ReferenceNft),
//             1,
//           ),
//       InlineDatum(
//         NftPosition {
//           metadata: [
//             (
//               bytearray.from_string(@"name"),
//               bytearray.from_string(string.concat(nft_prefix, @"1111")),
//             ),
//             (bytearray.from_string(@"image"), bytearray.from_string(nft_image)),
//           ],
//           version: 1,
//           extra: CollateralDetails {
//             policy_id: #"0000",
//             asset_name: #"0011",
//             collateral_amount: 2_000_000,
//           },
//         },
//       ),
//       None,
//     )

//   let output2 =
//     Output(
//       Address {
//         payment_credential: VerificationKey(owner_hash),
//         stake_credential: None,
//       },
//       from_lovelace(300_000_000)
//         |> add(
//             validator_hash,
//             get_nft_position_ident(ident, 0)
//               |> ident_to_asset_name(UserNft),
//             1,
//           ),
//       NoDatum,
//       None,
//     )

//   let validator_creds = Script(validator_hash)

//   let tx =
//     placeholder
//       |> fn(tx) {
//           Transaction {
//             ..tx,
//             withdrawals: [Pair(validator_creds, 0)],
//             inputs: [input],
//             outputs: [output1, output2],
//             mint: zero
//               |> add(
//                   validator_hash,
//                   get_nft_position_ident(ident, 0)
//                     |> ident_to_asset_name(UserNft),
//                   1,
//                 )
//               |> add(
//                   validator_hash,
//                   get_nft_position_ident(ident, 0)
//                     |> ident_to_asset_name(ReferenceNft),
//                   1,
//                 )
//               |> add(
//                   validator_hash,
//                   reference_prefix |> bytearray.concat(#"1111"),
//                   -1,
//                 )
//               |> add(
//                   validator_hash,
//                   user_nft_prefix |> bytearray.concat(#"1111"),
//                   -1,
//                 ),
//           }
//         }

//   let action1 =
//     Action {
//       input_index: 0,
//       output_indexes: OutputIndexes {
//         self_output_index: 1,
//         return_output_index: Some(0),
//       },
//       action_type: CancelAction,
//     }
//   let withdraw_redeemer: WithdrawRedeemer = [action1]

//   and {
//     nft_position.nft_position.mint(None, validator_hash, tx)?,
//     nft_position.nft_position.withdraw(
//       withdraw_redeemer,
//       Script(validator_hash),
//       tx,
//     )?,
//   }
// }
