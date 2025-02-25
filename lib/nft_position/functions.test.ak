use aiken/primitive/bytearray
use aiken/primitive/string
use cardano/address.{Address, Script, VerificationKey}
use cardano/assets.{add, from_lovelace, zero}
use cardano/transaction.{
  InlineDatum, Input, NoDatum, Output, OutputReference, Transaction, placeholder,
}
use nft_position/functions.{cancel, mint_token, unique_token_name}
use utils/functions.{get_transaction_details} as util_functions
use utils/types.{
  Cip68Metadata, CollateralDetails, OutputIndexes, nft_image, nft_prefix,
  reference_prefix, user_nft_prefix,
}

// test deposit_mint_test() {
//   let validator_hash = #"0000"
//   let sample_hash = #"001100"

//   let input1 =
//     Input {
//       output_reference: OutputReference {
//         transaction_id: #"1e6929fbb57ff137dc4b8a226bd1ba1e1e8abcd704ad4fe9b5c7350284b84855",
//         output_index: 1,
//       },
//       output: Output(
//         Address {
//           payment_credential: VerificationKey(sample_hash),
//           stake_credential: None,
//         },
//         from_lovelace(4_000_000),
//         InlineDatum(
//           CollateralDetails {
//             policy_id: #"0000",
//             asset_name: #"0011",
//             collateral_amount: 200_000,
//           },
//         ),
//         None,
//       ),
//     }

//   let input2 =
//     Input {
//       output_reference: OutputReference {
//         transaction_id: #"1235",
//         output_index: 0,
//       },
//       output: Output(
//         Address {
//           payment_credential: VerificationKey(sample_hash),
//           stake_credential: None,
//         },
//         from_lovelace(100_000_000),
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

//   let input3 =
//     Input {
//       output_reference: OutputReference {
//         transaction_id: #"1235",
//         output_index: 0,
//       },
//       output: Output(
//         Address {
//           payment_credential: VerificationKey(sample_hash),
//           stake_credential: None,
//         },
//         from_lovelace(100_000_000),
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

//   let inputs = [input1, input2, input3]
//   let ident = get_unique_ident_from_inputs(inputs)

//   let output1 =
//     Output(
//       Address {
//         payment_credential: Script(validator_hash),
//         stake_credential: None,
//       },
//       from_lovelace(2_000_000)
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
//               bytearray.from_string(string.concat(nft_prefix, @"test1")),
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
//         payment_credential: Script(validator_hash),
//         stake_credential: None,
//       },
//       from_lovelace(2_000_000)
//         |> add(
//             validator_hash,
//             get_nft_position_ident(ident, 1)
//               |> ident_to_asset_name(ReferenceNft),
//             1,
//           ),
//       InlineDatum(
//         NftPosition {
//           metadata: [
//             (
//               bytearray.from_string(@"name"),
//               bytearray.from_string(string.concat(nft_prefix, @"test2")),
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

//   let output3 =
//     Output(
//       Address {
//         payment_credential: VerificationKey(sample_hash),
//         stake_credential: None,
//       },
//       from_lovelace(2_000_000)
//         |> add(
//             validator_hash,
//             get_nft_position_ident(ident, 0)
//               |> ident_to_asset_name(UserNft),
//             1,
//           ),
//       NoDatum,
//       None,
//     )

//   let output4 =
//     Output(
//       Address {
//         payment_credential: VerificationKey(#"000012"),
//         stake_credential: None,
//       },
//       from_lovelace(2_000_000)
//         |> add(
//             validator_hash,
//             get_nft_position_ident(ident, 1)
//               |> ident_to_asset_name(UserNft),
//             1,
//           ),
//       NoDatum,
//       None,
//     )

//   let tx =
//     placeholder
//       |> fn(tx) {
//           Transaction {
//             ..tx,
//             inputs: inputs,
//             outputs: [output1, output2, output3, output4],
//             mint: zero
//               |> add(
//                   validator_hash,
//                   get_nft_position_ident(ident, 0)
//                     |> ident_to_asset_name(UserNft),
//                   1,
//                 )
//               |> add(
//                   validator_hash,
//                   get_nft_position_ident(ident, 1)
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
//                   get_nft_position_ident(ident, 1)
//                     |> ident_to_asset_name(ReferenceNft),
//                   1,
//                 ),
//           }
//         }
//   mint_and_burn(validator_hash, tx)?
// }

// test burn_test() {
//   let validator_hash = #"0000"
//   let owner_hash = #"0011"

//   let input =
//     Input {
//       output_reference: OutputReference {
//         transaction_id: #"2c8a537791851569cbc30a54e6b615dcd8a2ccb40fe8840b864110c2827e7e7e",
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
//           NftPosition {
//             metadata: [
//               (
//                 bytearray.from_string(@"name"),
//                 bytearray.from_string(string.concat(nft_prefix, @"test1")),
//               ),
//               (
//                 bytearray.from_string(@"image"),
//                 bytearray.from_string(nft_image),
//               ),
//             ],
//             version: 1,
//             extra: CollateralDetails {
//               policy_id: #"0000",
//               asset_name: #"0011",
//               collateral_amount: 2_000_000,
//             },
//           },
//         ),
//         None,
//       ),
//     }

//   // let input2 =
//   //   Input {
//   //     output_reference: OutputReference {
//   //       transaction_id: #"f4482bfa9e5eaff3492f9e1045a0c6725094c92fcafd81c6921fbe26d17cb627",
//   //       output_index: 0,
//   //     },
//   //     output: Output(
//   //       Address {
//   //         payment_credential: Script(validator_hash),
//   //         stake_credential: None,
//   //       },
//   //       from_lovelace(100_000_000),
//   //       NoDatum,
//   //       None,
//   //     ),
//   //   }

//   let input3 =
//     Input {
//       output_reference: OutputReference {
//         transaction_id: #"2c8a537791851569cbc30a54e6b615dcd8a2ccb40fe8840b864110c2827e7e7e",
//         output_index: 1,
//       },
//       output: Output(
//         Address {
//           payment_credential: Script(validator_hash),
//           stake_credential: None,
//         },
//         from_lovelace(100_000_000),
//         NoDatum,
//         None,
//       ),
//     }

//   let ident = get_unique_ident_from_inputs([input, input3])
//   let ident1 = get_unique_ident_from_inputs([input])
//   trace get_nft_position_ident(ident1, 0)
//     |> ident_to_asset_name(ReferenceNft)

//   let output1 =
//     Output(
//       Address {
//         payment_credential: Script(validator_hash),
//         stake_credential: None,
//       },
//       from_lovelace(20_000_000),
//       InlineDatum(
//         NftPosition {
//           metadata: [
//             (
//               bytearray.from_string(@"name"),
//               bytearray.from_string(string.concat(nft_prefix, @"test1")),
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

//   let minted_value =
//     zero
//       |> add(
//           validator_hash,
//           get_nft_position_ident(ident, 0)
//             |> ident_to_asset_name(UserNft),
//           1,
//         )
//       |> add(
//           validator_hash,
//           get_nft_position_ident(ident, 0)
//             |> ident_to_asset_name(ReferenceNft),
//           1,
//         )
//       |> add(validator_hash, reference_prefix |> bytearray.concat(#"1111"), -1)
//       |> add(validator_hash, user_nft_prefix |> bytearray.concat(#"1111"), -1)

//   let returned_output =
//     output1
//       |> fn(output) {
//           Output {
//             ..output,
//             value: output.value
//               |> add(
//                   validator_hash,
//                   get_nft_position_ident(ident, 0)
//                     |> ident_to_asset_name(ReferenceNft),
//                   1,
//                 ),
//           }
//         }

//   let datum_tag =
//     input.output_reference
//       |> cbor.serialise()
//       |> crypto.blake2b_256()

//   // let repay_output =
//   //   Output {
//   //     address: Address {
//   //       payment_credential: VerificationKey(owner_hash),
//   //       stake_credential: None,
//   //     },
//   //     value: from_asset(#"0000", #"0011", 2_000_000),
//   //     datum: InlineDatum(datum_tag),
//   //     reference_script: None,
//   //   }
//   let tx =
//     placeholder
//       |> fn(tx) {
//           Transaction {
//             ..tx,
//             inputs: [input],
//             outputs: [returned_output],
//             mint: minted_value,
//           }
//         }

//   mint_and_burn(validator_hash, tx)?
// }

// test claim_test() {
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
//           NftPosition {
//             metadata: [
//               (
//                 bytearray.from_string(@"name"),
//                 bytearray.from_string(string.concat(nft_prefix, @"test1")),
//               ),
//               (
//                 bytearray.from_string(@"image"),
//                 bytearray.from_string(nft_image),
//               ),
//             ],
//             version: 1,
//             extra: CollateralDetails {
//               policy_id: #"0000",
//               asset_name: #"0011",
//               collateral_amount: 2_000_000,
//             },
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
//       from_lovelace(100_000_000),
//       InlineDatum(
//         NftPosition {
//           metadata: [
//             (
//               bytearray.from_string(@"name"),
//               bytearray.from_string(string.concat(nft_prefix, @"test1")),
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

//   let minted_value =
//     zero
//       |> add(
//           validator_hash,
//           get_nft_position_ident(ident, 0)
//             |> ident_to_asset_name(UserNft),
//           1,
//         )
//       |> add(
//           validator_hash,
//           get_nft_position_ident(ident, 0)
//             |> ident_to_asset_name(ReferenceNft),
//           1,
//         )
//       |> add(validator_hash, reference_prefix |> bytearray.concat(#"1111"), -1)
//       |> add(validator_hash, user_nft_prefix |> bytearray.concat(#"1111"), -1)

//   let returned_output =
//     output1
//       |> fn(output) {
//           Output {
//             ..output,
//             value: output.value
//               |> add(
//                   validator_hash,
//                   get_nft_position_ident(ident, 0)
//                     |> ident_to_asset_name(ReferenceNft),
//                   1,
//                 ),
//           }
//         }

//   let datum_tag =
//     input.output_reference
//       |> cbor.serialise()
//       |> crypto.blake2b_256()

//   let repay_output =
//     Output {
//       address: Address {
//         payment_credential: VerificationKey(owner_hash),
//         stake_credential: None,
//       },
//       value: from_asset(#"0000", #"0011", 2_000_000),
//       datum: InlineDatum(datum_tag),
//       reference_script: None,
//     }

//   let tx =
//     placeholder
//       |> fn(tx) {
//           Transaction {
//             ..tx,
//             inputs: [input],
//             outputs: [returned_output, repay_output],
//             mint: minted_value,
//           }
//         }

//   claim(
//     validator_hash,
//     0,
//     OutputIndexes { self_output_index: 0, return_output_index: Some(1) },
//     tx,
//   )
// }

test cancel_test() {
  let validator_hash =
    #"8469500b8d58ab5c0905d0d9c38e48c4ef5a27e76b7a9af57bab0fba"

  let inline_datum =
    InlineDatum(
      Cip68Metadata {
        metadata: [
          (
            bytearray.from_string(@"name"),
            bytearray.from_string(string.concat(nft_prefix, @"Testers")),
          ),
          (bytearray.from_string(@"image"), bytearray.from_string(nft_image)),
        ],
        version: 1,
        extra: CollateralDetails {
          policy_id: #"0000",
          asset_name: #"0011",
          collateral_amount: 4_000_000,
        },
      },
    )

  let input =
    Input {
      output_reference: OutputReference {
        transaction_id: #"1234",
        output_index: 0,
      },
      output: Output(
        Address {
          payment_credential: Script(validator_hash),
          stake_credential: None,
        },
        from_lovelace(100_000_000)
          |> add(
              validator_hash,
              reference_prefix
                |> bytearray.concat("Testers"),
              1,
            ),
        inline_datum,
        None,
      ),
    }

  let output1 =
    Output(
      Address {
        payment_credential: Script(validator_hash),
        stake_credential: None,
      },
      from_lovelace(100_000_000),
      InlineDatum(
        Cip68Metadata {
          metadata: [
            (
              bytearray.from_string(@"name"),
              bytearray.from_string(string.concat(nft_prefix, @"Testers")),
            ),
            (bytearray.from_string(@"image"), bytearray.from_string(nft_image)),
          ],
          version: 1,
          extra: CollateralDetails {
            policy_id: #"0000",
            asset_name: #"0011",
            collateral_amount: 4_000_000,
          },
        },
      ),
      None,
    )

  let minted_value =
    zero
      |> add(
          validator_hash,
          unique_token_name(
            input.output_reference.transaction_id,
            1,
            reference_prefix,
          ),
          1,
        )
      |> add(
          validator_hash,
          unique_token_name(
            input.output_reference.transaction_id,
            1,
            user_nft_prefix,
          ),
          1,
        )
      |> add(
          validator_hash,
          reference_prefix
            |> bytearray.concat(bytearray.from_string(@"Testers")),
          -1,
        )
      |> add(
          validator_hash,
          user_nft_prefix |> bytearray.concat(bytearray.from_string(@"Testers")),
          -1,
        )

  let tx =
    placeholder
      |> fn(tx) {
          Transaction {
            ..tx,
            inputs: [input],
            outputs: [output1],
            mint: minted_value,
          }
        }

  cancel(
    0,
    OutputIndexes { self_output_index: 0, return_output_index: Some(0) },
    tx,
  )
}

test mint_test() {
  let validator_hash = #"0000"
  let sample_hash = #"001100"

  let inline_datum =
    InlineDatum(
      Cip68Metadata {
        metadata: [
          (
            bytearray.from_string(@"name"),
            bytearray.from_string(string.concat(nft_prefix, @"test1")),
          ),
          (bytearray.from_string(@"image"), bytearray.from_string(nft_image)),
        ],
        version: 1,
        extra: CollateralDetails {
          policy_id: #"0000",
          asset_name: #"0011",
          collateral_amount: 2_000_000,
        },
      },
    )
  let input1 =
    Input {
      output_reference: OutputReference {
        transaction_id: #"2c8a537791851569cbc30a54e6b615dcd8a2ccb40fe8840b864110c2827e7e7e",
        output_index: 1,
      },
      output: Output(
        Address {
          payment_credential: Script(validator_hash),
          stake_credential: None,
        },
        from_lovelace(5_000_000),
        inline_datum,
        None,
      ),
    }

  let output1 =
    Output(
      Address {
        payment_credential: Script(validator_hash),
        stake_credential: None,
      },
      from_lovelace(12_000_000)
        |> add(
            validator_hash,
            unique_token_name(
              input1.output_reference.transaction_id,
              1,
              reference_prefix,
            ),
            1,
          ),
      InlineDatum(
        Cip68Metadata {
          metadata: [
            (
              bytearray.from_string(@"name"),
              bytearray.from_string(string.concat(nft_prefix, @"test1")),
            ),
            (bytearray.from_string(@"image"), bytearray.from_string(nft_image)),
          ],
          version: 1,
          extra: CollateralDetails {
            policy_id: #"0000",
            asset_name: #"0011",
            collateral_amount: 2_000_000,
          },
        },
      ),
      None,
    )

  let output2 =
    Output(
      Address {
        payment_credential: VerificationKey(sample_hash),
        stake_credential: None,
      },
      from_lovelace(8_000_000)
        |> add(
            validator_hash,
            unique_token_name(
              input1.output_reference.transaction_id,
              1,
              user_nft_prefix,
            ),
            1,
          ),
      NoDatum,
      None,
    )

  let tx =
    placeholder
      |> fn(tx) {
          Transaction {
            ..tx,
            inputs: [input1],
            outputs: [output1, output2],
            mint: zero
              |> add(
                  validator_hash,
                  unique_token_name(
                    input1.output_reference.transaction_id,
                    1,
                    reference_prefix,
                  ),
                  1,
                )
              |> add(
                  validator_hash,
                  unique_token_name(
                    input1.output_reference.transaction_id,
                    1,
                    user_nft_prefix,
                  ),
                  1,
                ),
          }
        }

  let tx_details = get_transaction_details(0, 0, Some(1), tx)
  mint_token(validator_hash, tx_details, tx)?
}
