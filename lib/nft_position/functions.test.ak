use aiken/primitive/bytearray
use aiken/primitive/string
use cardano/address.{Address, Script, VerificationKey}
use cardano/assets.{add, from_lovelace, zero}
use cardano/transaction.{
  InlineDatum, Input, NoDatum, Output, OutputReference, Transaction, placeholder,
}
use nft_position/functions.{mint_and_burn}
use utils/functions.{
  get_nft_position_ident, get_unique_ident_from_inputs, ident_to_asset_name,
} as util_functions
use utils/types.{
  CollateralDetails, NftPosition, ReferenceNft, UserNft, nft_image, nft_prefix,
  reference_prefix, user_nft_prefix,
}

test deposit_mint_test() {
  let validator_hash = #"0000"

  let input1 =
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
              reference_prefix |> bytearray.concat(#"1111"),
              1,
            ),
        InlineDatum(
          CollateralDetails {
            policy_id: #"0000",
            asset_name: #"0011",
            collateral_amount: 2_000_000,
          },
        ),
        None,
      ),
    }

  let input2 =
    Input {
      output_reference: OutputReference {
        transaction_id: #"1235",
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
              reference_prefix |> bytearray.concat(#"2111"),
              1,
            ),
        InlineDatum(
          CollateralDetails {
            policy_id: #"0000",
            asset_name: #"0011",
            collateral_amount: 2_000_000,
          },
        ),
        None,
      ),
    }

  let input3 =
    Input {
      output_reference: OutputReference {
        transaction_id: #"1235",
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
              reference_prefix |> bytearray.concat(#"3111"),
              1,
            ),
        InlineDatum(
          CollateralDetails {
            policy_id: #"0000",
            asset_name: #"0011",
            collateral_amount: 2_000_000,
          },
        ),
        None,
      ),
    }

  let inputs = [input1, input2, input3]
  let ident = get_unique_ident_from_inputs(inputs)

  let output1 =
    Output(
      Address {
        payment_credential: Script(validator_hash),
        stake_credential: None,
      },
      from_lovelace(300_000_000)
        |> add(
            validator_hash,
            get_nft_position_ident(ident, 0)
              |> ident_to_asset_name(ReferenceNft),
            1,
          ),
      InlineDatum(
        NftPosition {
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
        payment_credential: Script(validator_hash),
        stake_credential: None,
      },
      from_lovelace(300_000_000)
        |> add(
            validator_hash,
            get_nft_position_ident(ident, 1)
              |> ident_to_asset_name(ReferenceNft),
            1,
          ),
      InlineDatum(
        NftPosition {
          metadata: [
            (
              bytearray.from_string(@"name"),
              bytearray.from_string(string.concat(nft_prefix, @"test2")),
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

  let output3 =
    Output(
      Address {
        payment_credential: VerificationKey(#"000012"),
        stake_credential: None,
      },
      from_lovelace(300_000_000)
        |> add(
            validator_hash,
            get_nft_position_ident(ident, 0)
              |> ident_to_asset_name(UserNft),
            1,
          ),
      NoDatum,
      None,
    )

  let output4 =
    Output(
      Address {
        payment_credential: VerificationKey(#"000012"),
        stake_credential: None,
      },
      from_lovelace(300_000_000)
        |> add(
            validator_hash,
            get_nft_position_ident(ident, 1)
              |> ident_to_asset_name(UserNft),
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
            inputs: inputs,
            outputs: [output1, output2, output3, output4],
            mint: zero
              |> add(
                  validator_hash,
                  get_nft_position_ident(ident, 0)
                    |> ident_to_asset_name(UserNft),
                  1,
                )
              |> add(
                  validator_hash,
                  get_nft_position_ident(ident, 1)
                    |> ident_to_asset_name(UserNft),
                  1,
                )
              |> add(
                  validator_hash,
                  get_nft_position_ident(ident, 0)
                    |> ident_to_asset_name(ReferenceNft),
                  1,
                )
              |> add(
                  validator_hash,
                  get_nft_position_ident(ident, 1)
                    |> ident_to_asset_name(ReferenceNft),
                  1,
                )
              |> add(
                  validator_hash,
                  reference_prefix |> bytearray.concat(#"1111"),
                  -1,
                )
              |> add(
                  validator_hash,
                  user_nft_prefix |> bytearray.concat(#"1111"),
                  -1,
                )
              |> add(
                  validator_hash,
                  reference_prefix |> bytearray.concat(#"2111"),
                  -1,
                )
              |> add(
                  validator_hash,
                  user_nft_prefix |> bytearray.concat(#"2111"),
                  -1,
                )
              |> add(
                  validator_hash,
                  reference_prefix |> bytearray.concat(#"3111"),
                  -1,
                )
              |> add(
                  validator_hash,
                  user_nft_prefix |> bytearray.concat(#"3111"),
                  -1,
                ),
          }
        }

  mint_and_burn(validator_hash, tx)?
}

test cancel_test() {
  let validator_hash = #"0000"
  let owner_hash = #"0011"

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
              reference_prefix |> bytearray.concat(#"1111"),
              1,
            ),
        InlineDatum(
          CollateralDetails {
            policy_id: #"0000",
            asset_name: #"0011",
            collateral_amount: 2_000_000,
          },
        ),
        None,
      ),
    }

  let ident = get_unique_ident_from_inputs([input])

  let output1 =
    Output(
      Address {
        payment_credential: Script(validator_hash),
        stake_credential: None,
      },
      from_lovelace(300_000_000)
        |> add(
            validator_hash,
            get_nft_position_ident(ident, 0)
              |> ident_to_asset_name(ReferenceNft),
            1,
          ),
      InlineDatum(
        NftPosition {
          metadata: [
            (
              bytearray.from_string(@"name"),
              bytearray.from_string(string.concat(nft_prefix, @"1111")),
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
        payment_credential: VerificationKey(owner_hash),
        stake_credential: None,
      },
      from_lovelace(300_000_000)
        |> add(
            validator_hash,
            get_nft_position_ident(ident, 0)
              |> ident_to_asset_name(UserNft),
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
            inputs: [input],
            outputs: [output1, output2],
            mint: zero
              |> add(
                  validator_hash,
                  get_nft_position_ident(ident, 0)
                    |> ident_to_asset_name(UserNft),
                  1,
                )
              |> add(
                  validator_hash,
                  get_nft_position_ident(ident, 0)
                    |> ident_to_asset_name(ReferenceNft),
                  1,
                )
              |> add(
                  validator_hash,
                  reference_prefix |> bytearray.concat(#"1111"),
                  -1,
                )
              |> add(
                  validator_hash,
                  user_nft_prefix |> bytearray.concat(#"1111"),
                  -1,
                ),
          }
        }

  mint_and_burn(validator_hash, tx)?
}
