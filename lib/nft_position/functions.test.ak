use aiken/primitive/bytearray
use cardano/address.{Address, Script, VerificationKey}
use cardano/assets.{add, from_asset, from_lovelace, zero}
use cardano/transaction.{
  InlineDatum, Input, NoDatum, Output, OutputReference, Transaction, placeholder,
}
use nft_position/functions.{cancel, claim, mint_token, unique_token_name}
use utils/functions.{get_transaction_details} as util_functions
use utils/types.{
  CIP68Metadata, CollateralDetails, OutputIndexes, nft_image, nft_prefix,
  reference_prefix, user_nft_prefix,
}

test claim_test() {
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
          payment_credential: VerificationKey(owner_hash),
          stake_credential: None,
        },
        from_lovelace(100_000_000)
          |> add(
              validator_hash,
              user_nft_prefix |> bytearray.concat(#"1111"),
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

  let returned_output =
    Output(
      Address {
        payment_credential: Script(validator_hash),
        stake_credential: None,
      },
      from_asset(#"0000", #"0011", 100_000_000),
      NoDatum,
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
      |> add(validator_hash, reference_prefix |> bytearray.concat(#"1111"), -1)
      |> add(validator_hash, user_nft_prefix |> bytearray.concat(#"1111"), -1)

  // let datum_tag =
  //   input.output_reference
  //     |> cbor.serialise()
  //     |> crypto.blake2b_256()
  let repay_output =
    Output {
      address: Address {
        payment_credential: VerificationKey(owner_hash),
        stake_credential: None,
      },
      value: from_asset(#"0000", #"0011", 2_000_000),
      datum: NoDatum,
      reference_script: None,
    }

  let tx =
    placeholder
      |> fn(tx) {
          Transaction {
            ..tx,
            inputs: [input],
            outputs: [returned_output, repay_output],
            mint: minted_value,
          }
        }

  claim(
    0,
    OutputIndexes { self_output_index: 0, return_output_index: Some(1) },
    tx,
  )
}

test cancel_test() {
  let validator_hash =
    #"8469500b8d58ab5c0905d0d9c38e48c4ef5a27e76b7a9af57bab0fba"

  let input =
    Input {
      output_reference: OutputReference {
        transaction_id: #"398d07f5bb38cf46a577c9fb42365453d9bf1a3919e31c265807ba698e3490a4",
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
              user_nft_prefix
                |> bytearray.concat("Testers"),
              1,
            ),
        NoDatum,
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
        CIP68Metadata {
          metadata: [
            Pair(#"6e616d65", #"5374616b65204e465420434e4354202d20323431303031"),
            Pair(
              #"6c6f636b65645f617373657473",
              #"5b2863323736303066336166663364393430343334363461333337383634323962373865366162396466356531643233623737346163623334632c34333465343335342c32333831383530295d",
            ),
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
    OutputIndexes { self_output_index: 0, return_output_index: None },
    tx,
  )
}

test mint_test() {
  let validator_hash = #"0000"
  let sample_hash = #"001100"

  let input1 =
    Input {
      output_reference: OutputReference {
        transaction_id: #"cfd34e88b1ac06dd1a7e318d991e4dfc5fb117556c9dc243b45e01488142aef9",
        output_index: 0,
      },
      output: Output(
        Address {
          payment_credential: Script(validator_hash),
          stake_credential: None,
        },
        from_lovelace(5_000_000),
        NoDatum,
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
              input1.output_reference.output_index,
              reference_prefix,
            ),
            1,
          ),
      InlineDatum(
        CIP68Metadata {
          metadata: [
            Pair(
              bytearray.from_string(@"name"),
              bytearray.from_string(nft_prefix)
                |> bytearray.concat(bytearray.from_string(@"NftPosition1")),
            ),
            Pair(
              bytearray.from_string(@"image"),
              bytearray.from_string(nft_image),
            ),
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
      from_lovelace(8_000_000),
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
                    input1.output_reference.output_index,
                    reference_prefix,
                  ),
                  1,
                )
              |> add(
                  validator_hash,
                  unique_token_name(
                    input1.output_reference.transaction_id,
                    input1.output_reference.output_index,
                    user_nft_prefix,
                  ),
                  1,
                ),
          }
        }

  trace unique_token_name(
    input1.output_reference.transaction_id,
    input1.output_reference.output_index,
    reference_prefix,
  )
  trace unique_token_name(
    input1.output_reference.transaction_id,
    input1.output_reference.output_index,
    user_nft_prefix,
  )
  let tx_details = get_transaction_details(0, 0, Some(1), tx)
  mint_token(validator_hash, tx_details, tx)?
}
