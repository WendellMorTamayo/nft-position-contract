use aiken/collection/list
use aiken/collection/pairs
use cardano/address.{Credential, Script, VerificationKey}
use cardano/assets.{PolicyId}
use cardano/transaction.{OutputReference, Transaction}
use nft_position/functions.{cancel,
  claim, mint_and_burn} as nft_position_functions
use utils/functions.{get_validator_hash}
use utils/types.{Action, CancelAction, ClaimAction, WithdrawRedeemer}

validator nft_position {
  spend(
    _datum: Option<Data>,
    _redeemer: Data,
    utxo: OutputReference,
    self: Transaction,
  ) {
    let self_hash = get_validator_hash(utxo, self)
    self.withdrawals
      |> pairs.has_key(Script(self_hash))
  }

  withdraw(redeemer: WithdrawRedeemer, account: Credential, self: Transaction) {
    let self_hash =
      when account is {
        VerificationKey(_) -> None
        Script(v_hash) -> Some(v_hash)
      }
    expect Some(self_hash) = self_hash
    redeemer
      |> list.all(
          fn(Action { input_index, output_indexes, action_type }) {
            when action_type is {
              ClaimAction -> claim(self_hash, input_index, output_indexes, self)
              CancelAction ->
                cancel(self_hash, input_index, output_indexes, self)
            }
          },
        )
  }

  mint(_redeemer: Data, policy_id: PolicyId, self: Transaction) {
    mint_and_burn(policy_id, self)
  }

  else(_) {
    fail
  }
}
