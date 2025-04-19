use aiken/collection/list
use aiken/collection/pairs
use cardano/address.{Credential, Script}
use cardano/assets.{PolicyId}
use cardano/transaction.{OutputReference, Transaction}
use nft_position/functions.{burn_asset,
  cancel, claim, lock_asset} as nft_position_functions
use utils/functions.{get_validator_hash}
use utils/types.{
  Action, AlwaysTrueAction, BurnAction, CancelAction, ClaimAction, MintAction, WithdrawRedeemer,
}

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

  withdraw(redeemer: WithdrawRedeemer, _account: Credential, self: Transaction) {
    redeemer
      |> list.all(
          fn(Action { input_index, output_indexes, action_type }) {
            when action_type is {
              ClaimAction -> claim(input_index, output_indexes, self)
              CancelAction -> cancel(input_index, output_indexes, self)
              MintAction -> lock_asset(input_index, output_indexes, self)
              BurnAction -> burn_asset(input_index, output_indexes, self)
              AlwaysTrueAction -> True
            }
          },
        )
  }

  mint(_redeemer: Data, _policy_id: PolicyId, _self: Transaction) {
    True
  }

  else(_) {
    fail
  }
}
