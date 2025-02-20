use aiken/collection/pairs
use cardano/address.{Credential, Script, VerificationKey}
use cardano/assets.{PolicyId}
use cardano/transaction.{OutputReference, Transaction}
use nft_position/functions.{claim, mint_and_burn} as nft_position_functions
use utils/functions.{get_validator_hash}

validator nft_position {
  mint(_redeemer: Data, policy_id: PolicyId, self: Transaction) {
    mint_and_burn(policy_id, self)
  }

  withdraw(_redeemer: Data, account: Credential, self: Transaction) {
    when account is {
      VerificationKey(_) -> False
      Script(validator_hash) -> claim(validator_hash, self)
    }
  }

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

  else(_) {
    fail
  }
}
