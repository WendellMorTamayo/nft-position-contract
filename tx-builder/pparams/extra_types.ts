import { Script } from "@blaze-cardano/core";
import { Data, type Static } from "@blaze-cardano/sdk";

const RationalSchema = Data.Object({
    Numerator: Data.Integer(),
    Denominator: Data.Integer(),
});

export type Rational = Static<typeof RationalSchema>;
export const Rational = RationalSchema as unknown as Rational;

// Address
const CredentialSchema = Data.Enum([
    Data.Object({ VerificationKey: Data.Object({ key_hash: Data.Bytes() }) }),
    Data.Object({ Script: Data.Object({ script_hash: Data.Bytes() }) })
]);

export type Credential = Static<typeof CredentialSchema>;
export const Credential = CredentialSchema as unknown as Credential;

const AddressSchema = Data.Object({
    PaymentCredential: Credential,
    StakeCredential: Credential // Inline<Credential>
});

export type Address = Static<typeof AddressSchema>;
export const Address = AddressSchema as unknown as Address;

// Multisig
const MultisigScriptSchema = Data.Enum([
    Data.Object({ Signature: Data.Object({ key_hash: Data.Bytes() }) }),
    Data.Object({ AllOf: Data.Object({ scripts: Data.Object({}) }) }),
    Data.Object({ AnyOf: Data.Object({ scripts: Data.Object({}) }) }),
    Data.Object({ AtLeast: Data.Object({ required: Data.Integer(), scripts: Data.Array({}) }) }),
    Data.Object({ Before: Data.Object({ time: Data.Integer() }) }),
    Data.Object({ After: Data.Object({ time: Data.Integer() }) }),
    Data.Object({ Script: Data.Object({ script_hash: Data.Bytes() }) }),
]);
type MultisigScript = Static<typeof MultisigScriptSchema>;
export const MultisigScript = MultisigScriptSchema as unknown as MultisigScript;