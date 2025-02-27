import { Data, type Static } from "@blaze-cardano/sdk";

const DatumSchema = Data.Object({
    msg: Data.Bytes(),
})
type Datum = Static<typeof DatumSchema>;
export const Datum = DatumSchema as unknown as Datum

const IntegerSchema = Data.Object({
    int: Data.Integer()
})
type Integer = Static<typeof IntegerSchema>;
export const Integer = IntegerSchema as unknown as Integer;

const WithdrawActionSchema = Data.Enum([
    Data.Object({ ClaimAction: Data.Object([]) }),
    Data.Object({ CancelAction: Data.Object([]) }),
    Data.Object({ MintAction: Data.Object([]) }),
    Data.Object({ BurnAction: Data.Object([]) }),
]);
type WithdrawAction = Static<typeof WithdrawActionSchema>;
export const WithdrawAction = WithdrawActionSchema as unknown as WithdrawAction;

const OutputIndexesSchema = Data.Object({
    self_output_index: Data.Integer(),
    return_output_index: Data.Nullable(Integer),
});
type OutputIndexes = Static<typeof OutputIndexesSchema>;
export const OutputIndexes = OutputIndexesSchema as unknown as OutputIndexes;

const ActionSchema = Data.Object({
    input_index: Data.Integer(),
    output_indexes: OutputIndexes,
    action_type: WithdrawAction,
});
    
type Action = Static<typeof ActionSchema>;
export const Action = ActionSchema as unknown as Action;

const WithdrawRedeemerSchema = Data.Array({Action});
type WithdrawRedeemer = Static<typeof WithdrawRedeemerSchema>;
export const WithdrawRedeemer = WithdrawRedeemerSchema as unknown as WithdrawRedeemer;

export const CollateralDetailSchema = Data.Object({
    PolicyId: Data.Bytes(),
    AssetName: Data.Bytes(),
    CollateralAmount: Data.Integer()
});

export type CollateralDatum = Static<typeof CollateralDetailSchema>;
export const CollateralDatum = CollateralDetailSchema as unknown as CollateralDatum;

export const NftPositionDatumSchema = Data.Object({
    Metadata: Data.Map(Data.Bytes(), Data.Bytes()),
    Version: Data.Integer(),
    Extra: CollateralDetailSchema
});

export type NftPositionDatum = Static<typeof NftPositionDatumSchema>;
export const NftPositionDatum = NftPositionDatumSchema as unknown as NftPositionDatum;

const DatumTagSchema = Data.Object({
    tag: Data.Bytes(),
})
export type DatumTag = Static<typeof DatumTagSchema>;
export const DatumTag = DatumTagSchema as unknown as DatumTag

export const OrderRedeemerSchema = Data.Enum([
    Data.Object({ Accept: Data.Object({}) }),
    Data.Object({ Cancel: Data.Object({}) })
]);

export type OrderRedeemer = Static<typeof OrderRedeemerSchema>;
export const OrderRedeemer = OrderRedeemerSchema as unknown as OrderRedeemer;