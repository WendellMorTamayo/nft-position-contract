import { Data, type Static } from "@blaze-cardano/sdk";
import { Address, MultisigScript, Rational } from "./extra_types";

const SubjectSchema = Data.Object({
    PolicyId: Data.Bytes(),
    AssetName: Data.Bytes(),
});

export type Subject = Static<typeof SubjectSchema>;
export const Subject = SubjectSchema as unknown as Subject;

// Pool details
const PoolDetailSchema = Data.Object({
    PrincipalAsset: Subject,
    CollateralAsset: Subject
});

export type PoolDetails = Static<typeof PoolDetailSchema>;
export const PoolDetails = PoolDetailSchema as unknown as PoolDetails;

// Pool param details
const PoolParamDetailSchema = Data.Object({
    Fee: Rational,
    FeeAddress: Address,
    PoolDetails: PoolDetails,
});

export type PoolParamDetails = Static<typeof PoolParamDetailSchema>;
export const PoolParamDetails = PoolParamDetailSchema as unknown as PoolParamDetails;

// Pool param details
const GlobalParamsDetailSchema = Data.Object({
    Fee: Rational,
    FeeAddress: Address,
    Admin: MultisigScript,
    PoolParamsPolicy: Data.Bytes(),
    NftPrefix: Data.Bytes(),
    NftImage: Data.Bytes(),
    ForeclosedNftImage: Data.Bytes()
});

export type GlobalParamsDetails = Static<typeof GlobalParamsDetailSchema>;
export const GlobalParamsDetails = GlobalParamsDetailSchema as unknown as GlobalParamsDetails;

// Protocol param datum
const ProtocolParamsDatumSchema = Data.Enum([
    Data.Object({ GlobalParams: Data.Object({ global_params: GlobalParamsDetails}) }),
    Data.Object({ PoolParams: Data.Object({ pool_params: PoolParamDetails}) })
]);

export type ProtocolParamsDatum = Static<typeof ProtocolParamsDatumSchema>;
export const ProtocolParamsDatum = ProtocolParamsDatumSchema as unknown as ProtocolParamsDatum;

const CIP68MetadataSchema = Data.Object({
    Metadata: Data.Map(Data.Bytes(), Data.Bytes()),
    Version: Data.Integer(),
    Extra: ProtocolParamsDatum
});

export type CIP68Metadata = Static<typeof CIP68MetadataSchema>;
export const CIP68Metadata = CIP68MetadataSchema as unknown as CIP68Metadata;