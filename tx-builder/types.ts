import { Data, type Static } from "@blaze-cardano/sdk";

const DatumSchema = Data.Object({
    msg: Data.Bytes(),
})
type Datum = Static<typeof DatumSchema>;
export const Datum = DatumSchema as unknown as Datum