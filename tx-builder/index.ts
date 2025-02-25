import {
    addressFromValidator,
    AssetId,
    Bip32PrivateKey,
    HexBlob,
    Credential,
    blake2b_256,
    mnemonicToEntropy,
    NetworkId,
    PlutusV3Script,
    Script,
    TransactionId,
    TransactionInput,
    TransactionOutput,
    Value,
    wordlist,
    PolicyId,
    type TokenMap,
    AssetName,
    TransactionUnspentOutput,
    Datum,
    CredentialType,
    DatumKind,
    PlutusData,
} from "@blaze-cardano/core";
import { Unwrapped } from "@blaze-cardano/ogmios";
import { HotWallet, Blaze, Blockfrost, Data, type Static, Core, Kupmios } from "@blaze-cardano/sdk";

export const CollateralDetailSchema = Data.Object({
    PolicyId: Data.Bytes(),
    AssetName: Data.Bytes(),
    CollateralAmount: Data.Integer()
});

export type CollateralDatum = Static<typeof CollateralDetailSchema>;
export const CollateralDatum = CollateralDetailSchema as unknown as CollateralDatum;

export const NftPositionDatumSchema = Data.Object({
    Metadata: Data.Array(Data.Tuple(Data.Bytes()), { minItems: 2, maxItems: 2 }),
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

//Prefix of the reference nft asset id according to CIP-68
const reference_prefix = "000643b0"

//Prefix of the nft asset id according to CIP-68
const user_nft_prefix = "000de140"


const validatorScript = Script.newPlutusV3Script(new PlutusV3Script(HexBlob.fromBytes(
    Buffer.from("590a4d01010029800aba2aba1aba0aab9faab9eaab9dab9a48888889660033001300337540112300730080019ba5480026e1d20029b8748001222223232332259800980300144c8c8ca600244b30010018a508acc004cdd78019808180a000c528c4cc008008c05400500f20249bab3012301330133013301330133013300f3754009301230130034888cc00c00c00866e95200233010375264b30013008300e375400313259800980518079baa00189bae3013301037540031640386024601e6ea8c048c03cdd5180598079baa3012300f375400316403464b30010018a6103d87a800089805198089809000a5eb8101019198008009bac3012300f375400844b30010018a5eb8226644b30013375e602a60246ea80080162660280046600800800313300400400140406026002602800280892f5c0602000260186ea800e264b300130010038cc004c040c034dd50024dd61808002c88c8cc00400400c88cc00c004c00800922233001002225980080144c8cc004004014896600200314a3159800cc004c050dd5180b800c8896600200514c103d87a80008acc004c0400062602466032603400497ae08cc00400e6036005337000029000a006405480c2460306032603200322232330010010042259800800c40122653001375c6032003375a603400333003003301e0024010603800280d2444646600200200844b3001001880244ca60026eb8c0640066eacc06800666006006603c0048020c07000501a48c060c064c064c064c06400644646600200200644b30010018a508acc004c00cdd6180d800c528c4cc008008c07000501620329111192cc004cdc78021bae301c0058acc004cdc78019bae301c001899b87002375a6038603a00314a080ba2941017180e002244444445300130200089bad301f0089803803ca60020034bd70488a6002005001911198129ba733025375200c6604a6ea400ccc094dd400125eb80005009200a4888a60026046009301f37546046604800922223259800980f18121baa0018992cc004c07cc094dd5000c4c084cc0a0c0a4c098dd500119814181498131baa0013302859800980f98129baa0048998041bac3010302637540066eb4c0a4c098dd50024530103d87a8000409097ae08b2048330073758601e604a6ea80080122c8118cc018dd6181398121baa001004911191919800800cc004dd5981098129baa3021302537546050604a6ea801297ae09114c00400a0032223259800981318159baa001880144cc0b8c0bcc0b0dd500080120545980099b8f00600b89813198169ba73302d37520166605a6ea400ccc0b4dd400125eb812f5c114c103d87a800040a4808900d112cc00400629462b3001323232980099b8a48904000de140009800a4011337006e340052007800ae31375c6058007375a6058605a0049112cc004cc048024a6002003003802ccdc0a4000004809226602401253001001801c01266e052000002404914a081506eb8c0ac004c0ac004dd61814800c4cc008008c0a80062941024204e30043756601460466ea8005222259800980e801c4c8c8c8cc8966002603a60506ea800a264b300130233029375400313232323322598009819801c4cc080dd61819002912cc00400a2b3001302a30303754009132323298009bad30370019bae30370039bae303700248896600260760091598009818181b1baa00f899192cc004c0b4c0e0dd5000c4c966002606860726ea80062b300198009bae303d303a3754003016817a02e8acc004cdc39991192cc004c0d8c0f0dd5000c4dd6981e9919bb030410013041304200137586080607a6ea80062c81d8c96600200314c0103d87a80008981c1981f991ba733040303d00133040303e0014bd701820000a5eb8103e1919800800992cc004c0e0c0f4dd5000c52f5bded8c1137566082607c6ea800503c19198008009bab303a303e375400e44b30010018a60103d87a8000899192cc004cdc8803800c56600266e3c01c0062607866086608200497ae08a60103d87a800040fd133004004304500340fc6eb8c0fc004c108005040112cc004006297adef6c60899912cc004cdc78029bae303f00289982100119802002000c4cc01001000503e18208009821000a07e375c607a60746ea8c090c0e8dd50089bae3036303a3754604860746ea8044dd69812181d1baa3024303a375402313371e6eb8c0f4c0e8dd50011b943766607a60746ea80522941038452820708b2070303c30393754607860726ea8c0d4c0e4dd5009c590371811181c1baa001303a3037375401f1640d51640e030370013036001303137540091640bd13232332259800981c801c4c014c0e401a2c81b0dd7181b0009bae303600230360013758606800481922c8180c0c0004dd698180011818000981780098151baa0018b2050302c3029375400516409c6022604e6ea8c08cc09cdd5000981518159815801181480098129baa0019800803cdd6981398121baa004981018121baa00480ca0048acc004c07800e26464b3001301a302537546020604c6ea8c088c098dd5000c4c9660026042604c6ea800633001375c6054604e6ea800600701c40111640946052604c6ea8c0a4c098dd5181118131baa0018b204830283025375400330010079bad3027302437540093020302437540090194009159800980c001c4c8cc89660026036604c6ea8c044c09cdd5181198139baa0028992cc004c088c09cdd5000c4c8c8cc8a60033001002800d220104000643b00040199800801400691104000de140004019300d3756602660586ea80866eb8c0bcc0b0dd5002cc0bcc0b0dd5181798161baa3028302c3754006911112cc004c0acc0c0dd5000c4c966002605860626ea80062b3001598009980c00214c004006009007a400480c226603000853001001802401a900120308a5040c113371e6eb8c0d4c0c8dd50009bae30353032375400514a081822c8180c0d0c0c4dd5181a18189baa303430350098b205e1bae302d302a3754605a60546ea8004dd6981318151baa302d302a3754002605800260506ea80122c8130c0a8c09cdd5181518139baa3023302737540051640946050604a6ea8004888dca4c0052000a40813371466e2800522010854657374696e675f0033716004006b8c4c00401e6eb4c09cc090dd50024c080c090dd500240650024528a0444088811044cc008008c0600062941012202a899912cc004c034c04cdd500144c8c8c8cc8966002603a0071332259800980a180d1baa00289919912cc004c08800626464b30013019001899192cc004c09800a01116408c6eb4c090004c080dd50014566002603400315980098101baa00280345902145901e203c301e3754002604200316407c6eb4c07c004c080004c06cdd5001459019180e0020992cc004c04c0062b3001301a37540070078b20368acc004c0500062b3001301a37540070078b20368acc004c0380062b3001301a37540070078b20368acc004cdc3a400c003159800980d1baa003803c5901b4590182030406080c0c060dd500145901a180d0009bad301a003301a001301900130143754005164048602a00426002602c00480991598009803001c4c9289bae3010300d375400916402c8058dc3a40088050c024dd50009806803980618068009806002a29344d9590011", "hex")
)));

const validatorAddr = addressFromValidator(NetworkId.Testnet, validatorScript);

async function main() {
    const provider = new Kupmios(
        "https://kupo1mkk2gvrdaf3xq4tlhgr.preview-v2.kupo-m1.demeter.run",
        await Unwrapped.Ogmios.new("https://ogmios1dvcw9kdyrdh65n83n89.preview-v6.ogmios-m1.demeter.run"),
    );

    const mnemonic =
        "tray hollow agent whip bamboo picture project notice stage ethics rose hockey special reduce coyote ship grit abuse upon alpha option nice sting asthma";
    const entropy = mnemonicToEntropy(mnemonic, wordlist);
    const masterkey = Bip32PrivateKey.fromBip39Entropy(Buffer.from(entropy), "");
    const wallet = await HotWallet.fromMasterkey(masterkey.hex(), provider);

    const blaze = await Blaze.from(provider, wallet);

    // Optional: Print the wallet address
    console.log("Wallet address", wallet.address.toBech32());

    // Optional: Print the wallet balance
    console.log("Wallet balance", (await wallet.getBalance()).toCore());

    // Optional: Print the wallet balance
    console.log("Validator address", validatorAddr.toBech32());

    const scriptRef = await blaze.provider.resolveUnspentOutputs([
        new TransactionInput(TransactionId("79330665ae8479379728a705b8c9101e98494b81559be3c62788e841337d0c13"), 0n)
    ]);

    const collateralDatum = {
        PolicyId: "",
        AssetName: "",
        CollateralAmount: 4_000_000n
    } as CollateralDatum;
    const collateralDatumPlutusData = Data.to(collateralDatum, CollateralDatum);

    const nftPositionDatumPlutusData = Data.to({
        Metadata: [["6e616d65", "54657374696e675f7465737431"], ["696d616765", "697066733a2f2f516d5268545462557250594577336d4a4747685171515354396b38367631445042695454574a474b444a73564677"]],
        Version: 1n,
        Extra: collateralDatum
    }, NftPositionDatum);

    const policyId = PolicyId("8469500b8d58ab5c0905d0d9c38e48c4ef5a27e76b7a9af57bab0fba");
    const assetName = AssetName("54455354455253");

    // const assetNameRef = AssetName((reference_prefix + HexBlob.fromBytes(Buffer.from("Testing_")).toString() + "6216B0CAFB8F4CE5E256577D4FD3F1ED5A03BA19".toLowerCase()).toString());
    // const assetNameUser = AssetName((user_nft_prefix + HexBlob.fromBytes(Buffer.from("Testing_")).toString() + "6216B0CAFB8F4CE5E256577D4FD3F1ED5A03BA19".toLowerCase()).toString());

    const refTokenMapper: TokenMap = new Map<AssetId, bigint>();
    const refNftIdent = AssetId.fromParts(policyId, AssetName("000643b054657374696e675f076cd86f368eea383a5bfe974df57334ae27fa25"));
    refTokenMapper.set(refNftIdent, 1n);

    const userTokenMapper: TokenMap = new Map<AssetId, bigint>();
    const userNftIdent = AssetId.fromParts(policyId, AssetName("000de14054657374696e675f830758cd2ddbf661c5aa86defaaf346519225a5a"));
    userTokenMapper.set(userNftIdent, 1n);

    const assetMapper: Map<AssetName, bigint> = new Map<AssetName, bigint>();
    assetMapper.set(AssetName("000643b054657374696e675f076cd86f368eea383a5bfe974df57334ae27fa25"), -1n);
    assetMapper.set(AssetName("000de14054657374696e675f830758cd2ddbf661c5aa86defaaf346519225a5a"), -1n);

    const walletUtxos = await blaze.provider.getUnspentOutputs(wallet.address);
    // console.log(walletUtxos[1].toCore());

    // const input = new TransactionInput(TransactionId("40eff06b1d31cf51980ae449d2555256886a0c52e28d2d5e1a7e118c3d64dcc1"), 4n);

    // const utxo = new TransactionUnspentOutput(input, output);
    // const sortedUtxos = walletUtxos.sort();

    // const validatorUtxos = await blaze.provider.getUnspentOutputs(validatorAddr);
    // console.log(validatorUtxos[0].output().toCore());
    // Cancel
    // const tx = await blaze
    //     .newTransaction()
    //     .addReferenceInput(scriptRef[0])
    //     // .addInput(walletUtxos[1])
    //     // .addInput(walletUtxos[1])
    //     .addInput(validatorUtxos[0])
    //     .addMint(policyId, assetMapper, Data.void())
    //     .lockAssets(validatorAddr, new Value(1_000_000n, refTokenMapper), nftPositionDatumPlutusData)
    //     .complete();

    // Mint
    // const tx = await blaze
    //     .newTransaction()
    //     .addReferenceInput(scriptRef[0])
    //     .addInput(walletUtxos[1])
    //     .addMint(policyId, assetMapper, Data.void())
    //     .lockAssets(validatorAddr, new Value(2_000_000n, refTokenMapper), nftPositionDatumPlutusData)
    //     .payAssets(wallet.address, new Value(2_000_000n, userTokenMapper))
    //     .complete();

    // const signedTx = await blaze.signTransaction(tx);
    // const txId = await blaze.provider.postTransactionToChain(signedTx);
    // console.log("Transaction ID", txId);
}

async function deployScript(blaze: Blaze<Kupmios, HotWallet>) {
    const tx = await blaze
        .newTransaction()
        .deployScript(validatorScript, validatorAddr)
        .complete();
    const signedTx = await blaze.signTransaction(tx);
    const txId = await blaze.provider.postTransactionToChain(signedTx);
    console.log("Transaction ID", txId);
}

main()