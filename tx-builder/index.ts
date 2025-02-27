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
    Address,
    Ed25519KeyHashHex,
    RewardAccount,
} from "@blaze-cardano/core";
import { Ogmios, Unwrapped } from "@blaze-cardano/ogmios";
import { HotWallet, Blaze, Blockfrost, Data, type Static, Core, Kupmios } from "@blaze-cardano/sdk";
import { Action, CollateralDatum, Integer, NftPositionDatum, OutputIndexes, WithdrawAction, WithdrawRedeemer } from "./types";

//Prefix of the reference nft asset id according to CIP-68
const reference_prefix = "000643b0"

//Prefix of the nft asset id according to CIP-68
const user_nft_prefix = "000de140"

const validatorScript = Script.newPlutusV3Script(new PlutusV3Script(HexBlob.fromBytes(
    Buffer.from("5914fe01010029800aba4aba2aba1aba0aab9faab9eaab9dab9cab9a488888888a60022a66004921336578706563742063697036385f706f736974696f6e3a2043495036384d65746164617461203d20696e6c696e655f646174756d00168a998012492f657870656374206e66745f706f736974696f6e3a2043495036384d65746164617461203d20696e7075745f6461746100168a998012494c657870656374205363726970742876616c696461746f725f6861736829203d2073656c665f696e7075742e6f75747075742e616464726573732e7061796d656e745f63726564656e7469616c00168a998012491a72656465656d65723a20576974686472617752656465656d65720016488896600330013008375401d2300c300d0019ba5480026e1d20029b8748001222223232980098071baa0019809003cc048009222598009803801c4c8c8ca600244b30010018a508acc004cdd7801980b180d000c528c4cc008008c06c00501420309bab30183019301930193019301930193015375400b301830190034888cc00c00c00866e95200233016375264b3001300930143754003132598009805980a9baa00189bae301930163754003010404c6030602a6ea8c060c054dd51806180a9baa301830153754003153301349013465787065637420536f6d652873656c665f696e70757429203d2073656c665f696e70757473207c3e206c6973742e6865616428290016404864b30010018a6103d87a8000898059980b980c000a5eb8101619198008009bac30183015375400a44b30010018a5eb8226644b30013375e603660306ea80080162660340046600800800313300400400140546032002603400280b92f5c0602c00260246ea8012264b300130010048992cc00400e01b00d8999119800801112cc00400a2646600200200a44b30010018a518acc006600260346ea8c074006444b30010028a6103d87a80008acc004c044006260266603e604000497ae08cc00400e6042005337000029000a006406880f24603c603e603e00322232330010010042259800800c40122653001375c603e003375a6040003330030033024002401060440028102444646600200200844b3001001880244ca60026eb8c07c0066eacc0800066600600660480048020c08800502048c078c07cc07cc07cc07c00644646600200200644b30010018a508acc004c00cdd61810800c528c4cc008008c08800501b203e9111192cc004cdc78021bae30220058acc004cdc78019bae3022001899b87002375a6044604600314a080e2294101c1811002488966002602260386ea800e264b300100180144c966002003003899912cc00400600b13259800800c01a00d006899912cc00400601113259800800c5660026052005133010006225980080145660026036604c6ea800e264b300100180644c96600200300d806c03601b1332259800800c03e264b30010018084042021010899912cc00400602513259800800c04e0270138992cc004c0d000e02b01440c46eb400602681a0c0c400502f1bae001303000240c4605c0028160dd70009816801205c302b00140a4604e6ea800e016812226464b3001001806c03601b00d899912cc00400601f00f807c03e264600c606000e6eb80050301bae001302900240b8604e002605400481420128132013009804c02502a1813800a04a375a002604c005006409c60480028110dd58009811801400e0070034090604200280f8c074dd5001c00501a2444444445300130270099bad302600998040044a60020034bd70488a6002005001911198161ba73302c375200c660586ea400ccc0b0dd400125eb8000500a200c4888a6002605400922223259800981018159baa0018992cc004c084c0b0dd5000c4c08ccc0bcc0c0c0b4dd500119817981818169baa0013302f59800981098161baa0048998041bac3011302d37540066eb4c0c0c0b4dd500245300103d87a800040a897ae08a99815a4814865787065637420536f6d652873656c665f6f757470757429203d0a2020202074782e6f7574707574730a2020202020207c3e206c6973742e6174286f75747075745f696e64657829001640a86600e6eb0c040c0b0dd5001002454cc0a924014565787065637420536f6d652873656c665f696e70757429203d0a2020202074782e696e707574730a2020202020207c3e206c6973742e617428696e7075745f696e64657829001640a46600c6eb0c0b8c0acdd50008024888c966002646600200330013756604660586ea8c08cc0b0dd5181798161baa004a5eb824453001002800c888c966002605060646ea8006200513303530363033375400200481816600266e3c01802e26050660686e9ccc0d0dd48059981a1ba900333034375000497ae04bd704530103d87a800040bc809100e112cc00400629462b3001323232980099b8a48904000de140009800a4011337006e340052007800ae31375c6066007375a606660680049112cc004cc04c0249660033001001801c01666e052000002404d14a3153303249013c65786163745f76616c756528792c20785f706f6c6963795f69642c20785f61737365745f6e616d652c202d785f616d6f756e7429203f2046616c73650014a0818a2660260124b30019800800c00e00933702900000120268a518a9981924814365786163745f76616c756528792c20785f706f6c6963795f69642c20757365725f6e66745f61737365745f6e616d652c202d785f616d6f756e7429203f2046616c73650014a0818a29410300dd7181900098190009bac30300018998010011818800c528205440b914a315330294911b69735f706f736974696f6e735f6275726e6564203f2046616c73650014a08140c010dd5980598151baa00198131baa302a302b0044888966002603e0031323232332259800980f18179baa0028992cc00400633001001899912cc004c0a0c0c8dd5000c566002b300198009bae303630333754003008811a0148a518a99818a4811569735f6d696e745f76616c6964203f2046616c73650014a081822b30010028a518a99818a4811b69735f636f6c6c61746572616c5f657175616c203f2046616c73650014a08182294103040b503019b8733223259800981418199baa00189bad303432337606070002607060720026eb0c0dcc0d0dd5000c54cc0c9241a265787065637420536f6d6528746f6b656e29203d0a20202020746f6b656e732876616c2c20706f6c6963795f6964290a2020202020207c3e20646963742e746f5f706169727328290a2020202020207c3e206c6973742e66696c74657228666e2850616972286e616d652c205f616d6f756e742929207b2061737365745f6e616d65203d3d206e616d65207d290a2020202020207c3e206c6973742e686561642829001640c464b30010018a6103d87a8000898151981b191ba73303730340013303730350014bd70181b800a5eb810351919800800992cc004c0a8c0d0dd5000c52f5bded8c1137566070606a6ea800503219198008009bab302c3035375400c44b30010018a60103d87a8000899192cc004cdc8803800c56600266e3c01c0062605c66074607000497ae08a60103d87a800040d5133004004303c00340d46eb8c0d8004c0e4005037112cc004006297adef6c60899912cc004cdc78029bae303600289981c80119802002000c4cc010010005034181c000981c800a06c375c606860626ea8c054c0c4dd50009bae302830313754602a60626ea8004dd6980a98189baa301530313754002606860626ea8c0d0c0c4dd5181418189baa004816201e81640b205902c40d8606660606ea800a2a6605c9213865787065637420496e6c696e65446174756d28696e7075745f6461746129203d2073656c665f696e7075742e6f75747075742e646174756d001640b46024605c6ea8c094c0b8dd500098189819001181800098161baa0019800803cdd6981718159baa004981118159baa00480da0068acc004c08000626464b3001301b302c37546022605a6ea8c0c0c0c4006264b30013023302d3754003198009bae3031302e375400300380f200a81420563030302d37546060605a6ea8c090c0b4dd51818000c54cc0ad24012965787065637420496e6c696e65446174756d285f29203d2073656c665f6f75747075742e646174756d001640a860586ea8006600200f375a605c60566ea8012604460566ea8012036801a2b300130190018cc0048966002003148002266e01200233002002303100140b92232330010010032259800800c5300103d87a80008992cc004cdc78021bae302f00189813198191818000a5eb8226600600660680048168c0c8005030488a600290005204099b8a3371400291010854657374696e675f0033716004006b8c6600200f375a605c60566ea8012604460566ea801203680192222332259800981318181baa0018acc004c8c8cc8a60033001002800d22104000643b00040219800801400691104000de140004021300f3756602c606a6ea80966eb8c0e0c0d4dd5002a4444b300159800992cc004c0a0c0e4dd5000c4c96600200319800800c4c966002606060766ea8006264b30013031303c3754003159800981598071bab3040303d375400715980099b8f9800a4001480426eb8c100c0f4dd50012e309110854657374696e675f008acc004cdc79bae3040303d3754002910135697066733a2f2f516d5834384d5476623836334276426b425342384253576f4d5542645541626e54376e51676675516a6164614361008acc00566002606260786ea8c0cccc0fc00d2f5c114a314a081d229462a6607692012569735f736f6d6528536f6d652863697036385f706f736974696f6e2929203f2046616c73650014a081d22a660769213065787065637420696d616765203d3d206279746561727261792e66726f6d5f737472696e67286e66745f696d61676529001640e9153303b4915f6578706563740a202020206279746561727261792e74616b65286e616d652c206279746561727261792e6c656e677468286e66745f7072656669785f6279746561727261792929203d3d206e66745f7072656669785f627974656172726179001640e9153303b49130657870656374206c6973742e6c656e6774682863697036385f706f736974696f6e2e6d6574616461746129203d3d2032001640e9153303b4916a65787065637420536f6d6528696d61676529203d0a2020202063697036385f706f736974696f6e2e6d657461646174610a2020202020207c3e2070616972732e6765745f6669727374286279746561727261792e66726f6d5f737472696e67284022696d616765222929001640e8660206eacc0fcc0f0dd500124505696d616765008a9981d2496865787065637420536f6d65286e616d6529203d0a2020202063697036385f706f736974696f6e2e6d657461646174610a2020202020207c3e2070616972732e6765745f6669727374286279746561727261792e66726f6d5f737472696e672840226e616d65222929001640e46601e6eacc0f8c0ecdd5000a45046e616d650081ba03281bc0de06f0374100607a60746ea80062a6607092013165787065637420496e6c696e65446174756d28696e6c696e655f646174756d29203d206f6e5f636861696e5f646174756d001640dc603a60726ea8c0f0c0f402229462a6606e92011d69735f6e66745f706f736974696f6e5f76616c6964203f2046616c73650014a081b22b3001598009980c80112cc0066002003002802d2002406514a315330384913f65786163745f76616c756528792c2076616c696461746f725f686173682c207265666572656e63655f746f6b656e5f6e616d652c203129203f2046616c73650014a081ba2660320044b30019800800c00a009480090194528c54cc0e12413a65786163745f76616c756528792c2076616c696461746f725f686173682c20757365725f746f6b656e5f6e616d652c203129203f2046616c73650014a081ba29410364528c54cc0dd2411b69735f746f6b656e5f6d696e745f76616c6964203f2046616c73650014a081b229410360dd7181b18199baa3036303337540026eb4c0a8c0ccdd5181b18199baa00130350013031375400714a3153302f491326d696e745f746f6b656e2876616c696461746f725f686173682c2074785f64657461696c732c20747829203f2046616c73650014a081722a6605e92146657870656374205363726970742876616c696461746f725f6861736829203d2073656c665f6f75747075742e616464726573732e7061796d656e745f63726564656e7469616c001640b860080086064605e6ea8c0c8c0bcdd51819181998179baa00144c8c8c9660026046605a6ea80062b3001301c302d37546024605c6ea8c094c0b8dd500145660033001375c6062605c6ea800600701e401514a3153302c4901326275726e5f746f6b656e2876616c696461746f725f686173682c2074785f64657461696c732c20747829203f2046616c73650014a0815a2a660589212f65787065637420496e6c696e65446174756d285f29203d2073656c665f696e7075742e6f75747075742e646174756d001640ad02840ac6060605a6ea8c0c0c0b4dd5181218169baa001302f302c375400330010079bad302e302b37540093022302b375400901b400c814102820501133002002301e0018a50405c80da264b30010018992cc004c038c064dd500144c9660020030148992cc00400602b01580ac4cc89660020030178992cc004006264b300100180cc4c966002003159800981280144c966002602c60426ea8012264b300100180e44c96600200301d80ec07626644b300100180fc4c966002003159800981580144c966002603800313259800800c08a264b3001001811c08e047132598009817801c02a0488160dd6800c08d02f1816000a05430283754005159800980e800c56600260506ea800a00f02140a502140948128c098dd5000c081028408204102081020583029001409c6eb4004c0a000a03a8148c09800502418111baa00480da03e13259800980b000c56600260446ea800a01301b408d159800980b800c56600260446ea800a01301b408d1598009808000c56600260446ea800a01301b408d15980099b87480180062b30013022375400500980da04680da03e407c80f901f18101baa00180d204480d406a03501a409860460028108c08c00a03101880c40610241810800a03e375a00260400050154084603c00280e0c068dd5001404d01709801180e801c04a025012809203c301b00240646eb000c88c8cc00400400c88cc00c004c00800a01b00d4064602c60266ea80162b30013007004899251375c602c60266ea80162c80810101b874801100f0c044c048004c044015149a2a6600c9211856616c696461746f722072657475726e65642066616c7365001365640141", "hex")
)));

const validatorAddr = addressFromValidator(NetworkId.Testnet, validatorScript);

async function main() {
    // const provider = new Kupmios(
    //     "https://kupo1mkk2gvrdaf3xq4tlhgr.preview-v2.kupo-m1.demeter.run",
    //     await Unwrapped.Ogmios.new("https://ogmios1dvcw9kdyrdh65n83n89.preview-v6.ogmios-m1.demeter.run"),
    // );
    const provider = new Blockfrost({
        network: "cardano-preview",
        projectId: "previewNGYfHvK4N27rb9424ZT8azHI5ud8y35y",
    });

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
        new TransactionInput(TransactionId("22d2d9d4f4fa3cf1f1d4dc9a6a7638394e1aad6fa54f96da9f863c9b67083a2d"), 0n)
    ]);

    const pId = PolicyId("e8c74e5a3cccf580d0054056775e3e52bfe8ce9314c64d292000cbed");

    // const tx = await mintToken(blaze, scriptRef, wallet, pId);
    // const tx = await cancelToken(blaze, scriptRef, wallet, pId);
    const tx = await claimToken(blaze, scriptRef, wallet, pId);
    // const tx = await deployScript(blaze);
    // const tx = await registerCredential(blaze, validatorScript);

    const signedTx = await blaze.signTransaction(tx);
    const txId = await blaze.provider.postTransactionToChain(signedTx);
    console.log("Transaction Id", txId);
}

export async function mintToken(blaze: Blaze<Blockfrost | Kupmios, HotWallet>, scriptRef: TransactionUnspentOutput[], wallet: HotWallet, pId: PolicyId) {
    const collateralDatum = {
        PolicyId: "",
        AssetName: "",
        CollateralAmount: 5_000_000n
    } as CollateralDatum;
    const collateralDatumPlutusData = Data.to(collateralDatum, CollateralDatum);

    const metadataMap = new Map([
        ["6e616d65", "54657374696E675F4E6674506F736974696F6E2333"],
        ["696d616765", "697066733A2F2F516D5834384D5476623836334276426B425342384253576F4D5542645541626E54376E51676675516A6164614361"]
      ]);

    const nftPositionDatumPlutusData = Data.to({
        Metadata: metadataMap,
        Version: 1n,
        Extra: collateralDatum
    }, NftPositionDatum);

    const policyId = PolicyId(pId);
    const assetName = AssetName("54657374696E675F4E6674506F736974696F6E2333");

    const refTokenMapper: TokenMap = new Map<AssetId, bigint>();
    const refNftIdent = AssetId.fromParts(policyId, AssetName("000643B054657374696E675F0027CAC73F6583EDD7E950C02767FDEE179B9C98"));
    refTokenMapper.set(refNftIdent, 1n);

    const userTokenMapper: TokenMap = new Map<AssetId, bigint>();
    const userNftIdent = AssetId.fromParts(policyId, AssetName("000DE14054657374696E675F0027CAC73F6583EDD7E950C02767FDEE179B9C98"));
    userTokenMapper.set(userNftIdent, 1n);

    const assetMapper: Map<AssetName, bigint> = new Map<AssetName, bigint>();
    assetMapper.set(AssetName("000643B054657374696E675F0027CAC73F6583EDD7E950C02767FDEE179B9C98"), 1n);
    assetMapper.set(AssetName("000DE14054657374696E675F0027CAC73F6583EDD7E950C02767FDEE179B9C98"), 1n);

    const mintAction = Data.to({ MintAction: Data.Object([]) }, WithdrawAction);
    const option = Data.to({ int: 1n }, Integer);
    const indexes = Data.to({
        self_output_index: 0n,
        return_output_index: option
    }, OutputIndexes);

    const action = Data.to({ input_index: 0n, output_indexes: indexes, action_type: mintAction }, Action);
    const withdrawRedeemer = Data.to([action], WithdrawRedeemer);

    const rewardAccount = RewardAccount.fromCredential({
        type: CredentialType.ScriptHash,
        hash: validatorScript.hash()
    }, NetworkId.Testnet);

    const walletUtxos = await blaze.provider.getUnspentOutputs(wallet.address);
    console.log(walletUtxos[0].toCore());

    // Mint
    const tx = await blaze
        .newTransaction()
        // .addReferenceInput(scriptRef[0])
        .addWithdrawal(rewardAccount, 0n, withdrawRedeemer)
        .addInput(walletUtxos[0])
        .addMint(policyId, assetMapper, Data.void())
        .lockAssets(validatorAddr, new Value(1_400_000n, refTokenMapper), nftPositionDatumPlutusData)
        .payAssets(wallet.address, new Value(1_400_000n, userTokenMapper))
        .lockLovelace(validatorAddr, 5_000_000n, collateralDatumPlutusData)
        .provideScript(validatorScript)
        .complete();

    return tx;
}

export async function cancelToken(blaze: Blaze<Blockfrost | Kupmios, HotWallet>, scriptRef: TransactionUnspentOutput[], wallet: HotWallet, pId: PolicyId) {
    const collateralDatum = {
        PolicyId: "",
        AssetName: "",
        CollateralAmount: 4_000_000n
    } as CollateralDatum;
    const collateralDatumPlutusData = Data.to(collateralDatum, CollateralDatum);

    const metadataMap = new Map([
        ["6e616d65", "54657374696E675F4E6674506F736974696F6E31"],
        ["696d616765", "697066733A2F2F516D5834384D5476623836334276426B425342384253576F4D5542645541626E54376E51676675516A6164614361"]
      ]);

    const nftPositionDatumPlutusData = Data.to({
        Metadata: metadataMap,
        Version: 1n,
        Extra: collateralDatumPlutusData
    }, NftPositionDatum);

    const policyId = PolicyId(pId);
    const assetName = AssetName("54657374696E675F4E6674506F736974696F6E31");

    const refTokenMapper: TokenMap = new Map<AssetId, bigint>();
    const refNftIdent = AssetId.fromParts(policyId, AssetName("000643B054657374696E675F00CFD34E88B1AC06DD1A7E318D991E4DFC5FB117"));
    refTokenMapper.set(refNftIdent, 1n);

    const userTokenMapper: TokenMap = new Map<AssetId, bigint>();
    const userNftIdent = AssetId.fromParts(policyId, AssetName("000DE14054657374696E675F00CFD34E88B1AC06DD1A7E318D991E4DFC5FB117"));
    userTokenMapper.set(userNftIdent, 1n);

    const assetMapper: Map<AssetName, bigint> = new Map<AssetName, bigint>();
    // assetMapper.set(AssetName("000643B054657374696E675F00F4482BFA9E5EAFF3492F9E1045A0C6725094C9"), 1n);
    // assetMapper.set(AssetName("000DE14054657374696E675F00F4482BFA9E5EAFF3492F9E1045A0C6725094C9"), 1n);
    assetMapper.set(AssetName("000643B054657374696E675F00CFD34E88B1AC06DD1A7E318D991E4DFC5FB117"), -1n);
    assetMapper.set(AssetName("000DE14054657374696E675F00CFD34E88B1AC06DD1A7E318D991E4DFC5FB117"), -1n);

    const walletUtxos = await blaze.provider.getUnspentOutputsWithAsset(wallet.address, userNftIdent);
    const validatorUtxos = await blaze.provider.getUnspentOutputsWithAsset(validatorAddr, refNftIdent);

    const cancelAction = Data.to({ BurnAction: Data.Object([]) }, WithdrawAction);
    const option = Data.to({ int: 0n }, Integer);
    const indexes = Data.to({
        self_output_index: 0n,
        return_output_index: option
    }, OutputIndexes);

    const action = Data.to({ input_index: 0n, output_indexes: indexes, action_type: cancelAction }, Action);

    const withdrawRedeemer = Data.to([action], WithdrawRedeemer);

    const rewardAccount = RewardAccount.fromCredential({
        type: CredentialType.ScriptHash,
        hash: validatorScript.hash()
    }, NetworkId.Testnet);

    console.log(nftPositionDatumPlutusData.toCbor());

    const utxos = await blaze.provider.getUnspentOutputs(validatorAddr);

    // Cancel
    const tx = await blaze
        .newTransaction()
        // .addReferenceInput(scriptRef[0])
        .addWithdrawal(rewardAccount, 0n, withdrawRedeemer)
        .addInput(walletUtxos[0])
        .addInput(validatorUtxos[0], Data.void())
        .addMint(policyId, assetMapper, Data.void())
        .provideScript(validatorScript)
        .complete();

    return tx;
}

export async function claimToken(blaze: Blaze<Blockfrost | Kupmios, HotWallet>, scriptRef: TransactionUnspentOutput[], wallet: HotWallet, pId: PolicyId) {
    const collateralDatum = {
        PolicyId: "",
        AssetName: "",
        CollateralAmount: 4_000_000n
    } as CollateralDatum;
    const collateralDatumPlutusData = Data.to(collateralDatum, CollateralDatum);

    const metadataMap = new Map([
        ["6e616d65", "54657374696E675F4E6674506F736974696F6E2333"],
        ["696d616765", "697066733A2F2F516D5834384D5476623836334276426B425342384253576F4D5542645541626E54376E51676675516A6164614361"]
      ]);

    const nftPositionDatumPlutusData = Data.to({
        Metadata: metadataMap,
        Version: 1n,
        Extra: collateralDatumPlutusData
    }, NftPositionDatum);

    const policyId = PolicyId(pId);
    const assetName = AssetName("54657374696E675F4E6674506F736974696F6E2333");

    const refTokenMapper: TokenMap = new Map<AssetId, bigint>();
    const refNftIdent = AssetId.fromParts(policyId, AssetName("000643B054657374696E675F0027CAC73F6583EDD7E950C02767FDEE179B9C98"));
    refTokenMapper.set(refNftIdent, 1n);

    const userTokenMapper: TokenMap = new Map<AssetId, bigint>();
    const userNftIdent = AssetId.fromParts(policyId, AssetName("000DE14054657374696E675F0027CAC73F6583EDD7E950C02767FDEE179B9C98"));
    userTokenMapper.set(userNftIdent, 1n);

    const assetMapper: Map<AssetName, bigint> = new Map<AssetName, bigint>();
    assetMapper.set(AssetName("000643B054657374696E675F0027CAC73F6583EDD7E950C02767FDEE179B9C98"), -1n);
    assetMapper.set(AssetName("000DE14054657374696E675F0027CAC73F6583EDD7E950C02767FDEE179B9C98"), -1n);

    const walletUtxos = await blaze.provider.getUnspentOutputsWithAsset(wallet.address, userNftIdent);
    const validatorUtxos = await blaze.provider.getUnspentOutputsWithAsset(validatorAddr, refNftIdent);

    const cancelAction = Data.to({ ClaimAction: Data.Object([]) }, WithdrawAction);
    const option = Data.to({ int: 0n }, Integer);
    const indexes = Data.to({
        self_output_index: 0n,
        return_output_index: option
    }, OutputIndexes);

    const action = Data.to({ input_index: 0n, output_indexes: indexes, action_type: cancelAction }, Action);

    const withdrawRedeemer = Data.to([action], WithdrawRedeemer);

    const rewardAccount = RewardAccount.fromCredential({
        type: CredentialType.ScriptHash,
        hash: validatorScript.hash()
    }, NetworkId.Testnet);

    // console.log(nftPositionDatumPlutusData.toCbor());

    // const input = new TransactionInput(TransactionId("d266ff2227e243a92084e8dad35908b91780f804ee85b858e7882f3b77730759"), 2n);
    // console.log(walletUtxos[0].output().datum()?.toCbor());
    // Claim
    const tx = await blaze
        .newTransaction()
        // .addReferenceInput(scriptRef[0])
        .addWithdrawal(rewardAccount, 0n, withdrawRedeemer)
        .addInput(validatorUtxos[0], Data.void())
        .addInput(walletUtxos[0])
        .payLovelace(validatorAddr, 5_000_000n, Data.void())
        .addMint(policyId, assetMapper, Data.void())
        .provideScript(validatorScript)
        .complete();

    return tx;
}

export async function deployScript(blaze: Blaze<Kupmios | Blockfrost, HotWallet>) {
    const tx = await blaze
        .newTransaction()
        .deployScript(validatorScript, validatorAddr)
        .complete();

    return tx;
}

export async function payLovelaceAsync(blaze: Blaze<Kupmios | Blockfrost, HotWallet>, address: Address) {
    const tx = await blaze
        .newTransaction()
        .payLovelace(
            address,
            5_000_000n
        )
        .complete();

    const signedTx = await blaze.signTransaction(tx);
    const txId = await blaze.provider.postTransactionToChain(signedTx);
    console.log("Transaction ID", txId);
}

export async function registerCredential(blaze: Blaze<Kupmios | Blockfrost, HotWallet>, script: Script) {
    const registerTx = await blaze
        .newTransaction()
        .addRegisterStake(Credential.fromCore({
            type: CredentialType.ScriptHash,
            hash: script.hash()
        }))
        .complete();

    return registerTx;
}

main()