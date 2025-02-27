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
    Buffer.from("59117701010029800aba4aba2aba1aba0aab9faab9eaab9dab9cab9a488888888a60022a66004921466578706563742072657475726e5f646174756d3a20486173683c426c616b6532625f3235362c204f75747075745265666572656e63653e203d2072657475726e5f646174756d00168a998012492f657870656374206e66745f706f736974696f6e3a2043697036384d65746164617461203d20696e7075745f6461746100168a998012494c657870656374205363726970742876616c696461746f725f6861736829203d2073656c665f696e7075742e6f75747075742e616464726573732e7061796d656e745f63726564656e7469616c00168a998012491a72656465656d65723a20576974686472617752656465656d65720016488896600330013008375401d2300c300d0019ba5480026e1d20029b8748001222223232980098071baa0019809003cc048009222598009803801c4c8c8ca600244b30010018a508acc004cdd7801980b180d000c528c4cc008008c06c00501420309bab30183019301930193019301930193015375400b301830190034888cc00c00c00866e95200233016375264b3001300930143754003132598009805980a9baa00189bae301930163754003010404c6030602a6ea8c060c054dd51806180a9baa301830153754003153301349013465787065637420536f6d652873656c665f696e70757429203d2073656c665f696e70757473207c3e206c6973742e6865616428290016404864b30010018a6103d87a8000898059980b980c000a5eb8101619198008009bac30183015375400a44b30010018a5eb8226644b30013375e603660306ea80080162660340046600800800313300400400140546032002603400280b92f5c0602c00260246ea8012264b300130010048992cc00400e01b00d8999119800801112cc00400a2646600200200a44b30010018a518acc006600260346ea8c074006444b30010028a6103d87a80008acc004c044006260266603e604000497ae08cc00400e6042005337000029000a006406880f24603c603e603e00322232330010010042259800800c40122653001375c603e003375a6040003330030033024002401060440028102444646600200200844b3001001880244ca60026eb8c07c0066eacc0800066600600660480048020c08800502048c078c07cc07cc07cc07c00644646600200200644b30010018a508acc004c00cdd61810800c528c4cc008008c08800501b203e9111192cc004cdc78021bae30220058acc004cdc78019bae3022001899b87002375a6044604600314a080e2294101c1811002244444445300130260089bad30250089803803ca60020034bd70488a6002005001911198159ba73302b375200c660566ea400ccc0acdd400125eb80005009200a4888a60026052009302537546052605400922223259800980f98151baa0018992cc004c080c0acdd5000c4c088cc0b8c0bcc0b0dd500119817181798161baa0013302e59800981018159baa0048998041bac3010302c37540066eb4c0bcc0b0dd50024530103d87a800040a497ae08a9981524814865787065637420536f6d652873656c665f6f757470757429203d0a2020202074782e6f7574707574730a2020202020207c3e206c6973742e6174286f75747075745f696e64657829001640a46600e6eb0c03cc0acdd5001002454cc0a524014565787065637420536f6d652873656c665f696e70757429203d0a2020202074782e696e707574730a2020202020207c3e206c6973742e617428696e7075745f696e64657829001640a06600c6eb0c0b4c0a8dd50008024888c966002646600200330013756604460566ea8c088c0acdd5181718159baa004a5eb824453001002800c888c966002604e60626ea8006200513303430353032375400200481796600266e3c01802e2604e660666e9ccc0ccdd4805998199ba900333033375000497ae04bd704530103d87a800040b8808900d112cc00400629462b3001323232980099b8a48904000de140009800a4011337006e340052007800ae31375c6064007375a606460660049112cc004cc0480249660033001001801c01666e052000002404914a3153303149013c65786163745f76616c756528792c20785f706f6c6963795f69642c20785f61737365745f6e616d652c202d785f616d6f756e7429203f2046616c73650014a081822660240124b30019800800c00e00933702900000120248a518a99818a4814365786163745f76616c756528792c20785f706f6c6963795f69642c20757365725f6e66745f61737365745f6e616d652c202d785f616d6f756e7429203f2046616c73650014a08182294102f0dd7181880098188009bac302f0018998010011818000c528205240b514a315330284911b69735f706f736974696f6e735f6275726e6564203f2046616c73650014a08138c010dd5980518149baa0014888966002603c0071323232332259800980e98171baa0028992cc0040062b30013024302f375400313259800800c0b2264b3001001816c0b626644b3001001817c4c96600200303081840c226644b300100181944c966002003159800981e00144cc08c01889660020051598009817181c9baa0038992cc00400606d13259800800c0de06f03781bc4cc89660020030398992cc00400607503a81d40ea26644b300100181e44c96600200303d81ec0f6264b300130470038acc004c0dcc108dd500ac4c8cc89660026068608a6ea8006264b3001001821c10e087043899912cc004c0f8c120dd5000c566002b300198009bae304c3049375400301f81ca0408a518a99823a4811569735f6d696e745f76616c6964203f2046616c73650014a082322b300159800802c528c54cc11d24011b69735f636f6c6c61746572616c5f657175616c203f2046616c73650014a082322b30010028a518a99823a4811c69735f646174756d5f7461675f636f7272656374203f2046616c73650014a0823229410464528208c821a08c3371e6eb8004dca1bb3304a304737540366094608e6ea8c128c11cdd5181f18239baa01b41306092608c6ea80062a6608892013665787065637420496e6c696e65446174756d2872657475726e5f646174756d29203d2072657475726e5f6f75747075742e646174756d0016410c66e1ccc88c9660026076608c6ea800626eb4c11cc8cdd81825800982598260009bac304a3047375400315330454901a265787065637420536f6d6528746f6b656e29203d0a20202020746f6b656e732876616c2c20706f6c6963795f6964290a2020202020207c3e20646963742e746f5f706169727328290a2020202020207c3e206c6973742e66696c74657228666e2850616972286e616d652c205f616d6f756e742929207b2061737365745f6e616d65203d3d206e616d65207d290a2020202020207c3e206c6973742e6865616428290016411064b30010018a6103d87a80008981e99824991ba73304a30470013304a30480014bd701825000a5eb810481919800800992cc004c0f4c11cdd5000c52f5bded8c113756609660906ea800504519198008009bab303f3048375400a44b30010018a60103d87a8000899192cc004cdc8803800c56600266e3c01c006260826609a609600497ae08a60103d87a80004121133004004304f00341206eb8c124004c13000504a112cc004006297adef6c60899912cc004cdc78029bae304900289982600119802002000c4cc01001000504718258009826000a092375c608e60886ea8c0a0c110dd500a9bae303b30443754605060886ea8054dd6981418221baa30283044375402a605060886ea8004c118c10cdd500ac54cc10524012a65787065637420536f6d652872657475726e5f6f757470757429203d2072657475726e5f6f75747075740016410103e41106eb400607a8238c1100050421bae00130430024110608200281f8dd700098200012082303e00140f060746ea800e06a81ba264b300100181b40da264b300100181bc4c96600200303881c40e20711332259800800c0ea264b300100181dc0ee07703b8992cc004c11400e26010608a01303c41086eb80050451821000a080375c00260820048210c0fc00503d1bac00181b40d9040181e8012076819a072819c0ce06703340f4607400281c0dd6800981c80140c103a181b800a06a3758002606c00502d816a06e303400140c860606ea8006056816a05702b815c0ad035181918179baa0028a99816a493865787065637420496e6c696e65446174756d28696e7075745f6461746129203d2073656c665f696e7075742e6f75747075742e646174756d001640b06022605a6ea8c090c0b4dd5000981818189818801181780098159baa0019800803cdd6981698151baa004981098151baa00480d20048acc004c07c00e26464b3001301a302b3754602060586ea8c0bcc0c0006264b30013022302c3754003198009bae3030302d375400300380ea008813a054302f302c3754605e60586ea8c08cc0b0dd51817800c54cc0a924012965787065637420496e6c696e65446174756d285f29203d2073656c665f6f75747075742e646174756d001640a460566ea8006600200f375a605a60546ea8012604260546ea801203480122b3001301800389919912cc004c088c0b0dd5001456600264664530019800801400691104000643b00040119800801400691104000de140004011300b3756602260606ea80826eb8c0ccc0c0dd5002a4444b3001598009980a00112cc0066002003002802d2002405114a3153303349013a65786163745f76616c756528792c2076616c696461746f725f686173682c207265666572656e63655f746f6b656e2c203129203f2046616c73650014a081922660280044b30019800800c00a009480090144528c54cc0cd2413565786163745f76616c756528792c2076616c696461746f725f686173682c20757365725f746f6b656e2c203129203f2046616c73650014a0819229410314528c54cc0c92411b69735f746f6b656e5f6d696e745f76616c6964203f2046616c73650014a081886eb8c0c4c0b8dd5181898171baa001375a604a605c6ea8c0c4c0b8dd5000981818169baa0038a518a99815a481326d696e745f746f6b656e2876616c696461746f725f686173682c2074785f64657461696c732c20747829203f2046616c73650014a081522a6605692146657870656374205363726970742876616c696461746f725f6861736829203d2073656c665f6f75747075742e616464726573732e7061796d656e745f63726564656e7469616c001640a8605c60566ea8c0b8c0acdd51817181798159baa0012229800a40014810266e28cdc5000a450854657374696e675f0033716004006b8c4c00401e6eb4c0b4c0a8dd50024c084c0a8dd500240690024528a04e409c813844cc008008c078006294101720368992cc004006264b3001300e3019375400513259800800c052264b300100180ac05602b1332259800800c05e264b30010018992cc00400603313259800800c566002604a00513259800980b18109baa0048992cc00400603913259800800c07603b01d899912cc00400603f13259800800c566002605600513259800980e000c4c9660020030228992cc004006047023811c4c966002605e00700a8122058375a00302340bc60580028150c0a0dd50014566002603a00315980098141baa002803c0850294085025204a3026375400302040a102081040820408160c0a40050271bad001302800280ea0523026001409060446ea801203680f84c966002602c00315980098111baa002804c06d0234566002602e00315980098111baa002804c06d0234566002602000315980098111baa002804c06d023456600266e1d20060018acc004c088dd50014026036811a03680f901f203e407c60406ea8006034811203501a80d40690261811800a042302300280c40620310184090604200280f8dd680098100014055021180f000a038301a3754005013405c26004603a007012809404a02480f0c06c0090191bac00322323300100100322330030013002002806c035019180b18099baa0058acc004c01c012264944dd7180b18099baa0058b202040406e1d2004403c30113012001301100545268a998032491856616c696461746f722072657475726e65642066616c7365001365640141", "hex")
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
        new TransactionInput(TransactionId("f5eaa68a929e89d0b0a0d2cfb3c204dfde5d72f9b84c364d7612d662c4a29377"), 0n)
    ]);

    const pId = PolicyId("d8fbe8730dd7c48356c64e7f1df9aba4e27a70686d3a76f6761a65e9");

    const tx = await mintToken(blaze, scriptRef, wallet, pId);
    // const tx = await cancelToken(blaze, scriptRef, wallet, pId);
    // const tx = await deployScript(blaze);
    // const tx = await registerCredential(blaze, validatorScript);

    const signedTx = await blaze.signTransaction(tx);
    const txId = await blaze.provider.postTransactionToChain(signedTx);
    console.log("Transaction Id", txId);
}

export async function mintToken(blaze: Blaze<Blockfrost, HotWallet>, scriptRef: TransactionUnspentOutput[], wallet: HotWallet, pId: PolicyId) {
    const collateralDatum = {
        PolicyId: "",
        AssetName: "",
        CollateralAmount: 4_000_000n
    } as CollateralDatum;
    const collateralDatumPlutusData = Data.to(collateralDatum, CollateralDatum);

    const metadataMap = new Map([
        ["6e616d65", "54657374696E675F4E6674506F736974696F6E31"],
        ["696d616765", "697066733a2f2f516d5268545462557250594577336d4a4747685171515354396b38367631445042695454574a474b444a73564677"]
      ]);

    const nftPositionDatumPlutusData = Data.to({
        Metadata: metadataMap,
        Version: 1n,
        Extra: collateralDatum
    }, NftPositionDatum);

    const policyId = PolicyId(pId);
    const assetName = AssetName("54657374696E675F4E6674506F736974696F6E31");

    const refTokenMapper: TokenMap = new Map<AssetId, bigint>();
    const refNftIdent = AssetId.fromParts(policyId, AssetName("000643B054657374696E675F02ACB22505077675D16B393CAD45D2AC9CD3DD3F"));
    refTokenMapper.set(refNftIdent, 1n);

    const userTokenMapper: TokenMap = new Map<AssetId, bigint>();
    const userNftIdent = AssetId.fromParts(policyId, AssetName("000DE14054657374696E675F02ACB22505077675D16B393CAD45D2AC9CD3DD3F"));
    userTokenMapper.set(userNftIdent, 1n);

    const assetMapper: Map<AssetName, bigint> = new Map<AssetName, bigint>();
    assetMapper.set(AssetName("000643B054657374696E675F02ACB22505077675D16B393CAD45D2AC9CD3DD3F"), 1n);
    assetMapper.set(AssetName("000DE14054657374696E675F02ACB22505077675D16B393CAD45D2AC9CD3DD3F"), 1n);

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
    console.log(walletUtxos[1].toCore());

    // Mint
    const tx = await blaze
        .newTransaction()
        // .addReferenceInput(scriptRef[0])
        .addWithdrawal(rewardAccount, 0n, withdrawRedeemer)
        .addInput(walletUtxos[1])
        .addMint(policyId, assetMapper, Data.void())
        .lockAssets(validatorAddr, new Value(2_000_000n, refTokenMapper), nftPositionDatumPlutusData)
        .payAssets(wallet.address, new Value(2_000_000n, userTokenMapper))
        .provideScript(validatorScript)
        .complete();

    return tx;
}

export async function cancelToken(blaze: Blaze<Blockfrost, HotWallet>, scriptRef: TransactionUnspentOutput[], wallet: HotWallet, pId: PolicyId) {
    const collateralDatum = {
        PolicyId: "",
        AssetName: "",
        CollateralAmount: 4_000_000n
    } as CollateralDatum;
    const collateralDatumPlutusData = Data.to(collateralDatum, CollateralDatum);

    const metadataMap = new Map([
        ["6e616d65", "54657374696E675F4E6674506F736974696F6E"],
        ["696d616765", "697066733a2f2f516d5268545462557250594577336d4a4747685171515354396b38367631445042695454574a474b444a73564677"]
      ]);

    const nftPositionDatumPlutusData = Data.to({
        Metadata: metadataMap,
        Version: 1n,
        Extra: collateralDatumPlutusData
    }, NftPositionDatum);

    const policyId = PolicyId(pId);
    const assetName = AssetName("54657374696E675F4E6674506F736974696F6E");

    const refTokenMapper: TokenMap = new Map<AssetId, bigint>();
    const refNftIdent = AssetId.fromParts(policyId, AssetName("000643B054657374696E675F4E6674506F736974696F6E54657374696E675F00"));
    refTokenMapper.set(refNftIdent, 1n);

    const userTokenMapper: TokenMap = new Map<AssetId, bigint>();
    const userNftIdent = AssetId.fromParts(policyId, AssetName("000DE14054657374696E675F4E6674506F736974696F6E54657374696E675F00"));
    userTokenMapper.set(userNftIdent, 1n);

    const assetMapper: Map<AssetName, bigint> = new Map<AssetName, bigint>();
    // assetMapper.set(AssetName("000643B054657374696E675F4E6674506F736974696F6E54657374696E675F02"), 1n);
    // assetMapper.set(AssetName("000DE14054657374696E675F4E6674506F736974696F6E54657374696E675F02"), 1n);
    assetMapper.set(AssetName("000643B054657374696E675F4E6674506F736974696F6E54657374696E675F00"), -1n);
    assetMapper.set(AssetName("000DE14054657374696E675F4E6674506F736974696F6E54657374696E675F00"), -1n);

    const walletUtxos = await blaze.provider.getUnspentOutputsWithAsset(wallet.address, userNftIdent);
    const validatorUtxos = await blaze.provider.getUnspentOutputsWithAsset(validatorAddr, refNftIdent);

    const cancelAction = Data.to({ BurnAction: Data.Object([]) }, WithdrawAction);
    const option = Data.to({ int: 1n }, Integer);
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

    const output = new TransactionOutput(wallet.address, new Value(5_000_000n));

    console.log(nftPositionDatumPlutusData.toCbor());

    const utxos = await blaze.provider.getUnspentOutputs(wallet.address);

    // Cancel
    const tx = await blaze
        .newTransaction()
        // .addReferenceInput(scriptRef[0])
        .addWithdrawal(rewardAccount, 0n, withdrawRedeemer)
        .addInput(walletUtxos[0])
        .addInput(validatorUtxos[0], Data.void())
        .addInput(utxos[0])
        .addMint(policyId, assetMapper, Data.void())
        .provideScript(validatorScript)
        .complete();

    return tx;
}

export async function deployScript(blaze: Blaze<Kupmios, HotWallet>) {
    const tx = await blaze
        .newTransaction()
        .deployScript(validatorScript, validatorAddr)
        .complete();

    return tx;
}

export async function payLovelaceAsync(blaze: Blaze<Kupmios, HotWallet>, address: Address) {
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

export async function registerCredential(blaze: Blaze<Kupmios, HotWallet>, script: Script) {
    const registerTx = await blaze
        .newTransaction()
        .addRegisterStake(Credential.fromCore({
            type: CredentialType.ScriptHash,
            hash: script.hash()
        }))
        .complete();

    return registerTx;
}

// Cancel a locked utxo from Smart Contract
async function cancel(
    blaze: Blaze<Blockfrost, HotWallet>,
    script: Script,
    rewardAccount: RewardAccount,
    feeAddr: Address,
    ownerWallet: HotWallet
) {
    // const cancelTx = await blaze
    //     .newTransaction()
    //     .addInput(lockedUtxos[0], Data.void())
    //     .addRequiredSigner(Ed25519KeyHashHex(ownerWallet.address.asBase()?.getPaymentCredential().hash!))
    //     .addWithdrawal(rewardAccount, 0n, withdrawRedeemer)
    //     .payLovelace(feeAddr, 2_000_000n)
    //     .provideScript(script)
    //     .complete();

    // const signedTx = await blaze.signTransaction(cancelTx);
    // const txId = await blaze.provider.postTransactionToChain(signedTx);
    // console.log("Transaction Id", txId);
}

main()