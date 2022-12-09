const { AtomicTransactionComposer, ABIContract, Transaction, Algod } = require('algosdk');
const algosdk = require('algosdk');
const { ABIMethod } = require('algosdk/dist/cjs/src/abi/method');
const { Router } = require('express');
const fs = require('fs')
const database = require('../utils/database')
const query = require('../utils/queries')
const crypto = require('crypto');
const base32 = require('base32')
const base64url = require('base64url');
const cbor = require('cbor');
const { MyAlgoConnect } = require('@randlabs/myalgo-connect');


const server="https://testnet-algorand.api.purestake.io/ps2";
const port="";
const token={
    "x-api-key": "cFytdDh7ETMLwFujzahn1V7710kbJFL5ZPIZhOMj" // fill in yours
};

let client = new algosdk.Algodv2(token,server,port);


/**
 * Create a wallet
 * @param {*} req 
 * @param {*} res 
 * @param {*} next 
 */
exports.createWallet = async (req, res, next) => {
    console.log("ok")
    //Use sandbox 
    const kmdPort = '4002'
    const kmdServer = 'http://localhost'
    const kmdToken = {
        "X-KMD-API-Token" : "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    }
  
    let walletName = 'My wallet 4'
    let walletPassword = 'pass'
   
    let kmd = new algosdk.Kmd(kmdToken, kmdServer, kmdPort)
    console.log("kmd " , kmd)
   
    let walletId = (await kmd.createWallet(walletName = walletName, walletPassword = walletPassword)).wallet.id 

    let walletHandle = (await kmd.initWalletHandle(walletId, walletPassword))['wallet_handle_token']
    console.log("wallet handle", walletHandle)
    let wallet = (await kmd.getWallet(walletHandle))
    console.log("wallet ", wallet)

    let listKeys = await kmd.listKeys(walletHandle)
    console.log("list keys ", listKeys)

    const connection = await database.getConnection(); 

    try{
        const [rows, field] = await connection.query(query.insertWallet, [walletId, walletName, walletPassword]); 
    }   
    catch(err){
        console.log("error: ", err)
    }
}


exports.algo = async (req, res, next) => {

    const myAlgoConnect = new MyAlgoConnect()
    const accountsSharedByUser = await myAlgoConnect.connect()





}


exports.rekeyTest = async (req, res, next) => {
    /**
     * 
     * A 
  EKWSBPB2TNASC5JUMW54EEXVET5H2ASRYTT7VNFGTKDL5LB7KEMDZ3G3NA wink great able cheese dog subway envelope air grain army puzzle example honey veteran obey evolve movie empty reunion embark crater mandate casual absent speed
B 
  3XWL2UF3HIIRAHGEI44IPLC6KSTG6IJXYRI5V262M74EYGMU7MSTI2SGAQ enact easy office initial whip resemble hammer weather bone combine illegal cart warrior hold sunny panda blame satisfy quit release gloom machine hip about price
C 
  DNFYBFJRKAJ4VBOM3OJYPFEK5EKKCT3VGNRZ7XXFAMRS4XJN2SQAFE3TP4 common peasant final message awake puzzle flame prefer bless fade custom muscle library mimic diesel fade tiny inquiry love truth vacant solid elbow able lounge
     * 
     * 
     */

    const server="https://testnet-algorand.api.purestake.io/ps2";
    const port="";
    const token={
        "x-api-key": "cFytdDh7ETMLwFujzahn1V7710kbJFL5ZPIZhOMj" // fill in yours    
    };

    let client = new algosdk.Algodv2(token,server,port);

    /**
     * Retrieve publick key of  webauthn
     */
     const connection = await database.getConnection(); //recupera una connessione dal pool di connessioni al dabatase

    var name;
    var credentialId;
    var cosePublicKeyBuffer;

     try{
        const [rows, field] = await connection.query(query.getUserByUsername, ['test']); //Creazione utente
        console.log("rows ", rows[0])
        if(rows != undefined){
            name = name;
            credentialId = base64url.toBuffer(rows[0].credential_id)
            cosePublicKeyBuffer = base64url.toBuffer(rows[0].public_key)
        }
    }
    catch(err){
        console.log("error: ", err)
    }

    console.log("cosePublicKeyBuffer ", cosePublicKeyBuffer)
    
    let publicKey = COSEECDHAtoPKCS(cosePublicKeyBuffer) //get Buffer from COSE format public key
    publicKey = Uint8Array.from(publicKey)
    console.log("pem public key ", publicKey)
    
    
    var encodedPubKey = base32.encode(publicKey)
    console.log("ecnoded key ", encodedPubKey,  algosdk.isValidAddress(encodedPubKey))

   
    // CRYPTO

    let options = {
        modulusLength: 4096,
        publicKeyEncoding: {
          type: 'spki',
          format: 'pem'
        },
        privateKeyEncoding: {
          type: 'pkcs8',
          format: 'pem',
          cipher: 'aes-256-cbc',
          passphrase: 'top-secret'
        }
    }

    crypto.generateKeyPair(type="ed25519", options=options, async (err, publicKey, privateKey) => {
             console.log("*********************publicKey ", publicKey, algosdk.isValidAddress(publicKey))
             console.log("*********************privateKey ", privateKey)
                
             //let addr = await (kmd.importKey(walletHandle, privateKey))
             //console.log("addr ", addr) // SEMWDPBHDQEFRI2JVDRCLAZOFABDWLRDQHTLSDATTHPQNGCPJOKQQDKEGQ
    })


    //let A = await algosdk.generateAccount(); //Account 1 -> rekey su B (firmare con chiave di B)
    //console.log("A \n ", A.addr, algosdk.secretKeyToMnemonic(A.sk))
    let Aaddr = 'EKWSBPB2TNASC5JUMW54EEXVET5H2ASRYTT7VNFGTKDL5LB7KEMDZ3G3NA'
    let Ask = await algosdk.mnemonicToSecretKey('wink great able cheese dog subway envelope air grain army puzzle example honey veteran obey evolve movie empty reunion embark crater mandate casual absent speed')

    //let B = await algosdk.generateAccount();
    //console.log("B \n ", B.addr, algosdk.secretKeyToMnemonic(B.sk))
    let Baddr = '3XWL2UF3HIIRAHGEI44IPLC6KSTG6IJXYRI5V262M74EYGMU7MSTI2SGAQ'
    let Bsk = await algosdk.mnemonicToSecretKey('enact easy office initial whip resemble hammer weather bone combine illegal cart warrior hold sunny panda blame satisfy quit release gloom machine hip about price')
    //console.log("A ", A, "\n B ", B)

    //let C = await algosdk.generateAccount(); //per test -> tx2 invia da A a C firmando con B
    //console.log("C \n ", C.addr, algosdk.secretKeyToMnemonic(C.sk))
    let Caddr = 'DNFYBFJRKAJ4VBOM3OJYPFEK5EKKCT3VGNRZ7XXFAMRS4XJN2SQAFE3TP4'
    let Csk = await algosdk.mnemonicToSecretKey('common peasant final message awake puzzle flame prefer bless fade custom muscle library mimic diesel fade tiny inquiry love truth vacant solid elbow able lounge')
    
    let params = await client.getTransactionParams().do()
    console.log("params ", params)

 
    let txn = await algosdk.makePaymentTxnWithSuggestedParams(Aaddr, Aaddr, 0, undefined, undefined, params, rekeyTo = Baddr);        
    console.log("txn ", txn)

    let strRek = await txn.signTxn(Ask.sk);
    console.log("str Rek ", strRek)
    let txID = await client.sendRawTransaction(strRek).do()
    console.log("Successfully sent transaction with txID: ", txID)

    console.log("A ", await client.accountInformation(Aaddr).do())
    console.log("B ", await client.accountInformation(Baddr).do())


    let txn2 = await algosdk.makePaymentTxnWithSuggestedParams(Aaddr, Baddr, 0, undefined, undefined, params)
    let sign = await txn2.signTxn(Bsk.sk)
    let txID2 = await client.sendRawTransaction(sign).do()
    console.log("Successfully sent second transaction with txID: ", txID2)


}

exports.ipfsTest = async (req, res, next) => {
    console.log("x")

    const server="https://testnet-algorand.api.purestake.io/ps2";
    const port="";
    const token={
        "x-api-key": "cFytdDh7ETMLwFujzahn1V7710kbJFL5ZPIZhOMj" // fill in yours    
    };

    let client = new algosdk.Algodv2(token,server,port);


    const { create } = await import('ipfs-core');
    let ipfs = await create()
    const version = await ipfs.version();
    console.log("Ipfs version : ", version.version)

    
    const { cid } = await ipfs.add('Hello world')
    console.log('cid ', cid)

    const stream = await ipfs.cat(cid)
    console.log(" stream ", stream)


    const decoder = new TextDecoder()
    let data = ''

    for await (const chunk of stream) {
    // chunks of data are returned as a Uint8Array, convert it back to a string
    data += decoder.decode(chunk, { stream: true })
    }

    console.log("data ", data)



}


exports.importKeyIntoWallet = async (req, res, next) => {

     //Use sandbox 
    //  const kmdPort = '4002'
    //  const kmdServer = 'http://localhost'
    //  const kmdToken = {
    //      "X-KMD-API-Token" : "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    //  }
   
     
    
    // let kmd = new algosdk.Kmd(kmdToken, kmdServer, kmdPort)
 
    //  console.log("kmd " , kmd)
    
    // let walletId = "5267757a35fe67bd3d98c976fa7fcbfb" //retrieve it from db

    // let walletHandle = (await kmd.initWalletHandle(walletId, "pass"))['wallet_handle_token']
    // console.log("wallet handle", walletHandle)
    // let wallet = (await kmd.getWallet(walletHandle))
    // console.log("wallet ", wallet)


    // let options = {
    //     modulusLength: 4096,
    //     publicKeyEncoding: {
    //       type: 'spki',
    //       format: 'pem'
    //     },
    //     privateKeyEncoding: {
    //       type: 'pkcs8',
    //       format: 'pem',
    //       cipher: 'aes-256-cbc',
    //       passphrase: 'top-secret'
    //     }
    // }
    // if(0){ 
    //     crypto.generateKeyPair(type="ed25519", options=options, async (err, publicKey, privateKey) => {
    //         console.log("publicKey ", publicKey)
    //         console.log("privateKey ", privateKey)
            
    //         let addr = await (kmd.importKey(walletHandle, privateKey))
    //         console.log("addr ", addr) // SEMWDPBHDQEFRI2JVDRCLAZOFABDWLRDQHTLSDATTHPQNGCPJOKQQDKEGQ
    //     })
    // }


    // let listKeys = await kmd.listKeys(walletHandle)
    // console.log("list keys ", listKeys)

    // let privKey = await kmd.exportKey(walletHandle, 'pass', 'SEMWDPBHDQEFRI2JVDRCLAZOFABDWLRDQHTLSDATTHPQNGCPJOKQQDKEGQ')
    // console.log("private key ", privKey)

    const server="https://testnet-algorand.api.purestake.io/ps2";
const port="";
const token={
    "x-api-key": "cFytdDh7ETMLwFujzahn1V7710kbJFL5ZPIZhOMj" // fill in yours    
};

    let client = new algosdk.Algodv2(token,server,port);

    let account = algosdk.generateAccount()
    /*
        Account = { addr , sk}
    */
   
    let sk =  crypto.generateKey(type = 'aes', options = {length : 128}, async (err, key) => {
        if (err) throw err;
        console.log(key.export().toString('hex'));  // 46e..........620

        let sign = algosdk.makeBasicAccountTransactionSigner({addr : 'addr', sk : key})
        console.log("sing ", sign)
        
      })
   
      algosdk.signTransaction()
 
 
 
    
 
//    let address = await kmd.importKey(walletHandle, privKey)
   // console.log("address ", address)


   // algosdk.secretKeyToMnemonic()
}

exports.createAccount = async (req, res, next) => {

    const server="https://testnet-algorand.api.purestake.io/ps2";
    const port="";
    const token={
        "x-api-key": "cFytdDh7ETMLwFujzahn1V7710kbJFL5ZPIZhOMj" // fill in yours
    };

    let client = new algosdk.Algodv2(token,server,port);

    
    let account = algosdk.generateAccount();
    console.log("Account Address: ", account.addr);
    
    let mn = algosdk.secretKeyToMnemonic(account.sk);
    console.log("Account Mnemonic: ", mn);

    console.log("Account ", account)

    console.log("account information ", client.accountInformation(account.addr))

    //let acc = new Account()


    res.send(account)
    
}

exports.getAccount = (req, res, next) => {

    const server="https://testnet-algorand.api.purestake.io/ps2";
    const port="";
    const token={
        "x-api-key": "cFytdDh7ETMLwFujzahn1V7710kbJFL5ZPIZhOMj" // fill in yours
    };

    let client = new algosdk.Algodv2(token,server,port);
    
    (async () => {
        let addr_1 = 'X7UCY46QD4RAFSGZWREELZZF7W5GJKHFUK6CLIFJYH7K7DAZIONTCKW6OE'
        let mnemonic_1 = 'grit session burger company shell junior erupt thank scatter dignity dentist exclude usual race jaguar loop cargo inject carbon usage used hub laundry abstract recall'
        let account1_info = (await client.accountInformation(addr_1).do());
        console.log("Balance of account 1: " + JSON.stringify(account1_info.amount));

        let addr_2 = 'UJMYQJIBIPH2WNPQUX6EKOB3WW6U4ZHAFDK45AG7QQQZQEOMDJFXEYK4BA'
        let mnemonic_2 = 'together dwarf inside submit supply lens maze pen cause stadium catalog believe citizen tourist doctor bonus moment flavor corn adult breeze series nature abstract mass'
    

        let params = await client.getTransactionParams().do();
    
        let amount =100000 // Math.floor(Math.random() * 1000);
        var mnemonic = mnemonic_1;
        var recoveredAccount = algosdk.mnemonicToSecretKey(mnemonic);
        
        let txn = {
            "from": recoveredAccount.addr,
            "to": addr_2,
            "fee": 1,
            "amount": amount,
            "firstRound": params.firstRound,
            "lastRound": params.lastRound,
            "genesisID": params.genesisID,
            "genesisHash": params.genesisHash,
            "note": new Uint8Array(0),
        };
    
        let signedTxn = algosdk.signTransaction(txn, recoveredAccount.sk);
        let sendTx = await client.sendRawTransaction(signedTxn.blob).do();
    
        console.log("Transaction : " + sendTx.txId);
    })().catch(e => {
        console.log(e);
    }); 
}

exports.createApp = async (req, res, next) => {
    let addr_1 = 'X7UCY46QD4RAFSGZWREELZZF7W5GJKHFUK6CLIFJYH7K7DAZIONTCKW6OE'
    let mnemonic_1 = 'grit session burger company shell junior erupt thank scatter dignity dentist exclude usual race jaguar loop cargo inject carbon usage used hub laundry abstract recall'
   
    // get account from mnemonic
    let creatorAccount = algosdk.mnemonicToSecretKey(mnemonic_1);
    let sender = addr_1 ;

    // user declared algod connection parameters
    
    const server="https://testnet-algorand.api.purestake.io/ps2";
    const port="";
    const token={
        "x-api-key": "cFytdDh7ETMLwFujzahn1V7710kbJFL5ZPIZhOMj" // fill in yours
    };

    let client = new algosdk.Algodv2(token,server,port);


    // declare application state storage (immutable)
    localInts = 2;
    localBytes = 2;
    globalInts = 2;
    globalBytes = 2;

    // get node suggested parameters
    let params = await client.getTransactionParams().do();
    // comment out the next two lines to use suggested fee
    params.fee = 1000;
    params.flatFee = true;

    // declare onComplete as NoOp
    onComplete = algosdk.OnApplicationComplete.NoOpOC;

    // helper function to compile program source  
    
    async function compileProgram(client, programSource) {
        let encoder = new TextEncoder();
        let programBytes = encoder.encode(programSource);
        let compileResponse = await client.compile(programBytes).do();
        let compiledBytes = new Uint8Array(Buffer.from(compileResponse.result, "base64"));
        return compiledBytes;
    }

    let approvalProgram = `#pragma version 7
    txn NumAppArgs
    intc_0 // 0
    ==
    bnz main_l2
    err
    main_l2:
    txn OnCompletion
    intc_0 // NoOp
    ==
    bnz main_l4
    err
    main_l4:
    txn ApplicationID
    intc_0 // 0
    ==
    assert
    callsub create_0
    intc_1 // 1
    return
    
    // create
    create_0:
    intc_1 // 1
    return`

    let clearProgram = `#pragma version 7
    pushint 0 // 0
    return`

    // create unsigned transaction
    let txn = algosdk.makeApplicationCreateTxn(sender, params, onComplete, 
        await compileProgram(client, approvalProgram), await compileProgram(client, clearProgram), 
        localInts, localBytes, globalInts, globalBytes,);
    let txId = txn.txID().toString();

    // Sign the transaction
    let signedTxn = txn.signTxn(creatorAccount.sk);
    console.log("Signed transaction with txID: %s", txId);

    // Submit the transaction
    await client.sendRawTransaction(signedTxn).do();

    // Wait for transaction to be confirmed
    confirmedTxn = await algosdk.waitForConfirmation(client, txId, 4);
    //Get the completed Transaction
    console.log("Transaction " + txId + " confirmed in round " + confirmedTxn["confirmed-round"]);

    // display results
    let transactionResponse = await client.pendingTransactionInformation(txId).do();
    let appId = transactionResponse['application-index'];
    console.log("Created new app-id: ",appId); 
    // Signed transaction with txID: SCXXDDNXR43WCAZ6KLQZEZWMTY3IN7AQPNGKMICLBBQMOBVZF2DQ
    // Transaction SCXXDDNXR43WCAZ6KLQZEZWMTY3IN7AQPNGKMICLBBQMOBVZF2DQ confirmed in round 25638945
    // Created new app-id:  123768175

    /**
     * Signed transaction with txID: GRDJLJAIL6O7CKFQRF3P67M374NUSTAUURR4KWZGYO6DDTIO2S2Q
    Transaction GRDJLJAIL6O7CKFQRF3P67M374NUSTAUURR4KWZGYO6DDTIO2S2Q confirmed in round 25656363
    Created new app-id:  123901690
     */


    }



// call Application 
exports.callApp = async (req, res, next) => {
    let mnemonic_1 = 'grit session burger company shell junior erupt thank scatter dignity dentist exclude usual race jaguar loop cargo inject carbon usage used hub laundry abstract recall'
    let mnemonic_2 = 'together dwarf inside submit supply lens maze pen cause stadium catalog believe citizen tourist doctor bonus moment flavor corn adult breeze series nature abstract mass'
    // get accounts from mnemonic
    let userAccount = algosdk.mnemonicToSecretKey(mnemonic_1);
    let sender = userAccount.addr;

    let sp = await client.getTransactionParams().do()

    let appId = 124087841
    console.log(" here ")
    
    const atc = new algosdk.AtomicTransactionComposer()

    // Read in the local contract.json file
    const buff = fs.readFileSync("./contracts/contract.json")

    //let buff = {"name": "my-first-router", "methods": [{"name": "increment", "args": [], "returns": {"type": "void"}}, {"name": "decrement", "args": [], "returns": {"type": "void"}}], "networks": {}}    


    // Parse the json file into an object, pass it to create an ABIContract object
    const contract = new algosdk.ABIContract(JSON.parse(buff))


    //console.log("get app Id ", await client.genesis().do())
    let genesis_hash = await client.genesis().do()

    const commonParams = {
        appID:appId, //contract.networks[genesis_hash],
        sender:userAccount.addr,
        suggestedParams:sp,
        signer: algosdk.makeBasicAccountTransactionSigner(userAccount)
    }

    //console.log("params ", commonParams)

    let app = await client.getApplicationByID(appId).do()
    console.log("State pre operation ", app['params']['global-state'])

    
    // Simple call to the `add` method, method_args can be any type but _must_ 
    // match those in the method signature of the contract
    atc.addMethodCall({
        appID : appId,
        sender : userAccount.addr,
        suggestedParams : sp,
        method: contract.getMethodByName("decrement"), 
        signer : algosdk.makeBasicAccountTransactionSigner(userAccount),
        methodArgs: []
    })

    result = await atc.execute(client, 2)

    for(const idx in result.methodResults){
        console.log(result.methodResults[idx])
    }

    //read application state
    //await readGlobalState(client, appId)

    app = await client.getApplicationByID(appId).do()
    console.log("State after operation ", app['params']['global-state'])
}







exports.getBalance = (req, res, next) => {
    
    const server="https://testnet-algorand.api.purestake.io/ps2";
    const port="";
    const token={
        "x-api-key": "cFytdDh7ETMLwFujzahn1V7710kbJFL5ZPIZhOMj" // fill in yours
    };

    let client=new algosdk.Algodv2(token,server,port);


    let account1 = 'Z7ITFTDEHJTFTIFDYBVZBO5PWLWWTIUA2PFBVJFQ75VUVCJFMU3VPRONK4';
    // Account 1 Mnemonic:  gospel term season cement bench window owner pumpkin insect boat kind defy clump trust recycle include taxi tornado spin original tooth clutch spend absorb put
   // let mnemonico = "gospel term season cement bench window owner pumpkin insect boat kind defy clump trust recycle include taxi tornado spin original tooth clutch spend absorb put"
    //let account2 = '6NAKWTCPPHB4RZFYS26RT5QDCO6BFNVY3OYJV4WPMGOPDPFOB2GCSR5Z4M';

   // let privKey = algosdk.mnemonicToSecretKey(mnemonico)
   // console.log("priv key ", privKey)


    ( async() => {
        let account1_info = (await client.accountInformation(account1).do());
        console.log("Balance of account 1: " + JSON.stringify(account1_info.amount));
        
    })().catch(e => {
        console.log(e);
    })
}



// read local state of application from user account
async function readLocalState(client, account, index){
    console.log("ac ", account)
    let accountInfoResponse = await client.accountInformation(account).do();
    for (let i = 0; i < accountInfoResponse['apps-local-state'].length; i++) { 
        console.log("i - ", i)
        if (accountInfoResponse['apps-local-state'][i].id == index) {
            console.log("User's local state:");
            for (let n = 0; n < accountInfoResponse['apps-local-state'][i][`key-value`].length; n++) {
                console.log(accountInfoResponse['apps-local-state'][i][`key-value`][n]);
            }
        }
    }
}

// read global state of application
async function readGlobalState(client, index){
    let applicationInfoResponse = await client.applicationInfo(index).do();
    let globalState = []
    if(applicationInfoResponse['params'].includes('global-state')) {
        globalState = applicationInfoResponse['params']['global-state']
    }
    for (let n = 0; n < globalState.length; n++) {
        console.log(applicationInfoResponse['params']['global-state'][n]);
    }
}




/**
 * Takes COSE encoded public key and converts it to RAW PKCS ECDHA key
 * @param  {Buffer} COSEPublicKey - COSE encoded public key
 * @return {Buffer}               - RAW PKCS encoded public key
 */
 let COSEECDHAtoPKCS = (COSEPublicKey) => {
    /* 
       +------+-------+-------+---------+----------------------------------+
       | name | key   | label | type    | description                      |
       |      | type  |       |         |                                  |
       +------+-------+-------+---------+----------------------------------+
       | crv  | 2     | -1    | int /   | EC Curve identifier - Taken from |
       |      |       |       | tstr    | the COSE Curves registry         |
       |      |       |       |         |                                  |
       | x    | 2     | -2    | bstr    | X Coordinate                     |
       |      |       |       |         |                                  |
       | y    | 2     | -3    | bstr /  | Y Coordinate                     |
       |      |       |       | bool    |                                  |
       |      |       |       |         |                                  |
       | d    | 2     | -4    | bstr    | Private key                      |
       +------+-------+-------+---------+----------------------------------+
    */

    let coseStruct = cbor.decodeAllSync(COSEPublicKey)[0];
    let tag = Buffer.from([0x04]);
    let x   = coseStruct.get(-2);
    let y   = coseStruct.get(-3);

    return Buffer.concat([tag, x, y])
}


/**
 * Convert binary certificate or public key to an OpenSSL-compatible PEM text format.
 * @param  {Buffer} buffer - Cert or PubKey buffer
 * @return {String}             - PEM
 */
 let ASN1toPEM = (pkBuffer) => {
    if (!Buffer.isBuffer(pkBuffer))
        throw new Error("ASN1toPEM: pkBuffer must be Buffer.")

    let type;
    if (pkBuffer.length == 65 && pkBuffer[0] == 0x04) {
        /*
            If needed, we encode rawpublic key to ASN structure, adding metadata:
            SEQUENCE {
              SEQUENCE {
                 OBJECTIDENTIFIER 1.2.840.10045.2.1 (ecPublicKey)
                 OBJECTIDENTIFIER 1.2.840.10045.3.1.7 (P-256)
              }
              BITSTRING <raw public key>
            }
            Luckily, to do that, we just need to prefix it with constant 26 bytes (metadata is constant).
        */
        
        pkBuffer = Buffer.concat([
            new Buffer.from("3059301306072a8648ce3d020106082a8648ce3d030107034200", "hex"),
            pkBuffer
        ]);

        type = 'PUBLIC KEY';
    } else {
        type = 'CERTIFICATE';
    }

    let b64cert = pkBuffer.toString('base64');

    let PEMKey = '';
    for(let i = 0; i < Math.ceil(b64cert.length / 64); i++) {
        let start = 64 * i;

        PEMKey += b64cert.substr(start, 64) + '\n';
    }

    PEMKey = `-----BEGIN ${type}-----\n` + PEMKey + `-----END ${type}-----\n`;
    
    return PEMKey
}
