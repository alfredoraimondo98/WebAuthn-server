const { AtomicTransactionComposer, ABIContract } = require('algosdk');
const algosdk = require('algosdk');
const { ABIMethod } = require('algosdk/dist/cjs/src/abi/method');
const { Router } = require('express');
const fs = require('fs')
const server="https://testnet-algorand.api.purestake.io/ps2";
const port="";
const token={
    "x-api-key": "cFytdDh7ETMLwFujzahn1V7710kbJFL5ZPIZhOMj" // fill in yours
};

let client = new algosdk.Algodv2(token,server,port);

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