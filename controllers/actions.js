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
const { check } = require('express-validator');
const Wallet = require('@lorena-ssi/wallet-lib').default
const utility = require('../utils/utility')
const { validationResult } = require('express-validator');

const server="https://testnet-algorand.api.purestake.io/ps2";
const port="";
const token={
    "x-api-key": "cFytdDh7ETMLwFujzahn1V7710kbJFL5ZPIZhOMj" // fill in yours
};

let client = new algosdk.Algodv2(token,server,port);


exports.getTransactionOptions = async (req, res, next) => {

    var name = req.body.username;
    console.log("name ",name)

   


    //options to authorize transaction
    let options = await utility.getOptions(name)


    res.send(options)


    
}


exports.createTransaction = async(req, res, next) => {
    console.log(" Create transaction")
    const errors = validationResult(req);

    if(!errors.isEmpty()){ //verifica parametri sulla base dei controlli inseriti come middleware nella routes
        return res.status(422).json({
            message : 'Error input Parametri',
            error : errors.array()
        });
    }

    let result = await utility.authenticateOp(req.body)


    console.log(" RESULT ", result)

    res.send(result)

/*
    let myAccount = result.account

    if (result.res == 'User is authenticated'){
        
        // Construct the transaction
        let params = await client.getTransactionParams().do();
        // comment out the next two lines to use suggested fee
        params.fee = algosdk.ALGORAND_MIN_TX_FEE;
        params.flatFee = true;
    
        const receiver = myAccount.addr; //"HZ57J3K46JIJXILONBBZOHX6BKPXEM2VVXNRFSUED6DKFD5ZD24PMJ3MVA";
        const enc = new TextEncoder();
        const note = enc.encode("My test transaction");
        let amount = 1000000; // equals 1 ALGO
        let sender = myAccount.addr;
    
        let txn = algosdk.makePaymentTxnWithSuggestedParamsFromObject({
            from: sender, 
            to: receiver, 
            amount: amount, 
            note: note, 
            suggestedParams: params
        });

        console.log(" UINT 8 ARRAY SK ", Uint8Array.from(Object.values(myAccount.sk)))

        // Sign the transaction
        let signedTxn = txn.signTxn(Uint8Array.from(Object.values(myAccount.sk)));
        let txId = txn.txID().toString();
        console.log("Signed transaction with txID: %s", txId);




        // Submit the transaction
        await client.sendRawTransaction(signedTxn).do();



        // Wait for confirmation
        let confirmedTxn = await algosdk.waitForConfirmation(client, txId, 4);
        //Get the completed Transaction
        console.log("Transaction " + txId + " confirmed in round " + confirmedTxn["confirmed-round"]);
        // let mytxinfo = JSON.stringify(confirmedTxn.txn.txn, undefined, 2);
        // console.log("Transaction information: %o", mytxinfo);
        let string = new TextDecoder().decode(confirmedTxn.txn.txn.note);
        console.log("Note field: ", string);
        accountInfo = await client.accountInformation(myAccount.addr).do();
        console.log("Transaction Amount: %d microAlgos", confirmedTxn.txn.txn.amt);        
        console.log("Transaction Fee: %d microAlgos", confirmedTxn.txn.txn.fee);
        console.log("Account balance: %d microAlgos", accountInfo.amount);

        }
*/

}