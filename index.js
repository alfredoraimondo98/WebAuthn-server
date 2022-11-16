const express = require('express');
const app = express();



app.use(express.urlencoded({extended: true})); 
app.use(express.json());  

const cors = require('cors');
app.use(cors());

 

//const db = require('./utils/connection');

const pkcs11js = require("pkcs11js")
//testPKCS11()


// *** Routes

/*
const algosdk = require('algosdk');
const baseServer = "https://testnet-algorand.api.purestake.io/idx2";
const port = "";

const token = {
    'X-API-key': 'cFytdDh7ETMLwFujzahn1V7710kbJFL5ZPIZhOMj',
}

let indexerClient = new algosdk.Indexer(token, baseServer, port);

(async () => {
    let blockInfo = await indexerClient.lookupBlock(5).do()
    console.log(blockInfo)
})().catch(e => {
    console.log(e);
});
*/

const auth = require('./routes/auth');
app.use('/auth', auth);

const algorand = require('./routes/algorand')
app.use('/algorand', algorand)



app.listen(3000, () => console.log("server started")); //localhost porta 3000



function testPKCS11(){

    var pkcs11 = new pkcs11js.PKCS11();
    pkcs11.load("C:/Program Files/OpenSC Project/OpenSC/pkcs11/opensc-pkcs11.dll")

    pkcs11.C_Initialize()

    try {
        // Getting info about PKCS11 Module
        var module_info = pkcs11.C_GetInfo();
        console.log("module info", module_info)
        // Getting list of slots
        
        // Getting list of slots
        var slots = pkcs11.C_GetSlotList(true);
        var slot = slots[0];
        console.log("slots ", slot)

        // Getting info about slot
        var slot_info = pkcs11.C_GetSlotInfo(slot);
        console.log("slot info ", slot_info)
        // Getting info about token
        var token_info = pkcs11.C_GetTokenInfo(slot);

        // Getting info about Mechanism
        var mechs = pkcs11.C_GetMechanismList(slot);
        var mech_info = pkcs11.C_GetMechanismInfo(slot, mechs[0]);

        var session = pkcs11.C_OpenSession(slot, pkcs11js.CKF_RW_SESSION | pkcs11js.CKF_SERIAL_SESSION);

        // Getting info about Session
        var info = pkcs11.C_GetSessionInfo(session);
        pkcs11.C_Login(session, 1, "648219");

        /**
         * Your app code here
         */
        
        //generate key
/*
         var publicKeyTemplate = [
            { type: pkcs11js.CKA_CLASS, value: pkcs11js.CKO_PUBLIC_KEY },
            { type: pkcs11js.CKA_TOKEN, value: false },
            { type: pkcs11js.CKA_LABEL, value: "My EC Public Key" },
            { type: pkcs11js.CKA_EC_PARAMS, value: new Buffer("06082A8648CE3D030107", "hex") }, // secp256r1
        ];
        var privateKeyTemplate = [
            { type: pkcs11js.CKA_CLASS, value: pkcs11js.CKO_PRIVATE_KEY },
            { type: pkcs11js.CKA_TOKEN, value: false },
            { type: pkcs11js.CKA_LABEL, value: "My EC Private Key" },
            { type: pkcs11js.CKA_DERIVE, value: true },
        ];
        var keys = pkcs11.C_GenerateKeyPair(session, { mechanism: pkcs11js.CKM_EC_KEY_PAIR_GEN }, publicKeyTemplate, privateKeyTemplate);
        console.log("keys ", keys)
*/
        pkcs11.g

        pkcs11.C_Logout(session);
        pkcs11.C_CloseSession(session);
    }
    catch(e){
        console.error(e);
    }
    finally {
        pkcs11.C_Finalize();
    }

}