const express = require('express');
const app = express();
const algosdk = require('algosdk')
const crypto = require('crypto')
 
app.use(express.urlencoded({extended: true})); 
app.use(express.json());  

const cors = require('cors');
app.use(cors());

 /**
  * ALGORAND 
  */

//  // Connect your client
// const tokenString = 'cFytdDh7ETMLwFujzahn1V7710kbJFL5ZPIZhOMj' //'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
// const algodServer = 'https://testnet-algorand.api.purestake.io/ps2' //'http://localhost';
// const algodPort = '' //4001;
// const algodToken={
//     "x-api-key": "cFytdDh7ETMLwFujzahn1V7710kbJFL5ZPIZhOMj" // fill in yours
// };
// const token2 = {
//     'X-API-Key' : 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
// }

// let client = new algosdk.Algodv2(algodToken, algodServer, algodPort);
// let indexer = new algosdk.Indexer(algodToken, algodServer, algodPort);


// console.log("client ", client)
// console.log("indexer ", indexer)





// let kmd = new algosdk.Kmd(algodToken, algodServer, algodPort)
// console.log("kmd " , kmd)

//testKmd()
    


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

const algorand = require('./routes/algorand');
const { Algodv2 } = require('algosdk');
app.use('/algorand', algorand)



 

app.listen(3000, () => console.log("server started")); //localhost porta 3000



async function testKmd(){
    const kmdPort = '4002'
    const kmdServer = 'http://localhost'
    const kmdToken = {
        "X-KMD-API-Token" : "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        //"x-api-key": "xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" // fill in yours

    }
   // let kmd = await (new algosdk.Kmd(kmdToken, kmdServer, kmdPort))
   // console.log("kmd ", kmd)

   let kmd = new algosdk.Kmd(kmdToken, kmdServer, kmdPort)
   console.log("kmd " , kmd)

    let walletId = (await kmd.createWallet(walletName = "Test Wallet ed25519 3", walletPassword = "pass")).wallet.id // 10b7427f1cc779e39a251ac0625b122d
    //console.log("wallet id ", walletId)
    //let walletId = "020685c4a866e23f73a0b055c58f9d07"
    let walletHandle = (await kmd.initWalletHandle(walletId, "pass"))['wallet_handle_token']
    console.log("wallet handle", walletHandle)
    let wallet = (await kmd.getWallet(walletHandle))
    console.log("wallet ", wallet)

    let listKeys = await kmd.listKeys(walletHandle)
    console.log("list keys ", listKeys)

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

    let wallets = await kmd.listWallets()
    
    console.log("wallets ", wallets)
    
    /* crea chiavi */
    
    crypto.generateKeyPair(type="ed25519", options=options, async (err, publicKey, privateKey) => {
        console.log("publicKey ", publicKey)
        console.log("privateKey ", privateKey)
        
        let addr = await (kmd.importKey(walletHandle, privateKey))
        console.log("addr ", addr) // SEMWDPBHDQEFRI2JVDRCLAZOFABDWLRDQHTLSDATTHPQNGCPJOKQQDKEGQ
    })
    

    let accInfo = await client.accountInformation('DNCVD5CLMR25KPKSO7TXUR4UNEYYRNKGWPKF3T4CG33GRLEGKPTBDOZQXY')
    console.log("acc info ", accInfo, algosdk.isValidAddress('DNCVD5CLMR25KPKSO7TXUR4UNEYYRNKGWPKF3T4CG33GRLEGKPTBDOZQXY'))
     


 
    // purse snow demand firm traffic brown abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon 
    // abandon portion
    
    

   
}


function testPKCS11(){

    var pkcs11 = new pkcs11js.PKCS11();
    pkcs11.load("C:/Program Files/OpenSC Project/OpenSC/pkcs11/onepin-opensc-pkcs11.dll")
    
    
    //pkcs11.load("D:/SoftHSM2/lib/softhsm2-x64.dll")
    //pkcs11.load("C:/Users/alfre/Desktop/OpenPGP11_64.dll")


    //pkcs11.load("C:/Users/alfre/Desktop/libcrypto.dll")


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
/*
        // Getting info about Mechanism
        var mechs = pkcs11.C_GetMechanismList(slot);
        var mech_info = pkcs11.C_GetMechanismInfo(slot, mechs[0]);

        var session = pkcs11.C_OpenSession(slot, pkcs11js.CKF_RW_SESSION | pkcs11js.CKF_SERIAL_SESSION);

        // Getting info about Session
        var info = pkcs11.C_GetSessionInfo(session);
        pkcs11.C_Login(session, 1, "648219");
*/
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

       // pkcs11.C_Logout(session);
       // pkcs11.C_CloseSession(session);
    }
    catch(e){
        console.error(e);
    }
    finally {
        pkcs11.C_Finalize();
    }

}