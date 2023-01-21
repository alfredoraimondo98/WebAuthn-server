const { validationResult, check } = require('express-validator');
const { Fido2Lib } = require("fido2-lib");
const WebAuthn = require('webauthn')
const crypto = require("crypto");
const base64url = require('base64url');
const cbor = require('cbor');
const vanillacbor = require("vanillacborsc")
const service = require("../utils/service")
const { user } = require('../utils/service');
const { CKM_ECDSA_SHA256 } = require('pkcs11js');
const database = require('../utils/database')
const query = require('../utils/queries')
const algosdk = require('algosdk');
const { generateAccount } = require('algosdk');
const Wallet = require('@lorena-ssi/wallet-lib').default
const utility = require('../utils/utility')

/**
 * Creazione opzioni per la creazione delle credenziali (pre - registrazione)
 * @param {*} req 
 * @param {*} res 
 * @param {*} next 
 * @returns 
 */
exports.getSigninOptions = async (req, res, next) => {


    const errors = validationResult(req);

    if(!errors.isEmpty()){ //verifica parametri sulla base dei controlli inseriti come middleware nella routes
        return res.status(422).json({
            message : 'Error input Parametri',
            error : errors.array()
        });
    }

    var name = req.body.username;
    let resCheck = await verifyUsername(name)
    if(resCheck){ //se ritorna true allora lo username è già presente nel DB, pertanto non permette la registrazione
        console.log("res ", res)
        res.send({result : 'username non disponibile'})
    }
    else{
 
        //store user name
        service.user.name = name
     
        //const userID = "UZSL85T9AFC"
        const randomUserID = crypto.randomBytes(8).toString('hex');
        const userID = randomUserID.concat(new Date().getTime())
        console.log("user ID", userID)

        //const challenge = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijk"
        const challenge = crypto.randomBytes(20).toString('hex');


        const publicKeyCredentialCreationOptions = {
            challenge: challenge, //Uint8Array.from(challengeResponse, c => c.charCodeAt(0)),
            rp: {
                name: "WebAuthn Demo ",
                id: "localhost",
            },
            user: {
                id: userID, //Uint8Array.from(id, c => c.charCodeAt(0)),
                name: name,
                displayName: name,
            },
            pubKeyCredParams: [
                //{alg: -6, type: "public-key"}, //Ed25519
                {alg: -7, type: "public-key"},
                //{alg: -257 , type: 'public-key'}
            ],
            authenticatorSelection: {
                authenticatorAttachment: "cross-platform",
                //userVerification: "required"
            },
            timeout: 60000,
            attestation: "direct"
        };

        
        console.log("publicKeyCredentialCreationOptions ", publicKeyCredentialCreationOptions)


        const options = {
            publicKeyCredentialCreationOptions : publicKeyCredentialCreationOptions
        }


    
        res.send(options);
    }
}




/**
 * Registrazione utente
 * @param {*} req 
 * @param {*} res 
 * @param {*} next 
 * @returns 
 */
 exports.signin = async (req, res, next) => {
    console.log("** signin *********************************************")
    const errors = validationResult(req);

    if(!errors.isEmpty()){ //verifica parametri sulla base dei controlli inseriti come middleware nella routes
        return res.status(422).json({
            message : 'Error input Parametri',
            error : errors.array()
        });
    }

    console.log("credential" , req.body)
      
    // Decode attestation object
    let attestationObjectBuffer = base64url.toBuffer(req.body.attestationObject);
    let ctapMakeCredResp = cbor.decodeAllSync(attestationObjectBuffer)[0];
    console.log("ctap ", ctapMakeCredResp)
   
    // parse authData
    let authData = parseAuthData(ctapMakeCredResp.authData)
    console.log("auth data", authData)

    // decode publicKey
    const publicKeyObject = cbor.decode(authData.cosePublicKeyBuffer)
    console.log("public key ", publicKeyObject)

     
    //store publicKey and CredentialId
    service.user.credentialId = authData.credIdBuffer //credentialId,// req.body.credentialId // base64url.encode(authData.credIdBuffer) // req.body.credentialId //authData.credIdBuffer
    service.user.publicKey = publicKeyObject
    service.user.cosePublicKeyBuffer = authData.cosePublicKeyBuffer
     
    console.log("user complete ", service.user)

    const connection = await database.getConnection(); //recupera una connessione dal pool di connessioni al dabatase
    const date = new Date(); 

    try{
        const [rows, field] = await connection.query(query.insertUser, [ base64url.encode(authData.credIdBuffer), req.body.username, req.body.userID, base64url.encode(authData.cosePublicKeyBuffer), date]); 

    }   
    catch(err){
        console.log("error: ", err)
    }    

    //let myWallet = await createAlgorandWallet(service.user.name)

    result = {
        res : "registrazione completata",
        bool : true,
        credentialId : base64url.encode(authData.credIdBuffer),
        userID : req.body.userID
        //myWallet : myWallet
    }
    res.send(result);
    
}



/**
 * Decoding AttestationObject.authData <Buffer> into Object structure 
 * {rpIdHashm counter, flags, counterBuffer, aaguid, credIdBuffer, cosePublicKeyBuffer, coseExtensionsDataBuffer}
 * @param {*} buffer 
 * @returns 
 */
function parseAuthData(buffer) {
    if(buffer.byteLength < 37)
        throw new Error('Authenticator Data must be at least 37 bytes long!');

    let rpIdHash = buffer.slice(0, 32);             
    buffer = buffer.slice(32);

    /* Flags */
    let flagsBuffer = buffer.slice(0, 1);              
    buffer = buffer.slice(1);
    let flagsInt = flagsBuffer[0];
    let up = !!(flagsInt & 0x01); // Test of User Presence
    let uv = !!(flagsInt & 0x04); // User Verification
    let at = !!(flagsInt & 0x40); // Attestation data
    let ed = !!(flagsInt & 0x80); // Extension data
    let flags = {up, uv, at, ed, flagsInt};

    let counterBuffer = buffer.slice(0, 4);               
    buffer = buffer.slice(4);
    let counter = counterBuffer.readUInt32BE(0);

    /* Attested credential data */
    let aaguid = undefined;
    let aaguidBuffer = undefined;
    let credIdBuffer = undefined;
    let cosePublicKeyBuffer = undefined;
    let attestationMinLen = 16 + 2 + 16 + 42; // aaguid + credIdLen + credId + pk


    if(at) { // Attested Data
        if(buffer.byteLength < attestationMinLen)
            throw new Error(`It seems as the Attestation Data flag is set, but the remaining data is smaller than ${attestationMinLen} bytes. You might have set AT flag for the assertion response.`)

        aaguid = buffer.slice(0, 16).toString('hex'); buffer = buffer.slice(16);
        aaguidBuffer = `${aaguid.slice(0, 8)}-${aaguid.slice(8, 12)}-${aaguid.slice(12, 16)}-${aaguid.slice(16, 20)}-${aaguid.slice(20)}`;

        let credIdLenBuffer = buffer.slice(0, 2);                  
        buffer = buffer.slice(2);
        let credIdLen = credIdLenBuffer.readUInt16BE(0);
        credIdBuffer = buffer.slice(0, credIdLen);          
        buffer = buffer.slice(credIdLen);

        let pubKeyLength = vanillacbor.decodeOnlyFirst(buffer).byteLength;
        cosePublicKeyBuffer = buffer.slice(0, pubKeyLength);  
        //console.log("pubKey ", cosePublicKeyBuffer)    
        buffer = buffer.slice(pubKeyLength);
    }

    let coseExtensionsDataBuffer = undefined;
    if(ed) { // Extension Data
        let extensionsDataLength = vanillacbor.decodeOnlyFirst(buffer).byteLength;

        coseExtensionsDataBuffer = buffer.slice(0, extensionsDataLength); buffer = buffer.slice(extensionsDataLength);
    }

    if(buffer.byteLength)
        throw new Error('Failed to decode authData! Leftover bytes been detected!');

    return {rpIdHash, counter, flags, counterBuffer, aaguid, credIdBuffer, cosePublicKeyBuffer, coseExtensionsDataBuffer}
}




/**
 * Creazione opzioni per il recupero delle credenziali (pre - login)
 * @param {*} req 
 * @param {*} res 
 * @param {*} next 
 * @returns 
 */
 exports.getLoginOptions = async (req, res, next) => {

    const errors = validationResult(req);

    if(!errors.isEmpty()){ //verifica parametri sulla base dei controlli inseriti come middleware nella routes
        return res.status(422).json({
            message : 'Error input Parametri',
            error : errors.array()
        });
    }

    var name = req.body.username;
    console.log("name ",name)

    //verificare la presenza dello username inserito nel database
    const connection = await database.getConnection(); //recupera una connessione dal pool di connessioni al dabatase

    try{
        const [rows, field] = await connection.query(query.getUserByUsername, [name]); //Creazione utente
        console.log("rows ", rows[0])
        if(rows != undefined){
            service.user.name = name;
            service.user.credentialId = base64url.toBuffer(rows[0].credential_id)
            service.user.cosePublicKeyBuffer = base64url.toBuffer(rows[0].public_key)
        }
    }
    catch(err){
        console.log("error: ", err)
    }

    /*
    if(!(name == service.user.name)){
        let result = 'utente non presente'
        res.send(result)
    }
    */

    var id = 'UZSL85T9AFC'

    //get user name
    let user = service.user
    console.log("user ", user) 
 
    const challengeResponse = crypto.randomBytes(20).toString('hex');
    //const challengeResponse = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijk'

    console.log("challenge response ", challengeResponse);
   
    const publicKeyCredentialRequestOptions = {
        challenge: challengeResponse, // Uint8Array.from(challengeResponse, c => c.charCodeAt(0)),
        allowCredentials: [{
            id: service.user.credentialId, //base64url.encode(service.user.credentialId), //id , //service.user.credentialId, //id, // service.user.credentialId, //Uint8Array.from(service.user.credentialId, c => c.charCodeAt(0)),
            type: 'public-key',
            transports: ['hybrid'],
        }],
        timeout: 60000,
    }
    
    console.log("publicKeyCredentialRequestOptions ", publicKeyCredentialRequestOptions)

    const options = {
        publicKeyCredentialRequestOptions : publicKeyCredentialRequestOptions
    }
    
    res.send(options);
    
}


/**
 * login
 * @param {*} req 
 * @param {*} res 
 * @param {*} next 
 */
exports.login = async (req, res, next) => {

    console.log("** LOGIN *********************************************")
    const errors = validationResult(req);

    if(!errors.isEmpty()){ //verifica parametri sulla base dei controlli inseriti come middleware nella routes
        return res.status(422).json({
            message : 'Error input Parametri',
            error : errors.array()
        });
    }
    var user;
    console.log("assertionCredential" , req.body)

    const connection = await database.getConnection(); //recupera una connessione dal pool di connessioni al dabatase

    try{
        const [rows, field] = await connection.query(query.getUserByUsername, [service.user.name]); //recupera informazioni utente
        console.log("rows ", rows[0])
        user = rows[0]
    }
    catch(err){
        console.log("error: ", error)
    }

    // Decode authenticatorData from Base64 to Buffer
    let authenticatorData = base64url.toBuffer(req.body.authenticatorData);
    console.log("authenticatorData ", authenticatorData)


    // Decode signature from Base64 to Buffer
    let signature = base64url.toBuffer(req.body.signature);
    console.log("signature ", signature)


    console.log("client data json ", req.body.clientDataJSON)
    let clientDataJson = JSON.stringify(req.body.clientDataJSON) 
    clientDataJson = base64url.encode(clientDataJson) //encode clientDataJson into base64
    console.log("client data Json base 64", clientDataJson);

    clientDataJson = base64url.toBuffer(clientDataJson) // convert clientDataJson into buffer
    console.log("client data json buffer ", clientDataJson)

    var hashedClientData = crypto.createHash('SHA256').update(clientDataJson).digest(); //create hash SHA256 of clientDataJson
    console.log("hashedData ", hashedClientData);


    let signedData = Buffer.concat([authenticatorData, hashedClientData]) //signedData = authenticatorData + hashedClientDataJson
    console.log("signed data ", signedData)


    let publicKey = COSEECDHAtoPKCS(service.user.cosePublicKeyBuffer) //get Buffer from COSE format public key
    console.log("public key ", publicKey)

    publicKey = ASN1toPEM(publicKey) //convert to pem format
    console.log("pem public key ", publicKey)

    const signatureIsValid = crypto.verify("SHA256", signedData, publicKey, signature) //verify signature with publicKey obtained during register
    
    const VALID_TIME = 180
    const last_update = new Date(user.last_update)
    console.log("last_date", last_update)
    const current_date = new Date()
    console.log("current_date ", current_date)
    const limit_date = new Date(last_update.setDate(last_update.getDate() + 180))
    console.log("limit ", limit_date)

    let checkCredentialBool = false
    if(limit_date <= current_date){ //le credenziali devono essere aggiornate
        console.log(" aggiornare le credenziali ")
        checkCredentialBool = true
    }

    
    if(signatureIsValid) {
        console.log(" User is authenticated")

        //recupera account algorand 
        console.log("username ", service.user.name)
        //let account = await loginAlgorandWallet(service.user.name)

        var result = {
            res : "User is authenticated",
            bool : true,
            credentialId : user.credential_id,
            userID : user.user_id,
            checkCredentialBool : checkCredentialBool,
            //account : account
        }
    }else {
        console.log("Verification failed")
        var result = {
            res : "Verification failed"
        }

    }
    
    res.send(result)
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




async function createAlgorandWallet(username){
     
    let account = await algosdk.generateAccount()

    console.log("account ", account.sk )

    

    let mnemonic = await algosdk.secretKeyToMnemonic(account.sk)
    console.log("mnemonic sk ", mnemonic)


     
    const options = {
        storage: 'fs', // 'fs' default in the filesystem; 'mem' for in-memory
        silent: true // default silences Zenroom debugging messages
    }
    
    // create your instance of the wallet with the username supplied
    const myWallet = new Wallet(username, options) 
    console.log("my wallet ", myWallet)

    // attempt to unlock an existing wallet (since it is in-memory, this will be `false`)
    let result = await myWallet.unlock('password')
    console.log("result unlock ", result)

    // this is a new wallet, so `unlock` returned `false`.
    if(result == false){
        console.log("false")
    }

    myWallet.pubKey = 'public key webauthN'
    myWallet.info.myData = 'this is my sensitive data'
    myWallet.info.myMnemonic = mnemonic
    myWallet.info.keyPair = account

    // write changes to disk (encrypted: you need to supply the password)
    result = await myWallet.lock('password')
    console.log("result lock ", result)


    console.log("my wallet writed ", myWallet)

    return myWallet
}


async function loginAlgorandWallet(username){

    const options = {
        storage: 'fs', // default in the filesystem; 'mem' for in-memory
        silent: true // default silences Zenroom debugging messages
    }

    const myWalletRetrieved = new Wallet(username, options)
    result = await myWalletRetrieved.unlock('password')
    if(result){
        console.log(" myWalletRetrieved" , myWalletRetrieved)
    }

    let account = myWalletRetrieved.info.keyPair

    console.log("my account ", account)
    

    const server="https://testnet-algorand.api.purestake.io/ps2";
    const port="";
    const token={
        "x-api-key": "cFytdDh7ETMLwFujzahn1V7710kbJFL5ZPIZhOMj" // fill in yours
    };

    let client = new algosdk.Algodv2(token,server,port);
    let infoClient =  await client.accountInformation(account.addr).do();

    console.log("account info ", infoClient)

    account.amount = infoClient.amount
    account.username = username
    
    return account;

}

/**
 * Verifica l'esistenza del credentialId associato all'utente e avvia il processo di creazione delle nuove credenziali
 * @param {*} req 
 * @param {*} res 
 * @param {*} next 
 */
exports.updateCredentialsGetOptions = async (req, res, next) => {
    
    let name = req.body.username;
    let userID = req.body.userID;
    console.log("user credId", name, userID)

     


    const challenge = crypto.randomBytes(20).toString('hex');
 

    const publicKeyCredentialCreationOptions = {
        challenge: challenge, //Uint8Array.from(challengeResponse, c => c.charCodeAt(0)),
        rp: {
            name: "WebAuthn Demo ",
            id: "localhost",
        },
        user: {
            id: userID, //Uint8Array.from(id, c => c.charCodeAt(0)),
            name: name,
            displayName: name,
        },
        pubKeyCredParams: [
            //{alg: -6, type: "public-key"}, //Ed25519
            {alg: -7, type: "public-key"},
            //{alg: -257 , type: 'public-key'}
        ],
        authenticatorSelection: {
            authenticatorAttachment: "cross-platform",
            //userVerification: "required"
        },
        timeout: 60000,
        attestation: "direct"
    };

    
    console.log("publicKeyCredentialCreationOptions ", publicKeyCredentialCreationOptions)


    const options = {
        publicKeyCredentialCreationOptions : publicKeyCredentialCreationOptions
    }

    res.send(options);

}


exports.updateCredentials = async (req, res, next) => {

    // Decode attestation object
    let attestationObjectBuffer = base64url.toBuffer(req.body.attestationObject);
    let ctapMakeCredResp = cbor.decodeAllSync(attestationObjectBuffer)[0];
    console.log("ctap ", ctapMakeCredResp)
   
    // parse authData
    let authData = parseAuthData(ctapMakeCredResp.authData)
    console.log("auth data", authData)

    // decode publicKey
    const publicKeyObject = cbor.decode(authData.cosePublicKeyBuffer)
    console.log("public key ", publicKeyObject)

     
    //store publicKey and CredentialId
    service.user.credentialId = authData.credIdBuffer //credentialId,// req.body.credentialId // base64url.encode(authData.credIdBuffer) // req.body.credentialId //authData.credIdBuffer
    service.user.publicKey = publicKeyObject
    service.user.cosePublicKeyBuffer = authData.cosePublicKeyBuffer
    console.log("user complete ", service.user)

    const connection = await database.getConnection(); //recupera una connessione dal pool di connessioni al dabatase
    const date = new Date(); 

    try{
 
        const [rows_delete, field_delete] = await connection.query(query.deleteUser, [req.body.username, req.body.userID]) //elimina vecchie credenziali
        
        const [rows, field] = await connection.query(query.insertUser, [ base64url.encode(authData.credIdBuffer), req.body.username, req.body.userID, base64url.encode(authData.cosePublicKeyBuffer), date]); 

    }   
    catch(err){
        console.log("error: ", err)
    }    

    //let myWallet = await createAlgorandWallet(service.user.name)

    result = {
        res : "registrazione completata",
        bool : true,
        credentialId : base64url.encode(authData.credIdBuffer),
        //myWallet : myWallet
    }
    res.send(result);
}


exports.deleteCredentials = async (req, res, next) => {
    
    let bool = false; 
    const connection = await database.getConnection(); //recupera una connessione dal pool di connessioni al dabatase
 
    try{
        const [rows_delete, field_delete] = await connection.query(query.deleteUser, [req.body.username, req.body.userID]) //elimina credenziali utente
        bool = true
    }   
    catch(err){
        console.log("error: ", err)
    }    

    result = {
        bool : bool
    }

    res.send(result)
}



async function verifyUsername(name){
    const connection = await database.getConnection(); //recupera una connessione dal pool di connessioni al dabatase
    const date = new Date(); 

    try{
        const [rows, field] = await connection.query(query.getUserByUsername, [name]);
        if(rows[0] != undefined){
            console.log("rows ", rows)
            return true
        }
        else{
            return false
        }

    }   
    catch(err){
        console.log("error: ", err)
    }    


}