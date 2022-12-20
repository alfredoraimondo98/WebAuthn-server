const service = require('../utils/service')
const database = require('../utils/database')
const crypto = require('crypto');
const query = require('../utils/queries')
const base32 = require('base32')
const base64url = require('base64url');
const cbor = require('cbor');
const Wallet = require('@lorena-ssi/wallet-lib').default
const algosdk = require('algosdk');

exports.getOptions = async function getOptions(name) {

    var name = name;
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
 

    //get user name
    let user = service.user
    console.log("user ", user) 
 
    const challengeResponse = crypto.randomBytes(20).toString('hex');

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
    
    return options;
}

exports.authenticateOp = async function authenticateOp(body){
    console.log("** authenticate op *********************************************")
    

    console.log("assertionCredential" , body)

    const connection = await database.getConnection(); //recupera una connessione dal pool di connessioni al dabatase

    try{
        const [rows, field] = await connection.query(query.getUserByUsername, [service.user.name]);  
        console.log("rows ", rows[0])
    }
    catch(err){
        console.log("error: ", error)
    }

    // Decode authenticatorData from Base64 to Buffer
    let authenticatorData = base64url.toBuffer(body.authenticatorData);
    console.log("authenticatorData ", authenticatorData)


    // Decode signature from Base64 to Buffer
    let signature = base64url.toBuffer(body.signature);
    console.log("signature ", signature)


    console.log("client data json ", body.clientDataJSON)
    let clientDataJson = JSON.stringify(body.clientDataJSON) 
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
   
    if (signatureIsValid) {
        console.log(" User is authenticated")

        //recupera account algorand 
        console.log("usernmae ", service.user.name)
        let account = await loginAlgorandWallet(service.user.name)

        var result = {
            res : "User is authenticated",
            account : account
        }
    } else {
        console.log("Verification failed")
        var result = {
            res : "Verification failed"
        }

    }
    
    return result

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