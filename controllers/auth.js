const { validationResult } = require('express-validator');
const { Fido2Lib } = require("fido2-lib");
const WebAuthn = require('webauthn')
const crypto = require("crypto");
const base64url = require('base64url');
const cbor = require('cbor');
const vanillacbor = require("vanillacborsc")
const service = require("../utils/service")
const { user } = require('../utils/service');
const { CKM_ECDSA_SHA256 } = require('pkcs11js');


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
    //var id = "2"
    var id = 'Kesv9fPtkDoh4Oz7Yq/pVgWHS8HhdlCto5cR0aBoVMw='

     
    //store user name
    service.user.name = name
    /*
    // generate challenge and encode to base64
    let challenge = new Uint8Array(32)
    crypto.webcrypto.getRandomValues(challenge)
    crypto.
    console.log("CHALLENGE ", challenge)
    challenge = base64url.encode(challenge)
    console.log("CHALLENGE BASE64 ", challenge)
    console.log("YYYY", base64url.decode(challenge))
    //crypto.getRandomValues(challenge)
    //const challengeResponse = crypto.randomBytes(20).toString('hex');

   // generate userID and encode in base64
    var userID = 'Kosv9fPtkDoh4Oz7Yq/pVgWHS8HhdlCto5cR0aBoVMw='
    var id = Uint8Array.from(atob(userID), c=>c.charCodeAt(0))
    console.log("id ", id)
    var id = base64url.encode(userID)
    var stringDecoded = base64url.decode(id)
    console.log("XXXXXXX ", stringDecoded)
    */

    const userID = "UZSL85T9AFC"
    const challenge = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijk"
 

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
            {alg: -7, type: "public-key"},
            {alg: -257 , type: 'public-key'}],
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


     result = {
        res : "registrazione completata"
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

    //verificare la presenza dello username inserito 
    if(!(name == service.user.name)){
        let result = 'utente non presente'
        res.send(result)
    }

    var id = 'UZSL85T9AFC'

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

    console.log("assertionCredential" , req.body)

     


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
   
    if (signatureIsValid) {
        console.log(" User is authenticated")
        var result = {
            res : "User is authenticated"
        }
    } else {
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
