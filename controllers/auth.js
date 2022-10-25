const { validationResult } = require('express-validator');
const { Fido2Lib } = require("fido2-lib");
const WebAuthn = require('webauthn')
const crypto = require("crypto");
const base64url = require('base64url');
const cbor = require('cbor');
const vanillacbor = require("vanillacborsc")
const service = require("../utils/service")
/**
 * Creazione opzioni per la creazione delle credenziali (pre - registrazione)
 * @param {*} req 
 * @param {*} res 
 * @param {*} next 
 * @returns 
 */
exports.getChallenge = async (req, res, next) => {

    const errors = validationResult(req);

    if(!errors.isEmpty()){ //verifica parametri sulla base dei controlli inseriti come middleware nella routes
        return res.status(422).json({
            message : 'Error input Parametri',
            error : errors.array()
        });
    }

    var name = req.body.username;
    var id = "1"
     
    //store publicKey and CredentialId
    service.user.name = name
    
    const challengeResponse = crypto.randomBytes(20).toString('hex');

    console.log("challenge response ", challengeResponse);
   
    const publicKeyCredentialCreationOptions = {
        challenge: challengeResponse, //Uint8Array.from(challengeResponse, c => c.charCodeAt(0)),
        rp: {
            name: "WebAuthn Demo ",
            id: "localhost",
        },
        user: {
            id: id, //Uint8Array.from(id, c => c.charCodeAt(0)),
            name: name,
            displayName: name,
        },
        pubKeyCredParams: [
            {alg: -7, type: "public-key"},
            {alg: -257 , type: 'public-key'}],
        authenticatorSelection: {
            authenticatorAttachment: "cross-platform",
        },
        timeout: 60000,
        attestation: "direct"
    };

    
    console.log("publicKeyCredentialCreationOptions ", publicKeyCredentialCreationOptions)

    const userRepository = {
        publicKeyCredentialCreationOptions : publicKeyCredentialCreationOptions
    }


 
    res.send(userRepository);
    
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
    service.user.credentialId = authData.credIdBuffer
    service.user.publicKey = publicKeyObject
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