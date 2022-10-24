const { validationResult } = require('express-validator');
const { Fido2Lib } = require("fido2-lib");
const WebAuthn = require('webauthn')
const crypto = require("crypto");
const base64url = require('base64url');
const cbor = require('cbor');
/**
 * Registrazione utente
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
            authenticatorAttachment: "platform",
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

    console.log("credential" , req.body.attestationObject)
      
        // Decode attestation object
    let attestationObjectBuffer = base64url.toBuffer(req.body.attestationObject);
    let ctapMakeCredResp = cbor.decodeAllSync(attestationObjectBuffer)[0];
    console.log("ctap ", ctapMakeCredResp)
    
    
    res.send("ok");
    

 
    //return null
    
}