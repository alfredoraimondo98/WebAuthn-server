const { validationResult } = require('express-validator');
const { Fido2Lib } = require("fido2-lib");
const { generateRegistrationChallenge, parseRegisterRequest } = require('@webauthn/server')
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
    console.log("username" , name)


    /*genera una challenge da restituire al client */
    const challengeResponse = generateRegistrationChallenge({
        relyingParty: { name: 'localhost' },
        user: { id, name },
        attestation : "direct"
    });

    console.log("challenge response ", challengeResponse);
   
    const publicKeyCredentialCreationOptions = {
        challenge: Uint8Array.from(challengeResponse.challenge, c => c.charCodeAt(0)),
        rp: {
            name: "WebAuthn Demo ",
            id: "localhost",
        },
        user: {
            id: Uint8Array.from(
                id, c => c.charCodeAt(0)),
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

  

    const userRepository = {
        id,
        challenge: challengeResponse.challenge,
        publicKeyCredentialCreationOptions : publicKeyCredentialCreationOptions
    }


    //console.log("challenge respense", challengeResponse)

    res.send(userRepository);
    

 
    //return null
    
}

