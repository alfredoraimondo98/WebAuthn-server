const { validationResult } = require('express-validator');
const { Fido2Lib } = require("fido2-lib");

/**
 * Registrazione utente
 * @param {*} req 
 * @param {*} res 
 * @param {*} next 
 * @returns 
 */
exports.signin = async (req, res, next) => {

    const errors = validationResult(req);

    if(!errors.isEmpty()){ //verifica parametri sulla base dei controlli inseriti come middleware nella routes
        return res.status(422).json({
            message : 'Error input Parametri',
            error : errors.array()
        });
    }

    var username = req.body.username;
    console.log("username" , username)
    return null
    
}

