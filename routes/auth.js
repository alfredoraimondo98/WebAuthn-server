const express = require('express');
const router = express.Router();
const { body } = require('express-validator');
const authController = require("../controllers/auth");


router.post('/getSigninOptions',    
    [
        body('username').isLength({max : 100})
    ], 
    authController.getSigninOptions); //pre-registrazione


router.post('/signin',[], authController.signin); //registrazione utente

router.post('/getLoginOptions',    
    [
        body('username').isLength({max : 100})
    ], 
    authController.getLoginOptions); //pre-login

router.post('/login',[], authController.login); //registrazione utente


router.post('/updateCredentialsGetOptions', authController.updateCredentialsGetOptions); //verifica l'esistenza del credentialId e avvia il processo di creazione di nuove credenziali


router.post('/updateCredentials', authController.updateCredentials); //Crea e aggiorna le credenziali dell'utente con una nuova coppia di chiavi WebAuthhN

router.post('/deleteCredentials', authController.deleteCredentials); //elimina le credenziali 

module.exports = router;
