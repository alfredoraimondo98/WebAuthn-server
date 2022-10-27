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

module.exports = router;
