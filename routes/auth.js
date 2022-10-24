const express = require('express');
const router = express.Router();
const { body } = require('express-validator');
const authController = require("../controllers/auth");


router.post('/getChallenge',    
    [
        body('username').isLength({max : 100})
    ], 
    authController.getChallenge); //registrazione utente


    router.post('/signin',    
    [ 
    ], 
    authController.signin); //registrazione utente

module.exports = router;
