const express = require('express');
const router = express.Router();
const { body } = require('express-validator');
const authController = require("../controllers/auth");


router.post('/signin',    
    [
        body('username').isLength({max : 100})
    ], 
    authController.signin); //registrazione utente


module.exports = router;
