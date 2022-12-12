const { makeKeyRegistrationTxnWithSuggestedParams } = require('algosdk');
const express = require('express');
const router = express.Router();
const { body } = require('express-validator');
const algorandController = require("../controllers/algorand");



router.get('/createAccount',    
    [], 
    algorandController.createAccount); 

router.get('/getAccount', [], algorandController.getAccount);

router.get('/importKeyIntoWallet', algorandController.importKeyIntoWallet)

router.get('/getBalance', [], algorandController.getBalance);

router.get('/createApp', algorandController.createApp)

router.get('/callApp', algorandController.callApp)

router.get('/createWallet', algorandController.createWallet)

router.get('/ipfs', algorandController.ipfsTest)

router.get('/rekey', algorandController.rekeyTest)

router.get('/algowallet', algorandController.algo)

router.get('/create-algorand-account', algorandController.createAlgorandAccount)

module.exports = router;
