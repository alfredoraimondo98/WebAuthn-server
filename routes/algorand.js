const express = require('express');
const router = express.Router();
const { body } = require('express-validator');
const algorandController = require("../controllers/algorand");



router.get('/createAccount',    
    [], 
    algorandController.createAccount); 

router.get('/getAccount', [], algorandController.getAccount);

router.get('/getBalance', [], algorandController.getBalance);

router.get('/createApp', algorandController.createApp)

router.get('/callApp', algorandController.callApp)


module.exports = router;
