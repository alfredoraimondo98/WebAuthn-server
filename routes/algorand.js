const express = require('express');
const router = express.Router();
const { body } = require('express-validator');
const algorandController = require("../controllers/algorand");



router.get('/createAccount',    
    [], 
    algorandController.createAccount); 

router.get('/getBalance', [], algorandController.getBalance);

module.exports = router;
