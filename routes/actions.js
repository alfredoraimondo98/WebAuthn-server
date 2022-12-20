const express = require('express');
const router = express.Router();
const { body } = require('express-validator');
const actionController = require("../controllers/actions");



router.post('/get_transaction_options',    
    [], 
    actionController.getTransactionOptions); 


router.post('/create_transaction',[], actionController.createTransaction);  

    
module.exports = router;
