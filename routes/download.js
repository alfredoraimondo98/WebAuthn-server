const express = require('express');
const router = express.Router();
const { body } = require('express-validator');
const downloadController = require("../controllers/download");



router.get('/downloadApp',    
    [], 
    downloadController.downloadApp); 


    
module.exports = router;
