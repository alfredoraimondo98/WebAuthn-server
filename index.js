const express = require('express');
const app = express();

app.use(express.urlencoded({extended: true})); 
app.use(express.json());  

// const cors = require('cors');
// app.use(cors());

 

//const db = require('./utils/connection');

 
// *** Routes

// const auth = require('./routes/auth');
// app.use('/auth', auth);

 
app.listen(3000, () => console.log("server started")); //localhost porta 3000