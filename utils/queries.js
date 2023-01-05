module.exports = { 

    insertUser : "INSERT INTO user (credential_id, username, public_key) VALUES (?, ?, ?)",
    insertWallet : "INSERT INTO wallet (idwallet, name, password) VALUES (?, ?, ?)",


    getUserByUsername : "SELECT * FROM user WHERE username = ?",


}