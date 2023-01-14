module.exports = { 

    insertUser : "INSERT INTO user (credential_id, username, user_id, public_key, last_update) VALUES (?, ?, ?, ?, ?)",
    insertWallet : "INSERT INTO wallet (idwallet, name, password) VALUES (?, ?, ?)",

    deleteUser : "DELETE FROM user WHERE username = ? AND user_id = ?",

    getUserByUsername : "SELECT * FROM user WHERE username = ?",


}