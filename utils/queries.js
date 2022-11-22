module.exports = { 

    insertUser : "INSERT INTO user (credential_id, username, public_key) VALUES (?, ?, ?)",

    getUserByUsername : "SELECT * FROM user WHERE username = ?",


}