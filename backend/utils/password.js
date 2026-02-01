const bcrypt = require('bcrypt');

const SALT_ROUNDS = 10;

async function hashpassword(password){
    return await bcrypt.hash(password, SALT_ROUNDS);
}

async function verifypassword(password, hashedpassword){
    return await bcrypt.compare(password, hashedpassword.toString());
}

module.exports = {hashpassword, verifypassword};