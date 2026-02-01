const jwt = require("jsonwebtoken");

const SECRET_KEY = "build_crew_app_secret_key";

function generateToken(payload) {
return jwt.sign(payload, SECRET_KEY, {
    expiresIn: "1d"
});
}

function verifyToken(token) {
return jwt.verify(token, SECRET_KEY);
}

module.exports = { generateToken, verifyToken };