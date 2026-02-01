const { verifyToken } = require("../middleware/jwt");

function auth(req, res, next) {
  const authHeader = req.headers.authorization;
  const cookieToken = req.cookies?.token;
  const token = authHeader?.split(" ")[1] || cookieToken;

  if (!token) {
    req.isAuth = false;
    return next();
    // return res.status(401).json({ message: "No token provided" });
  }

  try {
    const decoded = verifyToken(token);
    req.user = decoded;
    req.isAuth = true;
    next();
  } catch (err) {
    req.isAuth = false;
    next();  
    // return res.status(401).json({ message: "Invalid token" });
  }
}

module.exports = auth;
