import jwt from "jsonwebtoken";

export const verifyToken = (req, res, next) => {
  try {
    let token = req.header("Authorization");
    if (!token) {
      return res.status(403).send("Access Denied");
    }

    if (token.startsWith("Bearer ")) {
      token = token.slice(7, token.length).trimLeft();
    }

    const verified = jwt.verify(token, process.env.JWT_SECRET);

    if (verified) {
      req.user = verified.id;
      next();
    } else {
      res.status(401).json({ message: "Invalid token" });
    }
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
};
