require("dotenv").config();
const express = require("express");
const app = express();
const bcrypt = require("bcrypt");
const bodyParser = require("body-parser");
const jwt = require("jsonwebtoken");

const users = [
  {
    name: "jamal",
    password: "password",
  },
];

// getting acces token from header and verifying it
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];
  if (token == null) return res.sendStatus(401);

  jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
};

app.use(bodyParser.json());

app.get("/users", authenticateToken, (req, res) => {
  res.json(users.filter((user) => user.name === req.user.name));
});

// app.get("/login", (req, res) => {});

app.listen(4000, () => {
  console.log("app started on port 4000");
});
