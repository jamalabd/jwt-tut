require("dotenv").config();
const express = require("express");
const app = express();
const bcrypt = require("bcrypt");
const bodyParser = require("body-parser");
const jwt = require("jsonwebtoken");

const users = [];

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

app.post("/users", async (req, res) => {
  // create user and hash password
  try {
    const salt = await bcrypt.genSalt();
    const hashedPassword = await bcrypt.hash(req.body.password, salt);
    const user = { name: req.body.name, password: hashedPassword };
    users.push(user);
    res.status(201).send();
  } catch (e) {
    res.status(500).send();
    console.log(e);
  }
});

app.post("/users/login", async (req, res) => {
  const user = users.find((user) => user.name == req.body.name);

  if (user == null) {
    return res.status(404).send("Cannot find user");
  }
  try {
    // autherizing user password
    if (await bcrypt.compare(req.body.password, user.password)) {
      // creating jwt accessToken and sending it to the client
      const accessToken = jwt.sign(user, process.env.ACCESS_TOKEN_SECRET);
      res.json(accessToken);
    } else {
      res.send("Not Allowed");
    }
  } catch {
    res.status(500).send();
  }
});

// app.get("/login", (req, res) => {});

app.listen(4000, () => {
  console.log("app started on port 4000");
});
