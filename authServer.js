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

let = refreshTokens = [];

app.use(bodyParser.json());
const genAccessToken = (user) => {
  return jwt.sign(user, process.env.ACCESS_TOKEN_SECRET, {
    expiresIn: "30s",
  });
};

app.post("/token", (req, res) => {
  const refreshToken = req.body.token;
  if (refreshToken == null) return sendStatus(401);
  if (!refreshTokens.includes(refreshToken)) return sendStatus(403);
  jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET, (err, user) => {
    if (err) return res.sendStatus(403);
    const accessToken = genAccessToken({ name: user.name });
    res.json({ accessToken });
  });
});

app.post("/users/register", async (req, res) => {
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

app.delete("/logout", (req, res) => {
  refreshTokens.filter((token) => token !== req.body.token);
  res.sendStatus(204);
});

app.post("/users/login", (req, res) => {
  const user = { name: req.body.name, password: req.body.password };
  if (user == null) {
    return res.status(404).send("Cannot find user");
  }
  try {
    // autherizing user password
    if (bcrypt.compare(req.body.password, user.password)) {
      // creating jwt accessToken and sending it to the client

      const refreshToken = jwt.sign(user, process.env.REFRESH_TOKEN_SECRET);
      refreshTokens.push(refreshToken);
      const accessToken = genAccessToken(user);
      res.json({ accessToken: accessToken, refreshToken: refreshToken });
    } else {
      res.send("Not Allowed");
    }
  } catch {
    res.status(500).send();
  }
});

app.listen(6000, () => {
  console.log("app started on port 6000");
});
