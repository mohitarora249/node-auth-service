require("dotenv").config();
const express = require("express");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");

const DATA = require("./data");

const app = express();
app.use(express.json());

const users = [];

app.listen(process.env.PORT, () => {
  console.log(`App running on port ${process.env.PORT}`);
});

app.post("/create-user", async (req, res) => {
  const { name, password } = req.body;
  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    users.push({ name, password: hashedPassword });
    console.table(users);
    res.status(201).json({ msg: "User created successfully" });
  } catch (err) {
    res.status(500).json({ err: "Error occurred while creating user" });
  }
});

const authentication = (req, res, next) => {
  const authHeader = req.headers["authorization"];
  // JWT [jwt_token]
  const token = authHeader && authHeader.split(" ")[1];
  if (!token) return res.status(401).json({ err: "Auth token is not present" });
  jwt.verify(token, process.env.ACCESS_KEY, (err, user) => {
    if (err) return res.status(403).json({ err: "Auth token expired" });
    req.user = user;
    next();
  });
};

app.post("/login", async (req, res) => {
  const { name, password } = req.body;
  const user = users.find((u) => u.name === name);
  if (user === null) {
    return res.status(400).json({ err: "User does not exists" });
  }
  try {
    const isCorrectPassword = await bcrypt.compare(password, user.password);
    if (isCorrectPassword) {
      const accessToken = jwt.sign(user, process.env.ACCESS_KEY);
      return res.status(200).json({ name, accessToken });
    }
    return res.status(400).json({ err: "Invalid credentials" });
  } catch (err) {
    return res
      .status(500)
      .json({ err: "Error occurred while logging in user" });
  }
});

app.get("/movies", authentication, (req, res) => {
  res.json({ data: DATA.MOVIES });
});
