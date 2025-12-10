const express = require("express");
const bodyParser = require("body-parser");
const cookieParser = require("cookie-parser");
const crypto = require("crypto");
const bcrypt = require("bcrypt");

const app = express();
const PORT = 3001;

app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());
app.use(cookieParser());
app.use(express.static("public"));

const users = [
  {
    id: 1,
    username: "student",
    passwordHash: bcrypt.hashSync("password123", 10)
  }
];

const sessions = {};

function findUser(username) {
  return users.find((u) => u.username === username);
}

function createSession(userId) {
  const token = crypto.randomBytes(32).toString("hex");
  const expires = Date.now() + 1000 * 60 * 30;
  sessions[token] = { userId, expires };
  return token;
}

function validateSession(token) {
  const session = sessions[token];
  if (!session) return null;
  if (Date.now() > session.expires) {
    delete sessions[token];
    return null;
  }
  return session;
}

app.get("/api/me", (req, res) => {
  const token = req.cookies.session;
  const session = validateSession(token);
  if (!session) return res.status(401).json({ authenticated: false });
  const user = users.find((u) => u.id === session.userId);
  res.json({ authenticated: true, username: user.username });
});

app.post("/api/login", async (req, res) => {
  const { username, password } = req.body;

  const user = findUser(username);
  const genericError = { success: false, message: "Invalid username or password" };
  if (!user) return res.status(401).json(genericError);

  const match = await bcrypt.compare(password, user.passwordHash);
  if (!match) return res.status(401).json(genericError);

  const token = createSession(user.id);

  res.cookie("session", token, {
    httpOnly: true,
    secure: true,
    sameSite: "strict",
    maxAge: 1000 * 60 * 30
  });

  res.json({ success: true });
});

app.post("/api/logout", (req, res) => {
  const token = req.cookies.session;
  if (token && sessions[token]) delete sessions[token];
  res.clearCookie("session");
  res.json({ success: true });
});

app.listen(PORT, () => {
  console.log(`FastBank Auth Lab running at http://localhost:${PORT}`);
});
