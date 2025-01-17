const express = require("express");
const session = require("express-session");
const bodyParser = require("body-parser");
const sqlite3 = require("sqlite3").verbose();
const bcrypt = require("bcrypt");

const app = express();
const db = new sqlite3.Database("./database.sqlite");

// Middleware
app.set("view engine", "ejs");
app.use(bodyParser.urlencoded({ extended: true }));
app.use(session({ secret: "secretKey", resave: false, saveUninitialized: true }));

// Tabelas do banco de dados
db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    password TEXT
  )`);
  db.run(`CREATE TABLE IF NOT EXISTS comments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    userId INTEGER,
    comment TEXT,
    FOREIGN KEY (userId) REFERENCES users(id)
  )`);
});

// Rotas
app.get("/", (req, res) => {
  db.all("SELECT comments.comment, users.username FROM comments JOIN users ON comments.userId = users.id", [], (err, comments) => {
    res.render("index", { user: req.session.user, comments });
  });
});

app.get("/login", (req, res) => {
  res.render("login", { error: null });
});

app.post("/login", (req, res) => {
  const { username, password } = req.body;
  db.get("SELECT * FROM users WHERE username = ?", [username], async (err, user) => {
    if (user && (await bcrypt.compare(password, user.password))) {
      req.session.user = { id: user.id, username: user.username };
      return res.redirect("/");
    }
    res.render("login", { error: "Invalid username or password" });
  });
});

app.get("/register", (req, res) => {
  res.render("register", { error: null });
});

app.post("/register", async (req, res) => {
  const { username, password } = req.body;
  const hashedPassword = await bcrypt.hash(password, 10);

  db.run("INSERT INTO users (username, password) VALUES (?, ?)", [username, hashedPassword], (err) => {
    if (err) return res.render("register", { error: "Username already exists" });
    res.redirect("/login");
  });
});

app.post("/comment", (req, res) => {
  if (!req.session.user) return res.redirect("/login");

  const { comment } = req.body;
  db.run("INSERT INTO comments (userId, comment) VALUES (?, ?)", [req.session.user.id, comment], (err) => {
    res.redirect("/");
  });
});

app.get("/logout", (req, res) => {
  req.session.destroy();
  res.redirect("/");
});

// Servidor
app.listen(3000, () => console.log("Server rodando em http://localhost:3000"));
