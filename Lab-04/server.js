
const express = require("express");
const sqlite3 = require("sqlite3");
const { open } = require("sqlite");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

const app = express();
app.use(express.json());

const JWT_SECRET = "lab4_new_secret_2026_secure_key";
const PORT = process.env.PORT || 3000;
const dbPath = "./users-database.db";

let db;

async function initializeDB() {
  try {
    db = await open({
      filename: dbPath,
      driver: sqlite3.Database,
    });

    await db.exec(`
      CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        name TEXT NOT NULL,
        password TEXT NOT NULL
      )
    `);

    app.listen(PORT, () => {
      console.log(`Server running at http://localhost:${PORT}`);
    });
  } catch (error) {
    console.error("Database initialization failed:", error.message);
    process.exit(1);
  }
}

// Registration API
app.post("/register", async (request, response) => {
  try {
    const { username, name, password } = request.body;

    if (!username || !name || !password) {
      return response.status(400).json({
        message: "Username, name and password are required",
      });
    }

    const existingUser = await db.get(
      "SELECT * FROM users WHERE username = ?",
      [username]
    );

    if (existingUser) {
      return response.status(400).json({
        message: "Username already exists",
      });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    await db.run(
      "INSERT INTO users (username, name, password) VALUES (?, ?, ?)",
      [username, name, hashedPassword]
    );

    return response.status(201).json({
      message: "User registered successfully",
    });
  } catch (error) {
    return response.status(500).json({
      message: "Internal server error",
    });
  }
});

// Login API
app.post("/login", async (request, response) => {
  try {
    const { username, password } = request.body;

    if (!username || !password) {
      return response.status(400).json({
        message: "Username and password are required",
      });
    }

    const user = await db.get(
      "SELECT * FROM users WHERE username = ?",
      [username]
    );

    if (!user) {
      return response.status(400).json({
        message: "Invalid username",
      });
    }

    const isPasswordCorrect = await bcrypt.compare(
      password,
      user.password
    );

    if (!isPasswordCorrect) {
      return response.status(400).json({
        message: "Invalid password",
      });
    }

    const payload = {
      username: user.username,
    };

    const jwtToken = jwt.sign(payload, JWT_SECRET);

    return response.status(200).json({
      jwt_token: jwtToken,
    });
  } catch (error) {
    return response.status(500).json({
      message: "Internal server error",
    });
  }
});

initializeDB();
