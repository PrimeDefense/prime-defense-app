import express from "express";
import mongoose from "mongoose";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";

const app = express();
const PORT = process.env.PORT || 4000;

app.use(express.json());

/* ================= DATABASE ================= */

mongoose.connect(process.env.MONGODB_URI)
.then(() => console.log("MongoDB Connected"))
.catch(err => console.log(err));

const UserSchema = new mongoose.Schema({
email: String,
password: String,
permitState: String,
issueDate: String,
expirationDate: String,
emergencyName: String,
emergencyPhone: String
});

const User = mongoose.model("User", UserSchema);

/* ================= AUTH ================= */

app.post("/api/register", async (req, res) => {
const { email, password } = req.body;

const hashed = await bcrypt.hash(password, 10);

const user = new User({ email, password: hashed });
await user.save();

res.json({ success: true });
});

app.post("/api/login", async (req, res) => {
const { email, password } = req.body;

const user = await User.findOne({ email });

if (!user) return res.json({ error: "User not found" });

const valid = await bcrypt.compare(password, user.password);

if (!valid) return res.json({ error: "Invalid password" });

const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET);

res.json({ token });
});

/* ================= PROFILE ================= */

app.post("/api/save-profile", async (req, res) => {
const { token, permitState, issueDate, expirationDate, emergencyName, emergencyPhone } = req.body;

const decoded = jwt.verify(token, process.env.JWT_SECRET);

await User.findByIdAndUpdate(decoded.id, {
permitState,
issueDate,
expirationDate,
emergencyName,
emergencyPhone
});

res.json({ success: true });
});

app.post("/api/get-profile", async (req, res) => {
const { token } = req.body;

const decoded = jwt.verify(token, process.env.JWT_SECRET);

const user = await User.findById(decoded.id);

res.json(user);
});

/* ================= FRONTEND ================= */

const html = `

<!DOCTYPE html>

<html>
<head>
  <title>Prime Defense Protection</title>
</head>
<body style="background:black;color:white;font-family:sans-serif;text-align:center;padding-top:50px;">

<h1>Prime Defense Protection</h1>

<div id="app"></div>

<script>
let token = localStorage.getItem("token");

function renderLogin() {
  document.getElementById("app").innerHTML = \`
    <h2>Login</h2>
    <input id="email" placeholder="Email"><br><br>
    <input id="password" type="password" placeholder="Password"><br><br>
    <button onclick="login()">Login</button>
    <button onclick="register()">Register</button>
  \`;
}

async function register() {
  const email = document.getElementById("email").value;
  const password = document.getElementById("password").value;

  await fetch("/api/register", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email, password })
  });

  alert("Registered. Now login.");
}

async function login() {
  const email = document.getElementById("email").value;
  const password = document.getElementById("password").value;

  const res = await fetch("/api/login", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email, password })
  });

  const data = await res.json();

  if (data.token) {
    localStorage.setItem("token", data.token);
    renderDashboard();
  } else {
    alert(data.error);
  }
}

async function renderDashboard() {
  const res = await fetch("/api/get-profile", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ token })
  });

  const user = await res.json();

  document.getElementById("app").innerHTML = \`
    <h2>Profile</h2>
    <input id="state" placeholder="Permit State" value="\${user.permitState || ''}"><br><br>
    <input id="issue" placeholder="Issue Date" value="\${user.issueDate || ''}"><br><br>
    <input id="exp" placeholder="Expiration Date" value="\${user.expirationDate || ''}"><br><br>

    <h3>Emergency Contact</h3>
    <input id="ename" placeholder="Name" value="\${user.emergencyName || ''}"><br><br>
    <input id="ephone" placeholder="Phone" value="\${user.emergencyPhone || ''}"><br><br>

    <button onclick="save()">Save</button>
  \`;
}

async function save() {
  await fetch("/api/save-profile", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      token,
      permitState: document.getElementById("state").value,
      issueDate: document.getElementById("issue").value,
      expirationDate: document.getElementById("exp").value,
      emergencyName: document.getElementById("ename").value,
      emergencyPhone: document.getElementById("ephone").value
    })
  });

  alert("Saved");
}

if (token) renderDashboard();
else renderLogin();
</script>

</body>
</html>
`;

app.get("/", (req, res) => res.send(html));
app.use((req, res) => res.send(html));

app.listen(PORT, () => console.log("App running on port " + PORT));
