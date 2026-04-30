import express from "express";
import mongoose from "mongoose";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";

const app = express();
const PORT = process.env.PORT || 4000;

app.use(express.json());

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

app.post("/api/register", async (req, res) => {
  try {
    const email = String(req.body.email || "").trim().toLowerCase();
    const password = String(req.body.password || "");

    if (!email || !password) return res.json({ error: "Email and password required" });

    const existing = await User.findOne({ email });
    if (existing) return res.json({ error: "Account already exists" });

    const hashed = await bcrypt.hash(password, 10);
    await new User({ email, password: hashed }).save();

    res.json({ success: true, message: "Registered. You can now login." });
  } catch (err) {
    res.json({ error: "Registration failed" });
  }
});

app.post("/api/login", async (req, res) => {
  try {
    const email = String(req.body.email || "").trim().toLowerCase();
    const password = String(req.body.password || "");

    const user = await User.findOne({ email });
    if (!user) return res.json({ error: "User not found" });

    const valid = await bcrypt.compare(password, user.password);
    if (!valid) return res.json({ error: "Invalid password" });

    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET);
    res.json({ token });
  } catch (err) {
    res.json({ error: "Login failed" });
  }
});

app.post("/api/get-profile", async (req, res) => {
  try {
    const decoded = jwt.verify(req.body.token, process.env.JWT_SECRET);
    const user = await User.findById(decoded.id);
    res.json(user || {});
  } catch {
    res.json({});
  }
});

app.post("/api/save-profile", async (req, res) => {
  try {
    const decoded = jwt.verify(req.body.token, process.env.JWT_SECRET);

    await User.findByIdAndUpdate(decoded.id, {
      permitState: req.body.permitState,
      issueDate: req.body.issueDate,
      expirationDate: req.body.expirationDate,
      emergencyName: req.body.emergencyName,
      emergencyPhone: req.body.emergencyPhone
    });

    res.json({ success: true });
  } catch {
    res.json({ error: "Save failed" });
  }
});

const html = `
<!DOCTYPE html>
<html>
<head>
<title>Prime Defense Protection</title>
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<style>
body{margin:0;font-family:Arial;background:radial-gradient(circle at top left,rgba(180,0,20,.35),transparent 35%),linear-gradient(135deg,#050505,#161616 55%,#050505);color:white;min-height:100vh}
.container{max-width:560px;margin:70px auto;padding:42px;background:rgba(15,15,15,.96);border:1px solid rgba(255,255,255,.10);border-radius:24px;box-shadow:0 30px 80px rgba(0,0,0,.65);text-align:center}
.brand{color:#ff2a2a;font-size:13px;letter-spacing:3px;font-weight:900;margin-bottom:10px}
h1{font-size:44px;line-height:.95;margin:10px 0 12px}
.subtitle{color:#cfcfcf;line-height:1.5;margin-bottom:26px}
input{width:100%;box-sizing:border-box;padding:16px;margin:9px 0;border:1px solid rgba(255,255,255,.13);border-radius:14px;background:#090909;color:white;font-size:16px}
.buttonRow{display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-top:14px}
button{padding:15px;border-radius:14px;font-weight:bold;border:none;cursor:pointer;font-size:15px}
.login,.save{background:#ef233c;color:white}
.register,.logout{background:#242424;color:white;border:1px solid rgba(255,255,255,.12)}
.dashboard{max-width:880px;margin:35px auto;padding:22px}
.card{background:rgba(15,15,15,.96);padding:24px;border-radius:20px;margin-bottom:16px;border:1px solid rgba(255,255,255,.09)}
.save{width:100%;margin-top:10px}
.msg{margin-top:16px;color:#ffe7b3;font-weight:bold}
</style>
</head>
<body>
<div id="app"></div>

<script>
var token = localStorage.getItem("token");

function byId(id){ return document.getElementById(id); }

function showLogin(){
  byId("app").innerHTML =
    '<div class="container">' +
    '<div class="brand">PRIME DEFENSE TRAINING</div>' +
    '<h1>Prime Defense Protection</h1>' +
    '<p class="subtitle">Member Access Portal</p>' +
    '<input id="email" placeholder="Email">' +
    '<input id="password" type="password" placeholder="Password">' +
    '<div class="buttonRow">' +
    '<button id="loginBtn" class="login" type="button">Login</button>' +
    '<button id="registerBtn" class="register" type="button">Register</button>' +
    '</div>' +
    '<div id="msg" class="msg"></div>' +
    '</div>';

  byId("loginBtn").onclick = login;
  byId("registerBtn").onclick = registerUser;
}

async function registerUser(){
  byId("msg").innerText = "Registering...";
  var email = byId("email").value;
  var password = byId("password").value;

  var res = await fetch("/api/register", {
    method: "POST",
    headers: {"Content-Type":"application/json"},
    body: JSON.stringify({email: email, password: password})
  });

  var data = await res.json();
  byId("msg").innerText = data.error || data.message || "Registered. You can now login.";
}

async function login(){
  byId("msg").innerText = "Logging in...";
  var email = byId("email").value;
  var password = byId("password").value;

  var res = await fetch("/api/login", {
    method: "POST",
    headers: {"Content-Type":"application/json"},
    body: JSON.stringify({email: email, password: password})
  });

  var data = await res.json();

  if(data.token){
    token = data.token;
    localStorage.setItem("token", token);
    showDashboard();
  } else {
    byId("msg").innerText = data.error || "Login failed";
  }
}

function logout(){
  localStorage.removeItem("token");
  token = null;
  showLogin();
}

async function showDashboard(){
  var res = await fetch("/api/get-profile", {
    method: "POST",
    headers: {"Content-Type":"application/json"},
    body: JSON.stringify({token: token})
  });

  var user = await res.json();

  byId("app").innerHTML =
    '<div class="dashboard">' +
    '<div class="card">' +
    '<div class="brand">PRIME DEFENSE PROTECTION</div>' +
    '<h1>Member Dashboard</h1>' +
    '<p class="subtitle">Manage your permit and emergency contact information.</p>' +
    '<button id="logoutBtn" class="logout" type="button">Logout</button>' +
    '</div>' +
    '<div class="card">' +
    '<div class="brand">MY PERMIT</div>' +
    '<h2>Permit Profile</h2>' +
    '<input id="state" placeholder="Permit State" value="' + (user.permitState || "") + '">' +
    '<input id="issue" placeholder="Issue Date" value="' + (user.issueDate || "") + '">' +
    '<input id="exp" placeholder="Expiration Date" value="' + (user.expirationDate || "") + '">' +
    '</div>' +
    '<div class="card">' +
    '<div class="brand">EMERGENCY CONTACT</div>' +
    '<h2>Family / Trusted Contact</h2>' +
    '<input id="ename" placeholder="Contact Name" value="' + (user.emergencyName || "") + '">' +
    '<input id="phone" placeholder="Contact Phone" value="' + (user.emergencyPhone || "") + '">' +
    '</div>' +
    '<button id="saveBtn" class="save" type="button">Save Profile</button>' +
    '<div id="msg" class="msg"></div>' +
    '</div>';

  byId("saveBtn").onclick = saveProfile;
  byId("logoutBtn").onclick = logout;
}

async function saveProfile(){
  byId("msg").innerText = "Saving...";

  var res = await fetch("/api/save-profile", {
    method: "POST",
    headers: {"Content-Type":"application/json"},
    body: JSON.stringify({
      token: token,
      permitState: byId("state").value,
      issueDate: byId("issue").value,
      expirationDate: byId("exp").value,
      emergencyName: byId("ename").value,
      emergencyPhone: byId("phone").value
    })
  });

  var data = await res.json();
  byId("msg").innerText = data.error || "Saved";
}

if(token){ showDashboard(); } else { showLogin(); }
</script>
</body>
</html>
`;

app.get("/", (req,res)=>res.send(html));
app.use((req,res)=>res.send(html));

app.listen(PORT, ()=>console.log("Running on port "+PORT));
