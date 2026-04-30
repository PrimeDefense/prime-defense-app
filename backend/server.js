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

  const existing = await User.findOne({ email });
  if (existing) return res.json({ error: "Account already exists" });

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

  res.json(user || {});
});

/* ================= UI ================= */
const html = `
<!DOCTYPE html>
<html>
<head>
<title>Prime Defense Protection</title>
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<style>
body {
  margin: 0;
  font-family: Arial, Helvetica, sans-serif;
  background:
    radial-gradient(circle at top left, rgba(180,0,20,.35), transparent 35%),
    linear-gradient(135deg, #050505, #161616 55%, #050505);
  color: white;
  min-height: 100vh;
}

.container {
  max-width: 520px;
  margin: 70px auto;
  padding: 42px;
  background: rgba(15,15,15,.96);
  border: 1px solid rgba(255,255,255,.10);
  border-radius: 24px;
  box-shadow: 0 30px 80px rgba(0,0,0,.65);
  text-align: center;
}

.brand {
  color: #ff2a2a;
  font-size: 13px;
  letter-spacing: 3px;
  font-weight: 900;
  margin-bottom: 10px;
}

h1 {
  font-size: 42px;
  line-height: .95;
  margin: 10px 0 12px;
}

.subtitle {
  color: #cfcfcf;
  line-height: 1.5;
  margin-bottom: 26px;
}

input {
  width: 100%;
  box-sizing: border-box;
  padding: 16px;
  margin: 9px 0;
  border: 1px solid rgba(255,255,255,.13);
  border-radius: 14px;
  background: #090909;
  color: white;
  font-size: 16px;
}

.buttonRow {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 12px;
  margin-top: 14px;
}

button {
  padding: 15px;
  border-radius: 14px;
  font-weight: bold;
  border: none;
  cursor: pointer;
}

.login { background:#ef233c; color:white; }
.register { background:#242424; color:white; }
.save { background:#ef233c; color:white; width:100%; margin-top:15px; }
.logout { background:#242424; color:white; margin-top:10px; }

.dashboard {
  max-width: 880px;
  margin: 35px auto;
  padding: 22px;
}

.card {
  background: rgba(15,15,15,.96);
  padding: 20px;
  border-radius: 20px;
  margin-bottom: 15px;
}
</style>
</head>

<body>
<div id="app"></div>

<script>
let token = localStorage.getItem("token");

function loginUI(){
document.getElementById("app").innerHTML = \`
<div class="container">
<div class="brand">PRIME DEFENSE TRAINING</div>
<h1>Prime Defense Protection</h1>
<p class="subtitle">Member Access Portal</p>

<input id="email" placeholder="Email">
<input id="password" type="password" placeholder="Password">

<div class="buttonRow">
<button id="loginBtn" class="login">Login</button>
<button id="registerBtn" class="register">Register</button>
</div>

<div id="msg"></div>
</div>\`;

document.getElementById("loginBtn").addEventListener("click", login);
document.getElementById("registerBtn").addEventListener("click", register);
}

async function register(){
const email = document.getElementById("email").value;
const password = document.getElementById("password").value;

const res = await fetch("/api/register",{
method:"POST",
headers:{"Content-Type":"application/json"},
body:JSON.stringify({email,password})
});

const data = await res.json();
document.getElementById("msg").innerText = data.error || "Registered. Now login.";
}

async function login(){
const email = document.getElementById("email").value;
const password = document.getElementById("password").value;

const res = await fetch("/api/login",{
method:"POST",
headers:{"Content-Type":"application/json"},
body:JSON.stringify({email,password})
});

const data = await res.json();

if(data.token){
localStorage.setItem("token",data.token);
token = data.token;
dashboard();
}else{
document.getElementById("msg").innerText = data.error;
}
}

function logout(){
localStorage.removeItem("token");
token = null;
loginUI();
}

async function dashboard(){
const res = await fetch("/api/get-profile",{
method:"POST",
headers:{"Content-Type":"application/json"},
body:JSON.stringify({token})
});

const user = await res.json();

document.getElementById("app").innerHTML = \`
<div class="dashboard">
<h1>Member Dashboard</h1>

<div class="card">
<h3>Permit Info</h3>
<input id="state" value="\${user.permitState||''}" placeholder="State">
<input id="issue" value="\${user.issueDate||''}" placeholder="Issue Date">
<input id="exp" value="\${user.expirationDate||''}" placeholder="Expiration Date">
</div>

<div class="card">
<h3>Emergency Contact</h3>
<input id="ename" value="\${user.emergencyName||''}" placeholder="Name">
<input id="phone" value="\${user.emergencyPhone||''}" placeholder="Phone">
</div>

<button id="saveBtn" class="save">Save</button>
<button id="logoutBtn" class="logout">Logout</button>

<div id="msg"></div>
</div>\`;

document.getElementById("saveBtn").addEventListener("click", save);
document.getElementById("logoutBtn").addEventListener("click", logout);
}

async function save(){
await fetch("/api/save-profile",{
method:"POST",
headers:{"Content-Type":"application/json"},
body:JSON.stringify({
token,
permitState:document.getElementById("state").value,
issueDate:document.getElementById("issue").value,
expirationDate:document.getElementById("exp").value,
emergencyName:document.getElementById("ename").value,
emergencyPhone:document.getElementById("phone").value
})
});

document.getElementById("msg").innerText = "Saved";
}

if(token) dashboard();
else loginUI();
</script>

</body>
</html>
`;

app.get("/", (req,res)=>res.send(html));
app.use((req,res)=>res.send(html));

app.listen(PORT, ()=>console.log("Running on port "+PORT));
