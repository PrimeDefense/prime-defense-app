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

h2, h3 {
  margin-top: 0;
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

button {
  padding: 15px 18px;
  border: none;
  border-radius: 14px;
  cursor: pointer;
  font-weight: 900;
  font-size: 15px;
}

.buttonRow {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 12px;
  margin-top: 14px;
}

.login, .save {
  background: #ef233c;
  color: white;
}

.register, .logout {
  background: #242424;
  color: white;
  border: 1px solid rgba(255,255,255,.12);
}

.dashboard {
  max-width: 880px;
  margin: 35px auto;
  padding: 22px;
}

.hero {
  background: rgba(15,15,15,.96);
  border: 1px solid rgba(255,255,255,.10);
  border-radius: 26px;
  padding: 30px;
  margin-bottom: 18px;
  box-shadow: 0 25px 70px rgba(0,0,0,.55);
}

.card {
  background: rgba(15,15,15,.96);
  border: 1px solid rgba(255,255,255,.09);
  padding: 24px;
  margin-bottom: 18px;
  border-radius: 22px;
  box-shadow: 0 18px 50px rgba(0,0,0,.35);
}

.grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(240px, 1fr));
  gap: 14px;
}

.save {
  width: 100%;
  margin-top: 10px;
  font-size: 17px;
}

.status {
  display: inline-block;
  background: rgba(34,197,94,.14);
  color: #8cffb0;
  border: 1px solid rgba(34,197,94,.35);
  padding: 9px 13px;
  border-radius: 999px;
  font-size: 13px;
  font-weight: 900;
}

.smallText {
  color: #aaa;
  font-size: 13px;
  line-height: 1.5;
}

@media (max-width: 650px) {
  .container {
    margin: 25px 14px;
    padding: 28px;
  }

  h1 {
    font-size: 34px;
  }

  .dashboard {
    padding: 14px;
  }
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
  <p class="subtitle">Member-only access for permit tracking, emergency contact information, and future legal resources.</p>

  <input id="email" placeholder="Membership Email">
  <input id="password" type="password" placeholder="Password">

  <div class="buttonRow">
    <button class="login" onclick="login()">Login</button>
    <button class="register" onclick="register()">Register</button>
  </div>

  <p class="smallText">Use the same email address associated with your Prime Defense Protection membership.</p>
</div>\`;
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
if(data.error) return alert(data.error);
alert("Registered. You can now login.");
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
alert(data.error);
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

  <div class="hero">
    <div class="brand">PRIME DEFENSE PROTECTION</div>
    <h1>Member Dashboard</h1>
    <span class="status">Active Member Access</span>
    <p class="subtitle">Manage your permit details and emergency contact information.</p>
    <button class="logout" onclick="logout()">Logout</button>
  </div>

  <div class="card">
    <div class="brand">MY PERMIT</div>
    <h2>Permit Profile</h2>
    <p class="smallText">Enter the information exactly as it appears on your permit.</p>

    <div class="grid">
      <input id="state" placeholder="Permit State" value="\${user.permitState || ''}">
      <input id="issue" placeholder="Issue Date" value="\${user.issueDate || ''}">
      <input id="exp" placeholder="Expiration Date" value="\${user.expirationDate || ''}">
    </div>
  </div>

  <div class="card">
    <div class="brand">EMERGENCY CONTACT</div>
    <h2>Family / Trusted Contact</h2>
    <p class="smallText">This contact can later appear inside emergency mode.</p>

    <div class="grid">
      <input id="ename" placeholder="Contact Name" value="\${user.emergencyName || ''}">
      <input id="phone" placeholder="Contact Phone" value="\${user.emergencyPhone || ''}">
    </div>
  </div>

  <button class="save" onclick="save()">Save Profile</button>

</div>\`;
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

alert("Saved");
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
