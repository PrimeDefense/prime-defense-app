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

/* ================= UI ================= */

const html = `

<!DOCTYPE html>

<html>
<head>
<title>Prime Defense Protection</title>
<style>
body {
  margin:0;
  font-family: Arial;
  background: linear-gradient(135deg,#0a0a0a,#1a1a1a);
  color:white;
}

.container {
max-width:400px;
margin:80px auto;
padding:30px;
background:#111;
border-radius:12px;
box-shadow:0 0 20px rgba(255,0,0,0.2);
text-align:center;
}

h1 { color:#ff2a2a; margin-bottom:10px; }
input {
width:100%;
padding:12px;
margin:8px 0;
border:none;
border-radius:6px;
background:#222;
color:white;
}

button {
width:48%;
padding:12px;
margin-top:10px;
border:none;
border-radius:6px;
cursor:pointer;
font-weight:bold;
}

.login { background:#ff2a2a; color:white; }
.register { background:#333; color:white; }

.dashboard {
max-width:600px;
margin:40px auto;
padding:20px;
}

.card {
background:#111;
padding:20px;
margin-bottom:20px;
border-radius:10px;
box-shadow:0 0 15px rgba(255,0,0,0.15);
}

.save {
width:100%;
background:#ff2a2a;
color:white;
} </style>

</head>

<body>

<div id="app"></div>

<script>
let token = localStorage.getItem("token");

function loginUI(){
document.getElementById("app").innerHTML = \`
<div class="container">
<h1>Prime Defense</h1>
<h3>Member Login</h3>
<input id="email" placeholder="Email">
<input id="password" type="password" placeholder="Password">
<button class="login" onclick="login()">Login</button>
<button class="register" onclick="register()">Register</button>
</div>\`;
}

async function register(){
const email = document.getElementById("email").value;
const password = document.getElementById("password").value;

await fetch("/api/register",{
method:"POST",
headers:{"Content-Type":"application/json"},
body:JSON.stringify({email,password})
});

alert("Registered. Login now.");
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
dashboard();
}else{
alert(data.error);
}
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
<input id="state" placeholder="State" value="\${user.permitState||''}">
<input id="issue" placeholder="Issue Date" value="\${user.issueDate||''}">
<input id="exp" placeholder="Expiration" value="\${user.expirationDate||''}">
</div>

<div class="card">
<h3>Emergency Contact</h3>
<input id="ename" placeholder="Name" value="\${user.emergencyName||''}">
<input id="phone" placeholder="Phone" value="\${user.emergencyPhone||''}">
</div>

<button class="save" onclick="save()">Save</button>

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
