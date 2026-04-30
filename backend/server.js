import express from "express";
import mongoose from "mongoose";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";

const app = express();
const PORT = process.env.PORT || 4000;

app.use(express.json());

mongoose.connect(process.env.MONGODB_URI)
  .then(() => console.log("MongoDB Connected"))
  .catch(err => console.log("MongoDB Error:", err));

const UserSchema = new mongoose.Schema({
  name: String,
  email: String,
  password: String,
  permitState: String,
  issueDate: String,
  expirationDate: String,
  emergencyName: String,
  emergencyPhone: String,
  createdAt: { type: Date, default: Date.now }
});

const User = mongoose.model("User", UserSchema);

function signToken(user) {
  return jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: "30d" });
}

app.post("/api/register", async (req, res) => {
  try {
    const name = String(req.body.name || "").trim();
    const email = String(req.body.email || "").trim().toLowerCase();
    const password = String(req.body.password || "");

    if (!name || !email || !password) {
      return res.json({ error: "Name, email, and password are required." });
    }

    const existing = await User.findOne({ email });
    if (existing) {
      return res.json({ error: "An account already exists for this email. Please login." });
    }

    const hashed = await bcrypt.hash(password, 10);

    const user = await User.create({
      name,
      email,
      password: hashed,
      permitState: "MI",
      issueDate: "",
      expirationDate: "",
      emergencyName: "",
      emergencyPhone: ""
    });

    res.json({
      success: true,
      message: "Account created.",
      token: signToken(user)
    });
  } catch (err) {
    console.log("Register error:", err);
    res.json({ error: "Registration failed." });
  }
});

app.post("/api/login", async (req, res) => {
  try {
    const email = String(req.body.email || "").trim().toLowerCase();
    const password = String(req.body.password || "");

    if (!email || !password) {
      return res.json({ error: "Email and password are required." });
    }

    const user = await User.findOne({ email });
    if (!user) {
      return res.json({ error: "No account found for this email." });
    }

    const valid = await bcrypt.compare(password, user.password);
    if (!valid) {
      return res.json({ error: "Invalid password." });
    }

    res.json({
      success: true,
      token: signToken(user)
    });
  } catch (err) {
    console.log("Login error:", err);
    res.json({ error: "Login failed." });
  }
});

app.post("/api/get-profile", async (req, res) => {
  try {
    const decoded = jwt.verify(req.body.token, process.env.JWT_SECRET);
    const user = await User.findById(decoded.id).lean();

    if (!user) return res.json({ error: "User not found." });

    delete user.password;
    res.json(user);
  } catch (err) {
    res.json({ error: "Session expired. Please login again." });
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

    res.json({ success: true, message: "Profile saved." });
  } catch (err) {
    res.json({ error: "Save failed. Please login again." });
  }
});

const html = `
<!DOCTYPE html>
<html>
<head>
<title>Prime Defense Protection</title>
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<style>
body{
  margin:0;
  font-family:Arial,Helvetica,sans-serif;
  background:radial-gradient(circle at top left,rgba(180,0,20,.35),transparent 35%),linear-gradient(135deg,#050505,#161616 55%,#050505);
  color:white;
  min-height:100vh;
}
.container{
  max-width:580px;
  margin:60px auto;
  padding:44px;
  background:rgba(15,15,15,.96);
  border:1px solid rgba(255,255,255,.10);
  border-radius:26px;
  box-shadow:0 30px 80px rgba(0,0,0,.65);
  text-align:center;
}
.brand{
  color:#ef233c;
  font-size:13px;
  letter-spacing:3px;
  font-weight:900;
  margin-bottom:12px;
}
h1{
  font-size:46px;
  line-height:.95;
  margin:10px 0 14px;
}
.subtitle{
  color:#cfcfcf;
  line-height:1.5;
  margin-bottom:26px;
}
.tabs{
  display:grid;
  grid-template-columns:1fr 1fr;
  gap:10px;
  margin-bottom:20px;
}
.tab{
  background:#202020;
  color:white;
  border:1px solid rgba(255,255,255,.12);
}
.tab.active{
  background:#ef233c;
}
input,select{
  width:100%;
  box-sizing:border-box;
  padding:16px;
  margin:9px 0;
  border:1px solid rgba(255,255,255,.13);
  border-radius:14px;
  background:#090909;
  color:white;
  font-size:16px;
}
button{
  padding:15px;
  border-radius:14px;
  font-weight:900;
  border:none;
  cursor:pointer;
  font-size:15px;
}
.primary{
  background:#ef233c;
  color:white;
  width:100%;
  margin-top:14px;
}
.secondary{
  background:#242424;
  color:white;
  border:1px solid rgba(255,255,255,.12);
}
.msg{
  margin-top:16px;
  color:#ffe7b3;
  font-weight:bold;
  min-height:22px;
}
.dashboard{
  max-width:920px;
  margin:35px auto;
  padding:22px;
}
.hero,.card{
  background:rgba(15,15,15,.96);
  border:1px solid rgba(255,255,255,.09);
  border-radius:24px;
  padding:26px;
  margin-bottom:18px;
  box-shadow:0 18px 50px rgba(0,0,0,.35);
}
.grid{
  display:grid;
  grid-template-columns:repeat(auto-fit,minmax(240px,1fr));
  gap:14px;
}
.status{
  display:inline-block;
  background:rgba(34,197,94,.14);
  color:#8cffb0;
  border:1px solid rgba(34,197,94,.35);
  padding:9px 13px;
  border-radius:999px;
  font-size:13px;
  font-weight:900;
}
.small{
  color:#aaa;
  font-size:13px;
  line-height:1.5;
}
.actions{
  display:flex;
  flex-wrap:wrap;
  gap:10px;
  margin-top:14px;
}
.actions button{
  min-width:150px;
}
@media(max-width:650px){
  .container{margin:22px 14px;padding:28px}
  h1{font-size:34px}
  .dashboard{padding:14px}
}
</style>
</head>
<body>
<div id="app"></div>

<script>
var token = localStorage.getItem("pd_token");
var authMode = "login";

function q(id){ return document.getElementById(id); }

function setMsg(text){
  var msg = q("msg");
  if(msg) msg.innerText = text || "";
}

function showAuth(){
  var isRegister = authMode === "register";

  q("app").innerHTML =
    '<div class="container">' +
      '<div class="brand">PRIME DEFENSE TRAINING</div>' +
      '<h1>Prime Defense Protection</h1>' +
      '<p class="subtitle">Member-only access for permit tracking, emergency contact information, and future legal resources.</p>' +

      '<div class="tabs">' +
        '<button id="loginTab" class="tab ' + (!isRegister ? 'active' : '') + '" type="button">Login</button>' +
        '<button id="registerTab" class="tab ' + (isRegister ? 'active' : '') + '" type="button">Register</button>' +
      '</div>' +

      (isRegister ? '<input id="name" placeholder="Full Name">' : '') +
      '<input id="email" placeholder="Membership Email">' +
      '<input id="password" type="password" placeholder="Password">' +

      '<button id="submitBtn" class="primary" type="button">' + (isRegister ? 'Create Account' : 'Login') + '</button>' +
      '<div id="msg" class="msg"></div>' +
      '<p class="small">Use the same email address associated with your Prime Defense Protection membership.</p>' +
    '</div>';

  q("loginTab").onclick = function(){ authMode = "login"; showAuth(); };
  q("registerTab").onclick = function(){ authMode = "register"; showAuth(); };
  q("submitBtn").onclick = function(){
    if(authMode === "register") registerUser();
    else loginUser();
  };
}

async function registerUser(){
  setMsg("Creating account...");

  var name = q("name").value;
  var email = q("email").value;
  var password = q("password").value;

  try{
    var res = await fetch("/api/register", {
      method:"POST",
      headers:{"Content-Type":"application/json"},
      body:JSON.stringify({name:name,email:email,password:password})
    });

    var data = await res.json();

    if(data.token){
      token = data.token;
      localStorage.setItem("pd_token", token);
      showDashboard();
    }else{
      setMsg(data.error || "Registration failed.");
    }
  }catch(e){
    setMsg("Registration failed.");
  }
}

async function loginUser(){
  setMsg("Logging in...");

  var email = q("email").value;
  var password = q("password").value;

  try{
    var res = await fetch("/api/login", {
      method:"POST",
      headers:{"Content-Type":"application/json"},
      body:JSON.stringify({email:email,password:password})
    });

    var data = await res.json();

    if(data.token){
      token = data.token;
      localStorage.setItem("pd_token", token);
      showDashboard();
    }else{
      setMsg(data.error || "Login failed.");
    }
  }catch(e){
    setMsg("Login failed.");
  }
}

function logout(){
  localStorage.removeItem("pd_token");
  token = null;
  authMode = "login";
  showAuth();
}

async function showDashboard(){
  try{
    var res = await fetch("/api/get-profile", {
      method:"POST",
      headers:{"Content-Type":"application/json"},
      body:JSON.stringify({token:token})
    });

    var user = await res.json();

    if(user.error){
      localStorage.removeItem("pd_token");
      token = null;
      showAuth();
      return;
    }

    q("app").innerHTML =
      '<div class="dashboard">' +
        '<div class="hero">' +
          '<div class="brand">PRIME DEFENSE PROTECTION</div>' +
          '<h1>Member Dashboard</h1>' +
          '<span class="status">Active App Login</span>' +
          '<p class="subtitle">Welcome' + (user.name ? ', ' + escapeHtml(user.name) : '') + '. Manage your permit details and emergency contact information.</p>' +
          '<div class="actions">' +
            '<button id="logoutBtn" class="secondary" type="button">Logout</button>' +
          '</div>' +
        '</div>' +

        '<div class="card">' +
          '<div class="brand">MY PERMIT</div>' +
          '<h2>Permit Profile</h2>' +
          '<p class="small">Enter the information exactly as it appears on your permit.</p>' +
          '<div class="grid">' +
            '<select id="state">' +
              '<option value="MI">Michigan</option>' +
              '<option value="OH">Ohio</option>' +
              '<option value="IN">Indiana</option>' +
              '<option value="FL">Florida</option>' +
              '<option value="TX">Texas</option>' +
            '</select>' +
            '<input id="issue" type="date" value="' + (user.issueDate || '') + '">' +
            '<input id="exp" type="date" value="' + (user.expirationDate || '') + '">' +
          '</div>' +
        '</div>' +

        '<div class="card">' +
          '<div class="brand">EMERGENCY CONTACT</div>' +
          '<h2>Family / Trusted Contact</h2>' +
          '<p class="small">This contact can later appear inside emergency mode.</p>' +
          '<div class="grid">' +
            '<input id="ename" placeholder="Contact Name" value="' + escapeHtml(user.emergencyName || '') + '">' +
            '<input id="phone" placeholder="Contact Phone" value="' + escapeHtml(user.emergencyPhone || '') + '">' +
          '</div>' +
        '</div>' +

        '<button id="saveBtn" class="primary" type="button">Save Profile</button>' +
        '<div id="msg" class="msg"></div>' +
      '</div>';

    q("state").value = user.permitState || "MI";
    q("saveBtn").onclick = saveProfile;
    q("logoutBtn").onclick = logout;

  }catch(e){
    localStorage.removeItem("pd_token");
    token = null;
    showAuth();
  }
}

async function saveProfile(){
  setMsg("Saving...");

  try{
    var res = await fetch("/api/save-profile", {
      method:"POST",
      headers:{"Content-Type":"application/json"},
      body:JSON.stringify({
        token:token,
        permitState:q("state").value,
        issueDate:q("issue").value,
        expirationDate:q("exp").value,
        emergencyName:q("ename").value,
        emergencyPhone:q("phone").value
      })
    });

    var data = await res.json();
    setMsg(data.error || data.message || "Saved.");
  }catch(e){
    setMsg("Save failed.");
  }
}

function escapeHtml(value){
  return String(value)
    .replaceAll("&","&amp;")
    .replaceAll("<","&lt;")
    .replaceAll(">","&gt;")
    .replaceAll('"',"&quot;")
    .replaceAll("'","&#039;");
}

if(token) showDashboard();
else showAuth();
</script>
</body>
</html>
`;

app.get("/", (req,res)=>res.send(html));
app.use((req,res)=>res.send(html));

app.listen(PORT, ()=>console.log("Running on port "+PORT));
