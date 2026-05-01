import express from "express";
import mongoose from "mongoose";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import Stripe from "stripe";

const app = express();
const PORT = process.env.PORT || 4000;
const stripe = new Stripe(process.env.STRIPE_SECRET_KEY);

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
  stripeCustomerId: String,
  stripeSubscriptionId: String,
  membershipStatus: String,
  createdAt: { type: Date, default: Date.now }
});

const User = mongoose.model("User", UserSchema);

function signToken(user) {
  return jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: "30d" });
}

function membershipLabel(status) {
  if (status === "active") return "Active Protection Member";
  if (status === "trialing") return "Trialing Protection Member";
  if (status === "past_due") return "Past Due — Payment Issue";
  if (status === "canceled") return "Canceled — Access Locked";
  if (status === "unpaid") return "Unpaid — Access Locked";
  if (status === "not_found") return "No Active Membership Found";
  return "Membership Issue";
}

function accessAllowed(status) {
  return status === "active" || status === "trialing";
}

async function checkStripeMembership(email) {
  const customers = await stripe.customers.list({ email, limit: 10 });

  if (!customers.data.length) {
    return { status: "not_found", customerId: "", subscriptionId: "" };
  }

  const customer = customers.data.sort((a, b) => b.created - a.created)[0];

  const subscriptions = await stripe.subscriptions.list({
    customer: customer.id,
    status: "all",
    limit: 20
  });

  if (!subscriptions.data.length) {
    return { status: "not_found", customerId: customer.id, subscriptionId: "" };
  }

  const priority = ["active", "trialing", "past_due", "unpaid", "incomplete", "canceled"];

  const sub = subscriptions.data.sort((a, b) => {
    const ar = priority.indexOf(a.status);
    const br = priority.indexOf(b.status);
    return (ar === -1 ? 99 : ar) - (br === -1 ? 99 : br);
  })[0];

  return { status: sub.status, customerId: customer.id, subscriptionId: sub.id };
}

function publicUser(user) {
  return {
    name: user.name || "",
    email: user.email || "",
    permitState: user.permitState || "MI",
    issueDate: user.issueDate || "",
    expirationDate: user.expirationDate || "",
    emergencyName: user.emergencyName || "",
    emergencyPhone: user.emergencyPhone || "",
    membershipStatus: user.membershipStatus || "not_found",
    membershipLabel: membershipLabel(user.membershipStatus || "not_found"),
    accessAllowed: accessAllowed(user.membershipStatus || "not_found")
  };
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

    const stripeCheck = await checkStripeMembership(email);
    const hashed = await bcrypt.hash(password, 10);

    const user = await User.create({
      name,
      email,
      password: hashed,
      permitState: "MI",
      issueDate: "",
      expirationDate: "",
      emergencyName: "",
      emergencyPhone: "",
      stripeCustomerId: stripeCheck.customerId,
      stripeSubscriptionId: stripeCheck.subscriptionId,
      membershipStatus: stripeCheck.status
    });

    res.json({ success: true, token: signToken(user), user: publicUser(user) });
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
    if (!user) return res.json({ error: "No account found for this email." });

    const valid = await bcrypt.compare(password, user.password);
    if (!valid) return res.json({ error: "Invalid password." });

    const stripeCheck = await checkStripeMembership(email);

    user.stripeCustomerId = stripeCheck.customerId;
    user.stripeSubscriptionId = stripeCheck.subscriptionId;
    user.membershipStatus = stripeCheck.status;
    await user.save();

    res.json({ success: true, token: signToken(user), user: publicUser(user) });
  } catch (err) {
    console.log("Login error:", err);
    res.json({ error: "Login failed." });
  }
});

app.post("/api/get-profile", async (req, res) => {
  try {
    const decoded = jwt.verify(req.body.token, process.env.JWT_SECRET);
    const user = await User.findById(decoded.id);

    if (!user) return res.json({ error: "User not found." });

    const stripeCheck = await checkStripeMembership(user.email);

    user.stripeCustomerId = stripeCheck.customerId;
    user.stripeSubscriptionId = stripeCheck.subscriptionId;
    user.membershipStatus = stripeCheck.status;
    await user.save();

    res.json(publicUser(user));
  } catch (err) {
    console.log("Profile load error:", err);
    res.json({ error: "Session expired. Please login again." });
  }
});

app.post("/api/refresh-membership", async (req, res) => {
  try {
    const decoded = jwt.verify(req.body.token, process.env.JWT_SECRET);
    const user = await User.findById(decoded.id);

    if (!user) return res.json({ error: "User not found." });

    const stripeCheck = await checkStripeMembership(user.email);

    user.stripeCustomerId = stripeCheck.customerId;
    user.stripeSubscriptionId = stripeCheck.subscriptionId;
    user.membershipStatus = stripeCheck.status;
    await user.save();

    res.json(publicUser(user));
  } catch (err) {
    res.json({ error: "Unable to refresh membership." });
  }
});

app.post("/api/billing-portal", async (req, res) => {
  try {
    const decoded = jwt.verify(req.body.token, process.env.JWT_SECRET);
    const user = await User.findById(decoded.id);

    if (!user || !user.stripeCustomerId) {
      return res.json({ error: "No Stripe customer found for this email." });
    }

    const session = await stripe.billingPortal.sessions.create({
      customer: user.stripeCustomerId,
      return_url: process.env.FRONTEND_URL || "https://app.primedefensetraining.com"
    });

    res.json({ url: session.url });
  } catch (err) {
    console.log("Billing portal error:", err);
    res.json({ error: "Unable to open billing portal." });
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
body{margin:0;font-family:Arial,Helvetica,sans-serif;background:radial-gradient(circle at top left,rgba(180,0,20,.35),transparent 35%),linear-gradient(135deg,#050505,#161616 55%,#050505);color:white;min-height:100vh}
.container{max-width:580px;margin:60px auto;padding:44px;background:rgba(15,15,15,.96);border:1px solid rgba(255,255,255,.10);border-radius:26px;box-shadow:0 30px 80px rgba(0,0,0,.65);text-align:center}
.brand{color:#ef233c;font-size:13px;letter-spacing:3px;font-weight:900;margin-bottom:12px}
h1{font-size:46px;line-height:.95;margin:10px 0 14px}
.subtitle{color:#cfcfcf;line-height:1.5;margin-bottom:26px}
.tabs{display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-bottom:20px}
.tab{background:#202020;color:white;border:1px solid rgba(255,255,255,.12)}
.tab.active{background:#ef233c}
input,select{width:100%;box-sizing:border-box;padding:16px;margin:9px 0;border:1px solid rgba(255,255,255,.13);border-radius:14px;background:#090909;color:white;font-size:16px}
button{padding:15px;border-radius:14px;font-weight:900;border:none;cursor:pointer;font-size:15px}
.primary{background:#ef233c;color:white;width:100%;margin-top:14px}
.secondary{background:#242424;color:white;border:1px solid rgba(255,255,255,.12)}
.msg{margin-top:16px;color:#ffe7b3;font-weight:bold;min-height:22px}
.dashboard{max-width:980px;margin:35px auto;padding:22px}
.hero,.card{background:rgba(15,15,15,.96);border:1px solid rgba(255,255,255,.09);border-radius:24px;padding:26px;margin-bottom:18px;box-shadow:0 18px 50px rgba(0,0,0,.35)}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(240px,1fr));gap:14px}
.status{display:inline-block;background:rgba(34,197,94,.14);color:#8cffb0;border:1px solid rgba(34,197,94,.35);padding:9px 13px;border-radius:999px;font-size:13px;font-weight:900}
.status.locked{background:rgba(239,35,60,.14);color:#ffb8c0;border:1px solid rgba(239,35,60,.35)}
.small{color:#aaa;font-size:13px;line-height:1.5}
.actions{display:flex;flex-wrap:wrap;gap:10px;margin-top:14px}
.actions button{min-width:150px}
.lockbox{max-width:720px;margin:60px auto;padding:36px;background:rgba(15,15,15,.96);border:1px solid rgba(239,35,60,.35);border-radius:26px;text-align:center}
.emergencyButton{position:fixed;right:22px;bottom:22px;width:86px;height:86px;border-radius:50%;background:#ef233c;color:white;font-size:20px;box-shadow:0 0 28px rgba(239,35,60,.7);z-index:50}
.emergencyScreen{position:fixed;inset:0;background:radial-gradient(circle at top left,rgba(180,0,20,.45),transparent 35%),#050505;z-index:999;padding:22px;overflow:auto}
.emergencyShell{max-width:850px;margin:0 auto}
.script{font-size:24px;line-height:1.25;font-weight:900;background:rgba(239,35,60,.12);border:1px solid rgba(239,35,60,.35);border-radius:20px;padding:20px;margin-top:14px}
.bigAction{width:100%;padding:20px;font-size:20px;margin:10px 0}
.warn{background:rgba(245,158,11,.12);border:1px solid rgba(245,158,11,.25);color:#ffe7b3;padding:16px;border-radius:16px;line-height:1.5}
.reciprocityBox{margin-top:14px;background:rgba(0,0,0,.28);border:1px solid rgba(255,255,255,.08);border-radius:16px;padding:16px;color:#ddd;line-height:1.5}
.legalItem{background:rgba(0,0,0,.24);border:1px solid rgba(255,255,255,.08);border-radius:16px;padding:18px;margin:14px 0;line-height:1.55}
.legalItem h3{margin-top:0;color:white}
.legalSource{font-size:12px;color:#999;margin-top:10px;border-top:1px solid rgba(255,255,255,.08);padding-top:10px}
@media(max-width:650px){.container{margin:22px 14px;padding:28px}h1{font-size:34px}.dashboard{padding:14px}.emergencyButton{width:74px;height:74px}}
</style>
</head>
<body>
<div id="app"></div>

<script>
var token = localStorage.getItem("pd_token");
var authMode = "login";
var currentUser = null;

var states = [
["AL","Alabama"],["AK","Alaska"],["AZ","Arizona"],["AR","Arkansas"],["CA","California"],["CO","Colorado"],["CT","Connecticut"],["DE","Delaware"],["FL","Florida"],["GA","Georgia"],
["HI","Hawaii"],["ID","Idaho"],["IL","Illinois"],["IN","Indiana"],["IA","Iowa"],["KS","Kansas"],["KY","Kentucky"],["LA","Louisiana"],["ME","Maine"],["MD","Maryland"],
["MA","Massachusetts"],["MI","Michigan"],["MN","Minnesota"],["MS","Mississippi"],["MO","Missouri"],["MT","Montana"],["NE","Nebraska"],["NV","Nevada"],["NH","New Hampshire"],["NJ","New Jersey"],
["NM","New Mexico"],["NY","New York"],["NC","North Carolina"],["ND","North Dakota"],["OH","Ohio"],["OK","Oklahoma"],["OR","Oregon"],["PA","Pennsylvania"],["RI","Rhode Island"],["SC","South Carolina"],
["SD","South Dakota"],["TN","Tennessee"],["TX","Texas"],["UT","Utah"],["VT","Vermont"],["VA","Virginia"],["WA","Washington"],["WV","West Virginia"],["WI","Wisconsin"],["WY","Wyoming"]
];

function q(id){return document.getElementById(id)}
function setMsg(text){var msg=q("msg"); if(msg) msg.innerText=text||""}

function escapeHtml(value){
  return String(value || "").replaceAll("&","&amp;").replaceAll("<","&lt;").replaceAll(">","&gt;").replaceAll('"',"&quot;").replaceAll("'","&#039;");
}

function getReciprocityText(state){
  var names = {};
  states.forEach(function(s){names[s[0]]=s[1]});
  var stateName = names[state] || state;
  if(state === "MI") return "Michigan CPL profile selected. Reciprocity guidance will display Michigan-based travel information as state-law data is added.";
  return stateName + " permit profile selected. Reciprocity guidance will update based on the selected permit state as verified legal data is added.";
}

function showAuth(){
  var isRegister = authMode === "register";
  q("app").innerHTML =
    '<div class="container">' +
      '<div class="brand">PRIME DEFENSE TRAINING</div>' +
      '<h1>Prime Defense Protection</h1>' +
      '<p class="subtitle">Member-only access for permit tracking, emergency tools, and future legal resources.</p>' +
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

  q("loginTab").onclick=function(){authMode="login";showAuth()};
  q("registerTab").onclick=function(){authMode="register";showAuth()};
  q("submitBtn").onclick=function(){ if(authMode==="register") registerUser(); else loginUser(); };
}

async function registerUser(){
  setMsg("Creating account and checking membership...");
  var name = q("name").value;
  var email = q("email").value;
  var password = q("password").value;

  try{
    var res = await fetch("/api/register",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({name:name,email:email,password:password})});
    var data = await res.json();
    if(data.token){
      token=data.token;
      localStorage.setItem("pd_token",token);
      if(data.user && data.user.accessAllowed) showDashboard(); else showLocked(data.user);
    } else setMsg(data.error || "Registration failed.");
  }catch(e){setMsg("Registration failed.")}
}

async function loginUser(){
  setMsg("Logging in and checking membership...");
  var email = q("email").value;
  var password = q("password").value;

  try{
    var res = await fetch("/api/login",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({email:email,password:password})});
    var data = await res.json();
    if(data.token){
      token=data.token;
      localStorage.setItem("pd_token",token);
      if(data.user && data.user.accessAllowed) showDashboard(); else showLocked(data.user);
    } else setMsg(data.error || "Login failed.");
  }catch(e){setMsg("Login failed.")}
}

function logout(){
  localStorage.removeItem("pd_token");
  token=null;
  authMode="login";
  showAuth();
}

async function refreshMembership(){
  setMsg("Refreshing membership status...");
  var res = await fetch("/api/refresh-membership",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({token:token})});
  var user = await res.json();
  if(user.accessAllowed) showDashboard(); else showLocked(user);
}

async function openBilling(){
  setMsg("Opening billing portal...");
  var res = await fetch("/api/billing-portal",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({token:token})});
  var data = await res.json();
  if(data.url) window.location.href=data.url; else setMsg(data.error || "Unable to open billing.");
}

function showLocked(user){
  user=user||{};
  q("app").innerHTML =
    '<div class="lockbox">' +
      '<div class="brand">MEMBERSHIP REQUIRED</div>' +
      '<h1>Access Locked</h1>' +
      '<span class="status locked">' + escapeHtml(user.membershipLabel || "Membership Required") + '</span>' +
      '<p class="subtitle">Your app account exists, but active Prime Defense Protection membership is required to access member tools.</p>' +
      '<div class="actions" style="justify-content:center">' +
        '<button id="refreshBtn" class="primary" type="button">Refresh Status</button>' +
        '<button id="billingBtn" class="secondary" type="button">Update Billing</button>' +
        '<button id="logoutBtn" class="secondary" type="button">Logout</button>' +
      '</div>' +
      '<div id="msg" class="msg"></div>' +
    '</div>';
  q("refreshBtn").onclick=refreshMembership;
  q("billingBtn").onclick=openBilling;
  q("logoutBtn").onclick=logout;
}

function buildStateOptions(selected){
  var html = "";
  states.forEach(function(s){
    html += '<option value="' + s[0] + '"' + (s[0]===selected?' selected':'') + '>' + s[1] + '</option>';
  });
  return html;
}

async function showDashboard(){
  try{
    var res = await fetch("/api/get-profile",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({token:token})});
    var user = await res.json();

    if(user.error){localStorage.removeItem("pd_token"); token=null; showAuth(); return;}
    if(!user.accessAllowed){showLocked(user); return;}

    currentUser=user;
    var selectedState = user.permitState || "MI";

    q("app").innerHTML =
      '<div class="dashboard">' +
        '<div class="hero">' +
          '<div class="brand">PRIME DEFENSE PROTECTION</div>' +
          '<h1>Member Dashboard</h1>' +
          '<span class="status">' + escapeHtml(user.membershipLabel) + '</span>' +
          '<p class="subtitle">Welcome' + (user.name ? ', ' + escapeHtml(user.name) : '') + '. Manage your permit details, emergency contact, and member tools.</p>' +
          '<div class="actions">' +
            '<button id="refreshBtn" class="secondary" type="button">Refresh Status</button>' +
            '<button id="logoutBtn" class="secondary" type="button">Logout</button>' +
          '</div>' +
        '</div>' +

        '<div class="card">' +
          '<div class="brand">MY PERMIT</div>' +
          '<h2>Permit Profile</h2>' +
          '<p class="small">Enter the information exactly as it appears on your permit.</p>' +
          '<div class="grid">' +
            '<select id="state">' + buildStateOptions(selectedState) + '</select>' +
            '<input id="issue" type="date" value="' + escapeHtml(user.issueDate || '') + '">' +
            '<input id="exp" type="date" value="' + escapeHtml(user.expirationDate || '') + '">' +
          '</div>' +
          '<div id="reciprocityBox" class="reciprocityBox"></div>' +
        '</div>' +

        '<div class="card">' +
          '<div class="brand">MICHIGAN LEGAL GUIDE</div>' +
          '<h2>Michigan CPL & Firearms Law Guide</h2>' +
          '<p class="small">Educational member reference for Michigan CPL holders. Not legal advice.</p>' +
          '<button id="miGuideBtn" class="primary" type="button">Open Michigan Legal Guide</button>' +
        '</div>' +

        '<div class="card">' +
          '<div class="brand">EMERGENCY CONTACT</div>' +
          '<h2>Family / Trusted Contact</h2>' +
          '<p class="small">This contact appears inside Emergency Mode.</p>' +
          '<div class="grid">' +
            '<input id="ename" placeholder="Contact Name" value="' + escapeHtml(user.emergencyName || '') + '">' +
            '<input id="phone" placeholder="Contact Phone" value="' + escapeHtml(user.emergencyPhone || '') + '">' +
          '</div>' +
        '</div>' +

        '<button id="saveBtn" class="primary" type="button">Save Profile</button>' +
        '<button id="emergencyBtn" class="emergencyButton" type="button">911</button>' +
        '<div id="msg" class="msg"></div>' +
      '</div>';

    updateReciprocity();
    q("state").onchange=updateReciprocity;
    q("saveBtn").onclick=saveProfile;
    q("logoutBtn").onclick=logout;
    q("refreshBtn").onclick=refreshMembership;
    q("emergencyBtn").onclick=openEmergency;
    q("miGuideBtn").onclick=showMichiganLegalGuide;

  }catch(e){
    localStorage.removeItem("pd_token");
    token=null;
    showAuth();
  }
}

function updateReciprocity(){
  var state = q("state").value;
  q("reciprocityBox").innerText = getReciprocityText(state);
}

async function saveProfile(){
  setMsg("Saving...");
  try{
    var res = await fetch("/api/save-profile",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({
      token:token,
      permitState:q("state").value,
      issueDate:q("issue").value,
      expirationDate:q("exp").value,
      emergencyName:q("ename").value,
      emergencyPhone:q("phone").value
    })});
    var data = await res.json();
    setMsg(data.error || data.message || "Saved.");
  }catch(e){setMsg("Save failed.")}
}
function showMichiganLegalGuide(){
  q("app").innerHTML =
    '<div class="dashboard">' +
      '<div class="hero">' +
        '<div class="brand">MICHIGAN LEGAL GUIDE</div>' +
        '<h1>Michigan CPL Field Guide</h1>' +
        '<p class="subtitle">Detailed Michigan CPL and firearms law reference. Educational only. Not legal advice.</p>' +
        '<div class="actions">' +
          '<button class="secondary" type="button" onclick="showDashboard()">Back to Dashboard</button>' +
          '<button class="secondary" type="button" onclick="openEmergency()">Emergency Mode</button>' +
        '</div>' +
      '</div>' +

      '<div class="card">' +

        '<div class="legalItem">' +
          '<h3>CPL Renewal & Expiration</h3>' +
          '<p><b>What the law/source says:</b> Michigan State Police states a CPL renewal may be submitted not more than 6 months before expiration and not more than 1 year after expiration.</p>' +
          '<p><b>What it means:</b> Do not wait until the last minute. Once you are inside the 6-month window, begin renewal planning. If the CPL expires, there may still be a renewal period, but carrying privileges and legal exposure must be understood carefully.</p>' +
          '<p><b>Common mistake:</b> Thinking the permit is automatically extended just because a renewal is possible. Renewal eligibility and lawful carry are not the same thing.</p>' +
          '<p><b>Training note:</b> Track the expiration date, renew early, and keep proof/receipts organized.</p>' +
          '<div class="legalSource">Reference: Michigan State Police CPL Renewal Information.</div>' +
        '</div>' +

        '<div class="legalItem">' +
          '<h3>Duty to Disclose During Police Contact</h3>' +
          '<p><b>What the law/source says:</b> MCL 28.425f addresses CPL possession and disclosure duties when a CPL holder is carrying a concealed pistol and is stopped by a peace officer.</p>' +
          '<p><b>What it means:</b> If you are carrying concealed and stopped by police, disclosure is not something to improvise. Calmly disclose, keep your hands visible, follow instructions, and do not reach for the firearm unless specifically directed.</p>' +
          '<p><b>Common mistake:</b> Saying too much, moving too quickly, reaching toward a firearm, or assuming the officer already knows everything from the plate/LEIN return.</p>' +
          '<p><b>Training note:</b> A safe disclosure sounds calm and simple: “Officer, I have a CPL and I am currently carrying. How would you like me to proceed?” Then stop and follow instructions.</p>' +
          '<div class="legalSource">Reference: MCL 28.425f.</div>' +
        '</div>' +

        '<div class="legalItem">' +
          '<h3>Pistol-Free Zones / Prohibited Premises</h3>' +
          '<p><b>What the law/source says:</b> MCL 28.425o lists premises where carrying a concealed pistol is prohibited for CPL holders, subject to statutory language and exceptions.</p>' +
          '<p><b>What it means:</b> These are not casual “policy preference” areas. They are statutory restricted locations. The exact text matters, including how “premises” is defined and what exceptions apply.</p>' +
          '<p><b>Common categories taught:</b> Schools/school property, certain day care facilities, sports arenas/stadiums, bars/taverns where alcohol sales are the primary source of income, places of worship unless permitted by the presiding official, entertainment facilities over statutory seating thresholds, hospitals, and dormitories/classrooms of colleges or universities.</p>' +
          '<p><b>Common mistake:</b> Assuming open carry, concealed carry, private policies, and statutory prohibited premises all work the same way. They do not.</p>' +
          '<p><b>Training note:</b> Before carrying into any sensitive location, pause and identify whether the issue is statutory law, private property policy, workplace policy, school policy, or a combination.</p>' +
          '<div class="legalSource">Reference: MCL 28.425o and Michigan State Police prohibited-premises guidance.</div>' +
        '</div>' +

        '<div class="legalItem">' +
          '<h3>No-Firearms Signs & Private Property</h3>' +
          '<p><b>What it means:</b> A sign is not the same thing as a statutory pistol-free zone, but that does not mean it can be ignored. Private property owners can set conditions for entry and may ask a person to leave.</p>' +
          '<p><b>Practical effect:</b> If you are asked to leave because of a firearm, leave immediately and peacefully. Refusing to leave can create a trespass issue even if the sign itself is not the same as a criminal carry statute.</p>' +
          '<p><b>Common mistake:</b> Treating every sign like it has no consequences. The better approach is to separate the question: Is this a statutory prohibited place, private property notice, workplace rule, or posted policy?</p>' +
          '<p><b>Training note:</b> Do not argue law with employees, managers, security, or bystanders. Leave, document if needed, and make decisions later.</p>' +
        '</div>' +

        '<div class="legalItem">' +
          '<h3>Open Carry in Michigan</h3>' +
          '<p><b>What the source says:</b> Michigan State Police Legal Update No. 86 explains that open carry is generally lawful when the firearm is carried with lawful intent and is not concealed, but premises restrictions still matter.</p>' +
          '<p><b>What it means:</b> Open carry is not a magic bypass around all firearm restrictions. Vehicle carry, prohibited premises, disturbing-the-peace type situations, brandishing concerns, and police interactions still matter.</p>' +
          '<p><b>Common mistake:</b> Thinking “open carry is legal” answers every situation. It does not. The location, manner of carry, intent, behavior, and whether the firearm becomes concealed can all matter.</p>' +
          '<p><b>Training note:</b> Open carry may draw attention. Even when lawful, it can create police contacts, business conflicts, or public concern. Know the law and your purpose before doing it.</p>' +
          '<div class="legalSource">Reference: Michigan State Police Legal Update No. 86.</div>' +
        '</div>' +

        '<div class="legalItem">' +
          '<h3>Vehicle Carry</h3>' +
          '<p><b>What it means:</b> Vehicle carry is one of the most misunderstood areas. Rules differ depending on whether a person has a valid CPL, whether the pistol is loaded, whether it is concealed, and how it is transported.</p>' +
          '<p><b>Practical reminder:</b> A valid CPL changes what may be lawful in a vehicle. Without a CPL, transport rules are far more restrictive and typically require the firearm to be unloaded and properly secured/transported.</p>' +
          '<p><b>Common mistake:</b> Assuming “open carry” allows a loaded pistol in a vehicle without a CPL. Vehicle carry has its own legal issues.</p>' +
          '<p><b>Training note:</b> Treat vehicles as a separate legal environment. Before crossing state lines, verify both Michigan rules and the laws of every state traveled through.</p>' +
        '</div>' +

        '<div class="legalItem">' +
          '<h3>Brandishing</h3>' +
          '<p><b>What the law/source says:</b> MCL 750.234e prohibits willfully and knowingly brandishing a firearm in public, subject to statutory exceptions.</p>' +
          '<p><b>What it means:</b> Displaying, exposing, touching, pointing, waving, or otherwise using the firearm as a visual threat can create legal risk depending on context. The facts matter.</p>' +
          '<p><b>Common mistake:</b> “I only showed it to scare him off.” That statement can be dangerous. The legal question becomes why it was displayed, whether there was a lawful defensive need, and whether the conduct was reasonable under the circumstances.</p>' +
          '<p><b>Training note:</b> Avoid using the firearm as a warning tool. If it comes out, there must be a lawful reason tied to an immediate defensive need. If there is no immediate threat, create distance, leave, call police, and document.</p>' +
          '<div class="legalSource">Reference: MCL 750.234e.</div>' +
        '</div>' +

        '<div class="legalItem">' +
          '<h3>Defensive Display vs. Brandishing</h3>' +
          '<p><b>Key distinction:</b> The same physical action may be viewed differently depending on facts. Exposing or drawing a firearm because of an immediate unlawful threat is different from showing a firearm to intimidate, win an argument, or control a non-deadly situation.</p>' +
          '<p><b>Factors that matter:</b> Who was the aggressor, whether there was an immediate threat, whether retreat/avoidance was possible, what was said, what witnesses saw, what cameras captured, and whether the firearm was pointed or merely exposed.</p>' +
          '<p><b>Training note:</b> The safest language after a no-shots-fired defensive display is factual, brief, and attorney-conscious. Report the attack or possible attack, describe the suspect and direction of travel, and avoid detailed argument on scene.</p>' +
        '</div>' +

        '<div class="legalItem">' +
          '<h3>Use of Force / Deadly Force</h3>' +
          '<p><b>What the law/source says:</b> MCL 780.972 addresses when deadly force may be used under Michigan law. Core concepts include honest and reasonable belief, immediacy, necessity, and the nature of the threatened harm.</p>' +
          '<p><b>What it means:</b> The legal standard is not simply “I was scared.” Fear must be tied to facts that support an honest and reasonable belief that force was necessary.</p>' +
          '<p><b>Deadly force concerns:</b> Deadly force is generally tied to threats such as death, great bodily harm, or sexual assault under the conditions described by law.</p>' +
          '<p><b>Common mistake:</b> Believing a firearm can be used to protect property alone. Property protection and defense against death/great bodily harm are not the same legal category.</p>' +
          '<p><b>Training note:</b> Articulation matters. The question is not whether you “won” the encounter. The question is whether your decisions were lawful, necessary, reasonable, and explainable based on the facts known at the time.</p>' +
          '<div class="legalSource">Reference: MCL 780.972.</div>' +
        '</div>' +

        '<div class="legalItem">' +
          '<h3>After a Defensive Gun Use</h3>' +
          '<p><b>Immediate priorities:</b> Get to safety, call 911, request police and medical, identify yourself as the caller when appropriate, follow commands, and avoid detailed statements until legal counsel is involved.</p>' +
          '<p><b>What to avoid:</b> Do not argue, speculate, exaggerate, discuss details with bystanders, post online, consent to broad searches without counsel, or make repeated statements while under adrenaline.</p>' +
          '<p><b>Training note:</b> The goal is to report the emergency, preserve safety, preserve evidence, identify witnesses if necessary, and protect legal rights.</p>' +
        '</div>' +

        '<div class="legalItem">' +
          '<h3>Final Disclaimer</h3>' +
          '<p>This guide is educational information only. It is not legal advice, does not create an attorney-client relationship, and should not be treated as a substitute for current statutes, official state guidance, or qualified legal counsel.</p>' +
          '<p>Firearms law changes. Case law changes. Policies change. Always verify current law before relying on any legal summary.</p>' +
        '</div>' +

      '</div>' +
    '</div>';
}

function openEmergency(){
  var phone = q("phone") ? q("phone").value : "";
  var name = q("ename") ? q("ename").value : "";

  q("app").innerHTML =
    '<div class="emergencyScreen">' +
      '<div class="emergencyShell">' +
        '<div class="brand">PRIME DEFENSE PROTECTION MEMBER</div>' +
        '<h1>Emergency Mode</h1>' +
        '<div class="card">' +
          '<div class="brand">STEP 1 — CALL 911</div>' +
          '<div class="script">“I was attacked, feared for my life, and had to defend myself. Please send both police and an ambulance to this location.”</div>' +
          '<button class="primary bigAction" type="button" onclick="window.location.href=\\'tel:911\\'">CALL 911</button>' +
          '<div class="warn">Secondary wording: “There has been a self-defense shooting at this location. Send help.” Provide only necessary information and follow dispatcher instructions.</div>' +
        '</div>' +
        '<div class="card">' +
          '<div class="brand">STEP 2 — CALL USCCA</div>' +
          '<p class="small">Contact the USCCA Critical Response Team after calling 911.</p>' +
          '<button class="primary bigAction" type="button" onclick="window.location.href=\\'tel:8776771919\\'">CALL USCCA</button>' +
        '</div>' +
        '<div class="card">' +
          '<div class="brand">STEP 3 — CONTACT FAMILY</div>' +
          '<h2>' + escapeHtml(name || "Emergency Contact") + '</h2>' +
          '<p class="small">' + escapeHtml(phone || "No phone saved") + '</p>' +
          (phone ? '<button class="primary bigAction" type="button" onclick="window.location.href=\\'tel:' + phone.replace(/[^0-9+]/g,"") + '\\'">CALL CONTACT</button>' : '<div class="warn">No emergency contact saved.</div>') +
          '<div class="script">“I’ve been involved in a defensive incident. I’m safe. Do not discuss anything with anyone until I have legal guidance.”</div>' +
        '</div>' +
        '<button class="secondary bigAction" type="button" onclick="showDashboard()">EXIT EMERGENCY MODE</button>' +
      '</div>' +
    '</div>';
}

if(token) showDashboard(); else showAuth();
</script>
</body>
</html>
`;

app.get("/", (req,res)=>res.send(html));
app.use((req,res)=>res.send(html));

app.listen(PORT, ()=>console.log("Running on port "+PORT));
