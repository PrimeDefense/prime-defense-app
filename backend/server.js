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
.modeButtonGrid{display:grid;grid-template-columns:repeat(auto-fit,minmax(210px,1fr));gap:12px;margin-top:14px}
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
          '<p class="small">Educational reference for Michigan CPL holders. Not legal advice.</p>' +
          '<button id="miGuideBtn" class="primary" type="button">Open Michigan Legal Guide</button>' +
        '</div>' +

        '<div class="card">' +
          '<div class="brand">INCIDENT MODES</div>' +
          '<h2>Emergency Tools</h2>' +
          '<p class="small">Use the appropriate mode based on what happened.</p>' +
          '<div class="modeButtonGrid">' +
            '<button id="shootingModeBtn" class="primary" type="button">Defensive Shooting</button>' +
            '<button id="displayModeBtn" class="secondary" type="button">No Shots Fired / Defensive Display</button>' +
            '<button id="aftermathBtn" class="secondary" type="button">Aftermath Mode</button>' +
          '</div>' +
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
    q("shootingModeBtn").onclick=openEmergency;
    q("displayModeBtn").onclick=openDefensiveDisplay;
    q("aftermathBtn").onclick=openAftermath;
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
  var guideSections = [
    {
      title: "CPL Renewal & Expiration",
      body: [
        "<b>What the law/source says:</b> Michigan State Police states a CPL renewal may be submitted not more than 6 months before expiration and not more than 1 year after expiration.",
        "<b>What it means:</b> Do not wait until the last minute. Once you are inside the 6-month window, begin renewal planning.",
        "<b>Common mistake:</b> Thinking the permit is automatically extended just because a renewal is possible. Renewal eligibility and lawful carry are not the same thing.",
        "<b>Training note:</b> Track the expiration date, renew early, and keep proof/receipts organized."
      ],
      source: "Reference: Michigan State Police CPL Renewal Information."
    },
    {
      title: "Use of Force / Deadly Force — MCL 780.972",
      body: [
        "<b>Core rule:</b> Deadly force may be used only when a person honestly and reasonably believes it is necessary to prevent imminent death, great bodily harm, or sexual assault.",
        "<b>Honest belief:</b> You genuinely believed the danger was real.",
        "<b>Reasonable belief:</b> A reasonable person in the same situation would likely see the same danger.",
        "<b>Imminent threat:</b> The danger must be happening now or immediately about to happen.",
        "<b>Necessity:</b> Deadly force must be necessary to stop the threat.",
        "<b>MCL 780.972(2) — Defense of others:</b> Deadly force may be used to protect another person under the same standards. The threshold is not lower just because someone else is in danger.",
        "<b>Important:</b> If you misunderstand the situation, even with good intentions, you may still face serious legal consequences.",
        "<b>Common mistakes:</b> Using a firearm to protect property only; acting out of anger; intervening in third-party situations without knowing who the aggressor is; assuming Stand Your Ground removes all legal scrutiny.",
        "<b>Training insight:</b> The issue is whether your actions were necessary, reasonable, and clearly tied to an immediate threat."
      ],
      source: "Reference: MCL 780.972."
    },
    {
      title: "After a Defensive Gun Use",
      body: [
        "<b>Immediate priorities:</b> Get to safety, call 911, request police and medical, identify yourself as the caller when appropriate, follow commands, and avoid detailed statements until legal counsel is involved.",
        "<b>What to avoid:</b> Do not argue, speculate, exaggerate, discuss details with bystanders, post online, consent to broad searches without counsel, or make repeated statements while under adrenaline.",
        "<b>Training note:</b> The goal is to report the emergency, preserve safety, preserve evidence, identify witnesses if necessary, and protect legal rights."
      ],
      source: ""
    },
    {
      title: "Final Disclaimer",
      body: [
        "This guide is educational information only. It is not legal advice, does not create an attorney-client relationship, and should not be treated as a substitute for current statutes, official state guidance, or qualified legal counsel.",
        "Firearms law changes. Case law changes. Policies change. Always verify current law before relying on any legal summary."
      ],
      source: ""
    }
  ];

  var html = '<div class="dashboard">' +
    '<div class="hero">' +
      '<div class="brand">MICHIGAN LEGAL GUIDE</div>' +
      '<h1>Michigan CPL Field Guide</h1>' +
      '<p class="subtitle">Detailed Michigan CPL and firearms law reference. Educational only. Not legal advice.</p>' +
      '<div class="actions">' +
        '<button class="secondary" type="button" onclick="showDashboard()">Back to Dashboard</button>' +
        '<button class="secondary" type="button" onclick="openEmergency()">Emergency Mode</button>' +
      '</div>' +
    '</div>' +
    '<div class="card">';

  guideSections.forEach(function(section){
    html += '<div class="legalItem">';
    html += '<h3>' + section.title + '</h3>';
    section.body.forEach(function(paragraph){
      html += '<p>' + paragraph + '</p>';
    });
    if(section.source){
      html += '<div class="legalSource">' + section.source + '</div>';
    }
    html += '</div>';
  });

  html += '</div></div>';
  q("app").innerHTML = html;
}

function openEmergency(){
  var phone = q("phone") ? q("phone").value : "";
  var name = q("ename") ? q("ename").value : "";

  q("app").innerHTML =
    '<div class="emergencyScreen">' +
      '<div class="emergencyShell">' +
        '<div class="brand">PRIME DEFENSE PROTECTION MEMBER</div>' +
        '<h1>Emergency Mode — Defensive Shooting</h1>' +
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

function openDefensiveDisplay(){
  q("app").innerHTML =
    '<div class="emergencyScreen">' +
      '<div class="emergencyShell">' +
        '<div class="brand">NO SHOTS FIRED</div>' +
        '<h1>Defensive Display Mode</h1>' +
        '<div class="card">' +
          '<div class="brand">STEP 1 — CALL 911</div>' +
          '<div class="script">“My name is [name], and I need to report an attack or possible attack at this location. I have a permit to carry a firearm and exposed it, but I did not pull the trigger.”</div>' +
          '<button class="primary bigAction" type="button" onclick="window.location.href=\\'tel:911\\'">CALL 911</button>' +
        '</div>' +
        '<div class="card">' +
          '<div class="brand">SUSPECT INFORMATION</div>' +
          '<p class="small">Give only necessary details: clothing, physical description, direction of travel, vehicle description, license plate if safely known, and whether they ran off or drove off.</p>' +
          '<div class="script">“The attacker was wearing [description] and ran/drove [direction]. I am not going to say another word until my attorney is present.”</div>' +
        '</div>' +
        '<div class="card">' +
          '<div class="brand">STEP 2 — CALL USCCA</div>' +
          '<button class="primary bigAction" type="button" onclick="window.location.href=\\'tel:8776771919\\'">CALL USCCA</button>' +
        '</div>' +
        '<div class="card">' +
          '<div class="brand">IMPORTANT</div>' +
          '<div class="warn">Do not over-explain. Do not argue. Do not speculate. Report the attack or possible attack, provide suspect direction/description, then wait for legal guidance.</div>' +
        '</div>' +
        '<button class="secondary bigAction" type="button" onclick="showDashboard()">BACK TO DASHBOARD</button>' +
      '</div>' +
    '</div>';
}

function openAftermath(){
  q("app").innerHTML =
    '<div class="emergencyScreen">' +
      '<div class="emergencyShell">' +
        '<div class="brand">POST-INCIDENT GUIDANCE</div>' +
        '<h1>Aftermath Mode</h1>' +
        '<div class="card">' +
          '<div class="brand">WHEN POLICE ARRIVE</div>' +
          '<p class="script">Keep your hands visible. Do not touch your firearm. Follow all commands immediately.</p>' +
          '<p class="small">Expect to be treated as a potential threat until officers secure the scene and understand what happened.</p>' +
        '</div>' +
        '<div class="card">' +
          '<div class="brand">WHAT TO SAY</div>' +
          '<div class="script">“I was attacked. I feared for my life. I will cooperate fully, but I would like to speak with my attorney before making a full statement.”</div>' +
        '</div>' +
        '<div class="card">' +
          '<div class="brand">WHAT TO DO NEXT</div>' +
          '<p class="small">• Identify yourself as the victim if appropriate.</p>' +
          '<p class="small">• Point out evidence if needed: “The weapon is there.”</p>' +
          '<p class="small">• Identify witnesses if safe: “That person saw what happened.”</p>' +
          '<p class="small">• Then stop talking until legal counsel is involved.</p>' +
        '</div>' +
        '<div class="card">' +
          '<div class="brand">WHAT NOT TO DO</div>' +
          '<p class="small">• Do not give a detailed statement under stress.</p>' +
          '<p class="small">• Do not speculate or guess.</p>' +
          '<p class="small">• Do not argue with police.</p>' +
          '<p class="small">• Do not talk to media, bystanders, or uninvolved people.</p>' +
          '<p class="small">• Do not post online.</p>' +
          '<p class="small">• Do not consent to broad searches without legal counsel.</p>' +
        '</div>' +
        '<div class="card">' +
          '<div class="brand">LEGAL REALITY</div>' +
          '<p class="warn">Even a justified defensive incident can result in detention, questioning, investigation, and legal review. Your words and behavior matter.</p>' +
        '</div>' +
        '<div class="card">' +
          '<div class="brand">NEXT STEPS</div>' +
          '<button class="primary bigAction" type="button" onclick="window.location.href=\\'tel:8776771919\\'">CALL USCCA</button>' +
          '<button class="secondary bigAction" type="button" onclick="showDashboard()">BACK TO DASHBOARD</button>' +
        '</div>' +
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
