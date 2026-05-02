import express from "express";
import mongoose from "mongoose";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import Stripe from "stripe";

const app = express();
const PORT = process.env.PORT || 4000;
const stripe = new Stripe(process.env.STRIPE_SECRET_KEY);

app.use(express.json({ limit: "1mb" }));

mongoose
  .connect(process.env.MONGODB_URI)
  .then(() => console.log("MongoDB Connected"))
  .catch((err) => console.log("MongoDB Error:", err));

const UserSchema = new mongoose.Schema({
  name: String,
  email: { type: String, unique: true, index: true },
  password: String,
  permitState: { type: String, default: "MI" },
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
  if (status === "incomplete") return "Incomplete Membership — Action Required";
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

  const priority = [
    "active",
    "trialing",
    "past_due",
    "unpaid",
    "incomplete",
    "canceled"
  ];

  const sub = subscriptions.data.sort((a, b) => {
    const ar = priority.indexOf(a.status);
    const br = priority.indexOf(b.status);
    return (ar === -1 ? 99 : ar) - (br === -1 ? 99 : br);
  })[0];

  return {
    status: sub.status,
    customerId: customer.id,
    subscriptionId: sub.id
  };
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

async function authUserFromToken(token) {
  const decoded = jwt.verify(token, process.env.JWT_SECRET);
  const user = await User.findById(decoded.id);
  if (!user) throw new Error("User not found.");
  return user;
}

app.post("/api/register", async (req, res) => {
  try {
    const name = String(req.body.name || "").trim();
    const email = String(req.body.email || "").trim().toLowerCase();
    const password = String(req.body.password || "");

    if (!name || !email || !password) {
      return res.json({ error: "Name, email, and password are required." });
    }

    if (password.length < 6) {
      return res.json({ error: "Password must be at least 6 characters." });
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
    const user = await authUserFromToken(req.body.token);
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
    const user = await authUserFromToken(req.body.token);
    const stripeCheck = await checkStripeMembership(user.email);

    user.stripeCustomerId = stripeCheck.customerId;
    user.stripeSubscriptionId = stripeCheck.subscriptionId;
    user.membershipStatus = stripeCheck.status;
    await user.save();

    res.json(publicUser(user));
  } catch (err) {
    console.log("Membership refresh error:", err);
    res.json({ error: "Unable to refresh membership." });
  }
});

app.post("/api/billing-portal", async (req, res) => {
  try {
    const user = await authUserFromToken(req.body.token);

    if (!user.stripeCustomerId) {
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
    const user = await authUserFromToken(req.body.token);

    user.permitState = String(req.body.permitState || "MI").trim().toUpperCase();
    user.issueDate = String(req.body.issueDate || "").trim();
    user.expirationDate = String(req.body.expirationDate || "").trim();
    user.emergencyName = String(req.body.emergencyName || "").trim();
    user.emergencyPhone = String(req.body.emergencyPhone || "").trim();

    await user.save();

    res.json({ success: true, message: "Profile saved." });
  } catch (err) {
    console.log("Save profile error:", err);
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
:root{
  --bg:#f4f5f7;
  --ink:#101318;
  --muted:#626975;
  --panel:#ffffff;
  --dark:#11151b;
  --dark2:#1b2028;
  --red:#d71920;
  --red2:#ef233c;
  --line:rgba(16,19,24,.12);
  --soft:#eef0f3;
  --gold:#d9a441;
  --green:#16a34a;
  --yellow:#d97706;
  --shadow:0 24px 70px rgba(16,19,24,.16);
}
*{box-sizing:border-box}
body{
  margin:0;
  font-family:Inter,Arial,Helvetica,sans-serif;
  background:
    radial-gradient(circle at top left,rgba(215,25,32,.16),transparent 34%),
    linear-gradient(135deg,#f7f8fa,#eceff3 48%,#f9fafb);
  color:var(--ink);
  min-height:100vh;
}
body:before{
  content:"";
  position:fixed;
  inset:0;
  pointer-events:none;
  background-image:
    linear-gradient(rgba(16,19,24,.035) 1px,transparent 1px),
    linear-gradient(90deg,rgba(16,19,24,.035) 1px,transparent 1px);
  background-size:34px 34px;
  opacity:.45;
}
button,input,select{font-family:inherit}
.container{
  max-width:620px;
  margin:54px auto;
  padding:42px;
  background:rgba(255,255,255,.92);
  border:1px solid rgba(16,19,24,.10);
  border-radius:30px;
  box-shadow:var(--shadow);
  text-align:center;
  backdrop-filter:blur(14px);
}
.brand{
  color:var(--red);
  font-size:12px;
  letter-spacing:3px;
  font-weight:950;
  text-transform:uppercase;
  margin-bottom:12px;
}
h1{
  font-size:48px;
  line-height:.98;
  margin:10px 0 14px;
  letter-spacing:-1.4px;
}
h2{font-size:28px;margin:6px 0 8px;letter-spacing:-.6px}
h3{font-size:19px;margin:10px 0 8px}
.subtitle{
  color:var(--muted);
  line-height:1.55;
  margin-bottom:24px;
}
.tabs{
  display:grid;
  grid-template-columns:1fr 1fr;
  gap:10px;
  margin-bottom:20px;
  background:#e9ecf1;
  padding:6px;
  border-radius:18px;
}
.tab{
  background:transparent;
  color:var(--ink);
  border:0;
}
.tab.active{
  background:var(--dark);
  color:white;
  box-shadow:0 10px 24px rgba(16,19,24,.15);
}
input,select{
  width:100%;
  padding:16px;
  margin:8px 0;
  border:1px solid rgba(16,19,24,.13);
  border-radius:16px;
  background:#fff;
  color:var(--ink);
  font-size:16px;
  outline:none;
}
input:focus,select:focus{
  border-color:rgba(215,25,32,.55);
  box-shadow:0 0 0 4px rgba(215,25,32,.10);
}
button{
  padding:15px 18px;
  border-radius:16px;
  font-weight:900;
  border:none;
  cursor:pointer;
  font-size:15px;
}
.primary{
  background:linear-gradient(135deg,var(--red),var(--red2));
  color:white;
  width:100%;
  margin-top:12px;
  box-shadow:0 14px 30px rgba(215,25,32,.24);
}
.secondary{
  background:white;
  color:var(--ink);
  border:1px solid rgba(16,19,24,.13);
}
.darkBtn{
  background:var(--dark);
  color:white;
  border:1px solid rgba(255,255,255,.08);
}
.msg{
  margin-top:16px;
  color:#9a3412;
  font-weight:800;
  min-height:22px;
}
.dashboard{
  max-width:1180px;
  margin:28px auto;
  padding:22px;
}
.hero,.card,.lockbox{
  background:rgba(255,255,255,.94);
  border:1px solid rgba(16,19,24,.10);
  border-radius:28px;
  padding:28px;
  margin-bottom:18px;
  box-shadow:0 18px 48px rgba(16,19,24,.10);
  backdrop-filter:blur(12px);
}
.hero{
  background:
    linear-gradient(135deg,rgba(255,255,255,.96),rgba(255,255,255,.90)),
    radial-gradient(circle at top right,rgba(215,25,32,.18),transparent 38%);
}
.grid{
  display:grid;
  grid-template-columns:repeat(auto-fit,minmax(240px,1fr));
  gap:14px;
}
.status{
  display:inline-block;
  background:rgba(22,163,74,.10);
  color:#13733a;
  border:1px solid rgba(22,163,74,.28);
  padding:9px 13px;
  border-radius:999px;
  font-size:13px;
  font-weight:950;
}
.status.locked{
  background:rgba(215,25,32,.10);
  color:#b91c1c;
  border:1px solid rgba(215,25,32,.30);
}
.small{
  color:var(--muted);
  font-size:13px;
  line-height:1.55;
}
.actions{
  display:flex;
  flex-wrap:wrap;
  gap:10px;
  margin-top:14px;
}
.actions button{min-width:150px}
.lockbox{
  max-width:750px;
  margin:60px auto;
  text-align:center;
  border-color:rgba(215,25,32,.25);
}
.modeButtonGrid{
  display:grid;
  grid-template-columns:repeat(auto-fit,minmax(220px,1fr));
  gap:12px;
  margin-top:14px;
}
.emergencyButton{
  position:fixed;
  right:22px;
  bottom:22px;
  width:88px;
  height:88px;
  border-radius:50%;
  background:linear-gradient(135deg,#b91c1c,#ef233c);
  color:white;
  font-size:20px;
  box-shadow:0 0 34px rgba(215,25,32,.45);
  z-index:50;
}
.emergencyScreen{
  position:fixed;
  inset:0;
  background:
    radial-gradient(circle at top left,rgba(215,25,32,.24),transparent 32%),
    linear-gradient(135deg,#f4f5f7,#e9ecf1);
  z-index:999;
  padding:22px;
  overflow:auto;
}
.emergencyShell{max-width:880px;margin:0 auto}
.script{
  font-size:23px;
  line-height:1.28;
  font-weight:950;
  background:rgba(215,25,32,.08);
  border:1px solid rgba(215,25,32,.22);
  border-radius:20px;
  padding:20px;
  margin-top:14px;
}
.bigAction{
  width:100%;
  padding:20px;
  font-size:20px;
  margin:10px 0;
}
.warn{
  background:rgba(217,164,65,.14);
  border:1px solid rgba(217,164,65,.32);
  color:#6b4b13;
  padding:16px;
  border-radius:18px;
  line-height:1.55;
}
.reciprocityBox{
  margin-top:14px;
  background:#f7f8fa;
  border:1px solid rgba(16,19,24,.08);
  border-radius:20px;
  padding:18px;
  color:var(--ink);
  line-height:1.55;
}
.reciprocityTitle{
  font-size:22px;
  font-weight:950;
  color:var(--ink);
  margin-bottom:10px;
}
.reciprocitySub{color:var(--muted);font-size:13px;line-height:1.45;margin:8px 0 14px}
.statePill{
  display:inline-block;
  padding:8px 10px;
  border-radius:999px;
  font-size:12px;
  font-weight:900;
  border:1px solid rgba(16,19,24,.12);
}
.green{background:rgba(22,163,74,.10);color:#13733a;border-color:rgba(22,163,74,.30)}
.yellow{background:rgba(217,119,6,.12);color:#9a3412;border-color:rgba(217,119,6,.32)}
.red{background:rgba(215,25,32,.10);color:#b91c1c;border-color:rgba(215,25,32,.30)}
.gray{background:rgba(100,116,139,.10);color:#475569;border-color:rgba(100,116,139,.22)}
.reciprocityGrid{
  display:grid;
  grid-template-columns:repeat(auto-fit,minmax(240px,1fr));
  gap:14px;
  margin-top:12px;
}
.reciprocityPanel{
  background:#fff;
  border:1px solid rgba(16,19,24,.08);
  border-radius:18px;
  padding:16px;
}
.mapGrid{
  display:grid;
  grid-template-columns:repeat(10,1fr);
  gap:7px;
  margin:18px 0;
  background:#fff;
  border:1px solid rgba(16,19,24,.08);
  border-radius:20px;
  padding:14px;
}
.mapState{
  padding:10px 5px;
  border-radius:10px;
  text-align:center;
  font-size:12px;
  font-weight:950;
  border:1px solid rgba(16,19,24,.10);
  cursor:pointer;
  user-select:none;
}
.mapState.selected{
  outline:3px solid var(--dark);
  transform:scale(1.04);
}
.mapLegend{display:flex;flex-wrap:wrap;gap:8px;margin:8px 0 14px}
.legendItem{font-size:12px;font-weight:900;padding:7px 10px;border-radius:999px;border:1px solid rgba(16,19,24,.12)}
.detailBox{
  background:#fff;
  border:1px solid rgba(16,19,24,.10);
  border-radius:20px;
  padding:18px;
  margin-top:14px;
}
.detailStatus{
  display:inline-block;
  padding:8px 12px;
  border-radius:999px;
  font-size:12px;
  font-weight:950;
  margin-bottom:10px;
}
.legalItem{
  background:#fff;
  border:1px solid rgba(16,19,24,.09);
  border-radius:20px;
  padding:20px;
  margin:14px 0;
  line-height:1.6;
}
.legalItem h3{margin-top:0;color:var(--ink)}
.legalSource{
  font-size:12px;
  color:#707887;
  margin-top:10px;
  border-top:1px solid rgba(16,19,24,.08);
  padding-top:10px;
}
.badgeRow{display:flex;flex-wrap:wrap;gap:8px;margin:12px 0}
.badge{
  display:inline-block;
  padding:8px 11px;
  border-radius:999px;
  background:#eef0f3;
  border:1px solid rgba(16,19,24,.08);
  color:#374151;
  font-size:12px;
  font-weight:900;
}
.callout{
  background:linear-gradient(135deg,#11151b,#252b36);
  color:white;
  border-radius:22px;
  padding:22px;
  margin:14px 0;
}
.callout .small{color:#d1d5db}
@media(max-width:650px){
  .container{margin:22px 14px;padding:28px}
  h1{font-size:34px}
  .dashboard{padding:14px}
  .hero,.card{padding:22px}
  .emergencyButton{width:74px;height:74px}
  .mapGrid{grid-template-columns:repeat(5,1fr)}
}
</style>
</head>
<body>
<div id="app"></div>

<script>
var token = localStorage.getItem("pd_token");
var authMode = "login";
var currentUser = null;
var selectedMapState = "";

var states = [
["AL","Alabama"],["AK","Alaska"],["AZ","Arizona"],["AR","Arkansas"],["CA","California"],["CO","Colorado"],["CT","Connecticut"],["DE","Delaware"],["FL","Florida"],["GA","Georgia"],
["HI","Hawaii"],["ID","Idaho"],["IL","Illinois"],["IN","Indiana"],["IA","Iowa"],["KS","Kansas"],["KY","Kentucky"],["LA","Louisiana"],["ME","Maine"],["MD","Maryland"],
["MA","Massachusetts"],["MI","Michigan"],["MN","Minnesota"],["MS","Mississippi"],["MO","Missouri"],["MT","Montana"],["NE","Nebraska"],["NV","Nevada"],["NH","New Hampshire"],["NJ","New Jersey"],
["NM","New Mexico"],["NY","New York"],["NC","North Carolina"],["ND","North Dakota"],["OH","Ohio"],["OK","Oklahoma"],["OR","Oregon"],["PA","Pennsylvania"],["RI","Rhode Island"],["SC","South Carolina"],
["SD","South Dakota"],["TN","Tennessee"],["TX","Utah"],["UT","Utah"],["VT","Vermont"],["VA","Virginia"],["WA","Washington"],["WV","West Virginia"],["WI","Wisconsin"],["WY","Wyoming"]
];

var mapOrder = ["WA","MT","ND","MN","WI","MI","NY","VT","NH","ME","OR","ID","SD","IA","IL","IN","OH","PA","NJ","MA","CA","NV","WY","NE","MO","KY","WV","VA","MD","CT","AK","UT","CO","KS","AR","TN","NC","SC","DE","RI","HI","AZ","NM","OK","LA","MS","AL","GA","FL","TX"];

var reciprocityData = {
  MI: {
    title: "Michigan CPL Reciprocity & Travel Guide",
    verifiedDate: "May 2, 2026",
    sourceNote: "Recognition does not mean identical laws. Follow the law of the state you are physically in.",
    recognized: ["AL","AK","AZ","AR","CO","FL","GA","ID","IN","IA","KS","KY","LA","ME","MN","MS","MO","MT","NE","NC","ND","OH","OK","PA","SD","TN","TX","UT","VA","VT","WV","WI","WY"],
    restricted: ["DE","NM","NV","SC","WA"],
    notRecognized: ["CA","CT","HI","IL","MD","MA","NJ","NY","OR","RI"],
    warnings: [
      "Recognition can depend on residency, age, permit type, and current state law.",
      "A recognized permit does not erase prohibited locations, vehicle carry rules, alcohol/location restrictions, signage/private property rules, or duty-to-inform requirements.",
      "Before travel, verify destination-state law using official state resources and at least one current reciprocity reference."
    ]
  }
};

function q(id){return document.getElementById(id)}
function setMsg(text){var msg=q("msg"); if(msg) msg.innerText=text||""}

function escapeHtml(value){
  return String(value || "")
    .replaceAll("&","&amp;")
    .replaceAll("<","&lt;")
    .replaceAll(">","&gt;")
    .replaceAll('"',"&quot;")
    .replaceAll("'","&#039;");
}

function stateName(abbr){
  var found = states.find(function(s){ return s[0] === abbr; });
  return found ? found[1] : abbr;
}

function statusClass(status){
  if(status === "recognized") return "green";
  if(status === "restricted") return "yellow";
  if(status === "not_recognized") return "red";
  return "gray";
}

function statusLabelByStatus(status){
  if(status === "recognized") return "Recognized";
  if(status === "restricted") return "Recognized with Restrictions";
  if(status === "not_recognized") return "Not Recognized";
  return "Not Yet Verified";
}

function stateStatus(permitState, travelState){
  var data = reciprocityData[permitState];
  if(!data) return "unverified";
  if(travelState === permitState) return "recognized";
  if(data.recognized.indexOf(travelState) !== -1) return "recognized";
  if(data.restricted.indexOf(travelState) !== -1) return "restricted";
  if(data.notRecognized.indexOf(travelState) !== -1) return "not_recognized";
  return "unverified";
}

function renderMap(permitState){
  return '<div class="mapLegend">' +
    '<span class="legendItem green">Recognized</span>' +
    '<span class="legendItem yellow">Recognized with Restrictions</span>' +
    '<span class="legendItem red">Not Recognized</span>' +
    '<span class="legendItem gray">Not Yet Verified</span>' +
  '</div>' +
  '<div class="mapGrid">' +
  mapOrder.map(function(abbr){
    var status = stateStatus(permitState, abbr);
    var cls = statusClass(status);
    var selected = selectedMapState === abbr ? " selected" : "";
    return '<div class="mapState ' + cls + selected + '" onclick="selectMapState(\\'' + abbr + '\\')">' + abbr + '</div>';
  }).join('') +
  '</div>';
}

function getStateDetailHtml(permitState, travelState){
  var status = stateStatus(permitState, travelState);
  var cls = statusClass(status);

  return '<div class="detailBox">' +
    '<h3>' + travelState + ' — ' + stateName(travelState) + '</h3>' +
    '<span class="detailStatus ' + cls + '">' + statusLabelByStatus(status) + '</span>' +
    '<p><b>Meaning:</b> This color is a starting point only. It does not guarantee lawful carry in every place or situation.</p>' +
    '<p><b>Check before travel:</b> permit recognition, prohibited places, vehicle carry, duty to inform, signage/private property rules, alcohol restrictions, age restrictions, magazine/ammunition rules, local restrictions, and whether your permit must be resident or nonresident.</p>' +
    '<p class="small"><b>Disclaimer:</b> Educational field reference only. Not legal advice.</p>' +
  '</div>';
}

function getReciprocityHtml(state){
  var data = reciprocityData[state];
  var selectedName = stateName(state);

  if(!selectedMapState) selectedMapState = state;

  if(!data){
    return '<div class="reciprocityTitle">' + selectedName + ' Permit Profile</div>' +
      '<p><b>Status:</b> State-specific outbound reciprocity data has not been fully verified in this app yet.</p>' +
      '<p class="reciprocitySub">This state is selectable for permit tracking. The verified reciprocity engine is being built state-by-state.</p>' +
      renderMap(state) +
      getStateDetailHtml(state, selectedMapState) +
      '<div class="warn">Before carrying outside your home state, verify destination-state recognition, prohibited locations, duty-to-inform rules, vehicle carry rules, age restrictions, permit residency requirements, and local restrictions.</div>';
  }

  return '<div class="reciprocityTitle">' + data.title + '</div>' +
    '<p><b>Selected permit:</b> ' + selectedName + '</p>' +
    '<p><b>Last reviewed:</b> ' + data.verifiedDate + '</p>' +
    '<p class="reciprocitySub">' + data.sourceNote + '</p>' +
    renderMap(state) +
    getStateDetailHtml(state, selectedMapState) +
    '<div class="reciprocityGrid">' +
      '<div class="reciprocityPanel"><h3>Recognized</h3><p class="small">' + data.recognized.length + ' states currently listed.</p></div>' +
      '<div class="reciprocityPanel"><h3>Recognized with Restrictions</h3><p class="small">' + data.restricted.length + ' states currently listed.</p></div>' +
      '<div class="reciprocityPanel"><h3>Not Recognized</h3><p class="small">' + data.notRecognized.length + ' states currently listed.</p></div>' +
    '</div>' +
    '<h3>Critical Travel Warnings</h3>' +
    data.warnings.map(function(w){ return '<p class="small">• ' + w + '</p>'; }).join('');
}

function selectMapState(abbr){
  selectedMapState = abbr;
  updateReciprocity();
}

function showAuth(){
  var isRegister = authMode === "register";
  q("app").innerHTML =
    '<div class="container">' +
      '<div class="brand">Prime Defense Training</div>' +
      '<h1>Prime Defense Protection</h1>' +
      '<p class="subtitle">Premium member-only protection dashboard for permit tracking, emergency tools, legal education, and defensive incident guidance.</p>' +
      '<div class="tabs">' +
        '<button id="loginTab" class="tab ' + (!isRegister ? 'active' : '') + '" type="button">Login</button>' +
        '<button id="registerTab" class="tab ' + (isRegister ? 'active' : '') + '" type="button">Register</button>' +
      '</div>' +
      (isRegister ? '<input id="name" placeholder="Full Name" autocomplete="name">' : '') +
      '<input id="email" placeholder="Membership Email" autocomplete="email">' +
      '<input id="password" type="password" placeholder="Password" autocomplete="' + (isRegister ? 'new-password' : 'current-password') + '">' +
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
  try{
    var res = await fetch("/api/refresh-membership",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({token:token})});
    var user = await res.json();
    if(user.accessAllowed) showDashboard(); else showLocked(user);
  }catch(e){setMsg("Unable to refresh membership.")}
}

async function openBilling(){
  setMsg("Opening billing portal...");
  try{
    var res = await fetch("/api/billing-portal",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({token:token})});
    var data = await res.json();
    if(data.url) window.location.href=data.url; else setMsg(data.error || "Unable to open billing.");
  }catch(e){setMsg("Unable to open billing.")}
}

function showLocked(user){
  user=user||{};
  q("app").innerHTML =
    '<div class="lockbox">' +
      '<div class="brand">Membership Required</div>' +
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
    selectedMapState = selectedState;

    q("app").innerHTML =
      '<div class="dashboard">' +
        '<div class="hero">' +
          '<div class="brand">Prime Defense Protection</div>' +
          '<h1>Member Dashboard</h1>' +
          '<span class="status">' + escapeHtml(user.membershipLabel) + '</span>' +
          '<p class="subtitle">Welcome' + (user.name ? ', ' + escapeHtml(user.name) : '') + '. Your premium member dashboard for permit tracking, incident tools, and Michigan legal education.</p>' +
          '<div class="badgeRow">' +
            '<span class="badge">Permit Profile</span>' +
            '<span class="badge">Reciprocity Map</span>' +
            '<span class="badge">Emergency Mode</span>' +
            '<span class="badge">Aftermath Guidance</span>' +
          '</div>' +
          '<div class="actions">' +
            '<button id="refreshBtn" class="secondary" type="button">Refresh Status</button>' +
            '<button id="logoutBtn" class="secondary" type="button">Logout</button>' +
          '</div>' +
        '</div>' +

        '<div class="card">' +
          '<div class="brand">My Permit</div>' +
          '<h2>Permit Profile & Reciprocity Map</h2>' +
          '<p class="small">Select your permit state to update your travel reference. Michigan is currently the deepest legal guide in this build.</p>' +
          '<div class="grid">' +
            '<select id="state">' + buildStateOptions(selectedState) + '</select>' +
            '<input id="issue" type="date" value="' + escapeHtml(user.issueDate || '') + '">' +
            '<input id="exp" type="date" value="' + escapeHtml(user.expirationDate || '') + '">' +
          '</div>' +
          '<div id="reciprocityBox" class="reciprocityBox"></div>' +
        '</div>' +

        '<div class="card">' +
          '<div class="brand">Michigan Legal Guide</div>' +
          '<h2>Michigan CPL & Firearms Law Field Guide</h2>' +
          '<p class="small">Expanded reference covering carry rules, prohibited places, secure storage, school zones, transport, ERPOs, civil liability exposure, and post-incident reminders. Educational only. Not legal advice.</p>' +
          '<button id="miGuideBtn" class="primary" type="button">Open Michigan Legal Guide</button>' +
        '</div>' +

        '<div class="card">' +
          '<div class="brand">Incident Modes</div>' +
          '<h2>Emergency Tools</h2>' +
          '<p class="small">Use the mode that best matches the situation. These tools are designed to help you slow down, call for help, and avoid damaging statements.</p>' +
          '<div class="modeButtonGrid">' +
            '<button id="shootingModeBtn" class="primary" type="button">Defensive Shooting</button>' +
            '<button id="displayModeBtn" class="secondary" type="button">No Shots Fired / Defensive Display</button>' +
            '<button id="aftermathBtn" class="darkBtn" type="button">Aftermath Mode</button>' +
          '</div>' +
        '</div>' +

        '<div class="card">' +
          '<div class="brand">Emergency Contact</div>' +
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
    q("state").onchange=function(){ selectedMapState = q("state").value; updateReciprocity(); };
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
  var stateEl = q("state");
  var box = q("reciprocityBox");
  if(!stateEl || !box) return;
  box.innerHTML = getReciprocityHtml(stateEl.value);
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
      title: "Quick Michigan Snapshot",
      body: [
        "<b>Concealed pistol carry:</b> Michigan generally requires a valid CPL to carry a concealed pistol.",
        "<b>Open carry:</b> Michigan generally permits open carry by a person who may lawfully possess a firearm, but locations, vehicles, intent, and eligibility matter.",
        "<b>Vehicle carry:</b> A pistol in a vehicle is a major legal dividing line. Without a CPL, transport must be treated as lawful transport, not ready-access carry.",
        "<b>Duty to disclose:</b> A CPL holder carrying concealed and stopped by a peace officer must immediately disclose that they are carrying.",
        "<b>Prohibited places:</b> Michigan has statutory pistol-free zones and separate general firearm-prohibited premises. Federal law and private policies may also apply.",
        "<b>Use of deadly force:</b> Deadly force is limited to situations where the person honestly and reasonably believes it is necessary to prevent imminent death, great bodily harm, or sexual assault."
      ],
      source: "References: Michigan Firearms Laws publication; MCL 28.425f; MCL 28.425o; MCL 750.234d; MCL 780.972."
    },
    {
      title: "CPL Basics",
      body: [
        "<b>What a Michigan CPL does:</b> It allows a qualified license holder to carry a concealed pistol, subject to Michigan law and restrictions.",
        "<b>What it does not do:</b> It does not override pistol-free zones, federal buildings, court rules, employer policies, school rules, private-property instructions, or another state’s laws.",
        "<b>Practical rule:</b> A CPL is permission under defined limits. It is not permission to carry everywhere.",
        "<b>Training note:</b> Every carry decision should answer three questions: Am I eligible? Is this location lawful? Is my method of carry lawful?"
      ],
      source: "Reference: Michigan Firearms Laws publication."
    },
    {
      title: "Duty to Disclose During Police Contact",
      body: [
        "<b>Core rule:</b> If you are carrying concealed under a CPL and are stopped by a peace officer, disclose immediately.",
        "<b>Recommended wording:</b> Officer, I have a CPL and I am currently carrying. How would you like me to proceed?",
        "<b>Hands:</b> Keep your hands visible. Do not reach for your firearm, wallet, purse, center console, glove box, or documents until instructed.",
        "<b>Common mistake:</b> Waiting until later in the stop because you think the officer already knows. Do not assume.",
        "<b>Training note:</b> Disclosure should be calm, early, and simple."
      ],
      source: "Reference: MCL 28.425f."
    },
    {
      title: "Pistol-Free Zones / Concealed Carry Restricted Premises",
      body: [
        "<b>Core rule:</b> MCL 28.425o lists places where a CPL holder generally may not carry a concealed pistol, subject to statutory exceptions and exact wording.",
        "<b>Common categories:</b> Schools and school property, public or private child care centers, sports arenas or stadiums, certain bars/taverns, places of worship unless allowed by the presiding official, certain entertainment facilities, hospitals, and college/university dormitories or classrooms.",
        "<b>Important nuance:</b> Do not rely on shorthand lists. Exact statutory definitions matter.",
        "<b>Separate issue:</b> A pistol-free zone, private no-firearm sign, workplace policy, school policy, federal restriction, and court rule are not all the same thing.",
        "<b>Training note:</b> If the location is sensitive, close-call, emotional, crowded, alcohol-related, school-related, government-related, or security-controlled, slow down and verify before entering."
      ],
      source: "Reference: MCL 28.425o."
    },
    {
      title: "General Firearm-Prohibited Premises",
      body: [
        "<b>Core issue:</b> Michigan also has general firearm-prohibited premises under MCL 750.234d. This can matter even when the discussion is not strictly about concealed carry.",
        "<b>Examples under this framework:</b> Certain financial institutions, churches or houses of religious worship, courts, theatres, sports arenas, day care centers, hospitals, and establishments licensed under the Michigan Liquor Control Code, subject to statutory language and exceptions.",
        "<b>Election-related expansion:</b> Michigan law has also addressed firearms at polling places, early voting sites, absentee ballot drop box locations, certain clerk offices, and absent voter counting locations.",
        "<b>Training note:</b> Do not assume a CPL automatically solves general prohibited-premises rules."
      ],
      source: "References: MCL 750.234d; MSP Legal Update No. 163."
    },
    {
      title: "Secure Storage / Child Access",
      body: [
        "<b>Core principle:</b> Firearms must be secured from unauthorized access, especially minors.",
        "<b>High-risk places:</b> Vehicles, nightstands, backpacks, purses, range bags, closets, bedside tables, garages, and unlocked cases.",
        "<b>Practical rule:</b> If the firearm is unattended, ask whether a child, visitor, prohibited person, roommate, worker, or thief could access it.",
        "<b>Vehicle warning:</b> A vehicle is not a safe by itself. Theft from vehicles is one of the most predictable ways firearms enter criminal circulation.",
        "<b>Training note:</b> Responsible defensive ownership requires two goals at the same time: fast lawful access for the authorized adult and reliable denial of access to everyone else."
      ],
      source: "Reference framework: Michigan secure-storage and firearms safety laws."
    },
    {
      title: "EMD / Stun Gun Disclosure",
      body: [
        "<b>Core issue:</b> Michigan law treats electro-muscular disruption devices, commonly called EMDs or stun guns, differently than ordinary defensive tools.",
        "<b>Disclosure warning:</b> If you are carrying an EMD under authority of a CPL or other lawful framework and are stopped by law enforcement, disclosure obligations may apply.",
        "<b>Practical wording:</b> Officer, I have a CPL and I am carrying an electronic defensive device. How would you like me to proceed?",
        "<b>Training note:</b> Do not assume that because it is less lethal it is legally casual. Possession, carry method, disclosure, prohibited locations, and use-of-force rules still matter."
      ],
      source: "Reference framework: Michigan EMD/stun gun statutes and CPL disclosure principles."
    },
    {
      title: "Casinos",
      body: [
        "<b>Core warning:</b> Casinos are high-risk environments for armed citizens because of private property rules, gaming regulations, alcohol, security screening, and tribal or federal issues depending on the property.",
        "<b>Practical rule:</b> Do not assume your CPL authorizes carry in a casino. Check the specific property, ownership, posted rules, gaming commission rules, tribal rules if applicable, and any law-enforcement/security direction.",
        "<b>Risk factors:</b> Alcohol, money disputes, crowds, surveillance, and armed security can make any incident more legally complex.",
        "<b>Training note:</b> If a property prohibits weapons and you are discovered, leave immediately and calmly when instructed."
      ],
      source: "Reference framework: Michigan premises law, private property rights, and federal/tribal considerations."
    },
    {
      title: "Federal Buildings / Post Offices",
      body: [
        "<b>Core rule:</b> Federal property can be controlled by federal law, not just Michigan law.",
        "<b>Post office warning:</b> Do not assume that a Michigan CPL allows carry inside a post office or on postal property. Postal property is a classic high-risk federal-location issue.",
        "<b>Federal buildings:</b> Courthouses, agency buildings, federal offices, secure federal facilities, and posted federal properties may be restricted even if state law otherwise allows carry.",
        "<b>Training note:</b> If the property is federal, stop relying on state carry summaries and verify federal law and posted instructions."
      ],
      source: "Reference framework: Federal facility and postal property restrictions."
    },
    {
      title: "Schools & School Zones Nuance",
      body: [
        "<b>High-risk area:</b> Schools, school property, and weapon-free school zones are among the most legally sensitive firearm locations.",
        "<b>Michigan law:</b> MCL 28.425o and MCL 750.237a both matter. One deals with CPL prohibited premises and the other addresses weapon-free school zones.",
        "<b>Nuance:</b> School property can include more than the building. Vehicles used by a school and property used for school purposes may matter depending on the statute.",
        "<b>Parent pickup/drop-off:</b> Do not rely on casual advice. Read the exact statute and exceptions before making decisions involving school property.",
        "<b>Training note:</b> School mistakes can create criminal exposure, CPL consequences, employment consequences, family-court consequences, and major public scrutiny."
      ],
      source: "References: MCL 28.425o; MCL 750.237a."
    },
    {
      title: "Transport Without CPL",
      body: [
        "<b>Core rule:</b> Without a CPL, do not treat a pistol in a vehicle as carry. Treat it as lawful transport only.",
        "<b>Practical transport method:</b> The pistol should generally be unloaded, secured, inaccessible, and transported only for lawful purposes such as going to or from a range, repair, purchase, sale, hunting-related lawful activity, or another lawful destination.",
        "<b>Common mistake:</b> Open carrying on foot and then getting into a vehicle with the pistol accessible.",
        "<b>Training note:</b> The moment you enter a vehicle, the legal analysis changes. Vehicle possession is one of the easiest ways for a lawful owner to make a serious mistake."
      ],
      source: "Reference: Michigan Firearms Laws publication."
    },
    {
      title: "Prohibited Persons / Domestic Violence / PPOs",
      body: [
        "<b>Core issue:</b> Not everyone who owns or wants a firearm is legally allowed to possess one.",
        "<b>Disqualifiers may include:</b> Certain felony convictions, certain misdemeanor convictions, domestic violence-related prohibitions, mental health adjudications, court orders, bond conditions, probation/parole restrictions, and protection orders.",
        "<b>PPO warning:</b> A personal protection order or court order can create serious possession and carry restrictions. Read the order and speak with counsel.",
        "<b>Domestic violence warning:</b> Domestic violence-related cases can trigger both state and federal restrictions.",
        "<b>Training note:</b> If there is a pending case, court order, PPO, domestic dispute, bond condition, or prior conviction, do not guess. Get legal guidance before possessing or carrying."
      ],
      source: "Reference framework: Michigan and federal prohibited-person laws."
    },
    {
      title: "ERPO / Red Flag Orders",
      body: [
        "<b>Core issue:</b> Michigan has an Extreme Risk Protection Order framework commonly called ERPO or red flag law.",
        "<b>Practical effect:</b> An ERPO can affect firearm possession and may require surrender or removal of firearms under court order.",
        "<b>Warning:</b> Violating an order can create serious criminal exposure and long-term firearm-rights consequences.",
        "<b>Training note:</b> If served with any court order involving firearms, do not argue at the door, hide property, transfer property casually, or post about it online. Contact qualified legal counsel immediately."
      ],
      source: "Reference framework: Michigan Extreme Risk Protection Order laws."
    },
    {
      title: "Purchase / Registration Basics",
      body: [
        "<b>Core issue:</b> Michigan pistol acquisition has paperwork and record requirements. The process can differ depending on whether the person has a CPL, the type of transaction, and where the pistol is obtained.",
        "<b>Practical rule:</b> Keep copies of purchase records, sales records, registration paperwork, and transfer documents organized.",
        "<b>Private transfer warning:</b> Do not assume a casual private sale is legally complete just because money changed hands.",
        "<b>Training note:</b> If you buy, sell, inherit, gift, or transfer a pistol, slow down and verify the required Michigan process before the transfer."
      ],
      source: "Reference: Michigan Firearms Laws publication."
    },
    {
      title: "Civil Liability / Wrongful Death Exposure",
      body: [
        "<b>Core warning:</b> Even when no criminal charge is filed, a defensive incident can still trigger civil claims.",
        "<b>Possible exposure:</b> Lawsuits may involve wrongful death, personal injury, negligence, emotional distress, property damage, or claims from the attacker’s family.",
        "<b>Michigan Self-Defense Act:</b> Michigan law includes civil-liability protection language in qualifying lawful self-defense situations, but whether it applies depends on the facts.",
        "<b>Training note:</b> Lawful self-defense is not just a trigger-pull decision. Your actions before, during, and after the incident may all be examined."
      ],
      source: "References: MCL 780.972; MCL 600.2922."
    },
    {
      title: "Hunting / DNR Context",
      body: [
        "<b>Core issue:</b> Hunting, public land, state land, DNR rules, species seasons, transport rules, and firearm-type rules can all affect what is lawful.",
        "<b>CPL warning:</b> A CPL does not replace hunting laws, game laws, DNR regulations, trespass rules, or public-land restrictions.",
        "<b>Transport warning:</b> Long guns, pistols, loaded firearms, vehicles, ORVs, boats, and hunting activity may have separate rules.",
        "<b>Training note:</b> If your carry or transport occurs during hunting, scouting, camping, boating, ORV use, or public-land activity, verify DNR rules in addition to CPL law."
      ],
      source: "Reference framework: Michigan DNR and firearms transport/hunting rules."
    },
    {
      title: "Open Carry",
      body: [
        "<b>Plain English:</b> Michigan generally permits open carry by people who may lawfully possess firearms, but important limits apply.",
        "<b>CPL impact:</b> A CPL holder may have different options than a non-CPL holder, especially regarding vehicle carry and certain locations.",
        "<b>Private property:</b> A property owner or authorized agent may prohibit weapons and require you to leave.",
        "<b>Common mistake:</b> Thinking 'open carry is legal' answers every question. Location, intent, vehicle status, concealment, and eligibility still matter.",
        "<b>Training note:</b> Open carry can increase police contacts, public complaints, and social friction even when lawful."
      ],
      source: "Reference framework: Michigan Firearms Laws publication and MSP legal guidance."
    },
    {
      title: "Private Property & No-Firearm Signs",
      body: [
        "<b>Plain English:</b> A private no-firearm sign is not always the same as a statutory pistol-free zone, but it still matters.",
        "<b>Practical effect:</b> A property owner, manager, employee, or authorized agent may direct you to leave. Refusing can create trespass exposure.",
        "<b>Best response:</b> Do not argue with staff or security. Leave calmly.",
        "<b>Training note:</b> Being technically right is not useful if the situation escalates into a trespass complaint, police contact, or public confrontation."
      ],
      source: "Reference framework: Michigan private-property and trespass principles."
    },
    {
      title: "Bars, Restaurants & Alcohol",
      body: [
        "<b>Core issue:</b> Michigan prohibited-premises law includes alcohol-related location restrictions, including bars/taverns where alcohol sales by the glass are the primary source of income.",
        "<b>Practical warning:</b> Do not guess whether a location is legally a restaurant or bar for CPL purposes.",
        "<b>Behavior warning:</b> Alcohol, crowds, emotion, and firearms create high legal risk.",
        "<b>Training note:</b> The safer lifestyle rule is simple: if alcohol is a central part of the environment, strongly reconsider being armed there."
      ],
      source: "Reference: MCL 28.425o."
    },
    {
      title: "Places of Worship",
      body: [
        "<b>Core issue:</b> Michigan law includes places of worship in prohibited-premises analysis unless permission is granted by the proper authority.",
        "<b>Practical rule:</b> Permission matters. Do not assume you can carry because you are a member, volunteer, usher, or safety-team participant.",
        "<b>Best practice:</b> Get written authorization, written policy, defined role, team training, and clear communication with leadership.",
        "<b>Training note:</b> Church safety work needs legal clarity, not informal hallway permission."
      ],
      source: "Reference: MCL 28.425o."
    },
    {
      title: "Hospitals & Medical Facilities",
      body: [
        "<b>Core issue:</b> Hospitals are specifically sensitive under Michigan prohibited-premises law.",
        "<b>Practical warning:</b> Medical emergencies do not automatically erase carry restrictions.",
        "<b>Private policy:</b> Medical facilities may also have security policies, signage, screening, and police/security procedures.",
        "<b>Training note:</b> Plan ahead for appointments, ER visits, and family emergencies."
      ],
      source: "Reference: MCL 28.425o."
    },
    {
      title: "Brandishing / Improper Display",
      body: [
        "<b>Core concept:</b> Displaying or exposing a firearm can become legally dangerous if it appears threatening, angry, careless, or unnecessary.",
        "<b>Defensive display:</b> Display may be defensible only when the facts support an immediate defensive need.",
        "<b>Bad explanation:</b> I showed him my gun to scare him. That can sound like intimidation rather than lawful defense.",
        "<b>Training note:</b> If the firearm comes out, you should be able to explain the immediate threat that made the display necessary."
      ],
      source: "Reference framework: Michigan brandishing and defensive-use principles."
    },
    {
      title: "Use of Force / Deadly Force",
      body: [
        "<b>Core standard:</b> Deadly force may be justified only when a person honestly and reasonably believes it is necessary to prevent imminent death, great bodily harm, or sexual assault.",
        "<b>Honest belief:</b> You genuinely believed the danger was real.",
        "<b>Reasonable belief:</b> A reasonable person in the same circumstances would likely understand the danger similarly.",
        "<b>Imminent threat:</b> The danger must be happening now or immediately about to happen.",
        "<b>Necessity:</b> Deadly force must be necessary to stop the threat. It is not punishment, warning, revenge, control, or intimidation.",
        "<b>Property warning:</b> Deadly force is not justified merely to protect property.",
        "<b>Training note:</b> The legal question is not simply whether you were afraid. The question is whether the facts support an honest and reasonable belief that deadly force was immediately necessary."
      ],
      source: "Reference: MCL 780.972."
    },
    {
      title: "Defense of Others",
      body: [
        "<b>Core rule:</b> Michigan law can allow force in defense of another person under the same basic necessity and reasonableness framework.",
        "<b>Important:</b> The threshold is not lower because another person is involved.",
        "<b>High-risk mistake:</b> Intervening in a third-party fight without knowing who started it, who escalated it, or whether the person you are defending is actually the aggressor.",
        "<b>Training note:</b> Defense of others is tactically and legally dangerous because you may not know the whole story."
      ],
      source: "Reference: MCL 780.972."
    },
    {
      title: "Stand Your Ground / No Duty to Retreat",
      body: [
        "<b>Plain English:</b> Michigan law may remove a duty to retreat in qualifying lawful self-defense situations.",
        "<b>Important limitation:</b> No duty to retreat does not mean permission to escalate, chase, re-engage, provoke, threaten, or use force over pride or property.",
        "<b>Training note:</b> Avoidance can still help show reasonableness. Leaving safely is often tactically and legally smarter than staying to prove a point."
      ],
      source: "Reference framework: Michigan Self-Defense Act."
    },
    {
      title: "Attorney / Contact-After-Incident Reminders",
      body: [
        "<b>First:</b> Get safe. Call 911. Request police and medical.",
        "<b>Second:</b> Call your legal-defense support/attorney contact as soon as practical after emergency help is coming.",
        "<b>Third:</b> Contact one trusted family member only if safe and appropriate.",
        "<b>Do not:</b> Post online, text multiple people, call friends to explain, argue with bystanders, speak to media, or repeatedly retell the story.",
        "<b>Family wording:</b> I was involved in a defensive incident. I am safe. Please do not discuss this with anyone. I am waiting for legal guidance.",
        "<b>Training note:</b> After an incident, your words can become evidence. Keep communications short, factual, and rights-protecting."
      ],
      source: "Training reference: Prime Defense aftermath protocol."
    },
    {
      title: "Common Legal Pitfalls",
      body: [
        "• Carrying in a prohibited location.",
        "• Failing to immediately disclose during police contact.",
        "• Mishandling pistol transport in a vehicle.",
        "• Displaying a firearm during an argument.",
        "• Intervening in someone else’s fight without knowing who the aggressor is.",
        "• Using or threatening deadly force over property.",
        "• Carrying while subject to a court order, PPO, bond condition, or disqualifying conviction.",
        "• Ignoring school-zone nuance.",
        "• Talking too much after a defensive incident.",
        "• Posting online after an incident."
      ],
      source: "Training reference: Prime Defense legal-risk framework."
    },
    {
      title: "Final Disclaimer",
      body: [
        "This guide is educational information only. It is not legal advice, does not create an attorney-client relationship, and should not be treated as a substitute for current statutes, official guidance, or qualified legal counsel.",
        "Firearms law changes. Court rulings change. Agency guidance changes. Private policies change. Always verify current law before relying on any legal summary."
      ],
      source: ""
    }
  ];

  var html = '<div class="dashboard">' +
    '<div class="hero">' +
      '<div class="brand">Michigan Legal Guide</div>' +
      '<h1>Michigan CPL Field Guide</h1>' +
      '<p class="subtitle">Expanded legal education built for practical decision-making before, during, and after a defensive incident. Educational only. Not legal advice.</p>' +
      '<div class="actions">' +
        '<button class="secondary" type="button" onclick="showDashboard()">Back to Dashboard</button>' +
        '<button class="primary" type="button" onclick="openEmergency()">Emergency Mode</button>' +
      '</div>' +
    '</div>' +
    '<div class="callout">' +
      '<div class="brand">Premium Member Reference</div>' +
      '<h2>Slow Down. Verify. Make Better Decisions.</h2>' +
      '<p class="small">This guide is intentionally detailed because real-world carry decisions are rarely answered by one sentence. Location, conduct, eligibility, method of carry, and post-incident behavior all matter.</p>' +
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
        '<div class="brand">Prime Defense Protection Member</div>' +
        '<h1>Emergency Mode — Defensive Shooting</h1>' +
        '<div class="card">' +
          '<div class="brand">Step 1 — Call 911</div>' +
          '<div class="script">“I was attacked, feared for my life, and had to defend myself. Please send both police and an ambulance to this location.”</div>' +
          '<button class="primary bigAction" type="button" onclick="window.location.href=\\'tel:911\\'">CALL 911</button>' +
          '<div class="warn">Secondary wording: “There has been a self-defense shooting at this location. Send help.” Provide only necessary information and follow dispatcher instructions.</div>' +
        '</div>' +
        '<div class="card">' +
          '<div class="brand">Step 2 — Call USCCA</div>' +
          '<p class="small">Contact the USCCA Critical Response Team after calling 911.</p>' +
          '<button class="primary bigAction" type="button" onclick="window.location.href=\\'tel:8776771919\\'">CALL USCCA</button>' +
        '</div>' +
        '<div class="card">' +
          '<div class="brand">Step 3 — Contact Family</div>' +
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
        '<div class="brand">No Shots Fired</div>' +
        '<h1>Defensive Display Mode</h1>' +
        '<div class="card">' +
          '<div class="brand">Step 1 — Call 911</div>' +
          '<div class="script">“My name is [name], and I need to report an attack or possible attack at this location. I have a permit to carry and exposed my defensive tool, but I did not fire.”</div>' +
          '<button class="primary bigAction" type="button" onclick="window.location.href=\\'tel:911\\'">CALL 911</button>' +
        '</div>' +
        '<div class="card">' +
          '<div class="brand">Suspect Information</div>' +
          '<p class="small">Give only necessary details: clothing, physical description, direction of travel, vehicle description, license plate if safely known, and whether they ran off or drove off.</p>' +
          '<div class="script">“The attacker was wearing [description] and ran/drove [direction]. I am not going to say another word until my attorney is present.”</div>' +
        '</div>' +
        '<div class="card">' +
          '<div class="brand">Step 2 — Call USCCA</div>' +
          '<button class="primary bigAction" type="button" onclick="window.location.href=\\'tel:8776771919\\'">CALL USCCA</button>' +
        '</div>' +
        '<div class="card">' +
          '<div class="brand">Important</div>' +
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
        '<div class="brand">Post-Incident Guidance</div>' +
        '<h1>Aftermath Mode</h1>' +

        '<div class="card">' +
          '<div class="brand">When Police Arrive</div>' +
          '<div class="script">Hands high and clearly visible. Do not move unless told. Do not resist, twitch, argue, or make sudden movements. Comply with all commands immediately.</div>' +
          '<div class="warn">Be prepared to be treated like a suspect at first. Officers may not know who the victim is, who the attacker is, or whether the threat is over.</div>' +
        '</div>' +

        '<div class="card">' +
          '<div class="brand">Four-Part Statement</div>' +
          '<p class="small">Say only what is necessary to identify the threat, evidence, witnesses, and your request for counsel.</p>' +
          '<div class="script">1. “I was attacked by that person.” or “The person who attacked me ran that direction.”</div>' +
          '<div class="script">2. “That is the evidence / weapon / object used as a weapon.”</div>' +
          '<div class="script">3. “That person, and those people, were witnesses.”</div>' +
          '<div class="script">4. “I have spoken with, or left a message with, my attorney. I am not saying another word or signing anything until my attorney is present.”</div>' +
        '</div>' +

        '<div class="card">' +
          '<div class="brand">What Not To Do</div>' +
          '<p class="small">• Do not give a detailed statement under stress.</p>' +
          '<p class="small">• Do not speculate, guess, exaggerate, or fill in blanks.</p>' +
          '<p class="small">• Do not argue with officers.</p>' +
          '<p class="small">• Do not talk to media, bystanders, or uninvolved people.</p>' +
          '<p class="small">• Do not post online.</p>' +
          '<p class="small">• Do not sign anything without legal guidance.</p>' +
        '</div>' +

        '<div class="card">' +
          '<div class="brand">Stop Talking</div>' +
          '<div class="warn">After the four-part statement, stop talking. Your body may be flooded with adrenaline. Details can be incomplete, distorted, or misunderstood. Protect your rights and wait for counsel.</div>' +
        '</div>' +

        '<div class="card">' +
          '<div class="brand">Next Steps</div>' +
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

app.get("/", (req, res) => res.send(html));
app.use((req, res) => res.send(html));

app.listen(PORT, () => console.log("Running on port " + PORT));
