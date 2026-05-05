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

  const priority = ["active", "trialing", "past_due", "unpaid", "incomplete", "canceled"];

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
  max-width:1260px;
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
.reciprocitySub{
  color:var(--muted);
  font-size:13px;
  line-height:1.45;
  margin:8px 0 14px;
}
.green{background:rgba(22,163,74,.10);color:#13733a;border-color:rgba(22,163,74,.30)}
.yellow{background:rgba(217,119,6,.12);color:#9a3412;border-color:rgba(217,119,6,.32)}
.red{background:rgba(215,25,32,.10);color:#b91c1c;border-color:rgba(215,25,32,.30)}
.gray{background:rgba(100,116,139,.10);color:#475569;border-color:rgba(100,116,139,.22)}

.mapShell{
  display:grid;
  grid-template-columns:minmax(360px,1fr) minmax(460px,1.15fr);
  gap:18px;
  align-items:start;
}
.mapPanel{
  background:#fff;
  border:1px solid rgba(16,19,24,.10);
  border-radius:24px;
  padding:18px;
  position:sticky;
  top:18px;
}
.mapSvg{
  width:100%;
  height:auto;
  background:linear-gradient(135deg,#f9fafb,#eef1f5);
  border:1px solid rgba(16,19,24,.08);
  border-radius:20px;
  overflow:hidden;
  display:block;
}
.mapCell{
  cursor:pointer;
  stroke:#ffffff;
  stroke-width:1.4;
  vector-effect:non-scaling-stroke;
  transition:.12s ease;
}
.mapCell:hover{filter:brightness(.93) drop-shadow(0 2px 4px rgba(16,19,24,.20));}
.mapCell.selected{stroke:#11151b;stroke-width:3;filter:url(#stateShadow);}
.mapText{
  pointer-events:none;
  font-weight:950;
  fill:#11151b;
  text-anchor:middle;
  dominant-baseline:middle;
  paint-order:stroke;
  stroke:#ffffff;
  stroke-width:3px;
  stroke-linejoin:round;
}
.mapLegend{
  display:flex;
  flex-wrap:wrap;
  gap:8px;
  margin:8px 0 14px;
}

.permitEngineCard{
  background:linear-gradient(135deg,#ffffff,#f7f8fa);
  border:1px solid rgba(16,19,24,.10);
  border-radius:18px;
  padding:14px;
  margin:10px 0 14px;
}
.permitEngineCard h3{margin:0 0 6px;font-size:16px}
.permitEngineStats{display:grid;grid-template-columns:repeat(4,1fr);gap:8px;margin-top:10px}
.permitEngineStat{border:1px solid rgba(16,19,24,.08);border-radius:14px;padding:10px;background:#fff;text-align:center}
.permitEngineStat b{display:block;font-size:18px;color:#11151b}
.permitEngineStat span{display:block;font-size:11px;font-weight:900;color:#626975;text-transform:uppercase}
@media(max-width:650px){.permitEngineStats{grid-template-columns:repeat(2,1fr)}}
.legendItem{
  font-size:12px;
  font-weight:900;
  padding:7px 10px;
  border-radius:999px;
  border:1px solid rgba(16,19,24,.12);
}
.detailBox,.legalItem{
  background:#fff;
  border:1px solid rgba(16,19,24,.10);
  border-radius:20px;
  padding:18px;
  margin-top:14px;
}
.legalItem{
  padding:20px;
  margin:14px 0;
  line-height:1.6;
}
.detailStatus,.lawPill{
  display:inline-block;
  padding:8px 12px;
  border-radius:999px;
  font-size:12px;
  font-weight:950;
  margin:4px 6px 8px 0;
}
.legalSource{
  font-size:12px;
  color:#707887;
  margin-top:10px;
  border-top:1px solid rgba(16,19,24,.08);
  padding-top:10px;
}
.badgeRow{
  display:flex;
  flex-wrap:wrap;
  gap:8px;
  margin:12px 0;
}
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
.profileGrid{
  display:grid;
  grid-template-columns:repeat(auto-fit,minmax(230px,1fr));
  gap:12px;
}
.miniPanel{
  background:#fff;
  border:1px solid rgba(16,19,24,.08);
  border-radius:18px;
  padding:16px;
}
.scenario{
  border-left:5px solid var(--red);
  background:#fff;
  border-radius:16px;
  padding:16px;
  margin:12px 0;
  border-top:1px solid rgba(16,19,24,.08);
  border-right:1px solid rgba(16,19,24,.08);
  border-bottom:1px solid rgba(16,19,24,.08);
}

.intelBanner{
  background:linear-gradient(135deg,#11151b,#252b36);
  color:#fff;
  border-radius:22px;
  padding:22px;
  margin-bottom:14px;
  box-shadow:0 16px 42px rgba(16,19,24,.18);
}
.intelBanner h3{color:#fff;margin:0 0 8px;font-size:24px}
.intelBanner p{color:#e5e7eb;margin:8px 0;line-height:1.5}
.intelGrid{
  display:grid;
  grid-template-columns:repeat(auto-fit,minmax(210px,1fr));
  gap:10px;
  margin-top:14px;
}
.intelTile{
  background:rgba(255,255,255,.08);
  border:1px solid rgba(255,255,255,.13);
  border-radius:16px;
  padding:13px;
}
.intelTile b{display:block;color:#fff;margin-bottom:5px;font-size:13px}
.intelTile span{display:block;color:#d1d5db;font-size:12px;line-height:1.4}
.riskStack{
  display:grid;
  grid-template-columns:repeat(auto-fit,minmax(230px,1fr));
  gap:10px;
  margin:12px 0;
}
.riskCard{
  background:#fff;
  border:1px solid rgba(16,19,24,.10);
  border-radius:18px;
  padding:15px;
  box-shadow:0 8px 24px rgba(16,19,24,.06);
}
.riskCard strong{display:block;margin-bottom:6px;color:#11151b}
.riskCard p{margin:0;color:#626975;font-size:13px;line-height:1.45}
.jumpNav{
  display:flex;
  flex-wrap:wrap;
  gap:8px;
  margin:14px 0 6px;
}
.jumpNav button{
  padding:9px 12px;
  border-radius:999px;
  font-size:12px;
  background:#fff;
  border:1px solid rgba(16,19,24,.12);
  color:#11151b;
}
.sectionHeader{
  margin-top:22px;
  padding:14px 16px;
  border-radius:18px;
  background:#eef0f3;
  border:1px solid rgba(16,19,24,.08);
}
.sectionHeader h3{margin:0;color:#11151b}
.sectionHeader p{margin:5px 0 0;color:#626975;font-size:13px}
.legalItem.critical{border-left:5px solid #d71920}
.legalItem.vehicle{border-left:5px solid #d97706}
.legalItem.police{border-left:5px solid #2563eb}
.legalItem.property{border-left:5px solid #64748b}
.legalItem.force{border-left:5px solid #7c3aed}

@media(max-width:950px){
  .mapShell{grid-template-columns:1fr}
  .mapPanel{position:static}
}
@media(max-width:650px){
  .container{margin:22px 14px;padding:28px}
  h1{font-size:34px}
  .dashboard{padding:14px}
  .hero,.card{padding:22px}
  .emergencyButton{width:74px;height:74px}
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
  ["AL","Alabama"],["AK","Alaska"],["AZ","Arizona"],["AR","Arkansas"],["CA","California"],
  ["CO","Colorado"],["CT","Connecticut"],["DE","Delaware"],["FL","Florida"],["GA","Georgia"],
  ["HI","Hawaii"],["ID","Idaho"],["IL","Illinois"],["IN","Indiana"],["IA","Iowa"],
  ["KS","Kansas"],["KY","Kentucky"],["LA","Louisiana"],["ME","Maine"],["MD","Maryland"],
  ["MA","Massachusetts"],["MI","Michigan"],["MN","Minnesota"],["MS","Mississippi"],["MO","Missouri"],
  ["MT","Montana"],["NE","Nebraska"],["NV","Nevada"],["NH","New Hampshire"],["NJ","New Jersey"],
  ["NM","New Mexico"],["NY","New York"],["NC","North Carolina"],["ND","North Dakota"],["OH","Ohio"],
  ["OK","Oklahoma"],["OR","Oregon"],["PA","Pennsylvania"],["RI","Rhode Island"],["SC","South Carolina"],
  ["SD","South Dakota"],["TN","Tennessee"],["TX","Texas"],["UT","Utah"],["VT","Vermont"],
  ["VA","Virginia"],["WA","Washington"],["WV","West Virginia"],["WI","Wisconsin"],["WY","Wyoming"]
];

var mapCells = [
  ["WA",0,1],["MT",1,1],["ND",2,1],["MN",3,1],["WI",4,1],["MI",5,1],["NY",7,1],["VT",8,1],["NH",9,1],["ME",10,1],
  ["OR",0,2],["ID",1,2],["SD",2,2],["IA",3,2],["IL",4,2],["IN",5,2],["OH",6,2],["PA",7,2],["NJ",8,2],["MA",9,2],
  ["CA",0,3],["NV",1,3],["WY",2,3],["NE",3,3],["MO",4,3],["KY",5,3],["WV",6,3],["VA",7,3],["MD",8,3],["CT",9,3],
  ["AK",0,5],["UT",1,4],["CO",2,4],["KS",3,4],["AR",4,4],["TN",5,4],["NC",6,4],["SC",7,4],["DE",8,4],["RI",9,4],
  ["HI",1,6],["AZ",1,5],["NM",2,5],["OK",3,5],["LA",4,5],["MS",5,5],["AL",6,5],["GA",7,5],["FL",8,6],["TX",3,6]
];

// Embedded real geographic state-shape paths generated from U.S. county/state boundary data.
// These are inline so the app does not depend on an external map library or CDN.
var realStatePaths = {"AK":"M160.2,584.5L156.1,585.0L156.8,583.2L155.9,583.0L152.6,587.1L151.2,584.8L151.3,587.4L148.8,586.0L149.3,587.2L147.7,588.1L148.9,589.2L147.7,588.4L141.0,589.6L143.2,586.4L147.3,586.1L148.0,587.5L148.3,585.8L151.7,584.5L155.2,581.0L159.1,580.6L158.4,581.2L159.2,582.5L159.4,581.5L161.4,582.5L160.3,580.8L161.5,578.7L167.8,574.8L168.5,575.6L169.9,572.2L173.1,570.8L173.6,564.2L176.0,560.0L171.2,562.4L169.9,560.9L171.5,559.4L170.6,559.1L168.5,563.9L166.0,559.7L164.8,560.8L163.3,558.5L157.7,561.7L156.2,560.8L157.8,560.0L157.2,556.4L158.7,554.8L156.6,548.7L158.0,546.3L156.2,548.9L156.2,550.8L151.8,551.7L150.2,551.1L147.3,546.2L148.0,545.6L146.5,545.5L149.0,541.6L146.5,541.1L146.4,538.2L145.1,537.5L145.4,536.3L146.5,536.9L145.7,535.7L147.4,535.6L147.3,534.0L151.1,530.8L153.0,526.5L157.0,528.3L160.2,525.1L163.9,525.8L165.4,523.5L165.0,520.5L163.4,519.1L166.0,517.1L164.9,515.5L159.4,519.2L158.5,516.8L158.3,518.5L156.4,516.9L152.5,517.4L148.5,515.2L147.6,511.3L149.5,510.5L144.7,506.9L156.9,502.2L158.4,502.4L159.2,502.7L158.2,502.4L157.3,505.2L158.2,506.2L163.8,507.3L165.1,505.7L166.5,506.0L165.1,504.7L163.8,505.5L164.1,503.7L162.3,501.0L163.3,500.5L165.1,504.3L165.8,503.8L164.3,502.2L165.5,500.4L159.5,498.7L158.8,494.9L152.3,488.5L153.8,488.0L154.7,484.9L159.9,485.4L161.7,484.5L167.3,476.5L170.0,476.5L174.5,473.0L174.1,473.8L177.7,473.4L181.0,470.0L183.3,471.4L182.3,473.9L184.6,471.6L186.7,474.3L189.0,473.2L191.4,473.7L191.0,475.3L192.8,475.7L192.4,476.6L198.4,475.7L203.1,477.6L207.7,477.4L210.1,478.5L213.4,476.6L220.5,479.1L233.8,545.9L237.5,546.1L240.4,544.1L240.5,546.1L247.6,550.8L248.5,553.1L250.6,550.7L251.5,550.4L251.8,546.8L254.2,544.8L255.3,545.3L257.1,547.9L264.6,552.2L274.6,562.9L282.4,563.9L285.0,569.4L283.7,574.3L281.7,572.9L281.6,572.3L282.4,571.9L282.6,571.7L282.5,571.5L281.1,572.0L282.2,570.2L278.7,565.7L278.0,566.6L280.6,568.7L280.6,571.7L280.0,570.4L279.5,571.6L277.3,570.9L277.8,569.9L277.1,568.7L277.8,568.1L277.0,567.2L276.1,568.1L276.7,570.7L275.6,570.4L275.4,565.6L274.5,566.4L274.5,568.8L272.8,567.9L272.5,565.7L273.8,566.3L272.7,564.4L273.8,564.8L272.7,563.1L271.6,563.1L272.0,562.1L270.5,562.5L269.7,560.8L266.7,561.1L267.6,559.8L265.2,557.5L267.3,557.7L263.0,555.5L262.5,553.5L262.3,554.6L260.4,554.8L255.3,547.1L256.2,549.7L255.1,548.9L259.0,555.7L257.1,554.6L255.4,555.3L253.5,551.3L253.5,553.0L252.0,551.8L250.1,551.6L250.2,553.1L252.1,552.7L254.7,554.8L253.0,557.2L245.9,552.9L239.0,550.6L239.7,550.1L240.1,549.2L239.5,546.7L237.1,549.8L232.9,549.3L233.0,547.7L232.1,548.8L222.6,550.0L222.3,548.8L219.8,548.4L219.9,547.2L219.0,547.5L218.3,548.2L216.0,547.6L216.5,547.1L216.9,546.0L214.8,546.6L215.3,545.4L213.2,546.2L214.8,544.9L212.6,545.4L214.2,543.0L210.6,545.1L209.8,543.3L209.8,545.4L208.0,546.0L209.1,542.4L206.2,546.6L207.6,546.3L207.6,546.7L207.9,547.4L206.7,547.8L206.2,548.7L208.8,548.1L207.5,550.3L208.8,550.5L208.4,551.5L207.6,550.7L206.7,552.6L205.1,551.6L204.4,553.1L204.1,551.6L203.7,551.3L203.6,554.4L202.7,552.6L202.8,554.9L201.7,553.9L200.9,556.7L200.8,555.0L200.2,556.4L199.5,555.8L198.4,558.4L195.6,558.8L195.0,556.9L198.4,554.0L196.3,555.3L195.0,554.5L196.9,549.7L196.4,547.3L199.9,544.8L204.8,545.9L200.9,543.9L202.6,541.3L201.2,543.3L198.8,542.9L195.2,545.9L195.3,547.4L191.7,551.1L191.9,553.3L190.0,553.8L190.8,554.1L190.0,555.4L189.1,554.3L188.1,556.9L186.7,557.4L186.5,560.0L188.2,559.5L189.9,561.1L186.9,563.9L186.3,566.4L183.3,567.3L182.0,569.4L180.9,568.9L180.3,570.6L177.2,572.1L178.0,572.4L177.0,574.7L174.4,576.1L173.4,575.4L173.2,577.1L170.5,577.5L171.6,578.1L169.4,578.1L169.5,579.9L170.4,579.8L169.0,581.5L168.6,580.3L168.0,581.7L167.4,581.3L164.9,582.7L164.6,581.9L164.4,583.5L163.6,584.2L163.3,582.1L160.2,584.5ZM186.4,569.9L187.9,572.2L187.6,570.0L188.5,569.9L187.4,568.8L188.5,568.3L189.0,569.5L189.0,567.6L190.7,568.4L189.9,567.4L191.8,568.0L191.4,568.6L191.5,569.3L193.2,567.5L193.1,570.3L194.3,570.1L193.6,571.6L191.2,570.9L192.5,572.3L190.2,573.2L191.6,573.6L189.9,574.8L189.7,573.3L186.6,576.6L188.0,573.6L185.9,575.9L184.0,572.6L186.4,569.9ZM272.2,572.5L270.6,571.6L271.3,570.1L270.1,568.3L270.3,569.8L269.9,569.0L268.5,570.1L268.3,566.9L270.2,566.6L271.0,567.8L276.1,571.2L274.4,570.9L274.2,571.7L277.2,572.4L278.4,576.3L275.4,575.3L275.4,574.3L274.6,573.4L272.2,573.8L272.2,572.5ZM257.5,558.4L259.0,559.1L260.3,558.6L261.3,560.4L257.8,559.8L258.6,561.4L257.6,562.2L253.6,558.1L256.0,555.8L257.4,556.3L257.3,557.8L257.8,556.4L259.8,556.8L259.9,558.5L257.5,558.4ZM135.0,519.5L135.4,521.0L139.3,523.2L138.8,524.0L136.9,523.8L135.7,525.1L133.5,521.4L129.6,519.8L130.6,517.4L132.6,519.6L135.0,519.5ZM143.7,545.8L145.1,546.8L145.2,549.5L142.9,550.5L138.9,547.4L139.1,546.2L143.7,545.8ZM264.0,569.1L262.5,566.6L260.6,566.0L259.8,562.7L258.3,562.3L258.7,561.6L258.7,561.4L258.5,561.0L258.9,560.5L261.7,561.4L264.0,569.1ZM262.5,555.6L264.9,558.7L262.2,556.0L262.1,556.3L262.5,557.2L265.2,560.2L263.1,563.5L262.9,560.6L258.9,554.1L260.4,555.5L262.5,555.6ZM268.8,561.7L271.9,564.0L270.2,565.0L270.0,564.4L268.6,563.3L270.0,565.1L268.0,566.3L267.0,563.6L265.2,562.5L268.8,561.7ZM131.3,591.6L134.8,592.3L133.1,593.6L135.0,593.5L131.8,595.4L126.9,595.4L131.9,593.7L130.7,592.3L131.3,591.6ZM191.8,567.4L189.4,567.0L193.4,562.7L192.9,564.8L194.3,564.4L194.9,565.7L192.6,566.0L191.8,567.4ZM120.7,597.6L125.5,593.5L127.5,593.9L123.9,596.6L120.7,597.6ZM266.9,564.1L267.0,567.5L267.6,569.1L266.9,568.3L266.5,569.0L267.1,570.0L265.7,567.7L266.5,566.9L264.2,564.5L264.6,563.6L266.9,564.1ZM97.8,596.8L94.8,596.6L92.3,595.7L96.6,595.9L98.1,594.5L97.8,596.8ZM209.6,553.4L211.7,548.8L212.7,549.1L211.0,552.6L209.6,553.4ZM46.1,569.8L45.0,567.8L47.7,568.7L48.4,570.4L46.1,569.8ZM86.0,593.9L87.5,596.2L84.2,596.1L86.0,593.9ZM81.8,594.4L84.2,593.5L84.7,594.0L83.8,595.1L81.8,594.4ZM275.8,577.3L272.8,575.4L272.7,573.9L275.8,577.3ZM213.7,549.5L213.7,547.7L215.5,548.1L213.7,549.5ZM210.1,547.4L210.1,548.9L209.7,550.6L209.0,550.0L210.1,547.4ZM98.0,596.7L102.7,598.4L100.0,598.1L98.0,596.7ZM82.1,593.4L79.6,593.8L80.5,593.5L79.8,592.1L82.1,593.4ZM271.3,565.2L272.2,566.3L271.4,566.8L270.4,566.2L271.3,565.2ZM120.9,541.1L120.3,538.8L122.1,541.5L120.9,541.1ZM257.7,562.6L259.3,564.0L258.5,565.0L257.7,562.6ZM160.9,589.1L162.7,586.2L162.8,587.4L160.9,589.1ZM158.9,585.1L159.9,587.1L158.6,587.0L158.9,585.1ZM279.2,573.6L278.8,571.6L280.2,573.2L279.2,573.6ZM48.7,573.2L48.0,574.1L46.7,573.0L48.7,573.2ZM66.8,589.1L68.5,591.7L65.7,588.4L66.8,589.1ZM137.3,591.3L135.6,591.6L135.6,590.7L137.3,591.3ZM62.9,583.2L60.8,584.7L60.5,584.2L62.9,583.2ZM160.4,560.9L161.9,560.1L160.3,562.0L160.4,560.9ZM137.4,590.5L138.6,591.0L137.7,591.5L137.4,590.5ZM118.0,596.4L118.0,597.4L116.8,596.6L118.0,596.4ZM270.1,571.4L269.7,570.4L270.8,570.4L270.1,571.4ZM105.5,596.9L105.4,597.8L104.5,597.6L105.5,596.9ZM150.7,591.0L149.8,591.4L149.7,590.6L150.7,591.0ZM280.7,573.2L280.7,574.3L279.9,574.0L280.7,573.2ZM113.5,596.9L113.9,597.6L112.8,597.7L113.5,596.9ZM70.6,588.7L71.0,587.6L71.4,588.3L70.6,588.7ZM274.2,575.2L274.0,574.0L274.8,575.3L274.2,575.2ZM187.3,578.3L185.7,578.1L187.6,578.0L187.3,578.3ZM214.7,547.4L216.5,546.4L214.6,547.8L214.7,547.4ZM270.4,574.3L271.1,573.4L270.8,574.7L270.4,574.3ZM194.1,550.2L194.4,549.6L194.6,548.9L194.9,549.1L194.5,549.9L194.1,550.2ZM164.2,587.4L163.5,588.0L164.2,586.5L164.2,587.4ZM123.3,565.9L123.0,565.3L123.9,565.4L123.3,565.9ZM159.4,524.3L159.9,525.1L158.9,524.7L159.4,524.3ZM89.5,594.6L88.6,594.3L89.1,593.9L89.5,594.6ZM272.0,574.6L271.6,573.6L272.3,574.0L272.0,574.6ZM208.4,551.7L208.9,550.9L209.0,550.6L209.3,551.0L208.4,551.7ZM152.6,588.0L151.8,587.6L152.3,587.3L152.6,588.0ZM161.6,585.4L160.8,585.0L161.7,584.9L161.6,585.4ZM277.3,571.1L278.3,572.3L278.4,573.0L277.3,571.1ZM270.3,573.2L270.5,572.5L271.1,573.0L270.3,573.2ZM164.3,588.0L164.8,588.6L164.3,588.8L164.3,588.0ZM221.6,551.4L222.7,550.1L221.5,551.8L221.6,551.4ZM89.2,596.0L88.2,595.4L89.3,595.7L89.2,596.0ZM154.5,586.1L154.8,587.1L154.2,586.4L154.5,586.1ZM207.7,546.7L208.1,546.4L208.0,547.3L207.7,546.7ZM167.2,582.2L167.8,582.6L167.1,582.7L167.2,582.2ZM140.2,592.2L139.5,591.7L140.5,591.9L140.2,592.2ZM185.5,578.0L183.9,579.0L185.5,577.8L185.5,578.0ZM270.9,572.5L271.4,572.2L271.3,572.8L270.9,572.5ZM210.4,547.1L210.5,546.5L211.0,546.7L210.4,547.1ZM270.5,570.2L270.6,569.6L271.0,570.5L270.5,570.2ZM209.3,551.2L209.3,551.9L208.9,552.2L209.3,551.2ZM188.9,557.7L189.4,557.1L189.6,557.5L188.9,557.7ZM66.5,586.3L65.9,586.4L66.0,585.8L66.5,586.3ZM125.5,570.4L124.6,570.4L124.3,570.0L125.5,570.4ZM174.1,577.5L174.4,577.9L173.7,577.9L174.1,577.5ZM208.2,549.5L208.8,549.2L208.5,549.8L208.2,549.5ZM116.5,597.0L115.9,597.2L116.1,596.8L116.5,597.0ZM275.6,576.7L275.3,575.7L275.8,576.7L275.6,576.7ZM211.4,545.2L210.8,545.1L211.7,544.9L211.4,545.2ZM180.6,583.7L180.5,582.6L180.7,582.7L180.6,583.7ZM199.1,557.5L199.7,556.9L199.3,557.6L199.1,557.5ZM272.3,565.2L272.9,565.2L272.4,565.5L272.3,565.2ZM268.5,570.7L268.0,570.3L268.3,570.1L268.5,570.7ZM159.3,581.0L159.3,581.4L158.8,581.3L159.3,581.0ZM160.6,586.0L160.8,585.5L160.8,586.3L160.6,586.0ZM75.0,594.3L75.3,594.8L74.9,594.8L75.0,594.3ZM163.6,589.6L163.9,590.1L163.5,590.1L163.6,589.6ZM155.3,585.7L155.6,586.1L155.1,586.1L155.3,585.7ZM76.6,591.8L77.2,592.1L76.9,592.2L76.6,591.8ZM118.3,595.6L118.6,595.8L118.3,596.1L118.3,595.6ZM259.1,563.0L259.6,563.3L259.4,563.6L259.1,563.0ZM259.2,563.0L259.6,562.8L259.6,563.2L259.2,563.0ZM266.5,570.8L266.9,571.4L266.6,571.3L266.5,570.8ZM110.8,597.4L110.8,598.0L110.6,597.9L110.8,597.4ZM218.9,548.0L218.8,548.4L218.4,548.3L218.9,548.0ZM164.8,588.9L165.1,589.4L164.8,589.4L164.8,588.9ZM208.2,552.3L208.6,552.0L208.9,551.5L208.7,552.1L208.2,552.3ZM256.5,555.0L256.5,555.4L256.1,555.2L256.5,555.0ZM276.8,567.6L277.3,567.8L276.8,567.9L276.8,567.6ZM275.0,567.2L275.4,567.1L275.3,567.5L275.0,567.2ZM254.2,556.7L253.8,556.5L254.3,556.4L254.2,556.7ZM222.1,549.2L222.1,549.5L221.7,549.1L222.1,549.2ZM139.0,591.9L138.6,592.0L138.0,591.8L139.0,591.9ZM211.2,549.5L210.6,549.7L211.1,549.3L211.2,549.5ZM171.6,578.9L171.6,579.3L171.3,579.1L171.6,578.9ZM74.1,594.8L74.4,595.1L74.0,595.2L74.1,594.8ZM208.8,547.0L208.8,546.4L209.0,546.8L208.8,547.0ZM156.3,586.0L156.5,586.5L156.1,586.2L156.3,586.0ZM270.1,572.0L269.8,571.6L270.1,571.6L270.1,572.0ZM269.5,573.4L270.3,572.8L269.6,573.6L269.5,573.4ZM277.1,570.4L277.5,570.3L277.3,570.7L277.1,570.4ZM90.2,595.4L90.2,595.8L89.8,595.4L90.2,595.4ZM175.9,581.6L176.1,581.3L176.2,581.8L175.9,581.6ZM64.8,586.9L64.9,586.7L65.0,587.2L64.8,586.9ZM150.6,530.3L151.0,530.7L150.8,530.7L150.6,530.3ZM116.5,596.3L117.0,596.1L116.9,596.4L116.5,596.3ZM64.8,585.3L64.7,584.8L65.0,585.0L64.8,585.3ZM262.7,556.5L262.6,556.8L262.3,556.5L262.7,556.5ZM90.4,595.7L90.5,595.4L90.8,595.6L90.4,595.7ZM273.6,574.2L273.8,573.9L273.8,574.2L273.6,574.2ZM191.7,567.5L191.9,567.9L191.6,567.7L191.7,567.5ZM186.6,576.9L187.0,577.0L186.5,577.1L186.6,576.9ZM166.1,582.1L166.2,582.5L165.9,582.4L166.1,582.1ZM254.8,556.0L255.2,556.2L254.7,556.2L254.8,556.0ZM163.0,589.5L162.8,589.8L162.6,589.6L163.0,589.5ZM89.9,595.1L89.8,595.3L89.5,595.0L89.9,595.1ZM256.5,550.6L256.4,550.7L256.2,550.2L256.5,550.6ZM195.6,565.5L195.2,565.9L195.5,565.3L195.6,565.5ZM56.9,578.6L56.6,578.7L56.6,578.4L56.9,578.6ZM76.5,593.5L76.2,593.5L76.1,593.3L76.5,593.5ZM271.6,572.8L271.9,573.0L271.6,573.1L271.6,572.8ZM163.2,561.3L163.5,561.4L163.4,561.6L163.2,561.3ZM262.9,557.2L263.3,557.4L263.4,557.6L262.9,557.2ZM137.8,591.9L137.9,592.1L137.6,592.0L137.8,591.9ZM280.8,572.5L280.6,572.7L280.6,572.3L280.8,572.5ZM193.4,560.7L193.7,560.5L194.1,560.4L193.4,560.7ZM165.1,582.7L165.4,582.7L165.3,583.0L165.2,582.7L165.1,582.7ZM162.9,560.8L163.0,561.1L162.8,561.3L162.9,560.8ZM272.0,563.8L272.5,563.2L272.6,563.2L272.0,563.8ZM194.6,560.4L194.4,560.6L194.4,560.4L194.6,560.4ZM192.3,551.5L192.1,551.6L192.1,551.4L192.3,551.5ZM50.7,572.6L50.8,572.4L50.9,572.8L50.7,572.6ZM259.4,554.2L259.2,553.8L259.5,554.2L259.4,554.2ZM200.4,543.8L200.4,544.1L200.2,544.1L200.4,543.8ZM210.6,546.3L210.3,546.3L210.7,546.1L210.6,546.3ZM272.1,577.5L272.2,577.9L272.0,577.4L272.1,577.5ZM150.4,552.1L150.7,552.3L150.6,552.4L150.4,552.1ZM240.0,549.1L239.7,549.2L239.7,549.0L240.0,549.1ZM155.5,586.8L155.4,587.1L155.4,586.7L155.5,586.8ZM120.4,597.7L120.2,597.9L120.0,597.9L120.4,597.7ZM271.5,567.5L271.7,567.8L271.5,567.7L271.5,567.5ZM279.8,573.6L279.8,573.8L279.6,573.5L279.8,573.6ZM270.3,569.3L270.5,569.5L270.4,569.7L270.3,569.3ZM218.9,548.1L219.1,548.4L219.1,548.5L218.9,548.1ZM77.2,593.4L77.0,593.5L77.0,593.3L77.2,593.4ZM135.0,591.9L135.0,592.2L134.9,591.9L135.0,591.9ZM163.0,587.7L162.8,587.8L162.9,587.6L163.0,587.7ZM163.2,587.6L163.1,587.6L163.3,587.4L163.2,587.6ZM251.0,552.2L251.2,552.4L250.9,552.2L251.0,552.2ZM111.5,597.1L111.6,597.4L111.4,597.2L111.5,597.1ZM271.2,566.9L271.0,567.1L271.0,566.9L271.2,566.9ZM170.4,580.6L170.2,580.4L170.5,580.4L170.4,580.6ZM271.3,567.2L271.3,567.4L271.1,567.2L271.3,567.2ZM141.2,591.3L140.8,591.5L140.7,591.4L141.2,591.3ZM162.0,585.7L161.8,585.9L161.7,585.8L162.0,585.7ZM239.4,549.8L239.2,550.4L239.3,549.8L239.4,549.8ZM118.4,595.3L118.2,595.3L118.3,595.1L118.4,595.3ZM50.4,572.2L50.2,572.2L50.2,572.1L50.4,572.2ZM271.8,564.7L272.0,565.0L271.7,564.8L271.8,564.7ZM82.9,593.4L83.0,593.2L83.1,593.4L82.9,593.4ZM253.9,553.8L253.7,553.6L253.7,553.5L253.9,553.8ZM175.7,580.5L175.9,580.6L175.9,580.7L175.7,580.5ZM271.2,573.2L271.2,573.4L271.1,573.1L271.2,573.2ZM188.8,575.5L188.7,575.4L188.9,575.4L188.8,575.5ZM49.9,571.7L50.2,572.0L50.1,572.0L49.9,571.7ZM162.8,588.1L162.6,588.0L162.7,587.9L162.8,588.1ZM120.0,538.0L119.8,538.2L120.0,537.9L120.0,538.0ZM195.8,559.0L195.7,559.2L195.6,559.1L195.8,559.0ZM149.4,583.6L149.2,583.7L149.3,583.6L149.4,583.6ZM210.8,546.4L210.6,546.4L210.8,546.3L210.8,546.4ZM271.0,566.6L271.0,566.9L270.9,566.7L271.0,566.6ZM204.2,552.6L204.1,552.9L204.2,552.6L204.2,552.6ZM77.3,593.7L77.3,593.5L77.4,593.5L77.3,593.7ZM280.7,573.1L280.6,573.0L280.7,572.9L280.7,573.1ZM272.0,564.1L272.1,564.4L272.1,564.5L272.0,564.1ZM267.3,566.2L267.5,566.4L267.2,566.2L267.3,566.2ZM254.3,553.9L254.2,554.0L254.1,553.9L254.3,553.9ZM142.5,505.7L142.7,505.5L142.6,505.7L142.5,505.7ZM195.1,558.8L195.4,558.9L195.1,558.9L195.1,558.8ZM193.9,572.0L193.9,571.8L194.0,571.8L193.9,572.0ZM272.0,564.5L272.0,564.7L271.8,564.6L272.0,564.5ZM271.2,567.5L271.1,567.3L271.2,567.5L271.2,567.5ZM185.3,567.0L185.1,566.9L185.4,567.0L185.3,567.0ZM153.9,587.1L153.9,586.8L154.0,587.1L153.9,587.1ZM204.2,477.3L204.3,477.3L204.2,477.4L204.2,477.3ZM196.5,558.8L196.6,559.1L196.4,558.8L196.5,558.8ZM262.7,555.3L262.5,555.4L262.5,555.3L262.7,555.3ZM203.9,553.1L204.0,553.4L204.0,553.3L203.9,553.1ZM272.4,564.1L272.3,564.3L272.3,564.1L272.4,564.1ZM265.5,560.5L265.5,560.6L265.4,560.5L265.5,560.5ZM278.4,571.4L278.6,571.6L278.3,571.4L278.4,571.4ZM150.4,530.3L150.1,530.8L150.1,530.7L150.4,530.3ZM92.0,594.4L91.8,594.3L91.9,594.3L92.0,594.4ZM269.1,570.2L269.2,570.5L269.0,570.2L269.1,570.2ZM154.3,586.7L154.1,586.6L154.1,586.6L154.3,586.7ZM163.7,560.1L163.7,560.3L163.7,560.1L163.7,560.1ZM75.3,593.0L75.3,592.8L75.4,593.0L75.3,593.0ZM272.4,563.6L272.3,564.0L272.3,564.0L272.4,563.6ZM274.0,575.0L273.9,575.0L274.0,574.9L274.0,575.0ZM89.1,595.3L89.1,595.1L89.1,595.1L89.1,595.3ZM266.8,560.7L266.6,560.6L266.6,560.5L266.8,560.7ZM88.7,594.9L88.9,595.1L88.7,595.0L88.7,594.9ZM143.9,511.8L143.9,511.7L144.0,511.7L143.9,511.8ZM194.7,560.6L194.7,560.5L194.8,560.6L194.7,560.6ZM270.3,573.4L270.3,573.3L270.3,573.3L270.3,573.4ZM202.6,554.8L202.4,554.7L202.4,554.7L202.6,554.8ZM269.9,561.6L269.8,561.3L270.0,561.6L269.9,561.6ZM265.4,560.6L265.3,560.6L265.3,560.5L265.4,560.6ZM254.8,554.5L254.8,554.3L254.9,554.4L254.8,554.5ZM210.4,545.2L210.3,545.2L210.3,545.1L210.4,545.2ZM267.5,566.7L267.4,566.8L267.4,566.7L267.5,566.7ZM123.7,597.2L123.7,597.1L123.8,597.2L123.7,597.2ZM163.6,587.0L163.6,587.1L163.5,587.0L163.6,587.0ZM164.9,588.1L164.9,588.0L165.0,588.1L164.9,588.1ZM173.5,577.0L173.4,577.0L173.4,577.0L173.5,577.0ZM219.3,548.0L219.2,548.0L219.3,547.9L219.3,548.0ZM258.4,553.4L258.7,553.5L258.8,553.6L258.4,553.4ZM239.5,549.8L239.7,549.8L239.6,549.9L239.5,549.8ZM222.3,548.9L222.2,549.0L222.3,548.9L222.3,548.9ZM281.1,570.6L281.1,570.3L281.1,570.6L281.1,570.6ZM140.8,591.5L141.0,591.5L141.0,591.6L140.8,591.5ZM267.2,567.7L267.1,567.8L267.1,567.7L267.2,567.7ZM89.3,595.2L89.2,595.1L89.3,595.1L89.3,595.2ZM222.0,549.9L222.1,550.2L222.1,550.3L222.0,549.9ZM127.0,590.8L127.1,590.7L127.1,590.8L127.0,590.8ZM154.1,587.5L154.2,587.4L154.1,587.5L154.1,587.5ZM269.9,570.1L269.8,570.0L269.9,570.0L269.9,570.1ZM270.3,569.9L270.2,569.9L270.3,569.8L270.3,569.9ZM194.0,569.0L193.9,568.9L194.0,568.9L194.0,569.0ZM269.8,569.9L269.8,569.8L269.9,569.9L269.8,569.9ZM93.6,594.6L93.6,594.5L93.7,594.6L93.6,594.6ZM148.9,516.3L148.8,516.3L148.9,516.3L148.9,516.3ZM78.3,594.9L78.3,594.8L78.4,594.9L78.3,594.9ZM164.5,561.9L164.4,561.9L164.4,561.9L164.5,561.9ZM269.6,572.2L269.6,572.3L269.6,572.2L269.6,572.2ZM279.3,571.6L279.4,571.8L279.3,571.6L279.3,571.6ZM270.1,570.0L270.1,569.9L270.2,569.9L270.1,570.0ZM165.2,582.9L165.1,582.8L165.2,582.9L165.2,582.9ZM276.5,568.1L276.4,568.1L276.4,568.1L276.5,568.1ZM280.9,570.8L280.8,570.8L280.8,570.8L280.9,570.8ZM277.5,569.9L277.6,570.1L277.6,570.1L277.5,569.9ZM63.9,585.8L63.9,585.7L63.9,585.7L63.9,585.8ZM61.9,582.9L61.9,582.9L61.9,582.9L61.9,582.9ZM91.6,595.8L91.5,595.7L91.8,595.8L91.6,595.8ZM258.8,552.9L258.7,552.9L258.7,552.9L258.8,552.9ZM252.1,552.3L252.0,552.3L252.0,552.3L252.1,552.3Z","AL":"M530.2,403.1L526.3,319.3L564.3,316.1L574.9,353.6L580.5,363.9L577.6,371.5L581.5,386.7L541.6,390.8L546.1,400.6L545.0,403.1L539.7,404.9L536.2,405.3L540.3,403.7L535.8,397.0L534.3,403.7L530.2,403.1ZM534.6,404.3L534.0,405.0L532.2,405.5L531.7,405.5L534.6,404.3ZM535.3,400.2L535.7,400.0L535.8,400.5L535.3,400.2Z","AR":"M485.3,357.9L441.5,359.7L441.3,350.1L434.7,348.6L435.0,316.8L431.9,296.7L496.1,294.3L497.6,297.8L493.4,303.6L502.8,303.0L504.1,304.8L497.1,313.8L498.9,318.9L495.7,324.4L493.1,323.9L492.3,332.3L485.1,340.8L485.3,357.9Z","AZ":"M181.2,372.1L128.8,341.4L135.1,336.2L132.9,327.3L138.0,316.6L145.0,311.9L139.8,299.6L142.5,277.6L150.8,280.4L155.6,263.4L226.1,275.0L212.0,376.7L181.2,372.1Z","CA":"M42.5,221.2L46.0,228.0L43.9,218.8L46.6,217.4L43.8,215.9L41.8,221.0L36.0,215.9L38.0,211.3L31.3,197.0L34.4,180.6L30.0,171.1L40.2,151.8L41.2,141.5L95.3,156.8L81.7,209.5L140.3,297.3L145.0,311.9L140.0,314.2L136.8,323.4L133.3,325.5L134.0,337.6L94.7,333.4L92.7,318.8L84.9,308.4L80.8,307.7L80.5,302.3L72.0,298.8L67.2,291.8L54.3,287.8L52.4,284.8L55.0,275.0L42.9,249.8L47.0,241.3L40.4,232.3L42.5,221.2ZM80.0,313.7L78.3,314.8L76.9,311.7L80.0,313.7ZM60.4,296.5L64.3,298.5L66.0,298.6L62.3,299.0L60.4,296.5ZM75.9,323.2L75.5,319.7L77.7,324.1L75.9,323.2ZM56.8,298.8L58.5,296.6L59.2,298.5L56.8,298.8ZM52.5,295.0L54.0,294.7L54.7,295.9L52.5,295.0ZM63.4,312.4L62.1,312.6L61.8,311.6L63.4,312.4ZM70.6,310.4L70.5,310.0L70.8,310.0L70.6,310.4ZM43.5,220.7L43.3,220.4L43.5,220.4L43.5,220.7ZM43.9,221.6L44.0,221.3L44.0,221.7L43.9,221.6ZM67.8,299.6L67.7,299.5L68.3,299.5L67.8,299.6ZM34.8,221.1L34.6,221.2L34.7,221.0L34.8,221.1Z","CO":"M325.7,285.2L226.1,275.0L236.0,203.0L330.2,212.5L325.7,285.2Z","CT":"M711.6,180.0L709.3,160.7L731.3,155.7L734.1,166.3L733.7,168.2L720.1,172.4L711.6,180.0ZM714.5,178.2L715.0,177.3L715.2,177.2L714.5,178.2Z","DE":"M694.0,229.2L688.4,208.8L691.3,206.0L693.2,206.4L691.1,210.1L692.0,212.9L703.4,229.2L694.0,229.2ZM691.9,210.2L691.7,209.9L691.8,209.8L691.9,210.2ZM691.9,210.6L691.7,210.5L691.7,210.4L691.9,210.6Z","FL":"M622.1,419.4L598.5,400.9L578.9,411.3L577.4,406.4L563.9,400.5L544.0,403.6L546.1,400.5L541.6,390.8L581.5,386.7L584.2,391.6L625.3,388.8L626.6,392.4L628.6,383.6L636.9,384.6L642.5,401.3L656.2,420.1L657.7,428.7L670.0,450.2L671.5,468.4L668.4,478.6L657.9,482.4L651.5,470.8L645.2,470.2L641.7,462.3L635.9,457.7L637.1,452.6L634.5,457.2L624.7,443.8L629.5,437.7L629.0,436.6L628.2,436.1L626.9,437.9L624.6,435.6L624.7,442.5L622.2,438.3L622.2,437.0L622.4,437.4L622.8,434.7L622.1,432.7L623.6,426.9L622.1,419.4ZM652.8,489.9L655.6,491.1L647.4,494.3L652.8,489.9ZM634.6,457.4L639.2,461.3L636.5,461.4L634.6,457.4ZM667.0,483.2L669.6,478.9L671.5,473.0L669.4,480.4L666.7,484.0L665.5,485.3L663.8,486.6L667.0,483.2ZM582.8,411.4L587.7,409.7L585.0,411.4L583.6,412.0L582.8,411.4ZM658.3,489.8L659.9,489.0L660.4,488.5L661.6,487.9L661.7,488.1L659.1,489.9L658.3,489.8ZM582.4,410.3L582.4,411.4L580.8,410.7L582.4,410.3ZM590.5,407.2L589.1,407.8L590.6,406.8L590.5,407.2ZM642.4,495.0L641.9,494.2L642.6,494.4L642.4,495.0ZM622.4,436.4L622.2,435.0L621.9,434.1L622.3,435.1L622.4,436.4ZM621.6,432.9L621.3,432.1L621.5,431.7L621.6,432.9ZM656.2,490.7L656.5,490.7L655.9,491.1L656.2,490.7ZM663.4,487.1L663.4,486.5L663.6,486.5L663.4,487.1ZM655.4,490.1L654.9,489.2L655.5,490.0L655.4,490.1ZM628.7,437.0L628.9,437.2L628.7,437.3L628.7,437.0ZM624.4,443.2L624.2,442.9L624.2,442.7L624.4,443.2ZM628.9,437.8L628.8,438.1L628.8,437.8L628.9,437.8ZM662.0,487.7L661.9,487.8L661.7,487.9L662.0,487.7ZM621.7,433.9L621.8,433.8L621.9,433.9L621.7,433.9ZM664.8,485.1L664.7,485.3L664.7,485.1L664.8,485.1Z","GA":"M583.8,391.2L577.7,372.9L580.5,363.9L574.9,353.6L564.3,316.1L600.7,311.3L598.1,317.5L605.4,320.3L611.4,329.1L629.6,343.5L637.7,358.6L642.1,360.3L637.6,365.9L636.7,384.5L627.7,384.3L628.3,392.1L625.3,388.8L583.8,391.2Z","HI":"M516.6,572.6L520.0,577.2L514.7,580.0L513.4,581.8L511.8,580.8L511.5,577.1L510.3,575.0L512.2,572.9L511.8,570.5L516.6,572.6ZM510.4,567.3L507.4,567.7L507.2,566.2L505.5,565.4L505.8,564.1L510.9,566.2L510.4,567.3ZM494.2,561.5L492.9,559.5L495.3,558.3L496.3,560.5L497.8,561.7L494.2,561.5ZM482.3,556.7L481.0,555.7L481.5,554.6L484.5,554.1L484.6,556.2L482.3,556.7ZM503.8,563.9L502.3,563.4L500.5,563.4L500.9,562.4L505.2,563.0L503.8,563.9ZM502.9,564.9L504.2,565.5L504.2,566.3L503.2,566.6L502.9,564.9ZM505.4,568.4L506.0,567.8L506.6,567.9L506.6,568.4L505.4,568.4ZM477.7,557.7L478.4,555.9L478.9,555.9L477.7,557.7ZM386.9,523.4L386.7,523.3L386.9,523.2L386.9,523.4ZM369.3,520.8L369.1,520.6L369.2,520.6L369.3,520.8ZM335.1,500.2L335.0,500.1L335.1,500.0L335.1,500.2ZM475.0,558.7L475.0,558.9L474.9,558.7L475.0,558.7ZM442.2,542.4L442.2,542.3L442.4,542.4L442.2,542.4ZM464.1,546.9L464.3,546.8L464.3,546.9L464.1,546.9ZM353.7,505.8L353.6,505.8L353.6,505.8L353.7,505.8ZM355.2,504.4L355.3,504.3L355.3,504.3L355.2,504.4ZM430.1,539.8L430.1,539.9L430.0,539.8L430.1,539.8ZM353.9,505.8L354.0,505.7L354.0,505.8L353.9,505.8ZM430.3,540.0L430.3,539.9L430.3,540.0L430.3,540.0ZM429.8,539.9L429.8,539.8L429.8,539.9L429.8,539.9ZM416.2,530.0L416.3,530.1L416.3,530.1L416.2,530.0ZM355.2,504.5L355.3,504.4L355.2,504.5L355.2,504.5ZM354.6,505.6L354.7,505.6L354.6,505.6L354.6,505.6ZM430.7,541.1L430.7,541.1L430.6,541.0L430.7,541.1ZM430.4,540.6L430.3,540.6L430.3,540.6L430.4,540.6ZM354.3,505.6L354.3,505.5L354.3,505.6L354.3,505.6ZM496.7,560.7L496.7,560.7L496.7,560.7L496.7,560.7Z","IA":"M470.1,220.8L415.2,222.6L413.6,220.2L413.1,206.9L403.6,183.6L406.3,176.6L404.2,169.8L474.4,168.2L477.1,181.7L482.0,183.5L490.2,194.5L487.9,202.2L478.7,205.9L480.4,214.1L475.1,224.7L470.1,220.8Z","ID":"M134.1,166.1L144.1,128.3L140.7,123.1L155.1,103.8L150.7,89.2L161.4,43.1L173.0,45.6L169.2,63.5L171.0,73.9L180.0,89.1L185.3,91.1L178.6,109.6L181.0,112.0L186.1,108.5L188.0,110.8L190.0,124.7L193.8,127.0L195.9,135.0L203.8,132.6L214.0,134.8L215.8,131.2L219.2,136.9L212.2,181.1L134.1,166.1Z","IL":"M491.7,263.8L494.1,251.6L486.9,251.3L473.5,229.5L474.6,221.7L480.4,214.1L478.7,205.9L486.4,203.4L489.8,198.0L489.7,192.5L482.8,186.1L520.5,183.4L525.4,196.9L527.9,243.7L530.6,250.8L524.7,260.8L524.6,274.3L518.9,276.5L519.6,282.2L512.2,279.9L510.2,284.6L506.6,283.8L503.8,272.1L491.7,263.8Z","IN":"M536.5,266.7L530.5,264.8L530.3,267.5L524.1,267.4L530.6,250.8L527.9,243.7L525.4,197.2L561.5,192.5L567.8,246.2L559.3,248.2L559.8,251.7L552.4,263.0L547.4,259.1L544.3,265.9L541.3,263.4L536.5,266.7Z","KS":"M325.7,285.2L329.1,230.6L421.5,233.2L427.5,236.4L424.3,241.3L431.6,248.5L431.8,287.7L359.9,286.8L325.7,285.2Z","KY":"M526.3,292.2L506.7,293.6L510.2,290.3L511.3,280.3L519.6,282.2L518.9,276.5L524.6,274.3L523.0,271.2L526.3,266.1L537.6,267.7L541.3,263.4L544.2,266.0L547.4,259.1L552.4,263.0L559.8,251.7L559.3,248.2L567.8,246.2L567.9,239.5L583.8,247.0L594.6,243.3L602.0,257.3L610.5,263.2L596.0,280.0L588.5,283.9L525.8,288.9L526.3,292.2ZM505.7,293.7L504.7,292.3L505.7,292.4L505.7,293.7Z","LA":"M480.7,417.7L471.6,418.0L474.8,420.1L470.0,421.8L444.5,417.9L448.0,413.0L447.1,404.4L450.4,395.4L441.9,378.3L441.5,359.7L485.9,358.7L486.0,367.8L489.8,369.6L480.7,383.5L479.4,394.9L508.8,393.2L507.3,399.5L512.9,407.8L508.2,412.2L511.9,413.4L513.7,409.6L515.7,412.5L518.0,411.2L515.6,413.8L517.4,415.1L511.5,415.7L514.2,417.7L511.6,417.1L511.0,419.9L522.4,425.2L516.3,430.2L517.5,426.5L508.9,423.7L508.7,420.8L504.0,427.8L501.3,428.8L502.4,426.1L498.5,424.7L493.6,429.6L486.1,425.9L488.7,424.5L480.7,417.7ZM477.7,422.5L474.3,420.8L479.4,420.9L477.7,422.5ZM518.6,409.9L515.9,409.8L518.2,407.8L518.6,409.9ZM523.0,415.9L524.1,412.4L523.1,409.4L524.3,412.2L523.0,415.9ZM499.4,428.7L499.4,428.9L498.1,428.3L499.4,428.7ZM514.5,408.6L514.3,408.4L514.7,408.4L514.5,408.6ZM508.0,424.1L507.5,424.6L507.4,424.5L508.0,424.1ZM492.0,429.3L492.1,429.4L491.7,429.2L492.0,429.3Z","MA":"M742.5,162.6L736.7,154.3L709.2,160.7L709.2,147.7L734.7,142.2L739.9,137.5L743.9,140.7L740.8,143.3L740.3,148.4L744.3,148.7L750.5,155.8L755.4,153.3L751.1,149.6L753.2,149.2L757.0,155.3L745.2,163.5L747.9,157.1L742.5,162.6ZM749.3,161.0L751.9,162.8L746.9,164.2L749.3,161.0ZM754.4,163.0L758.6,162.3L758.6,162.9L756.7,163.5L754.4,163.0ZM740.7,147.4L740.8,147.8L740.5,147.8L740.7,147.4ZM741.5,147.2L741.7,146.9L741.7,147.1L741.5,147.2ZM746.0,159.9L745.7,159.9L745.7,159.7L746.0,159.9ZM747.6,165.6L747.5,165.8L747.4,165.7L747.6,165.6ZM740.9,147.4L741.1,147.4L741.2,147.5L740.9,147.4ZM741.2,147.9L741.0,148.1L741.2,147.8L741.2,147.9ZM754.1,162.5L753.8,162.5L754.1,162.4L754.1,162.5Z","MD":"M687.5,240.3L676.4,235.0L673.4,236.8L676.3,226.8L668.1,225.0L661.1,216.6L656.2,215.8L651.5,220.0L648.4,218.2L640.1,227.9L638.5,218.6L688.4,208.8L694.5,231.0L703.4,229.2L702.8,235.9L694.0,241.3L692.6,233.4L690.8,236.3L687.3,235.1L687.6,229.2L684.8,229.1L686.3,225.9L683.6,224.4L686.0,222.8L683.9,220.1L686.8,215.8L686.2,212.2L680.2,220.1L687.5,240.3ZM691.1,237.0L691.5,238.9L690.3,236.6L691.1,237.0ZM692.3,240.9L691.4,239.6L692.4,239.7L692.3,240.9ZM684.3,227.8L683.8,227.6L684.0,227.2L684.3,227.8ZM682.3,219.1L682.4,218.7L682.6,218.7L682.3,219.1ZM683.5,218.1L683.7,217.9L683.5,218.2L683.5,218.1Z","ME":"M736.2,129.7L725.1,95.9L728.3,96.5L728.1,92.8L730.3,93.0L731.7,68.2L737.1,52.3L742.4,56.1L749.4,50.7L756.1,54.1L763.0,77.8L768.3,78.2L769.1,83.6L778.2,89.6L775.2,94.6L774.4,92.8L768.7,97.4L767.3,102.1L765.7,99.9L763.9,100.3L764.5,105.0L762.7,101.6L760.6,102.9L762.0,105.7L758.9,104.7L757.8,105.3L757.5,102.4L755.3,103.9L756.3,110.5L752.2,113.3L748.2,119.5L745.3,117.4L743.5,119.6L740.8,133.5L736.2,129.7ZM758.5,107.5L758.7,110.5L757.4,109.2L758.5,107.5ZM761.7,106.4L759.6,106.6L759.8,105.3L761.7,106.4ZM756.7,107.4L756.5,104.5L756.8,104.2L757.1,104.7L756.7,107.4ZM764.1,106.4L762.6,106.8L763.4,106.0L764.1,106.4ZM761.5,104.0L761.4,102.9L762.1,103.9L761.5,104.0ZM771.6,97.3L772.6,97.9L772.4,98.3L771.6,97.3ZM762.0,108.6L761.1,108.8L761.5,108.3L762.0,108.6ZM765.9,101.7L765.7,100.8L765.6,100.4L766.0,101.0L765.9,101.7ZM772.8,95.6L772.7,96.3L772.2,95.8L772.8,95.6ZM772.9,97.1L772.7,97.7L772.4,97.1L772.9,97.1ZM758.9,107.0L758.1,106.5L759.0,106.7L758.9,107.0ZM744.4,120.2L744.7,119.5L744.6,120.5L744.4,120.2ZM759.6,113.8L759.1,113.6L759.2,113.1L759.6,113.8ZM769.6,98.4L769.0,98.1L768.9,97.7L769.6,98.4ZM753.4,113.4L753.0,113.9L753.3,113.2L753.4,113.4ZM762.6,106.0L762.6,105.5L763.0,105.9L762.6,106.0ZM756.3,111.4L756.4,112.1L756.1,112.0L756.3,111.4ZM762.6,103.0L762.2,103.4L762.5,102.8L762.6,103.0ZM764.7,105.4L764.0,105.9L764.6,105.3L764.7,105.4ZM764.4,107.1L765.0,107.0L764.6,107.3L764.4,107.1ZM758.9,105.0L759.5,105.6L758.8,105.2L758.9,105.0ZM764.9,104.2L765.3,104.5L765.0,104.6L764.9,104.2ZM745.2,119.1L745.4,119.3L745.3,119.6L745.2,119.1ZM744.3,121.4L743.9,121.5L744.1,121.3L744.3,121.4ZM756.4,114.0L756.3,114.3L756.3,113.6L756.4,114.0ZM752.4,114.4L752.1,114.1L752.1,113.8L752.4,114.4ZM744.2,121.2L744.4,120.6L744.5,120.6L744.2,121.2ZM762.7,107.8L762.9,107.5L762.9,107.8L762.7,107.8ZM753.9,114.6L754.1,114.9L754.0,115.1L753.9,114.6ZM754.4,116.6L754.7,116.5L754.4,116.8L754.4,116.6ZM745.1,120.6L745.0,120.4L745.0,120.3L745.1,120.6ZM762.2,104.8L762.5,104.8L762.7,104.9L762.2,104.8ZM744.0,121.2L743.8,121.1L743.9,121.0L744.0,121.2ZM741.9,134.7L742.1,134.8L742.1,134.9L741.9,134.7ZM745.2,120.8L745.1,120.9L745.2,120.6L745.2,120.8ZM744.2,123.8L744.0,123.7L744.2,123.6L744.2,123.8ZM745.2,118.6L745.3,118.8L745.3,118.9L745.2,118.6ZM744.2,119.5L744.0,119.8L744.3,119.3L744.2,119.5ZM744.5,119.1L744.6,119.2L744.4,119.1L744.5,119.1ZM744.4,119.5L744.3,119.5L744.5,119.4L744.4,119.5ZM745.2,120.1L745.1,120.2L745.1,120.1L745.2,120.1Z","MI":"M579.8,190.6L534.7,195.4L541.1,177.8L534.7,153.6L538.8,137.7L544.9,131.6L544.2,138.2L545.0,139.6L546.2,135.4L546.0,139.8L546.9,130.2L552.4,127.4L549.6,121.0L553.9,120.1L572.0,127.1L574.9,143.7L568.3,155.3L569.2,156.8L572.4,157.7L576.0,152.0L575.0,151.4L583.2,148.9L590.0,166.0L589.8,172.8L587.8,175.2L588.1,172.4L585.8,173.3L579.8,190.6ZM518.2,136.1L517.8,131.4L515.0,131.9L515.8,125.9L511.4,121.9L485.6,116.3L481.6,112.4L510.6,93.9L514.0,95.0L507.9,99.2L505.6,106.8L509.2,103.3L513.5,104.3L519.9,110.7L528.1,111.1L534.3,106.3L548.9,102.8L548.9,108.1L560.0,106.1L559.1,112.4L563.7,115.8L554.3,115.2L553.6,119.2L543.7,115.6L534.2,119.4L530.6,126.0L531.0,120.7L526.1,125.1L525.0,122.3L518.2,136.1ZM494.7,87.7L501.4,82.8L504.1,81.7L498.6,87.5L494.7,87.7ZM565.5,114.4L566.9,112.7L569.2,114.6L564.1,115.5L565.5,114.4ZM543.5,121.7L544.7,124.3L543.2,125.0L543.5,121.7ZM558.7,119.8L556.9,120.6L555.6,119.3L558.7,119.8ZM538.6,134.2L539.5,133.5L539.9,134.9L538.6,134.2ZM537.7,135.4L538.3,135.9L537.5,136.1L537.7,135.4ZM540.8,128.1L540.9,129.0L540.1,127.9L540.8,128.1ZM544.2,120.5L544.4,121.4L543.9,120.4L544.2,120.5ZM542.0,122.1L542.3,123.0L542.0,123.1L542.0,122.1ZM564.6,113.2L565.0,112.9L565.4,113.2L564.6,113.2ZM562.7,113.8L562.2,113.6L562.5,113.3L562.7,113.8ZM574.5,131.0L574.7,130.7L575.0,131.1L574.5,131.0ZM515.3,94.8L514.7,94.7L515.5,94.6L515.3,94.8ZM565.8,113.9L565.3,113.9L565.6,113.6L565.8,113.9ZM545.6,121.3L546.1,120.8L545.9,121.3L545.6,121.3ZM528.7,128.2L529.0,127.9L529.0,128.4L528.7,128.2ZM564.5,113.7L564.0,113.6L564.2,113.4L564.5,113.7ZM554.8,118.6L555.4,118.7L555.2,118.9L554.8,118.6ZM541.3,126.9L541.5,127.4L541.2,127.0L541.3,126.9ZM530.3,127.1L530.5,126.5L530.4,127.1L530.3,127.1ZM529.9,125.9L529.5,126.1L529.4,125.9L529.9,125.9ZM554.7,116.9L555.0,116.6L555.1,116.7L554.7,116.9ZM555.4,116.8L555.6,116.6L555.6,116.9L555.4,116.8ZM551.9,119.0L552.1,119.0L552.1,119.1L551.9,119.0ZM540.2,123.0L540.1,123.4L540.1,123.0L540.2,123.0ZM572.8,128.5L573.0,128.4L573.0,128.6L572.8,128.5ZM529.5,127.8L529.5,128.0L529.3,127.5L529.5,127.8ZM545.2,137.8L545.1,137.7L545.2,137.6L545.2,137.8ZM574.2,149.5L574.4,149.5L574.3,149.6L574.2,149.5ZM570.1,156.6L570.3,156.6L570.1,156.7L570.1,156.6ZM555.5,119.3L555.3,119.0L555.6,119.2L555.5,119.3ZM543.0,120.4L543.1,120.3L543.0,120.5L543.0,120.4ZM543.0,120.9L542.8,120.9L542.8,120.8L543.0,120.9ZM530.1,127.5L530.2,127.3L530.2,127.5L530.1,127.5ZM541.9,121.6L542.0,121.7L541.8,121.7L541.9,121.6ZM574.7,152.0L574.8,152.2L574.7,152.1L574.7,152.0Z","MN":"M474.4,168.2L406.1,169.8L406.3,137.3L401.2,131.7L405.1,123.1L397.3,70.8L422.2,70.9L422.2,64.0L424.5,64.3L428.4,75.4L438.7,79.2L448.8,76.9L456.2,84.0L459.9,81.4L466.1,86.7L474.2,82.7L476.0,85.4L491.4,85.8L476.6,93.7L458.2,111.7L458.6,122.4L451.6,129.1L454.6,134.0L453.0,146.5L471.2,159.4L474.4,168.2Z","MO":"M496.1,294.3L431.9,296.7L431.6,248.5L424.3,241.5L426.8,235.2L420.2,232.6L415.1,222.8L470.1,220.8L474.5,224.9L475.8,236.6L485.1,244.8L486.4,250.8L494.1,251.7L491.3,263.2L503.8,272.1L506.5,283.7L510.7,284.9L509.5,291.9L506.1,294.4L504.5,292.5L503.1,302.9L493.4,303.6L497.6,297.8L496.1,294.3Z","MS":"M508.8,393.2L479.4,394.9L480.7,383.5L489.8,369.6L486.0,367.8L486.0,350.4L483.4,350.6L483.3,346.1L486.7,344.2L485.1,340.8L489.0,337.2L487.1,336.0L492.2,332.4L492.3,325.7L495.5,321.7L526.4,319.5L526.9,375.8L530.3,403.5L515.6,404.1L512.2,407.9L507.3,399.5L508.8,393.2ZM527.5,406.0L525.4,405.6L527.9,405.9L527.5,406.0ZM520.0,406.1L519.2,406.6L518.6,406.5L520.0,406.1ZM528.7,406.0L529.7,406.2L530.4,406.0L528.7,406.0ZM521.9,406.6L522.3,406.4L523.0,406.0L522.6,406.3L521.9,406.6Z","MT":"M196.0,135.1L186.3,108.6L181.0,112.0L178.6,109.6L185.3,91.1L180.0,89.1L171.0,73.9L169.2,63.5L173.0,45.6L238.1,57.6L315.5,66.8L309.5,138.4L220.6,127.5L219.2,136.9L215.8,131.2L214.0,134.8L203.8,132.6L196.0,135.1Z","NC":"M600.7,311.3L583.0,313.8L583.0,309.5L604.8,291.2L606.2,293.0L613.3,289.0L617.4,284.4L617.1,279.8L699.4,265.4L707.1,277.9L699.1,266.7L702.3,273.7L695.9,270.8L698.2,273.2L692.6,273.5L695.0,274.8L691.4,277.2L688.8,272.7L690.0,278.6L698.8,275.9L700.5,281.9L701.9,275.6L704.9,281.4L700.1,288.0L695.1,288.2L694.6,284.9L693.8,288.2L686.9,287.2L695.7,290.1L692.0,296.4L687.9,294.1L692.8,297.0L696.5,293.4L700.0,294.1L697.1,300.6L695.3,299.0L697.3,301.3L699.3,296.8L702.7,292.4L697.3,302.3L690.4,302.2L683.1,308.3L679.2,319.7L670.7,321.1L651.1,307.1L634.8,309.5L630.2,304.2L610.5,306.0L600.7,311.3ZM703.2,291.5L709.0,287.1L707.3,278.1L709.4,288.0L703.2,291.5ZM705.8,277.8L703.8,275.9L705.0,276.2L705.8,277.8Z","ND":"M405.0,125.8L310.9,121.4L315.5,66.8L397.3,70.8L405.0,125.8Z","NE":"M421.5,233.2L329.1,230.6L330.2,212.5L303.2,210.5L306.3,174.3L379.2,178.4L385.2,182.8L394.8,181.1L401.4,184.2L406.9,188.4L413.8,209.7L413.6,220.2L421.5,233.2Z","NH":"M719.6,145.5L717.7,117.0L722.7,111.5L721.0,98.2L725.1,95.9L735.3,129.0L740.5,133.8L734.7,142.2L719.6,145.5ZM741.9,135.1L742.0,134.9L741.9,135.1L741.9,135.1Z","NJ":"M704.7,218.8L702.7,216.1L699.2,216.5L691.8,209.8L701.0,198.1L692.4,189.9L696.5,176.6L708.5,180.5L705.6,190.7L709.7,190.6L710.9,203.0L704.7,218.8Z","NM":"M304.4,374.4L250.2,369.6L251.4,373.4L225.9,370.4L224.8,378.4L212.0,376.7L226.1,275.0L312.0,284.1L304.4,374.4Z","NV":"M140.3,297.3L81.7,209.5L95.3,156.9L172.8,174.3L152.8,277.7L150.7,280.5L142.4,277.7L140.3,297.3Z","NY":"M685.5,167.3L627.6,178.5L626.8,173.7L637.0,162.4L632.6,154.4L661.7,147.9L668.2,142.2L666.1,136.9L668.5,134.0L665.9,135.0L664.6,130.9L675.1,116.6L680.1,112.4L698.6,108.2L709.2,147.7L708.9,160.1L713.0,175.4L710.2,178.2L710.2,183.2L729.0,172.5L732.0,174.8L734.9,172.6L720.9,183.7L709.8,188.7L708.5,180.5L692.2,175.3L685.5,167.3ZM705.9,187.9L708.0,188.2L705.8,190.5L705.9,187.9ZM731.8,172.8L731.1,173.1L731.2,172.7L731.8,172.8ZM731.8,169.6L732.2,169.9L731.7,170.1L731.8,169.6ZM665.8,136.1L665.2,136.7L665.8,135.8L665.8,136.1ZM730.0,171.6L730.0,172.1L729.8,172.0L730.0,171.6ZM664.7,136.2L664.4,136.1L664.8,136.0L664.7,136.2ZM664.3,133.8L664.8,133.8L664.3,134.0L664.3,133.8ZM665.1,133.9L664.9,133.9L665.1,133.5L665.1,133.9ZM710.7,182.8L710.7,182.6L710.8,182.8L710.7,182.8ZM710.6,182.1L710.6,182.2L710.5,182.2L710.6,182.1ZM707.8,186.3L707.7,186.4L707.8,186.2L707.8,186.3Z","OH":"M589.3,246.9L576.1,244.8L572.0,239.5L567.0,240.4L561.7,193.7L579.6,190.7L593.4,195.3L603.0,191.9L617.7,180.6L621.7,204.6L619.7,223.6L609.7,231.6L609.6,238.0L605.6,236.7L602.9,247.9L599.6,248.9L594.5,243.3L589.3,246.9ZM589.6,191.4L590.1,192.0L589.4,191.8L589.6,191.4ZM588.0,189.7L588.1,190.1L587.8,190.0L588.0,189.7ZM588.2,190.3L588.3,190.7L588.0,190.5L588.2,190.3ZM588.5,190.9L588.0,191.0L588.5,190.8L588.5,190.9Z","OK":"M380.8,339.1L364.8,337.6L362.4,333.1L357.8,334.4L353.0,330.8L354.5,295.7L311.4,293.2L312.0,284.1L431.8,287.7L434.6,348.9L423.6,342.9L406.8,347.9L397.4,343.0L395.2,347.3L394.0,343.6L390.8,345.4L387.2,342.2L384.1,344.7L380.8,339.1Z","OR":"M133.8,166.1L40.4,140.3L41.2,125.7L52.1,108.6L65.8,69.1L76.5,73.1L78.1,83.5L83.3,87.1L89.9,85.9L107.1,90.7L125.7,89.9L151.1,95.9L154.6,101.2L140.7,123.1L144.1,128.3L133.8,166.1Z","PA":"M624.3,221.0L617.7,180.6L626.8,173.7L627.6,178.5L685.2,167.2L696.5,176.5L692.4,189.9L701.0,198.1L693.1,206.3L624.3,221.0Z","RI":"M733.8,167.0L731.4,155.9L736.7,154.3L740.1,160.0L737.4,160.4L738.5,166.2L733.8,167.0ZM740.7,159.7L742.5,162.6L740.7,160.7L741.1,163.4L739.7,164.2L740.1,163.6L740.0,160.9L740.7,159.7ZM739.1,164.4L738.9,162.1L739.6,163.7L739.1,164.4ZM737.9,168.9L738.6,170.1L737.9,170.4L737.9,168.9ZM739.3,161.1L739.5,161.0L739.5,161.9L739.3,161.1ZM739.6,163.4L739.9,163.4L739.9,163.5L739.6,163.4ZM739.9,160.6L739.7,160.6L739.7,160.5L739.9,160.6Z","SC":"M629.7,343.6L605.4,320.3L598.1,317.5L600.7,311.3L610.5,306.0L629.3,304.3L634.8,309.5L651.1,307.1L670.7,321.1L665.5,326.0L661.3,338.4L646.3,350.3L647.1,353.3L642.9,354.1L641.5,359.5L637.7,358.6L629.7,343.6Z","SD":"M379.2,178.4L306.3,174.3L310.9,121.4L405.0,125.8L401.2,131.7L406.3,137.3L404.2,170.6L406.3,176.6L403.6,183.6L406.2,188.1L395.7,181.4L385.2,182.8L379.2,178.4Z","TN":"M583.0,313.8L495.5,321.7L498.9,318.9L497.0,314.5L500.8,311.8L499.8,308.0L504.1,304.8L505.0,293.8L526.3,292.2L525.8,288.9L617.5,279.3L613.3,289.0L606.2,293.0L604.8,291.2L600.5,297.1L588.3,303.4L583.0,309.5L583.0,313.8Z","TX":"M326.4,416.0L307.4,415.5L298.9,428.7L285.5,421.4L278.2,414.3L273.8,397.1L249.8,371.2L304.4,374.4L310.8,293.1L354.5,295.7L353.0,330.8L357.8,334.4L362.4,333.1L364.8,337.6L375.2,340.6L380.7,339.1L382.7,344.1L394.0,343.6L395.2,347.3L397.4,343.0L406.8,347.9L423.7,342.9L436.2,350.3L441.3,350.1L441.9,378.3L450.4,395.4L446.0,419.7L431.3,425.9L435.9,422.4L431.2,422.8L431.9,418.2L428.3,419.8L429.9,425.7L425.2,430.4L430.8,426.0L432.2,426.4L421.8,434.8L406.0,443.5L412.4,438.7L404.3,440.2L401.7,437.6L405.6,442.5L398.7,442.7L399.3,446.3L392.6,448.7L395.7,448.4L393.0,453.4L392.4,453.4L392.0,452.5L391.6,452.4L388.3,452.8L391.9,455.7L389.4,462.1L384.6,461.4L389.1,463.4L386.7,470.9L390.9,484.0L393.2,484.9L389.5,488.8L361.7,478.2L356.3,466.9L355.6,457.1L343.6,443.9L336.4,426.1L326.4,416.0ZM393.2,484.8L389.5,471.3L389.6,465.3L390.1,461.7L393.9,453.4L395.1,453.1L398.0,448.0L405.7,443.4L396.6,451.2L391.0,460.9L389.8,469.7L392.5,480.5L393.2,484.8ZM394.4,453.2L395.0,452.3L394.9,451.8L395.2,452.0L395.1,452.8L394.4,453.2ZM393.7,453.6L392.4,453.7L393.7,453.5L393.7,453.6ZM392.3,456.1L392.5,456.0L392.3,456.7L392.3,456.1ZM388.4,467.3L388.2,467.3L388.2,466.9L388.4,467.3ZM388.4,467.4L388.3,467.9L388.3,467.4L388.4,467.4ZM388.5,468.3L388.3,468.1L388.5,468.1L388.5,468.3ZM392.0,452.6L391.9,452.7L391.7,452.5L392.0,452.6ZM393.9,452.1L394.1,452.4L393.9,452.2L393.9,452.1ZM388.6,467.0L388.5,466.6L388.6,466.6L388.6,467.0Z","UT":"M226.1,275.0L155.6,263.4L172.8,174.3L212.2,181.1L209.3,199.1L236.0,203.0L226.1,275.0Z","VA":"M699.4,265.4L588.7,283.6L596.0,280.0L610.5,263.3L615.5,268.8L633.8,260.3L639.7,239.2L645.3,241.5L647.8,233.1L649.9,234.3L654.9,225.9L654.7,220.4L662.9,225.0L665.8,221.2L674.5,227.5L672.5,237.0L676.2,235.9L689.2,242.7L688.5,248.0L681.7,244.6L689.5,248.7L690.8,253.1L688.5,251.9L687.9,255.1L691.6,258.7L685.9,255.8L682.1,256.7L685.5,256.3L689.7,261.3L696.2,259.2L699.4,265.4ZM702.4,237.3L695.9,256.2L695.8,241.0L702.4,237.3ZM691.6,241.0L692.1,241.3L691.9,241.7L691.6,241.0ZM693.1,243.0L692.7,243.0L692.7,242.7L693.1,243.0Z","VT":"M717.7,117.0L719.6,145.5L709.1,147.8L698.5,108.6L721.8,102.2L722.7,111.5L717.7,117.0Z","WA":"M78.6,75.6L65.3,68.2L67.5,61.8L67.3,65.2L70.5,61.4L67.7,60.1L68.0,57.1L71.5,57.3L68.9,54.8L67.6,56.6L68.9,29.6L76.4,36.1L86.8,38.8L88.5,42.8L91.2,41.6L91.0,45.5L87.6,48.4L88.5,46.6L88.3,45.7L82.0,52.8L91.9,45.2L92.0,48.3L91.0,48.2L88.8,56.1L87.7,54.3L85.7,57.4L86.0,53.9L85.0,55.3L84.5,57.1L86.4,58.8L91.8,55.8L96.2,44.6L95.2,40.4L94.8,43.5L93.4,41.6L95.8,39.5L94.4,36.2L92.7,35.3L95.5,36.0L96.7,33.9L94.8,25.9L161.4,43.1L151.1,95.9L125.7,89.9L107.1,90.7L89.9,85.9L83.3,87.1L78.1,83.5L78.6,75.6ZM92.6,43.6L94.5,43.8L93.9,46.0L92.2,44.4L90.8,39.2L93.6,36.5L92.6,43.6ZM90.8,52.5L91.4,54.9L89.4,55.4L90.8,52.5ZM88.9,31.3L89.7,34.7L87.8,31.2L88.9,31.3ZM90.0,34.5L92.3,34.3L91.3,35.7L90.0,34.5ZM90.4,33.1L89.8,32.2L91.1,32.7L90.4,33.1ZM91.7,30.3L91.7,30.7L89.8,31.4L91.7,30.3ZM94.1,30.4L94.8,32.5L93.9,30.9L94.1,30.4ZM93.0,33.2L93.7,33.6L93.0,34.0L93.0,33.2ZM91.9,33.0L92.5,33.6L91.9,33.8L91.9,33.0ZM87.8,56.2L87.7,57.1L87.3,55.9L87.8,56.2ZM86.3,58.4L86.4,57.3L86.8,57.6L86.3,58.4ZM90.4,30.4L89.7,30.1L90.5,29.9L90.4,30.4ZM86.8,57.3L86.9,56.6L87.3,57.2L86.8,57.3ZM90.9,25.3L91.6,25.0L91.7,25.5L90.9,25.3ZM93.8,34.4L94.7,34.3L94.6,34.7L93.8,34.4ZM92.3,29.6L91.7,29.6L91.8,29.4L92.3,29.6ZM93.7,32.8L94.0,32.6L94.1,33.0L93.7,32.8ZM88.5,40.2L88.7,40.4L88.2,40.4L88.5,40.2ZM90.7,52.1L90.6,51.8L90.9,51.9L90.7,52.1ZM85.3,55.7L85.3,55.4L85.4,55.4L85.3,55.7ZM91.5,29.1L91.3,28.9L91.7,29.0L91.5,29.1ZM88.4,30.6L88.9,30.9L89.0,31.1L88.4,30.6ZM95.2,32.6L95.0,32.5L95.1,32.4L95.2,32.6ZM95.1,44.2L95.0,44.4L94.9,44.2L95.1,44.2ZM87.2,58.1L87.1,58.1L87.2,57.9L87.2,58.1ZM93.3,30.9L93.1,31.1L93.2,31.0L93.3,30.9ZM94.6,33.2L94.7,33.1L94.7,33.2L94.6,33.2ZM88.5,30.3L87.7,29.7L88.8,30.6L88.5,30.3ZM92.6,29.9L92.7,30.1L92.5,30.0L92.6,29.9ZM89.6,31.5L89.5,31.6L89.5,31.5L89.6,31.5ZM95.0,34.9L94.9,34.7L94.9,34.7L95.0,34.9ZM92.3,32.8L92.2,32.6L92.3,32.7L92.3,32.8Z","WI":"M483.0,185.6L475.9,178.9L476.8,172.5L472.1,160.4L453.0,146.5L454.6,134.0L451.4,131.3L458.6,122.4L458.2,111.7L475.8,105.6L475.1,112.4L477.5,110.4L485.6,116.3L510.2,121.5L515.4,125.5L515.0,131.9L517.8,131.4L519.2,136.3L514.7,146.7L526.7,132.2L519.2,158.2L520.5,183.4L483.0,185.6ZM527.6,131.8L526.9,129.6L528.5,129.4L527.6,131.8ZM477.1,109.3L478.8,107.1L479.4,107.5L477.1,109.3ZM479.7,106.4L478.5,105.8L480.0,105.4L479.7,106.4ZM481.3,104.2L480.7,103.5L481.4,103.3L481.3,104.2ZM522.4,134.8L521.7,134.1L522.2,133.8L522.4,134.8ZM477.8,106.0L476.9,105.8L477.2,105.5L477.8,106.0ZM474.4,105.7L474.8,105.0L474.8,105.7L474.4,105.7ZM477.9,104.5L477.8,104.1L478.3,103.9L477.9,104.5ZM479.6,104.4L479.3,104.8L479.3,104.0L479.6,104.4ZM477.3,107.8L477.2,107.4L477.5,107.2L477.3,107.8ZM477.8,105.2L477.7,104.7L478.1,104.8L477.8,105.2ZM477.2,104.6L476.7,104.5L476.9,104.3L477.2,104.6ZM478.1,106.7L478.1,107.0L477.8,106.9L478.1,106.7ZM478.3,105.6L478.3,105.2L478.5,105.2L478.3,105.6ZM478.7,105.0L478.8,104.7L478.9,104.9L478.7,105.0ZM480.4,107.0L480.9,106.5L480.9,106.5L480.4,107.0ZM475.8,105.2L475.5,105.2L475.5,105.1L475.8,105.2ZM478.4,104.3L478.2,104.2L478.3,104.1L478.4,104.3ZM526.8,131.7L526.9,131.6L527.0,131.8L526.8,131.7ZM477.3,103.5L477.3,103.8L477.2,103.4L477.3,103.5ZM476.6,105.5L476.5,105.3L476.6,105.3L476.6,105.5ZM520.4,136.7L520.5,136.8L520.3,136.8L520.4,136.7ZM479.0,103.6L479.1,103.5L479.0,103.7L479.0,103.6Z","WV":"M617.1,268.4L602.0,257.3L599.4,248.8L604.7,244.6L605.6,236.7L609.6,238.0L609.7,231.6L619.7,223.6L620.3,205.1L624.3,221.0L638.5,218.6L640.0,227.9L648.4,218.2L651.5,220.0L656.2,215.8L661.2,216.6L662.9,225.0L654.7,220.4L654.9,225.9L649.9,234.3L647.8,233.1L645.3,241.5L639.7,239.2L633.8,260.3L617.1,268.4Z","WY":"M303.2,210.5L209.3,199.1L220.6,127.5L309.3,138.4L303.2,210.5Z"};
var realStateLabels = {"AK":[191.1,529.6],"AL":[552.9,358.7],"AR":[463.8,328.4],"AZ":[177.5,321.9],"CA":[71.8,236.8],"CO":[279.4,243.7],"CT":[722.0,167.3],"DE":[694.7,221.0],"FL":[641.5,433.7],"GA":[602.9,348.6],"HI":[515.0,576.1],"IA":[449.3,198.3],"ID":[166.9,117.6],"IL":[502.7,236.6],"IN":[545.7,220.5],"KS":[379.3,266.8],"KY":[572.8,266.9],"LA":[464.6,394.1],"MA":[728.0,151.5],"MD":[676.1,225.4],"ME":[753.8,91.2],"MI":[522.0,113.8],"MN":[431.3,117.1],"MO":[462.2,257.5],"MS":[506.4,359.2],"MT":[247.4,99.9],"NC":[648.2,293.2],"ND":[356.9,96.1],"NE":[357.3,199.0],"NH":[725.8,123.0],"NJ":[703.6,194.4],"NM":[263.7,326.9],"NV":[131.9,243.6],"NY":[678.2,151.2],"OH":[592.3,214.1],"OK":[393.4,313.3],"OR":[96.4,115.9],"PA":[658.3,194.0],"RI":[735.4,163.3],"SC":[640.6,332.2],"SD":[356.6,154.0],"TN":[549.4,300.3],"TX":[355.2,386.9],"UT":[196.6,233.2],"VA":[662.2,252.5],"VT":[711.7,131.3],"WA":[113.5,60.7],"WI":[485.3,141.4],"WV":[628.1,237.4],"WY":[260.4,168.7]};


var reciprocityData = {
  MI: {
    title: "Michigan CPL Reciprocity & Travel Guide",
    verifiedDate: "May 2, 2026",
    sourceNote: "Recognition does not mean identical laws. Follow the law of the state you are physically in. Michigan MSP advises CPL holders to check the destination state directly before travel.",
    recognized: [
      "AL","AK","AZ","AR","CO","FL","GA","ID","IN","IA","KS","KY","LA","ME","MN","MS",
      "MO","MT","NE","NH","NM","NC","ND","OH","OK","PA","SC","SD","TN","TX","UT","VA","VT",
      "WA","WV","WI","WY"
    ],
    restricted: ["NV"],
    notRecognized: ["CA","CT","DE","HI","IL","MD","MA","NJ","NY","OR","RI"],
    warnings: [
      "This is an outbound Michigan CPL travel reference, not a substitute for destination-state law.",
      "Recognition can depend on residency, age, permit type, current state law, and state-specific restrictions.",
      "Nevada has conflicting official online references regarding Michigan CPL recognition; this app flags Nevada as VERIFY before travel, not clean green.",
      "A recognized permit does not override prohibited places, vehicle rules, alcohol rules, duty-to-inform rules, private-property rules, federal property, court rules, tribal property, or local restrictions.",
      "Before traveling, verify the destination state using official state resources."
    ]
  }
};

function makeProfile(name, level, summary, quick, alerts, sections, decisionBlocks, scenarios, mistakes, checklist, plainEnglishReality) {
  return {
    name: name,
    lastReviewed: String(level).includes("Expanded") || String(level).includes("Law-Backed") ? "May 4, 2026" : "Starter profile — verify before reliance",
    profileStatus: level,
    summary: summary,
    quick: quick,
    travelAlerts: alerts || [],
    legalSections: sections || [],
    decisionBlocks: decisionBlocks || [],
    scenarios: scenarios || [],
    commonMistakes: mistakes || [],
    beforeCarryChecklist: checklist || [],
    plainEnglishReality: plainEnglishReality || []
  };
}

function starterProfile(abbr, name, recognizedText) {
  return makeProfile(
    name,
    "Starter",
    name + " is included in the state-law engine as a starter profile. This panel is designed to be expanded to Michigan-level detail. Verify official " + name + " law before carrying or transporting.",
    {
      reciprocity: recognizedText || "Verify permit recognition before travel.",
      permitlessCarry: "Verify current permitless carry status.",
      concealedCarry: "Verify current concealed carry rules.",
      openCarry: "Verify current open carry rules.",
      vehicleCarry: "Verify vehicle carry and transport rules.",
      dutyToInform: "Verify police-contact and duty-to-inform rules.",
      privateSigns: "Verify private property and signage rules.",
      forceLaw: "Verify current self-defense law."
    },
    [
      "Do not assume Michigan rules apply in " + name + ".",
      "Verify recognition, vehicle carry, prohibited places, schools, private property, and duty-to-inform rules before travel.",
      "Check current official state sources before relying on this summary."
    ],
    [
      {
        title: "State Profile Pending Full Expansion",
        risk: "Verify Before Travel",
        body: [
          "This state profile is active so the map can populate a state intelligence panel.",
          "The detailed legal buildout for this state should include permit recognition, permitless carry, prohibited places, vehicle carry, school rules, private property rules, signage, alcohol rules, federal property, magazine and ammunition restrictions where relevant, and use-of-force law.",
          "Until this state is fully expanded, use the map status as a starting warning only."
        ],
        source: "Starter profile. Official source verification required."
      }
    ],
    [
      {
        title: "Before Carrying in " + name,
        steps: [
          "1. Verify whether Michigan CPL is recognized.",
          "2. Verify whether permitless carry applies and whether you qualify.",
          "3. Verify prohibited places.",
          "4. Verify vehicle carry and transport rules.",
          "5. Verify school, alcohol, private property, and federal-location restrictions.",
          "6. Verify police-contact and duty-to-inform rules."
        ]
      }
    ],
    [
      {
        title: "Crossing State Lines",
        summary: "Rules change immediately when you cross into another state.",
        guidance: [
          "Do not rely on Michigan assumptions.",
          "Check recognition before travel.",
          "Check vehicle carry before entering the state.",
          "Check prohibited places before arriving at your destination."
        ]
      }
    ],
    [
      "Assuming Michigan CPL rules apply outside Michigan.",
      "Ignoring vehicle carry and transport differences.",
      "Ignoring prohibited places.",
      "Failing to check duty-to-inform requirements.",
      "Relying on old reciprocity data."
    ],
    [
      "Permit recognition checked.",
      "Vehicle carry checked.",
      "Prohibited places checked.",
      "School rules checked.",
      "Private property/signage checked.",
      "Duty-to-inform checked.",
      "Magazine/ammo restrictions checked."
    ],
    [
      {
        myth: "If the map is green, I can carry anywhere in the state.",
        reality: "No. Green only means the Michigan CPL is treated as recognized in this app's travel engine. You still must follow that state's law."
      }
    ]
  );
}

var stateLawData = {
  MI: makeProfile(
    "Michigan",
    "Elite Level – Michigan CPL Core State",
    "Michigan is the core state for Prime Defense members. Michigan is a CPL-based concealed carry state with strong self-defense protections, but it also has specific carry restrictions, vehicle rules, police-contact duties, prohibited-location laws, storage duties, and post-incident risks. This elite Michigan profile is built to help members understand where the law creates exposure before they make a carry, transport, storage, or self-defense decision.",
    {
      reciprocity: "Home state profile. Michigan CPL controls Michigan concealed pistol carry for eligible license holders, but location restrictions and other state/federal laws still apply.",
      permitlessCarry: "No general permitless concealed pistol carry. Michigan generally requires a CPL to carry a concealed pistol.",
      concealedCarry: "MCL 28.425c and Michigan CPL framework: a valid CPL is generally required to carry a concealed pistol.",
      openCarry: "Open carry may be lawful for eligible persons, but restricted locations, vehicle rules, brandishing, disturbing-the-peace concerns, and private property still matter.",
      vehicleCarry: "MCL 750.227 and Michigan transport rules: carrying a pistol in a vehicle without a CPL is a major legal trap unless strict transport rules apply.",
      dutyToInform: "MCL 28.425f: a CPL holder carrying concealed and stopped by a peace officer must immediately disclose that they are carrying.",
      privateSigns: "Private property owners may require you to leave. Refusal after notice can create trespass exposure.",
      forceLaw: "MCL 780.972: deadly force requires an honest and reasonable belief that it is necessary to prevent imminent death, great bodily harm, or sexual assault."
    },
    [
      "Restricted & sensitive locations: schools, hospitals, sports arenas, certain bars, places of worship without permission, casinos, courts, federal property, school zones, and posted/private property all require careful analysis.",
      "Vehicle carry is one of the biggest Michigan legal traps. Without a CPL, do not treat a pistol in a vehicle as carry; treat it as lawful transport only.",
      "Duty to inform is immediate during a lawful police stop when carrying concealed under a CPL. Hands visible. No reaching.",
      "Open carry does not solve every location issue and does not override vehicle rules, schools, private property, federal property, courts, or brandishing laws.",
      "Secure storage and child access rules are now a major Michigan responsibility area.",
      "Self-defense law is not a permission slip to escalate, chase, threaten, punish, or use force over property."
    ],
    [
      {
        title: "Michigan CPL Authority",
        risk: "Core Carry Rule",
        body: [
          "STATUTE / SOURCE: MCL 28.425c; Michigan CPL framework.",
          "SUMMARY: Michigan generally requires a valid CPL to carry a concealed pistol. A CPL allows concealed carry only within the limits of Michigan law.",
          "GUIDANCE: A CPL is not unlimited permission. The user must still verify location, vehicle status, police-contact duties, prohibited-person status, and federal/private-property restrictions before carrying."
        ],
        source: "MCL 28.425c; Michigan Firearms Laws publication."
      },
      {
        title: "Restricted & Sensitive Locations",
        risk: "Location Restriction",
        body: [
          "STATUTE: MCL 28.425o.",
          "SUMMARY: Michigan restricts CPL holders from carrying concealed in designated pistol-free zones, subject to statutory language and exceptions.",
          "GUIDANCE: Treat schools, school property, child care centers, sports arenas/stadiums, certain bars/taverns, places of worship without permission, entertainment facilities, hospitals, and college/university dormitories/classrooms as verify-before-entry locations. Do not rely on memory or internet summaries for close calls."
        ],
        source: "MCL 28.425o; Michigan State Police prohibited premises guidance."
      },
      {
        title: "General Firearm-Prohibited Premises",
        risk: "Separate Location Law",
        body: [
          "STATUTE: MCL 750.234d.",
          "SUMMARY: Michigan has a separate statute restricting possession of firearms on certain premises. This statute is different from the CPL-specific pistol-free-zone statute.",
          "GUIDANCE: A CPL may affect the analysis in some situations, but do not assume it overrides every premises restriction. Identify the location first, then determine which statute applies."
        ],
        source: "MCL 750.234d."
      },
      {
        title: "Duty to Inform Police",
        risk: "Immediate Police-Contact Duty",
        body: [
          "STATUTE: MCL 28.425f.",
          "SUMMARY: A CPL holder who is carrying a concealed pistol and is stopped by a peace officer must immediately disclose that they are carrying a concealed pistol upon their person or in their vehicle.",
          "GUIDANCE: Keep hands visible. Do not reach. Recommended wording: Officer, I have a CPL and I am currently carrying. How would you like me to proceed? Wait for instructions before touching wallet, purse, glove box, center console, registration, or firearm."
        ],
        source: "MCL 28.425f."
      },
      {
        title: "Vehicle Carry With a CPL",
        risk: "Traffic Stop / Vehicle Carry Risk",
        body: [
          "STATUTE / SOURCE: MCL 28.425f; Michigan CPL vehicle-carry framework.",
          "SUMMARY: A valid CPL generally allows a license holder to carry a concealed pistol in a vehicle, but disclosure, location restrictions, prohibited-person rules, and officer-safety conduct still apply.",
          "GUIDANCE: During a stop, visible hands and controlled movement are critical. Do not reach near the firearm, center console, glove box, bag, or pocket until instructed."
        ],
        source: "MCL 28.425f; Michigan Firearms Laws publication."
      },
      {
        title: "Transport Without a CPL",
        risk: "Top Arrest Trap",
        body: [
          "STATUTE / SOURCE: MCL 750.227; Michigan pistol transport framework.",
          "SUMMARY: Carrying a pistol in a vehicle without a CPL can create serious criminal exposure unless the person is transporting lawfully under the applicable statutory rules and exceptions.",
          "GUIDANCE: Without a CPL, treat a pistol in a vehicle as transport only: unloaded, secured, inaccessible, and connected to a lawful purpose. Do not keep it loaded in a glove box, center console, backpack, purse, door pocket, or within ready reach."
        ],
        source: "MCL 750.227; Michigan Firearms Laws publication."
      },
      {
        title: "Open Carry Reality",
        risk: "Often Misunderstood",
        body: [
          "STATUTE / SOURCE: Michigan firearms law framework; MCL 750.234d; MCL 750.234e; vehicle carry rules.",
          "SUMMARY: Open carry may be lawful for eligible persons in some circumstances, but it does not override restricted locations, vehicle carry laws, school rules, brandishing laws, private property, or federal property.",
          "GUIDANCE: Open carry should not be used to test boundaries, make a point, pressure a business, or escalate a tense encounter. Once a person enters a vehicle, the legal analysis changes."
        ],
        source: "Michigan Firearms Laws publication; MCL 750.234d; MCL 750.234e."
      },
      {
        title: "Brandishing / Defensive Display",
        risk: "Common Criminal Allegation",
        body: [
          "STATUTE: MCL 750.234e.",
          "SUMMARY: Michigan prohibits willfully and knowingly brandishing a firearm in public, except as otherwise provided by law, including lawful self-defense circumstances.",
          "GUIDANCE: Do not display, wave, point, expose, or touch a firearm to scare someone, win an argument, stop a verbal dispute, protect pride, or intimidate. If display was necessary due to an immediate threat, call 911 first and report the attack or attempted attack."
        ],
        source: "MCL 750.234e."
      },
      {
        title: "Schools and Weapon-Free School Zones",
        risk: "Extreme Location Risk",
        body: [
          "STATUTE: MCL 28.425o; MCL 750.237a.",
          "SUMMARY: Michigan school property and weapon-free school-zone rules can involve multiple statutes and fact-specific exceptions.",
          "GUIDANCE: School buildings, parking lots, school events, school vehicles, student pickup/drop-off, and school-controlled property should be treated as verify-before-entry areas. Do not rely on what another parent, online comment, or old article says."
        ],
        source: "MCL 28.425o; MCL 750.237a."
      },
      {
        title: "Alcohol Locations and Impairment",
        risk: "Judgment / Location Risk",
        body: [
          "STATUTE / SOURCE: MCL 28.425o; MCL 750.234d; Michigan alcohol/carry framework.",
          "SUMMARY: Certain bar/tavern and alcohol-related premises can be restricted depending on the statutory category, and impairment creates serious legal, tactical, and evidentiary risk.",
          "GUIDANCE: If drinking is part of the plan, carrying should not be. Restaurants, bars, breweries, event venues, stadiums, and private events should be checked before entry."
        ],
        source: "MCL 28.425o; MCL 750.234d; Michigan Firearms Laws publication."
      },
      {
        title: "Casinos",
        risk: "Special Michigan Trap",
        body: [
          "STATUTE / SOURCE: Michigan State Police prohibited premises guidance; gaming/property-control framework.",
          "SUMMARY: Michigan State Police guidance flags casinos as prohibited premises and notes seizure risk for pistols in casinos whether carried concealed or exposed.",
          "GUIDANCE: Do not assume a CPL authorizes casino carry. Casinos can involve gaming rules, private property, tribal property, alcohol, surveillance, security screening, and separate regulatory issues."
        ],
        source: "Michigan State Police prohibited premises guidance."
      },
      {
        title: "Places of Worship",
        risk: "Permission Required / Property Control",
        body: [
          "STATUTE: MCL 28.425o; MCL 750.234d.",
          "SUMMARY: Michigan law includes restrictions involving churches and other houses of religious worship, with statutory language and permission issues that must be checked carefully.",
          "GUIDANCE: Do not assume carry is allowed at a place of worship. Verify permission or policy from the proper authority, especially for events, schools, daycares, security teams, and posted property."
        ],
        source: "MCL 28.425o; MCL 750.234d."
      },
      {
        title: "Federal Buildings / Post Offices",
        risk: "Federal Law Overlay",
        body: [
          "STATUTE / SOURCE: Federal facility and postal property framework.",
          "SUMMARY: Michigan CPL authority does not override federal property restrictions.",
          "GUIDANCE: Post offices, federal courthouses, federal agency buildings, secure federal facilities, and posted federal property must be checked separately from Michigan law."
        ],
        source: "Federal facility and postal property framework."
      },
      {
        title: "Secure Storage / Child Access",
        risk: "Storage and Unauthorized Access",
        body: [
          "STATUTE: MCL 28.429.",
          "SUMMARY: Michigan secure storage law requires firearms to be secured when minors are, or are likely to be, present under the statutory conditions.",
          "GUIDANCE: Vehicle storage, nightstands, purses, backpacks, range bags, closets, and bedside tables are common failure points. A locked vehicle is not a gun safe. If a firearm is unattended, ask who could access it."
        ],
        source: "MCL 28.429."
      },
      {
        title: "EMD / Stun Gun Carry",
        risk: "Less-Lethal Tool Misunderstanding",
        body: [
          "STATUTE / SOURCE: Michigan CPL and electro-muscular disruption device framework.",
          "SUMMARY: Michigan law includes electro-muscular disruption devices in parts of the defensive-tool and prohibited-premises framework.",
          "GUIDANCE: Less lethal does not mean consequence-free. Possession, carry method, disclosure, prohibited premises, and use-of-force principles still matter."
        ],
        source: "Michigan EMD/stun gun statutory framework; Michigan State Police prohibited premises guidance."
      },
      {
        title: "Prohibited Persons / PPOs / Domestic Violence",
        risk: "Possession Eligibility Risk",
        body: [
          "STATUTE / SOURCE: Michigan and federal prohibited-person framework.",
          "SUMMARY: A person may be legally prohibited from possessing or carrying due to felony history, certain misdemeanors, domestic violence restrictions, PPOs, bond conditions, probation/parole restrictions, court orders, mental health adjudications, or federal prohibitions.",
          "GUIDANCE: Do not assume physical possession of a CPL card means current eligibility. If any court order, pending case, PPO, domestic dispute, bond condition, or prior conviction is involved, get qualified legal guidance before possessing or carrying."
        ],
        source: "Michigan and federal prohibited-person framework."
      },
      {
        title: "ERPO / Red Flag Orders",
        risk: "Court Order Emergency",
        body: [
          "STATUTE: Michigan Extreme Risk Protection Order Act; MCL 691.1801 to MCL 691.1821 framework.",
          "SUMMARY: Michigan ERPO law can temporarily restrict possession, purchase, and access to firearms under court order.",
          "GUIDANCE: If served with an ERPO or firearm-related court order, comply safely at the scene, do not hide or transfer firearms casually, do not argue during service, and contact qualified counsel immediately."
        ],
        source: "MCL 691.1801 to MCL 691.1821."
      },
      {
        title: "Pistol Purchase / Transfer / Registration Basics",
        risk: "Paperwork and Transfer Risk",
        body: [
          "STATUTE / SOURCE: Michigan pistol purchase, transfer, and record framework.",
          "SUMMARY: Michigan pistol acquisition and transfer rules involve paperwork and record obligations that depend on the transaction and the person's status.",
          "GUIDANCE: Private sales, gifts, inherited firearms, family transfers, out-of-state purchases, and used pistols require process verification before transfer. Keep records organized."
        ],
        source: "Michigan Firearms Laws publication."
      },
      {
        title: "Hunting / DNR / Public Land Context",
        risk: "CPL Does Not Replace DNR Rules",
        body: [
          "STATUTE / SOURCE: Michigan DNR and firearms transport/hunting framework.",
          "SUMMARY: Hunting, public land, state land, ORVs, boats, blinds, seasons, species rules, and firearm-type restrictions can affect what is lawful.",
          "GUIDANCE: A CPL does not replace hunting rules, trespass law, DNR regulations, or public-land restrictions. Check DNR rules separately when carrying or transporting during outdoor activity."
        ],
        source: "Michigan DNR and firearms transport/hunting framework."
      },
      {
        title: "Use of Deadly Force",
        risk: "Life-Altering Legal Standard",
        body: [
          "STATUTE: MCL 780.972.",
          "SUMMARY: Michigan law allows deadly force under statutory conditions when a person honestly and reasonably believes it is necessary to prevent imminent death, great bodily harm, or sexual assault, and the person is not engaged in the commission of a crime.",
          "GUIDANCE: Deadly force is not for arguments, insults, warning shots, property disputes, road rage, punishment, intimidation, or ego. The legal question is whether the facts support an honest and reasonable belief that deadly force was immediately necessary."
        ],
        source: "MCL 780.972."
      },
      {
        title: "Defense of Others",
        risk: "Third-Party Uncertainty",
        body: [
          "STATUTE: MCL 780.972.",
          "SUMMARY: Defense of another person can be analyzed under the same honest, reasonable, imminent-threat framework, but third-party situations are often factually unclear.",
          "GUIDANCE: Do not jump into a third-party fight unless the legal threshold is clearly met. You may not know who started it, who escalated it, who is armed, or whether the person you are helping is legally innocent."
        ],
        source: "MCL 780.972."
      },
      {
        title: "Civil Liability / Wrongful Death Exposure",
        risk: "Aftermath and Financial Risk",
        body: [
          "STATUTE / SOURCE: MCL 780.972; MCL 600.2922 framework; Michigan civil liability framework.",
          "SUMMARY: A defensive incident can create civil exposure even when criminal charges are not filed or are later dismissed.",
          "GUIDANCE: The defender's behavior before, during, and after the incident may all matter. Angry texts, social posts, prior threats, inconsistent statements, reckless behavior, or bad training comments can become evidence."
        ],
        source: "MCL 780.972; MCL 600.2922 framework."
      },
      {
        title: "Aftermath / Attorney Contact",
        risk: "Post-Incident Statement Risk",
        body: [
          "STATUTE / SOURCE: General criminal procedure, evidence, and self-defense investigation framework.",
          "SUMMARY: Statements after a defensive incident can become evidence and may be made while the defender is under extreme stress.",
          "GUIDANCE: Call 911, request police and medical, identify the attacker/evidence/witnesses if necessary, state that you will cooperate after counsel, then stop talking. Do not post online, argue with bystanders, or give repeated explanations."
        ],
        source: "Prime Defense aftermath protocol; general criminal procedure/evidence framework."
      }
    ],
    [
      {
        title: "Michigan Carry Decision Checklist",
        steps: [
          "1. Am I legally eligible to possess and carry today?",
          "2. Is my CPL valid, current, and physically available?",
          "3. Am I under any PPO, bond condition, ERPO, probation/parole condition, domestic violence restriction, or court order?",
          "4. Is this location restricted under MCL 28.425o, MCL 750.234d, school-zone law, court rules, casino/property rules, federal law, or private policy?",
          "5. Am I carrying in a vehicle, and do I understand the vehicle rules?",
          "6. Do I know my immediate police disclosure script?",
          "7. Am I sober, calm, and prepared to avoid conflict?",
          "8. If anything is uncertain, do not enter armed until verified."
        ]
      },
      {
        title: "Traffic Stop Script",
        steps: [
          "1. Pull over safely.",
          "2. Turn the vehicle off if appropriate.",
          "3. Keep both hands visible.",
          "4. Immediately disclose: Officer, I have a CPL and I am currently carrying. How would you like me to proceed?",
          "5. Do not reach for anything until instructed.",
          "6. Move slowly and narrate only as needed."
        ]
      },
      {
        title: "Restricted Location Decision",
        steps: [
          "1. Is it school-related, court-related, federal, hospital, casino, sports arena, place of worship, alcohol-centered, college/university, daycare, posted, or security-screened?",
          "2. Does MCL 28.425o apply?",
          "3. Does MCL 750.234d apply?",
          "4. Does federal law, private property policy, employer policy, or event security apply?",
          "5. If uncertain, do not enter armed."
        ]
      },
      {
        title: "No Shots Fired / Defensive Display Decision",
        steps: [
          "1. Was there an immediate unlawful threat?",
          "2. Was display necessary to stop the threat right now?",
          "3. Was I acting from fear and necessity, not anger or intimidation?",
          "4. Can I safely leave, lock a door, drive away, or call 911 instead?",
          "5. If displayed lawfully, call 911 first and report the attack or attempted attack.",
          "6. Do not say: I showed it to scare him."
        ]
      },
      {
        title: "After a Defensive Incident",
        steps: [
          "1. Get safe and make sure the threat has stopped.",
          "2. Call 911 and request police and medical.",
          "3. Keep hands visible when police arrive.",
          "4. Identify the attacker, evidence, and witnesses only as necessary.",
          "5. State that you will cooperate fully after speaking with counsel.",
          "6. Stop talking and do not post online."
        ]
      }
    ],
    [
      {
        title: "Traffic Stop With CPL",
        summary: "Michigan's immediate disclosure rule makes traffic stops one of the most important CPL scenarios.",
        guidance: [
          "Disclose immediately.",
          "Keep hands visible.",
          "Do not reach for license, registration, wallet, phone, or firearm until instructed.",
          "Ask how the officer wants you to proceed."
        ]
      },
      {
        title: "School Pickup or Drop-Off",
        summary: "School property and school-zone issues are among the most confusing Michigan carry topics.",
        guidance: [
          "Verify MCL 28.425o and MCL 750.237a before entering school property armed.",
          "Parking lots, events, school vehicles, and extracurricular activities can change the analysis.",
          "When uncertain, choose the safest lawful option."
        ]
      },
      {
        title: "Restaurant, Bar, or Brewery",
        summary: "Alcohol-related locations require more than a quick yes/no answer.",
        guidance: [
          "Check whether the location is a pistol-free zone under MCL 28.425o.",
          "Check whether MCL 750.234d or private property rules apply.",
          "Do not carry while impaired. If alcohol is part of the plan, carrying should not be."
        ]
      },
      {
        title: "Casino Night",
        summary: "Casinos are a special trap area in Michigan and are specifically flagged by Michigan State Police guidance.",
        guidance: [
          "Do not assume your CPL authorizes casino carry.",
          "Expect security, surveillance, alcohol, private property rules, gaming rules, and possible seizure risk.",
          "Verify before arrival, not at the door."
        ]
      },
      {
        title: "Road Rage or Parking Lot Confrontation",
        summary: "These situations often make both sides look like aggressors and create bad evidence.",
        guidance: [
          "Do not gesture, follow, challenge, or get out to argue.",
          "Create distance and leave if safe.",
          "Call 911 if actively threatened.",
          "Do not display a firearm unless the immediate threat legally justifies it."
        ]
      },
      {
        title: "Home Defense",
        summary: "Michigan self-defense law may protect lawful defenders, but target identification and post-incident discipline still matter.",
        guidance: [
          "Identify before acting.",
          "Do not shoot at sounds or shadows.",
          "Use lights, barriers, verbal commands, and 911 when safe.",
          "Do not chase after the threat has left."
        ]
      },
      {
        title: "Unsecured Firearm in Vehicle",
        summary: "Vehicle storage is a major theft and child-access risk.",
        guidance: [
          "Avoid leaving firearms in vehicles whenever possible.",
          "If unavoidable, lock and secure in a purpose-built container.",
          "Do not rely on a glove box or center console as responsible storage."
        ]
      }
    ],
    [
      "Failing to immediately disclose during a police stop.",
      "Reaching during a traffic stop before being instructed.",
      "Carrying into a restricted or sensitive location without checking MCL 28.425o and MCL 750.234d.",
      "Assuming open carry avoids all restrictions.",
      "Carrying in a vehicle without understanding CPL vs transport rules.",
      "Assuming a private sign or instruction to leave can be debated at the door.",
      "Carrying while drinking or impaired.",
      "Displaying a firearm to scare someone during a non-deadly dispute.",
      "Using or threatening deadly force over property, anger, or road rage.",
      "Talking too much after an incident.",
      "Posting about an incident online.",
      "Ignoring PPOs, ERPOs, domestic violence restrictions, bond conditions, or other eligibility problems.",
      "Leaving a firearm unsecured where a child, thief, guest, or prohibited person can access it."
    ],
    [
      "CPL valid and physically available.",
      "State ID/driver license available.",
      "Eligibility confirmed today.",
      "No PPO, ERPO, bond condition, domestic violence restriction, or court order issue.",
      "Restricted & sensitive locations checked.",
      "Vehicle carry/transport rules checked.",
      "Duty-to-inform script ready.",
      "Private property/posting checked.",
      "Federal property checked separately.",
      "Safe storage plan in place.",
      "Emergency contact/legal-defense contact ready.",
      "Aftermath statement plan understood."
    ],
    [
      {
        myth: "My CPL means I can carry anywhere in Michigan.",
        reality: "No. Michigan has restricted and sensitive locations, pistol-free zones, federal property limits, court rules, private property rules, and vehicle-related restrictions."
      },
      {
        myth: "Open carry avoids CPL restrictions.",
        reality: "No. Open carry can still be restricted by location, vehicle rules, schools, private property, courts, federal property, and brandishing/display laws."
      },
      {
        myth: "If I do not fire, it is not serious.",
        reality: "A defensive display can still create criminal allegations if it was not legally justified."
      },
      {
        myth: "Stand your ground means I can use force whenever I feel threatened.",
        reality: "No. Michigan deadly-force law still requires an honest and reasonable belief that force is necessary to prevent imminent death, great bodily harm, or sexual assault."
      },
      {
        myth: "If the shooting is justified, I do not need to worry about civil court.",
        reality: "Civil claims can still be filed, and the defender's conduct before, during, and after the incident may all matter."
      }
    ]
  ),

  OH: makeProfile(
    "Ohio",
    "Law-Backed Ultra Expanded Travel State",
    "Ohio is one of the most important travel states for Michigan CPL holders. Ohio allows permitless concealed carry for a qualifying adult, but users must still follow Ohio eligibility rules, restricted-location statutes, school safety zone laws, alcohol-location rules, private property rules, vehicle rules, federal property restrictions, and self-defense standards.",
    {
          "reciprocity": "Michigan CPL treated as recognized in this app travel engine. Ohio also allows permitless concealed carry for a qualifying adult.",
          "permitlessCarry": "ORC 2923.111: qualifying adults may carry a concealed handgun without obtaining an Ohio concealed handgun license.",
          "concealedCarry": "ORC 2923.111 and ORC 2923.126: concealed carry may be lawful, but restricted locations and eligibility rules still apply.",
          "openCarry": "Ohio generally recognizes open carry, but location restrictions, private property, vehicles, and police contact still matter.",
          "vehicleCarry": "ORC 2923.16 and ORC 2923.111: vehicle carry must still comply with Ohio law.",
          "dutyToInform": "Ohio no longer uses the old automatic prompt-notification model. If an officer asks whether you are carrying, answer truthfully.",
          "privateSigns": "ORC 2923.126: private property owners and employers may post against firearms.",
          "forceLaw": "Ohio self-defense law is fact-specific. Force must still be legally justified."
    },
    [
          "Ohio permitless carry is not ruleless carry.",
          "Ohio law controls while the user is physically in Ohio.",
          "A green map status only means recognition. It does not mean every location is lawful.",
          "Every major Ohio section below is tied to an Ohio statute or legal source.",
          "Users should verify current law before relying on any summary."
    ],
    [
          {
                "title": "Permitless Carry / Qualifying Adult",
                "risk": "Core Eligibility Rule",
                "body": [
                      "STATUTE / SOURCE: ORC 2923.111.",
                      "SUMMARY: A qualifying adult is not required to obtain a concealed handgun license to carry a concealed handgun in Ohio, as long as the handgun is not a restricted firearm.",
                      "GUIDANCE: This does not apply to everyone. The user must still be legally eligible, old enough, not prohibited, sober, and not otherwise disqualified."
                ],
                "source": "ORC 2923.111."
          },
          {
                "title": "Qualifying Adult Requirements",
                "risk": "Disqualification Risk",
                "body": [
                      "STATUTE / SOURCE: ORC 2923.111; ORC 2923.125 eligibility framework.",
                      "SUMMARY: Ohio permitless carry applies only to a qualifying adult. A prohibited person cannot rely on permitless carry.",
                      "GUIDANCE: If the user has a protection order, domestic violence issue, pending criminal case, bond condition, probation condition, felony history, drug-related disqualifier, or other legal disability, they should not carry until they receive qualified legal guidance."
                ],
                "source": "ORC 2923.111; ORC 2923.125."
          },
          {
                "title": "Michigan CPL Recognition in Ohio",
                "risk": "Travel Law Context",
                "body": [
                      "STATUTE / SOURCE: Ohio recognition and permitless carry framework.",
                      "SUMMARY: This app treats Michigan CPL as recognized in Ohio. Ohio also allows permitless concealed carry for qualifying adults.",
                      "GUIDANCE: Recognition does not mean Michigan law follows the user. Ohio law controls while physically in Ohio."
                ],
                "source": "Ohio carry recognition framework; ORC 2923.111."
          },
          {
                "title": "Duties and Restricted Locations",
                "risk": "Major Carry Restriction",
                "body": [
                      "STATUTE / SOURCE: ORC 2923.126.",
                      "SUMMARY: Ohio carry authority does not authorize carry in every location. ORC 2923.126 identifies important restrictions and duties.",
                      "GUIDANCE: Treat schools, courthouses, law-enforcement facilities, correctional facilities, airport secure areas, government buildings, places of worship, posted private property, and security-screened locations as verify-first areas."
                ],
                "source": "ORC 2923.126."
          },
          {
                "title": "Private Property and Posted Businesses",
                "risk": "Trespass / Property Control",
                "body": [
                      "STATUTE / SOURCE: ORC 2923.126.",
                      "SUMMARY: Ohio allows private property owners and employers to post signs prohibiting firearms.",
                      "GUIDANCE: If a business is posted or staff/security asks the user to leave, leave immediately. Do not argue, debate, or create a trespass issue."
                ],
                "source": "ORC 2923.126; Ohio Investigative Unit firearms/signage guidance."
          },
          {
                "title": "School Safety Zones",
                "risk": "Extreme Risk Area",
                "body": [
                      "STATUTE / SOURCE: ORC 2923.122.",
                      "SUMMARY: Ohio law restricts deadly weapons and dangerous ordnance in school safety zones unless a statutory exception applies.",
                      "GUIDANCE: School buildings, school property, school events, parking areas, and student activities require extra caution. Do not assume a Michigan CPL or Ohio permitless carry solves the issue."
                ],
                "source": "ORC 2923.122."
          },
          {
                "title": "Courthouses and Courtrooms",
                "risk": "Hard Stop Area",
                "body": [
                      "STATUTE / SOURCE: ORC 2923.123; ORC 2923.126.",
                      "SUMMARY: Ohio restricts deadly weapons and dangerous ordnance in courthouse and court-related facilities.",
                      "GUIDANCE: Do not bring a firearm into a courthouse, courtroom building, or security-screened court facility unless a specific legal exception clearly applies."
                ],
                "source": "ORC 2923.123; ORC 2923.126."
          },
          {
                "title": "Liquor Permit Premises / Alcohol Locations",
                "risk": "Alcohol Location Risk",
                "body": [
                      "STATUTE / SOURCE: ORC 2923.121.",
                      "SUMMARY: Ohio restricts firearm possession in certain liquor-permit premises where alcohol is being consumed unless an exception applies.",
                      "GUIDANCE: Bars, breweries, restaurants, festivals, stadiums, and event venues should be checked carefully. If drinking is part of the plan, carrying should not be."
                ],
                "source": "ORC 2923.121."
          },
          {
                "title": "Airport Passenger Terminals / Secure Areas",
                "risk": "Transportation Security Risk",
                "body": [
                      "STATUTE / SOURCE: ORC 2923.126; federal airport/security framework.",
                      "SUMMARY: Ohio and federal rules may restrict carry in airport terminals, secure areas, passenger screening areas, and aircraft-related areas.",
                      "GUIDANCE: Proper checked-airline transport is different from carrying into a secure airport area. Know the airline and TSA process before arriving."
                ],
                "source": "ORC 2923.126; TSA/firearm transport framework."
          },
          {
                "title": "Law Enforcement / Correctional / Detention Facilities",
                "risk": "Restricted Facility Risk",
                "body": [
                      "STATUTE / SOURCE: ORC 2923.126.",
                      "SUMMARY: Ohio restricts carry in certain law-enforcement, jail, detention, correctional, and government-controlled facilities.",
                      "GUIDANCE: Police stations, sheriff offices, jails, detention centers, and correctional facilities should be treated as restricted unless a clear legal exception applies."
                ],
                "source": "ORC 2923.126."
          },
          {
                "title": "Places of Worship",
                "risk": "Permission Required / Property Control",
                "body": [
                      "STATUTE / SOURCE: ORC 2923.126.",
                      "SUMMARY: Ohio includes restrictions involving places of worship unless the place of worship permits otherwise under the statute.",
                      "GUIDANCE: Do not assume carry is allowed in a church, synagogue, mosque, temple, or other place of worship. Verify the policy with the proper authority."
                ],
                "source": "ORC 2923.126."
          },
          {
                "title": "Vehicle Carry and Traffic Stops",
                "risk": "Officer Safety / Legal Risk",
                "body": [
                      "STATUTE / SOURCE: ORC 2923.111; ORC 2923.126; Ohio Attorney General guidance.",
                      "SUMMARY: Ohio permitless carry changed notification duties. The Ohio Attorney General states carriers no longer must immediately reveal they are armed if stopped, but if asked, they must answer truthfully.",
                      "GUIDANCE: Keep hands visible, do not reach, and calmly say: Officer, I am lawfully carrying. How would you like me to proceed?"
                ],
                "source": "ORC 2923.111; ORC 2923.126; Ohio Attorney General concealed carry guidance."
          },
          {
                "title": "Improper Handling in a Motor Vehicle",
                "risk": "Vehicle-Specific Offense Risk",
                "body": [
                      "STATUTE / SOURCE: ORC 2923.16.",
                      "SUMMARY: Ohio has a specific statute addressing improper handling of firearms in a motor vehicle.",
                      "GUIDANCE: Vehicle carry should be treated as its own legal topic. Do not assume permitless carry alone answers every vehicle question."
                ],
                "source": "ORC 2923.16."
          },
          {
                "title": "Carrying While Impaired",
                "risk": "Intoxication / Disability Risk",
                "body": [
                      "STATUTE / SOURCE: ORC 2923.15; ORC 2923.121.",
                      "SUMMARY: Ohio law creates serious risk when weapons and impairment are combined.",
                      "GUIDANCE: If the user is drinking, using drugs, or impaired, they should not carry."
                ],
                "source": "ORC 2923.15; ORC 2923.121."
          },
          {
                "title": "Federal Property / Post Offices",
                "risk": "Federal Law Overlay",
                "body": [
                      "STATUTE / SOURCE: Federal facility and postal property framework.",
                      "SUMMARY: Ohio carry permission does not override federal restrictions.",
                      "GUIDANCE: Federal buildings, federal courthouses, post offices, and secure federal property must be checked separately from Ohio law."
                ],
                "source": "Federal facility and postal property framework."
          },
          {
                "title": "Use of Force / Self-Defense",
                "risk": "Slogans Are Not Law",
                "body": [
                      "STATUTE / SOURCE: Ohio self-defense statutes and case-law framework.",
                      "SUMMARY: Ohio self-defense law may protect lawful defenders, but force must still be justified under the facts.",
                      "GUIDANCE: Deadly force is not for insults, property disputes, road rage, warning shots, punishment, intimidation, or ego. Avoidance and de-escalation still matter."
                ],
                "source": "Ohio self-defense framework. Verify current Ohio statutory and case-law guidance."
          },
          {
                "title": "Defensive Display / No Shots Fired",
                "risk": "Menacing / Disorderly Conduct / Assault Allegation Risk",
                "body": [
                      "STATUTE / SOURCE: Ohio criminal law framework involving threats, menacing-type allegations, disorderly conduct, and weapon-related offenses.",
                      "SUMMARY: A person can create criminal exposure by displaying a firearm even if no shot is fired.",
                      "GUIDANCE: Do not display to scare, intimidate, win an argument, end a verbal dispute, or protect pride. If display was necessary due to an immediate threat, call 911 first."
                ],
                "source": "Ohio criminal law framework; Prime Defense defensive display protocol."
          },
          {
                "title": "Calling 911 After an Ohio Defensive Incident",
                "risk": "Post-Incident Statement Risk",
                "body": [
                      "STATUTE / SOURCE: General criminal procedure, evidence, and self-defense investigation framework.",
                      "SUMMARY: Statements after a defensive incident can become evidence.",
                      "GUIDANCE: Report the emergency, request police/medical if needed, identify the attacker/evidence/witnesses if necessary, request counsel, then stop talking."
                ],
                "source": "Prime Defense aftermath protocol; general criminal procedure/evidence framework."
          }
    ],
    [
          {
                "title": "Can I Carry Here in Ohio?",
                "steps": [
                      "1. Check ORC 2923.111: Am I a qualifying adult?",
                      "2. Check ORC 2923.126: Is this a restricted location?",
                      "3. Check ORC 2923.122: Is this a school safety zone?",
                      "4. Check ORC 2923.123: Is this courthouse or courtroom related?",
                      "5. Check ORC 2923.121: Is this a liquor-permit premises issue?",
                      "6. Check ORC 2923.16: Is this a vehicle-specific issue?",
                      "7. Check posted signs, employer rules, private property instructions, and federal property.",
                      "8. If any answer is uncertain, do not enter armed until verified."
                ]
          },
          {
                "title": "Ohio Traffic Stop Script",
                "steps": [
                      "1. Pull over safely.",
                      "2. Keep both hands visible.",
                      "3. Do not reach for anything until instructed.",
                      "4. If asked whether you are carrying, answer truthfully.",
                      "5. Recommended wording: Officer, I am lawfully carrying. How would you like me to proceed?",
                      "6. Follow instructions calmly and slowly."
                ]
          }
    ],
    [
          {
                "title": "Michigan Driver Pulled Over in Ohio",
                "summary": "The law may allow carry, but movement during a traffic stop can create danger.",
                "guidance": [
                      "Hands visible.",
                      "No reaching.",
                      "Tell the truth if asked.",
                      "Ask for instructions before moving."
                ]
          },
          {
                "title": "Restaurant With Alcohol",
                "summary": "Ohio alcohol-location rules depend on premises type, whether alcohol is being consumed, and whether an exception applies.",
                "guidance": [
                      "Check ORC 2923.121.",
                      "Do not drink while armed.",
                      "Check signs.",
                      "Leave if asked."
                ]
          },
          {
                "title": "School Pickup While Traveling",
                "summary": "A Michigan CPL holder visiting family in Ohio may misunderstand school safety zone rules.",
                "guidance": [
                      "Check ORC 2923.122.",
                      "Do not rely on Michigan school rules.",
                      "When uncertain, do not enter armed."
                ]
          }
    ],
    [
          "Assuming Ohio disclosure rules are identical to Michigan.",
          "Assuming ORC 2923.111 means anyone can carry.",
          "Assuming permitless carry means no prohibited places.",
          "Ignoring ORC 2923.122 school safety zones.",
          "Ignoring ORC 2923.121 liquor-premises rules.",
          "Ignoring ORC 2923.126 private-property and restricted-location rules.",
          "Ignoring ORC 2923.123 courthouse/courtroom restrictions.",
          "Ignoring ORC 2923.16 vehicle-specific issues.",
          "Carrying while drinking or impaired.",
          "Reaching during a traffic stop.",
          "Arguing with staff or security over signs.",
          "Assuming federal property follows Ohio carry rules."
    ],
    [
          "ORC 2923.111 qualifying-adult status checked.",
          "ORC 2923.126 restricted locations checked.",
          "ORC 2923.122 school safety zone issues checked.",
          "ORC 2923.123 courthouse/courtroom issues checked.",
          "ORC 2923.121 liquor premises checked.",
          "ORC 2923.16 vehicle issues checked.",
          "Private signs and property instructions checked.",
          "Federal property checked separately.",
          "Vehicle/traffic stop behavior plan ready.",
          "Next state on trip route checked."
    ],
    [
          {
                "myth": "Ohio has permitless carry, so anyone can carry there.",
                "reality": "No. ORC 2923.111 applies to a qualifying adult. Eligibility still matters."
          },
          {
                "myth": "If Ohio recognizes my Michigan CPL, Michigan rules follow me.",
                "reality": "No. Ohio law controls once you are physically in Ohio."
          },
          {
                "myth": "Permitless carry means I can carry in schools, courthouses, and government buildings.",
                "reality": "No. ORC 2923.126, ORC 2923.122, ORC 2923.123, and other laws still restrict locations."
          },
          {
                "myth": "If a private business posts a sign, I can just debate them.",
                "reality": "No. Leave calmly if asked."
          },
          {
                "myth": "A defensive display is not serious if I do not fire.",
                "reality": "A bad display can still create criminal allegations. Display must be tied to a real, immediate threat."
          }
    ]
  ),

  IN: makeProfile(
    "Indiana",
    "Law-Backed Ultra Expanded Travel State",
    "Indiana is a high-priority travel state for Michigan CPL holders. Indiana has permitless carry for a proper person, but carry remains subject to prohibited-person rules, restricted locations, school property, courthouse and airport issues, private property, vehicle considerations, and use-of-force law.",
    {
          "reciprocity": "Michigan CPL treated as recognized in this app travel engine. Indiana also has permitless carry for a proper person.",
          "permitlessCarry": "IC 35-47-2-1.5 / Indiana State Police guidance: permitless carry is available only if the person meets proper-person criteria.",
          "concealedCarry": "Indiana permitless carry may allow concealed handgun carry by a proper person, but restrictions still apply.",
          "openCarry": "Indiana carry may be lawful for a proper person, but location and conduct restrictions matter.",
          "vehicleCarry": "Indiana permitless carry affects carrying, concealing, and transporting a handgun, but the person must not be prohibited.",
          "dutyToInform": "Verify Indiana police-contact requirements; keep hands visible and follow commands.",
          "privateSigns": "Private property instructions and posted restrictions can matter; leave if asked.",
          "forceLaw": "Indiana self-defense law is fact-specific and should be verified from Indiana Code."
    },
    [
          "Indiana law controls while the user is physically in Indiana.",
          "A green map status is only a starting point for reciprocity, not a location-by-location authorization.",
          "Every section below is tied to a statute or official source where possible.",
          "Users should verify current law before relying on any summary."
    ],
    [
          {
                "title": "Permitless Carry / Proper Person",
                "risk": "Core Eligibility Rule",
                "body": [
                      "STATUTE / SOURCE: IC 35-47-2-1.5; Indiana State Police permitless carry guidance.",
                      "SUMMARY: Indiana no longer requires a handgun permit for a proper person to carry, conceal, or transport a handgun within the state.",
                      "GUIDANCE: The user must not be a prohibited person. If the user's status is uncertain, they should not carry until qualified legal counsel confirms eligibility."
                ],
                "source": "IC 35-47-2-1.5; Indiana State Police Firearms Licensing guidance."
          },
          {
                "title": "Prohibited Persons",
                "risk": "Disqualification Risk",
                "body": [
                      "STATUTE / SOURCE: IC 35-47-2-1.5; IC 35-47 framework.",
                      "SUMMARY: Indiana permitless carry does not apply to prohibited persons.",
                      "GUIDANCE: Felony history, domestic violence, protection orders, mental health adjudications, substance issues, or other disqualifiers require attorney review before carrying."
                ],
                "source": "IC 35-47-2-1.5; Indiana State Police permitless carry notice."
          },
          {
                "title": "License / Permit Still Has Value",
                "risk": "Travel and Documentation",
                "body": [
                      "STATUTE / SOURCE: Indiana handgun licensing framework.",
                      "SUMMARY: Indiana permitless carry does not make a license useless; a license may still matter for travel, reciprocity, documentation, and certain practical situations.",
                      "GUIDANCE: A Michigan CPL holder should still maintain current license documentation and should not assume permitless carry in Indiana helps in the next state."
                ],
                "source": "Indiana State Police Firearms Licensing guidance."
          },
          {
                "title": "School Property and School Functions",
                "risk": "Extreme Risk Area",
                "body": [
                      "STATUTE / SOURCE: Indiana school weapons statutes; IC 35-47 framework.",
                      "SUMMARY: Schools and school-related property remain high-risk restricted areas.",
                      "GUIDANCE: Do not rely on a one-line permitless carry summary for school parking lots, events, buses, or school-controlled property."
                ],
                "source": "Indiana Code school weapons framework."
          },
          {
                "title": "Courthouses / Government / Secure Buildings",
                "risk": "Hard Stop Area",
                "body": [
                      "STATUTE / SOURCE: Indiana Code restricted premises framework.",
                      "SUMMARY: Court and secure government buildings may restrict weapons regardless of carry eligibility.",
                      "GUIDANCE: Treat court, jail, police, correctional, and security-screened buildings as verify-first or avoid-carry locations."
                ],
                "source": "Indiana Code restricted-location framework."
          },
          {
                "title": "Airports / Aircraft / Secure Areas",
                "risk": "Transportation Security Risk",
                "body": [
                      "STATUTE / SOURCE: Indiana law and federal airport/TSA framework.",
                      "SUMMARY: Airport secure areas and aircraft are governed by federal and state restrictions.",
                      "GUIDANCE: Checked transport is different from carry into a secure area. Know the airline/TSA process before arriving."
                ],
                "source": "Federal TSA framework; Indiana restricted-location framework."
          },
          {
                "title": "Private Property / Posted Locations",
                "risk": "Property Control",
                "body": [
                      "STATUTE / SOURCE: Indiana trespass and private-property framework.",
                      "SUMMARY: Private property owners and event venues may restrict weapons and direct a person to leave.",
                      "GUIDANCE: Leave if asked. Do not turn a carry issue into trespass or disorderly conduct."
                ],
                "source": "Indiana private property/trespass framework."
          },
          {
                "title": "Vehicle Carry / Transport",
                "risk": "Travel Risk",
                "body": [
                      "STATUTE / SOURCE: IC 35-47-2-1.5; Indiana State Police guidance.",
                      "SUMMARY: Indiana permitless carry impacts carrying, concealing, and transporting a handgun for proper persons.",
                      "GUIDANCE: Keep hands visible during police contact and do not reach. Verify storage rules if crossing into another state."
                ],
                "source": "Indiana State Police Firearms Licensing guidance."
          },
          {
                "title": "Alcohol / Impairment",
                "risk": "Judgment and Criminal Risk",
                "body": [
                      "STATUTE / SOURCE: Indiana weapons and intoxication framework.",
                      "SUMMARY: Carrying while impaired can create serious legal and evidentiary risk.",
                      "GUIDANCE: If drinking or impaired, do not carry. Avoid alcohol-centered locations when armed."
                ],
                "source": "Indiana weapons/intoxication framework."
          },
          {
                "title": "Federal Property / Post Offices",
                "risk": "Federal Law Overlay",
                "body": [
                      "STATUTE / SOURCE: Federal facility and postal property framework.",
                      "SUMMARY: Indiana carry permission does not override federal restrictions.",
                      "GUIDANCE: Federal buildings, post offices, and secure federal property require separate federal-law analysis."
                ],
                "source": "Federal facility and postal property framework."
          },
          {
                "title": "Use of Force / Defense of Self and Others",
                "risk": "Force Law",
                "body": [
                      "STATUTE / SOURCE: Indiana self-defense statutes and case law framework.",
                      "SUMMARY: Indiana self-defense law may justify force in specific factual circumstances, but force must still be legally justified.",
                      "GUIDANCE: Do not use force over insults, ego, property disputes, road rage, or punishment. Avoid and call 911 when safe."
                ],
                "source": "Indiana self-defense law framework."
          },
          {
                "title": "Aftermath / Statements",
                "risk": "Post-Incident Risk",
                "body": [
                      "STATUTE / SOURCE: Criminal procedure and evidence framework.",
                      "SUMMARY: Statements after an incident can become evidence.",
                      "GUIDANCE: Report the emergency, request help, identify evidence/witnesses if necessary, request counsel, then stop talking."
                ],
                "source": "Prime Defense aftermath protocol; Indiana criminal procedure framework."
          }
    ],
    [
          {
                "title": "Can I Carry Here in Indiana?",
                "steps": [
                      "1. Am I a proper person under Indiana law?",
                      "2. Am I prohibited under state or federal law?",
                      "3. Is this school-related, court-related, government-secure, airport-secure, posted, federal, or employer-controlled?",
                      "4. Am I in a vehicle or crossing into another state?",
                      "5. If uncertain, do not enter armed."
                ]
          },
          {
                "title": "Indiana Traffic Stop / Police Contact",
                "steps": [
                      "1. Pull over or stop safely.",
                      "2. Keep hands visible.",
                      "3. Do not reach for anything until instructed.",
                      "4. Follow state-specific disclosure or identification rules.",
                      "5. Answer lawful questions truthfully and wait for legal guidance before detailed statements."
                ]
          }
    ],
    [
          {
                "title": "Michigan Driver Crossing Into Indiana",
                "summary": "Rules change at the state line even though Indiana is close to Michigan.",
                "guidance": [
                      "Confirm proper-person status.",
                      "Check vehicle carry.",
                      "Check destination restrictions.",
                      "Do not rely on Michigan school or disclosure rules."
                ]
          },
          {
                "title": "Indiana School Event",
                "summary": "School-related locations are high-risk.",
                "guidance": [
                      "Verify before arrival.",
                      "Do not rely on permitless carry.",
                      "When uncertain, do not enter armed."
                ]
          }
    ],
    [
          "Assuming Michigan rules apply outside Michigan.",
          "Ignoring prohibited places.",
          "Ignoring private-property or signage rules.",
          "Ignoring vehicle carry differences.",
          "Ignoring school-zone restrictions.",
          "Ignoring alcohol-location rules.",
          "Assuming federal property follows state carry rules.",
          "Relying on old reciprocity information.",
          "Assuming proper-person status without checking disqualifiers.",
          "Assuming Indiana rules apply in Illinois, Ohio, or Kentucky after crossing the next state line."
    ],
    [
          "Permit recognition checked.",
          "Eligibility checked.",
          "Prohibited places checked.",
          "School rules checked.",
          "Vehicle carry checked.",
          "Private property/signage checked.",
          "Alcohol-related restrictions checked.",
          "Federal property checked separately.",
          "Use-of-force standards reviewed.",
          "Next state on trip route checked."
    ],
    [
          {
                "myth": "If my Michigan CPL is recognized, Michigan law follows me into Indiana.",
                "reality": "No. Indiana law controls once you are physically in Indiana."
          },
          {
                "myth": "A recognized permit means I can carry anywhere.",
                "reality": "No. Recognition does not override prohibited places, private property, federal property, schools, alcohol rules, or vehicle restrictions."
          }
    ]
  ),

  FL: makeProfile(
    "Florida",
    "Law-Backed Ultra Expanded Travel State",
    "Florida is a major travel state for Michigan members. Florida has permitless concealed carry for persons who meet statutory requirements, but Florida still has detailed prohibited-place rules, school restrictions, open carry limits, vehicle/travel concerns, airport rules, alcohol-location restrictions, private property and venue issues, and use-of-force standards.",
    {
          "reciprocity": "Michigan CPL treated as recognized in this app travel engine. Florida also has permitless concealed carry for qualifying people.",
          "permitlessCarry": "F.S. 790.013 and 790.01 framework: Florida permits concealed carry without a license for people who meet the statutory criteria.",
          "concealedCarry": "F.S. 790.01, 790.013, and 790.06: concealed carry may be lawful, but prohibited places still apply.",
          "openCarry": "F.S. 790.053: open carry is generally restricted except for statutory exceptions.",
          "vehicleCarry": "Florida vehicle and lawful possession rules must be verified for loaded, concealed, securely encased, and accessible firearms.",
          "dutyToInform": "Florida licensees must display identification upon demand under F.S. 790.06; verify current duties for permitless carry situations.",
          "privateSigns": "Private property and venue rules may restrict entry or require leaving when instructed.",
          "forceLaw": "Florida self-defense law is fact-specific; do not rely on slogans."
    },
    [
          "Florida law controls while the user is physically in Florida.",
          "A green map status is only a starting point for reciprocity, not a location-by-location authorization.",
          "Every section below is tied to a statute or official source where possible.",
          "Users should verify current law before relying on any summary."
    ],
    [
          {
                "title": "Permitless Concealed Carry",
                "risk": "Core Eligibility Rule",
                "body": [
                      "STATUTE / SOURCE: F.S. 790.013; F.S. 790.01.",
                      "SUMMARY: Florida allows concealed carry without a license for a person who satisfies the statutory requirements.",
                      "GUIDANCE: Permitless carry is not universal carry. The user must be eligible and must comply with prohibited-place rules."
                ],
                "source": "Florida Statutes 790.013 and 790.01."
          },
          {
                "title": "License Carry and Identification",
                "risk": "Documentation Rule",
                "body": [
                      "STATUTE / SOURCE: F.S. 790.06.",
                      "SUMMARY: Florida concealed weapon/firearm licensees must carry valid identification and display it upon demand by a law enforcement officer.",
                      "GUIDANCE: Even where permitless carry exists, members should carry identification and understand officer-contact duties."
                ],
                "source": "F.S. 790.06."
          },
          {
                "title": "Prohibited Places",
                "risk": "Major Location Restriction",
                "body": [
                      "STATUTE / SOURCE: F.S. 790.06(12).",
                      "SUMMARY: Florida law lists locations where carrying a concealed weapon or firearm is not authorized.",
                      "GUIDANCE: Police stations, jails, courthouses, courtrooms, polling places, school-related locations, legislative meetings, secure airport areas, nuisance places, and federally prohibited locations require careful review."
                ],
                "source": "F.S. 790.06(12)."
          },
          {
                "title": "Schools / School Property / School Events",
                "risk": "Extreme Risk Area",
                "body": [
                      "STATUTE / SOURCE: F.S. 790.115.",
                      "SUMMARY: Florida restricts weapons and firearms at school-sponsored events and on school property, subject to statutory language and exceptions.",
                      "GUIDANCE: Do not assume a license, permitless carry, or vehicle presence automatically solves a school issue."
                ],
                "source": "F.S. 790.115."
          },
          {
                "title": "Open Carry",
                "risk": "Often Misunderstood",
                "body": [
                      "STATUTE / SOURCE: F.S. 790.053.",
                      "SUMMARY: Florida generally restricts open carry except for specified statutory exceptions.",
                      "GUIDANCE: Do not open carry in ordinary public settings unless a specific Florida exception clearly applies."
                ],
                "source": "F.S. 790.053."
          },
          {
                "title": "Vehicle Carry / Securely Encased / Travel",
                "risk": "Road Trip Risk",
                "body": [
                      "STATUTE / SOURCE: F.S. 790.25 and Chapter 790 framework.",
                      "SUMMARY: Florida has specific lawful-use and vehicle-related firearm provisions.",
                      "GUIDANCE: Rental cars, hotels, beaches, theme parks, valet parking, and vehicle storage require advance planning."
                ],
                "source": "F.S. 790.25; Florida Chapter 790 framework."
          },
          {
                "title": "Theme Parks / Resorts / Event Venues",
                "risk": "Private Property and Security Risk",
                "body": [
                      "STATUTE / SOURCE: Florida private property and venue framework.",
                      "SUMMARY: Private venues may restrict firearms, use security screening, or require guests to leave.",
                      "GUIDANCE: Do not argue with security. Know storage plans before arriving at a theme park, stadium, concert, cruise terminal, resort, or event venue."
                ],
                "source": "Florida private property/trespass framework."
          },
          {
                "title": "Airports / Aircraft / TSA",
                "risk": "Transportation Security Risk",
                "body": [
                      "STATUTE / SOURCE: F.S. 790.06; federal TSA/airport framework.",
                      "SUMMARY: Secure airport areas and aircraft involve state and federal restrictions.",
                      "GUIDANCE: Checked transport is different from carry into a secure area. Know TSA and airline rules before arrival."
                ],
                "source": "F.S. 790.06; TSA firearm transport framework."
          },
          {
                "title": "Alcohol / Bars / Impairment",
                "risk": "Alcohol Location Risk",
                "body": [
                      "STATUTE / SOURCE: F.S. 790.06(12); Florida intoxication/weapon framework.",
                      "SUMMARY: Florida prohibits carry in certain portions of establishments primarily devoted to dispensing alcohol for consumption on premises.",
                      "GUIDANCE: If drinking is part of the plan, carrying should not be. Treat bars, clubs, festivals, and resort nightlife as high-risk."
                ],
                "source": "F.S. 790.06(12)."
          },
          {
                "title": "Places of Worship",
                "risk": "Policy and School-Property Overlay",
                "body": [
                      "STATUTE / SOURCE: Florida religious institution and school-property framework.",
                      "SUMMARY: Florida does not generally prohibit carry in places of worship solely because they are places of worship, but school/property overlays can matter.",
                      "GUIDANCE: Verify policy and whether the property is also school-related, daycare-related, posted, or security-controlled."
                ],
                "source": "Florida Chapter 790 framework; Florida religious institution guidance."
          },
          {
                "title": "Federal Property / Post Offices",
                "risk": "Federal Law Overlay",
                "body": [
                      "STATUTE / SOURCE: Federal facility and postal property framework.",
                      "SUMMARY: Florida carry permission does not override federal restrictions.",
                      "GUIDANCE: Post offices, federal courthouses, federal buildings, and secure federal property require separate federal analysis."
                ],
                "source": "Federal facility and postal property framework."
          },
          {
                "title": "Use of Force / Stand Your Ground",
                "risk": "Force Law",
                "body": [
                      "STATUTE / SOURCE: Florida self-defense statutes including Chapter 776 framework.",
                      "SUMMARY: Florida self-defense law can provide strong protections, but force must still be justified by the facts.",
                      "GUIDANCE: Avoid slogans. Deadly force is not for anger, insults, warning shots, property disputes, or punishment."
                ],
                "source": "Florida Chapter 776 self-defense framework."
          },
          {
                "title": "Aftermath / Statements",
                "risk": "Post-Incident Risk",
                "body": [
                      "STATUTE / SOURCE: Criminal procedure and evidence framework.",
                      "SUMMARY: Post-incident statements can become evidence.",
                      "GUIDANCE: Call 911, request help, identify evidence/witnesses if necessary, request counsel, and avoid detailed statements under adrenaline."
                ],
                "source": "Prime Defense aftermath protocol; Florida criminal procedure framework."
          }
    ],
    [
          {
                "title": "Can I Carry Here in Florida?",
                "steps": [
                      "1. Am I legally eligible under Florida law?",
                      "2. Is this prohibited by F.S. 790.06(12)?",
                      "3. Is this school-related under F.S. 790.115?",
                      "4. Am I accidentally open carrying under F.S. 790.053?",
                      "5. Is this airport, theme park, resort, event, bar, federal, posted, or security-controlled?",
                      "6. If uncertain, do not enter armed."
                ]
          },
          {
                "title": "Florida Traffic Stop / Police Contact",
                "steps": [
                      "1. Pull over or stop safely.",
                      "2. Keep hands visible.",
                      "3. Do not reach for anything until instructed.",
                      "4. Follow state-specific disclosure or identification rules.",
                      "5. Answer lawful questions truthfully and wait for legal guidance before detailed statements."
                ]
          }
    ],
    [
          {
                "title": "Florida Theme Park or Resort",
                "summary": "Vacation venues often have strict property rules and screening.",
                "guidance": [
                      "Check venue policy before arrival.",
                      "Do not bring a firearm to security screening.",
                      "Have a lawful storage plan."
                ]
          },
          {
                "title": "Airport Trip",
                "summary": "Airports require strict separation between checked transport and unlawful carry into secure areas.",
                "guidance": [
                      "Follow TSA and airline rules.",
                      "Do not enter secure areas armed.",
                      "Plan before arrival."
                ]
          },
          {
                "title": "Restaurant / Bar Night",
                "summary": "Florida alcohol-location rules and impairment risk can quickly turn lawful carry into a problem.",
                "guidance": [
                      "Check the location.",
                      "Do not drink while armed.",
                      "Leave if instructed."
                ]
          }
    ],
    [
          "Assuming Michigan rules apply outside Michigan.",
          "Ignoring prohibited places.",
          "Ignoring private-property or signage rules.",
          "Ignoring vehicle carry differences.",
          "Ignoring school-zone restrictions.",
          "Ignoring alcohol-location rules.",
          "Assuming federal property follows state carry rules.",
          "Relying on old reciprocity information.",
          "Confusing Florida concealed carry with open carry.",
          "Ignoring theme park, resort, cruise terminal, or venue rules.",
          "Assuming vacation status changes the law."
    ],
    [
          "Permit recognition checked.",
          "Eligibility checked.",
          "Prohibited places checked.",
          "School rules checked.",
          "Vehicle carry checked.",
          "Private property/signage checked.",
          "Alcohol-related restrictions checked.",
          "Federal property checked separately.",
          "Use-of-force standards reviewed.",
          "Next state on trip route checked."
    ],
    [
          {
                "myth": "If my Michigan CPL is recognized, Michigan law follows me into Florida.",
                "reality": "No. Florida law controls once you are physically in Florida."
          },
          {
                "myth": "A recognized permit means I can carry anywhere.",
                "reality": "No. Recognition does not override prohibited places, private property, federal property, schools, alcohol rules, or vehicle restrictions."
          }
    ]
  ),

  TX: makeProfile(
    "Texas",
    "Law-Backed Ultra Expanded Travel State",
    "Texas is a major travel state with permitless carry and License to Carry recognition, but Texas has detailed rules involving prohibited places, 30.05/30.06/30.07 signage, alcohol locations, school/event restrictions, vehicle carry, open carry, government meetings, and use-of-force law.",
    {
          "reciprocity": "Michigan CPL treated as recognized in this app travel engine. Texas also has permitless carry for eligible people.",
          "permitlessCarry": "Texas Penal Code 46.02 framework: permitless handgun carry may be lawful for eligible people, subject to restrictions.",
          "concealedCarry": "Concealed carry may be lawful, but Penal Code 46.03 prohibited places and signage rules still apply.",
          "openCarry": "Open carry may be lawful for eligible people but must comply with Texas holster/display rules and 30.07 signage.",
          "vehicleCarry": "Texas vehicle carry can be lawful, but prohibited-person, criminal activity, and location rules still matter.",
          "dutyToInform": "Verify current Texas duties for LTC holders and officer contact; keep hands visible and follow commands.",
          "privateSigns": "Texas 30.05, 30.06, and 30.07 signage rules are critical.",
          "forceLaw": "Texas force and deadly force law is detailed and fact-specific."
    },
    [
          "Texas law controls while the user is physically in Texas.",
          "A green map status is only a starting point for reciprocity, not a location-by-location authorization.",
          "Every section below is tied to a statute or official source where possible.",
          "Users should verify current law before relying on any summary."
    ],
    [
          {
                "title": "Permitless Carry / Unlawful Carrying Weapons",
                "risk": "Core Eligibility Rule",
                "body": [
                      "STATUTE / SOURCE: Texas Penal Code 46.02.",
                      "SUMMARY: Texas law allows some people to carry a handgun without an LTC, but unlawful carry restrictions still apply.",
                      "GUIDANCE: Confirm eligibility, age, prohibited-person status, intoxication status, and location before carrying."
                ],
                "source": "Texas Penal Code 46.02."
          },
          {
                "title": "Prohibited Places",
                "risk": "Major Location Restriction",
                "body": [
                      "STATUTE / SOURCE: Texas Penal Code 46.03.",
                      "SUMMARY: Texas prohibits weapons in specific places including schools, polling places, courts, racetracks, secure airport areas, correctional facilities, and other listed locations.",
                      "GUIDANCE: Treat every location as a separate question. Gun-friendly does not mean carry-anywhere."
                ],
                "source": "Texas Penal Code 46.03."
          },
          {
                "title": "30.05 Signs / Unlicensed Carry Trespass",
                "risk": "Private Property Signage",
                "body": [
                      "STATUTE / SOURCE: Texas Penal Code 30.05.",
                      "SUMMARY: Texas property owners may use 30.05 signage to restrict firearms by persons carrying without a license.",
                      "GUIDANCE: Do not ignore 30.05 signs. Leave if instructed."
                ],
                "source": "Texas Penal Code 30.05."
          },
          {
                "title": "30.06 Signs / Licensed Concealed Carry",
                "risk": "Private Property Signage",
                "body": [
                      "STATUTE / SOURCE: Texas Penal Code 30.06.",
                      "SUMMARY: Texas 30.06 signage restricts concealed handgun carry by license holders when statutory notice requirements are met.",
                      "GUIDANCE: A Michigan permit holder should treat proper 30.06 signage as serious legal notice."
                ],
                "source": "Texas Penal Code 30.06."
          },
          {
                "title": "30.07 Signs / Licensed Open Carry",
                "risk": "Private Property Signage",
                "body": [
                      "STATUTE / SOURCE: Texas Penal Code 30.07.",
                      "SUMMARY: Texas 30.07 signage restricts open handgun carry by license holders when statutory notice requirements are met.",
                      "GUIDANCE: Open carry increases visibility and sign-related risk. Check entrances before entering."
                ],
                "source": "Texas Penal Code 30.07."
          },
          {
                "title": "Alcohol / 51% Locations",
                "risk": "Alcohol Location Risk",
                "body": [
                      "STATUTE / SOURCE: Texas Penal Code 46.03; Texas Alcoholic Beverage Code signage framework.",
                      "SUMMARY: Texas restricts weapons in certain alcohol-related locations, including 51% premises.",
                      "GUIDANCE: Look for 51% signs and avoid alcohol-centered venues while armed."
                ],
                "source": "Texas Penal Code 46.03; Texas Alcoholic Beverage Commission signage framework."
          },
          {
                "title": "Schools and School Activities",
                "risk": "Extreme Risk Area",
                "body": [
                      "STATUTE / SOURCE: Texas Penal Code 46.03.",
                      "SUMMARY: Texas prohibits weapons in many school-related places and activities unless a specific legal exception applies.",
                      "GUIDANCE: Do not assume vehicle or parking lot presence is automatically lawful. Verify school/event specifics."
                ],
                "source": "Texas Penal Code 46.03."
          },
          {
                "title": "Courts / Government Meetings / Polling Places",
                "risk": "Hard Stop Area",
                "body": [
                      "STATUTE / SOURCE: Texas Penal Code 46.03; Texas Penal Code 46.15 framework.",
                      "SUMMARY: Courts, court offices, polling places, and certain government meetings can be restricted.",
                      "GUIDANCE: Do not bring a handgun to court, polling place, or government meeting without verifying exact law and notice."
                ],
                "source": "Texas Penal Code 46.03."
          },
          {
                "title": "Airport Secure Areas",
                "risk": "Transportation Security Risk",
                "body": [
                      "STATUTE / SOURCE: Texas Penal Code 46.03; federal TSA framework.",
                      "SUMMARY: Secure airport areas and aircraft are restricted under state and federal law.",
                      "GUIDANCE: Checked transport is different from entering secure areas armed."
                ],
                "source": "Texas Penal Code 46.03; TSA firearm transport framework."
          },
          {
                "title": "Open Carry / Plain View",
                "risk": "Display Risk",
                "body": [
                      "STATUTE / SOURCE: Texas Penal Code 46.02; Texas handgun carry framework.",
                      "SUMMARY: Texas open carry rules require compliance with manner-of-carry and location restrictions.",
                      "GUIDANCE: Open carry can trigger 30.07 signage issues and public attention. Do not use open carry to test boundaries."
                ],
                "source": "Texas Penal Code 46.02; Texas Penal Code 30.07."
          },
          {
                "title": "Vehicle Carry",
                "risk": "Travel Risk",
                "body": [
                      "STATUTE / SOURCE: Texas Penal Code 46.02 and 46.03 framework.",
                      "SUMMARY: Texas vehicle carry may be lawful for eligible people, but unlawful carry and prohibited-place rules still apply.",
                      "GUIDANCE: Traffic stops require visible hands, no reaching, and calm compliance."
                ],
                "source": "Texas Penal Code 46.02; Texas Penal Code 46.03."
          },
          {
                "title": "Federal Property / Post Offices",
                "risk": "Federal Law Overlay",
                "body": [
                      "STATUTE / SOURCE: Federal facility and postal property framework.",
                      "SUMMARY: Texas carry permission does not override federal restrictions.",
                      "GUIDANCE: Federal buildings, federal courthouses, post offices, and secure federal property require separate analysis."
                ],
                "source": "Federal facility and postal property framework."
          },
          {
                "title": "Use of Force / Deadly Force",
                "risk": "Force Law",
                "body": [
                      "STATUTE / SOURCE: Texas Penal Code Chapter 9.",
                      "SUMMARY: Texas use-of-force and deadly-force law is detailed and circumstance-specific.",
                      "GUIDANCE: Do not reduce Texas law to slogans. Avoidance, proportionality, reasonableness, and facts still matter."
                ],
                "source": "Texas Penal Code Chapter 9."
          },
          {
                "title": "Aftermath / Statements",
                "risk": "Post-Incident Risk",
                "body": [
                      "STATUTE / SOURCE: Criminal procedure and evidence framework.",
                      "SUMMARY: Statements after a defensive incident can become evidence.",
                      "GUIDANCE: Call 911, request help, identify evidence/witnesses if necessary, request counsel, then stop talking."
                ],
                "source": "Prime Defense aftermath protocol; Texas criminal procedure framework."
          }
    ],
    [
          {
                "title": "Can I Carry Here in Texas?",
                "steps": [
                      "1. Am I legally eligible under Texas law?",
                      "2. Is this prohibited under Penal Code 46.03?",
                      "3. Is this property posted under 30.05, 30.06, or 30.07?",
                      "4. Is this alcohol-related, school-related, court-related, polling-place-related, airport-secure, or federal?",
                      "5. If uncertain, do not enter armed."
                ]
          },
          {
                "title": "Texas Traffic Stop / Police Contact",
                "steps": [
                      "1. Pull over or stop safely.",
                      "2. Keep hands visible.",
                      "3. Do not reach for anything until instructed.",
                      "4. Follow state-specific disclosure or identification rules.",
                      "5. Answer lawful questions truthfully and wait for legal guidance before detailed statements."
                ]
          }
    ],
    [
          {
                "title": "Posted Texas Business",
                "summary": "Texas signage is technical and important.",
                "guidance": [
                      "Look for 30.05, 30.06, and 30.07 signs.",
                      "Do not ignore signs.",
                      "Leave if instructed."
                ]
          },
          {
                "title": "Restaurant With 51% Sign",
                "summary": "Alcohol signage can make carry unlawful.",
                "guidance": [
                      "Check entrance signs.",
                      "Avoid alcohol-centered locations while armed.",
                      "Do not drink while armed."
                ]
          },
          {
                "title": "School or Sporting Event",
                "summary": "Schools and sporting events require special caution.",
                "guidance": [
                      "Check Penal Code 46.03.",
                      "Do not rely on assumptions.",
                      "When uncertain, do not enter armed."
                ]
          }
    ],
    [
          "Assuming Michigan rules apply outside Michigan.",
          "Ignoring prohibited places.",
          "Ignoring private-property or signage rules.",
          "Ignoring vehicle carry differences.",
          "Ignoring school-zone restrictions.",
          "Ignoring alcohol-location rules.",
          "Assuming federal property follows state carry rules.",
          "Relying on old reciprocity information.",
          "Ignoring 30.05/30.06/30.07 signs.",
          "Assuming Texas is carry-anywhere because it is gun-friendly.",
          "Ignoring 51% alcohol premises."
    ],
    [
          "Permit recognition checked.",
          "Eligibility checked.",
          "Prohibited places checked.",
          "School rules checked.",
          "Vehicle carry checked.",
          "Private property/signage checked.",
          "Alcohol-related restrictions checked.",
          "Federal property checked separately.",
          "Use-of-force standards reviewed.",
          "Next state on trip route checked."
    ],
    [
          {
                "myth": "If my Michigan CPL is recognized, Michigan law follows me into Texas.",
                "reality": "No. Texas law controls once you are physically in Texas."
          },
          {
                "myth": "A recognized permit means I can carry anywhere.",
                "reality": "No. Recognition does not override prohibited places, private property, federal property, schools, alcohol rules, or vehicle restrictions."
          }
    ]
  ),

  KY: makeProfile(
    "Kentucky",
    "Law-Backed Ultra Expanded Travel State",
    "Kentucky is a common travel state for Michigan members and has permitless concealed carry for eligible adults, but users must still understand KRS 237.110, KRS 527.020, school restrictions, court/government buildings, posted private property, federal property, vehicle issues, and use-of-force law.",
    {
          "reciprocity": "Michigan CPL treated as recognized in this app travel engine. Kentucky also has permitless concealed carry for eligible adults.",
          "permitlessCarry": "KRS 237.110 / KRS 527.020 framework: Kentucky permitless concealed carry is available to eligible persons under statutory conditions.",
          "concealedCarry": "Kentucky concealed carry may be lawful, but prohibited places still apply.",
          "openCarry": "Kentucky generally recognizes open carry, but location, vehicle, private property, and conduct restrictions matter.",
          "vehicleCarry": "Vehicle carry must comply with Kentucky law and changes when crossing state lines.",
          "dutyToInform": "Verify current Kentucky officer-contact rules; keep hands visible and follow commands.",
          "privateSigns": "KRS 237.110 and Kentucky property rules: posted premises and private instructions can matter.",
          "forceLaw": "Kentucky self-protection law is fact-specific and should be verified from KRS Chapter 503."
    },
    [
          "Kentucky law controls while the user is physically in Kentucky.",
          "A green map status is only a starting point for reciprocity, not a location-by-location authorization.",
          "Every section below is tied to a statute or official source where possible.",
          "Users should verify current law before relying on any summary."
    ],
    [
          {
                "title": "Permitless Concealed Carry",
                "risk": "Core Eligibility Rule",
                "body": [
                      "STATUTE / SOURCE: KRS 237.110; KRS 527.020.",
                      "SUMMARY: Kentucky allows eligible persons to carry concealed deadly weapons without a license in many circumstances.",
                      "GUIDANCE: Eligibility still matters. Permitless does not mean prohibited persons or restricted locations are allowed."
                ],
                "source": "KRS 237.110; KRS 527.020; Kentucky State Police permitless carry guidance."
          },
          {
                "title": "CCDW License Still Has Value",
                "risk": "Travel / Reciprocity",
                "body": [
                      "STATUTE / SOURCE: KRS 237.110.",
                      "SUMMARY: A Kentucky CCDW license may still matter for reciprocity, documentation, and travel outside Kentucky.",
                      "GUIDANCE: A Michigan traveler should not assume Kentucky permitless carry helps in the next state."
                ],
                "source": "KRS 237.110; Kentucky State Police CCDW guidance."
          },
          {
                "title": "Prohibited Places",
                "risk": "Major Location Restriction",
                "body": [
                      "STATUTE / SOURCE: KRS 237.110; KRS 527.020.",
                      "SUMMARY: Kentucky law identifies locations where concealed deadly weapons may not be carried or may be restricted.",
                      "GUIDANCE: Schools, courthouses, detention facilities, police stations, federal property, and posted/private property require verification."
                ],
                "source": "KRS 237.110; KRS 527.020."
          },
          {
                "title": "Schools / School Property",
                "risk": "Extreme Risk Area",
                "body": [
                      "STATUTE / SOURCE: Kentucky school weapons statutes; KRS framework.",
                      "SUMMARY: School property and school activities remain high-risk restricted locations.",
                      "GUIDANCE: Do not rely on permitless carry for school parking lots, events, or school-controlled property without verifying law."
                ],
                "source": "Kentucky school weapons framework."
          },
          {
                "title": "Courthouses / Courtrooms",
                "risk": "Hard Stop Area",
                "body": [
                      "STATUTE / SOURCE: Kentucky court/security framework.",
                      "SUMMARY: Courthouses and courtrooms can be restricted and security-screened.",
                      "GUIDANCE: Do not bring a weapon to a courthouse unless a clear legal exception applies."
                ],
                "source": "Kentucky court/security framework."
          },
          {
                "title": "Private Property / Posted Premises",
                "risk": "Property Control",
                "body": [
                      "STATUTE / SOURCE: KRS 237.110; Kentucky private-property framework.",
                      "SUMMARY: Private businesses and property owners may restrict weapons on their premises.",
                      "GUIDANCE: If posted or told to leave, leave immediately."
                ],
                "source": "KRS 237.110; Kentucky private property framework."
          },
          {
                "title": "Government Buildings",
                "risk": "Public Building Risk",
                "body": [
                      "STATUTE / SOURCE: KRS 237.115.",
                      "SUMMARY: Kentucky law addresses local government restrictions and public buildings.",
                      "GUIDANCE: Government buildings should be treated as verify-first locations; do not assume public property means lawful carry."
                ],
                "source": "KRS 237.115."
          },
          {
                "title": "Vehicle Carry / Travel",
                "risk": "Travel Risk",
                "body": [
                      "STATUTE / SOURCE: KRS Chapter 237 and 527 framework.",
                      "SUMMARY: Kentucky vehicle carry can differ from Michigan and from neighboring states.",
                      "GUIDANCE: Verify storage, accessibility, and route. Check Ohio, Indiana, Tennessee, Illinois, or West Virginia if crossing borders."
                ],
                "source": "Kentucky firearms carry framework."
          },
          {
                "title": "Alcohol / Impairment",
                "risk": "Intoxication Risk",
                "body": [
                      "STATUTE / SOURCE: Kentucky weapons and intoxication framework.",
                      "SUMMARY: Carrying while impaired can create serious criminal and civil risk.",
                      "GUIDANCE: If drinking is part of the plan, carrying should not be."
                ],
                "source": "Kentucky weapons/intoxication framework."
          },
          {
                "title": "Federal Property / Post Offices",
                "risk": "Federal Law Overlay",
                "body": [
                      "STATUTE / SOURCE: Federal facility and postal property framework.",
                      "SUMMARY: Kentucky carry permission does not override federal restrictions.",
                      "GUIDANCE: Post offices, federal buildings, federal courthouses, and secure federal property require separate analysis."
                ],
                "source": "Federal facility and postal property framework."
          },
          {
                "title": "Use of Force / Self-Protection",
                "risk": "Force Law",
                "body": [
                      "STATUTE / SOURCE: KRS Chapter 503.",
                      "SUMMARY: Kentucky self-protection and defense-of-others law is fact-specific.",
                      "GUIDANCE: Do not use force over insults, ego, property disputes, road rage, warning shots, or punishment."
                ],
                "source": "KRS Chapter 503."
          },
          {
                "title": "Aftermath / Statements",
                "risk": "Post-Incident Risk",
                "body": [
                      "STATUTE / SOURCE: Criminal procedure and evidence framework.",
                      "SUMMARY: Statements after a defensive incident can become evidence.",
                      "GUIDANCE: Call 911, request help, identify evidence/witnesses if necessary, request counsel, then stop talking."
                ],
                "source": "Prime Defense aftermath protocol; Kentucky criminal procedure framework."
          }
    ],
    [
          {
                "title": "Can I Carry Here in Kentucky?",
                "steps": [
                      "1. Am I legally eligible to possess and carry?",
                      "2. Is this restricted by KRS 237.110, KRS 527.020, or another Kentucky law?",
                      "3. Is this school-related, court-related, government-controlled, posted/private, federal, or alcohol-related?",
                      "4. Am I crossing into another state?",
                      "5. If uncertain, do not enter armed."
                ]
          },
          {
                "title": "Kentucky Traffic Stop / Police Contact",
                "steps": [
                      "1. Pull over or stop safely.",
                      "2. Keep hands visible.",
                      "3. Do not reach for anything until instructed.",
                      "4. Follow state-specific disclosure or identification rules.",
                      "5. Answer lawful questions truthfully and wait for legal guidance before detailed statements."
                ]
          }
    ],
    [
          {
                "title": "Kentucky Road Trip",
                "summary": "Rules change from Michigan, Ohio, Indiana, and Tennessee.",
                "guidance": [
                      "Check route states.",
                      "Check vehicle carry.",
                      "Check destination rules."
                ]
          },
          {
                "title": "Posted Business",
                "summary": "Private property restrictions can matter.",
                "guidance": [
                      "Look for signs.",
                      "Leave if instructed.",
                      "Do not argue with staff."
                ]
          }
    ],
    [
          "Assuming Michigan rules apply outside Michigan.",
          "Ignoring prohibited places.",
          "Ignoring private-property or signage rules.",
          "Ignoring vehicle carry differences.",
          "Ignoring school-zone restrictions.",
          "Ignoring alcohol-location rules.",
          "Assuming federal property follows state carry rules.",
          "Relying on old reciprocity information.",
          "Assuming Kentucky permitless carry applies to every person.",
          "Ignoring KRS 237.110 location restrictions.",
          "Ignoring government building rules under KRS 237.115."
    ],
    [
          "Permit recognition checked.",
          "Eligibility checked.",
          "Prohibited places checked.",
          "School rules checked.",
          "Vehicle carry checked.",
          "Private property/signage checked.",
          "Alcohol-related restrictions checked.",
          "Federal property checked separately.",
          "Use-of-force standards reviewed.",
          "Next state on trip route checked."
    ],
    [
          {
                "myth": "If my Michigan CPL is recognized, Michigan law follows me into Kentucky.",
                "reality": "No. Kentucky law controls once you are physically in Kentucky."
          },
          {
                "myth": "A recognized permit means I can carry anywhere.",
                "reality": "No. Recognition does not override prohibited places, private property, federal property, schools, alcohol rules, or vehicle restrictions."
          }
    ]
  ),

  TN: makeProfile(
    "Tennessee",
    "Law-Backed Ultra Expanded Travel State",
    "Tennessee is a common travel state and has permitless handgun carry for people who meet statutory requirements, but users must understand TCA Title 39 Chapter 17 Part 13, prohibited locations, school property, posted private property, government buildings, vehicle issues, alcohol/impairment, and the current evolving legal landscape around parks and public recreational areas.",
    {
          "reciprocity": "Michigan CPL treated as recognized in this app travel engine. Tennessee also has permitless handgun carry for qualifying persons.",
          "permitlessCarry": "TCA 39-17-1307 framework: Tennessee permits many qualifying persons to carry a handgun without a permit, subject to restrictions.",
          "concealedCarry": "Concealed carry may be lawful for qualifying persons, but prohibited places and posting rules still apply.",
          "openCarry": "Tennessee permitless carry applies to handguns for qualifying persons, but open carry may still create practical and location-specific issues.",
          "vehicleCarry": "Tennessee vehicle carry must comply with state law and route-state rules.",
          "dutyToInform": "Verify Tennessee officer-contact rules; keep hands visible and follow commands.",
          "privateSigns": "TCA 39-17-1359: posted property rules can restrict carry.",
          "forceLaw": "Tennessee self-defense law is fact-specific and should be verified from current TCA provisions."
    },
    [
          "Tennessee law controls while the user is physically in Tennessee.",
          "A green map status is only a starting point for reciprocity, not a location-by-location authorization.",
          "Every section below is tied to a statute or official source where possible.",
          "Users should verify current law before relying on any summary."
    ],
    [
          {
                "title": "Permitless Handgun Carry",
                "risk": "Core Eligibility Rule",
                "body": [
                      "STATUTE / SOURCE: TCA 39-17-1307; Tennessee Department of Safety guidance.",
                      "SUMMARY: Tennessee allows many qualifying persons to carry a handgun without a permit, subject to statutory requirements and restrictions.",
                      "GUIDANCE: Permitless carry is not universal and does not apply to everyone or every location."
                ],
                "source": "TCA 39-17-1307; Tennessee Department of Safety handgun carry guidance."
          },
          {
                "title": "Handgun Permits Still Matter",
                "risk": "Travel / Reciprocity",
                "body": [
                      "STATUTE / SOURCE: Tennessee Department of Safety handgun permit framework.",
                      "SUMMARY: Tennessee permits may still matter for reciprocity, documentation, and travel outside Tennessee.",
                      "GUIDANCE: A Michigan traveler should not assume Tennessee permitless carry helps in the next state."
                ],
                "source": "Tennessee Department of Safety handgun permit guidance."
          },
          {
                "title": "Prohibited Places",
                "risk": "Major Location Restriction",
                "body": [
                      "STATUTE / SOURCE: TCA Title 39, Chapter 17, Part 13.",
                      "SUMMARY: Tennessee law identifies locations where firearms or handguns are prohibited or restricted.",
                      "GUIDANCE: Check schools, courtrooms, public buildings, posted private property, federal property, and other sensitive places before entering."
                ],
                "source": "TCA Title 39, Chapter 17, Part 13."
          },
          {
                "title": "Schools / School Property",
                "risk": "Extreme Risk Area",
                "body": [
                      "STATUTE / SOURCE: TCA 39-17-1309 and related school-property framework.",
                      "SUMMARY: Tennessee law restricts firearms on school property and school-related locations, subject to statutory provisions.",
                      "GUIDANCE: Do not assume permitless carry or a Michigan CPL solves school property, parking, event, or student activity issues."
                ],
                "source": "TCA 39-17-1309."
          },
          {
                "title": "Posted Property / Private Signs",
                "risk": "Property Control",
                "body": [
                      "STATUTE / SOURCE: TCA 39-17-1359.",
                      "SUMMARY: Tennessee law allows property to be posted against firearms under statutory requirements.",
                      "GUIDANCE: Look for signs. If posted or instructed to leave, leave immediately."
                ],
                "source": "TCA 39-17-1359."
          },
          {
                "title": "Government Buildings / Security Screening",
                "risk": "Public Building Risk",
                "body": [
                      "STATUTE / SOURCE: TCA 39-17-1359 and local-government building framework.",
                      "SUMMARY: Some local government properties may restrict handguns only if statutory security measures are provided, but exceptions and special locations apply.",
                      "GUIDANCE: Government buildings, libraries, schools, law-enforcement facilities, courtrooms, and mental health/substance facilities require careful verification."
                ],
                "source": "TCA 39-17-1359; Tennessee public building framework."
          },
          {
                "title": "Courthouses / Courtrooms",
                "risk": "Hard Stop Area",
                "body": [
                      "STATUTE / SOURCE: Tennessee court/security framework.",
                      "SUMMARY: Courtrooms and court facilities can be restricted and security-screened.",
                      "GUIDANCE: Do not bring a firearm to a courtroom or courthouse unless a clear legal exception applies."
                ],
                "source": "Tennessee court/security framework."
          },
          {
                "title": "Parks / Recreation Areas",
                "risk": "Evolving Law Warning",
                "body": [
                      "STATUTE / SOURCE: Recent Tennessee court decisions and TCA framework.",
                      "SUMMARY: Tennessee restrictions involving parks and public recreation areas have been subject to recent litigation and legal changes.",
                      "GUIDANCE: Because this area is evolving, verify current law before relying on older summaries."
                ],
                "source": "Recent Tennessee litigation and TCA public recreation framework."
          },
          {
                "title": "Vehicle Carry / Travel",
                "risk": "Travel Risk",
                "body": [
                      "STATUTE / SOURCE: TCA Title 39, Chapter 17, Part 13 framework.",
                      "SUMMARY: Tennessee vehicle carry may be lawful for qualifying persons but remains subject to eligibility and location restrictions.",
                      "GUIDANCE: Check vehicle rules and the next state on the route."
                ],
                "source": "TCA Title 39, Chapter 17, Part 13."
          },
          {
                "title": "Alcohol / Impairment",
                "risk": "Intoxication Risk",
                "body": [
                      "STATUTE / SOURCE: Tennessee weapons/intoxication framework.",
                      "SUMMARY: Weapons and impairment create serious criminal and civil risk.",
                      "GUIDANCE: If drinking is part of the plan, carrying should not be."
                ],
                "source": "Tennessee weapons/intoxication framework."
          },
          {
                "title": "Federal Property / Post Offices",
                "risk": "Federal Law Overlay",
                "body": [
                      "STATUTE / SOURCE: Federal facility and postal property framework.",
                      "SUMMARY: Tennessee carry permission does not override federal restrictions.",
                      "GUIDANCE: Post offices, federal buildings, federal courthouses, and secure federal property require separate federal-law analysis."
                ],
                "source": "Federal facility and postal property framework."
          },
          {
                "title": "Use of Force / Self-Defense",
                "risk": "Force Law",
                "body": [
                      "STATUTE / SOURCE: Tennessee self-defense statutes and case law framework.",
                      "SUMMARY: Tennessee self-defense law is fact-specific and must be verified from current law.",
                      "GUIDANCE: Avoid slogans. Deadly force is not for insults, ego, property disputes, road rage, warning shots, or punishment."
                ],
                "source": "Tennessee self-defense framework."
          },
          {
                "title": "Aftermath / Statements",
                "risk": "Post-Incident Risk",
                "body": [
                      "STATUTE / SOURCE: Criminal procedure and evidence framework.",
                      "SUMMARY: Statements after an incident can become evidence.",
                      "GUIDANCE: Call 911, request help, identify evidence/witnesses if necessary, request counsel, then stop talking."
                ],
                "source": "Prime Defense aftermath protocol; Tennessee criminal procedure framework."
          }
    ],
    [
          {
                "title": "Can I Carry Here in Tennessee?",
                "steps": [
                      "1. Am I legally eligible under Tennessee law?",
                      "2. Is this prohibited under TCA Title 39, Chapter 17, Part 13?",
                      "3. Is this school-related under TCA 39-17-1309?",
                      "4. Is this posted under TCA 39-17-1359?",
                      "5. Is this government, courtroom, law-enforcement, federal, alcohol-related, or security-controlled?",
                      "6. If uncertain, do not enter armed."
                ]
          },
          {
                "title": "Tennessee Traffic Stop / Police Contact",
                "steps": [
                      "1. Pull over or stop safely.",
                      "2. Keep hands visible.",
                      "3. Do not reach for anything until instructed.",
                      "4. Follow state-specific disclosure or identification rules.",
                      "5. Answer lawful questions truthfully and wait for legal guidance before detailed statements."
                ]
          }
    ],
    [
          {
                "title": "Nashville / Memphis Venue",
                "summary": "Entertainment venues often combine private signs, alcohol, crowds, and security screening.",
                "guidance": [
                      "Check posted signs.",
                      "Do not drink while armed.",
                      "Do not argue with security."
                ]
          },
          {
                "title": "School or University Event",
                "summary": "School-related property remains high-risk.",
                "guidance": [
                      "Check TCA 39-17-1309.",
                      "Do not rely on permitless carry.",
                      "When uncertain, do not enter armed."
                ]
          },
          {
                "title": "Public Park or Recreation Area",
                "summary": "Tennessee law in this area has been evolving.",
                "guidance": [
                      "Verify current law before relying on older summaries.",
                      "Check whether a school event or government facility is involved.",
                      "Follow posted restrictions and current legal guidance."
                ]
          }
    ],
    [
          "Assuming Michigan rules apply outside Michigan.",
          "Ignoring prohibited places.",
          "Ignoring private-property or signage rules.",
          "Ignoring vehicle carry differences.",
          "Ignoring school-zone restrictions.",
          "Ignoring alcohol-location rules.",
          "Assuming federal property follows state carry rules.",
          "Relying on old reciprocity information.",
          "Assuming permitless handgun carry applies to every person.",
          "Ignoring TCA 39-17-1359 posted property rules.",
          "Relying on outdated Tennessee parks/recreation summaries."
    ],
    [
          "Permit recognition checked.",
          "Eligibility checked.",
          "Prohibited places checked.",
          "School rules checked.",
          "Vehicle carry checked.",
          "Private property/signage checked.",
          "Alcohol-related restrictions checked.",
          "Federal property checked separately.",
          "Use-of-force standards reviewed.",
          "Next state on trip route checked."
    ],
    [
          {
                "myth": "If my Michigan CPL is recognized, Michigan law follows me into Tennessee.",
                "reality": "No. Tennessee law controls once you are physically in Tennessee."
          },
          {
                "myth": "A recognized permit means I can carry anywhere.",
                "reality": "No. Recognition does not override prohibited places, private property, federal property, schools, alcohol rules, or vehicle restrictions."
          }
    ]
  ),

  PA: makeProfile(
    "Pennsylvania",
    "Law-Backed Ultra Expanded Travel State",
    "Pennsylvania is a high-priority travel state for Michigan CPL holders because it is a common eastern travel route and has strict license rules for concealed carry and vehicle carry. Pennsylvania generally requires a valid license to carry a firearm concealed or in a vehicle, and state law includes important restrictions involving schools, courts, Philadelphia, emergency conditions, private property, federal property, and use-of-force conduct.",
    {
      reciprocity: "Michigan CPL should be verified against current Pennsylvania reciprocity before travel. This app treats Pennsylvania as recognized for Michigan CPL travel, but Pennsylvania law controls while physically in Pennsylvania.",
      permitlessCarry: "No general permitless concealed carry. 18 Pa.C.S. § 6106 generally prohibits concealed carry or vehicle carry without a valid license unless an exception applies.",
      concealedCarry: "18 Pa.C.S. § 6106 and § 6109: concealed carry generally requires a valid and lawfully issued license.",
      openCarry: "Open carry may be lawful in some areas, but Philadelphia, vehicles, emergency conditions, prohibited places, and police contact create major risk.",
      vehicleCarry: "18 Pa.C.S. § 6106: carrying a firearm in a vehicle generally requires a valid license unless a statutory exception applies.",
      dutyToInform: "Pennsylvania does not use the same automatic disclosure rule as Michigan, but police-contact behavior still matters. Answer lawful questions truthfully and avoid reaching.",
      privateSigns: "Private property rules and trespass law matter. Leave immediately if asked.",
      forceLaw: "Pennsylvania self-defense law is fact-specific. Deadly force must still be legally justified."
    },
    [
      "Pennsylvania is not permitless for concealed carry or vehicle carry.",
      "Vehicle carry is one of the biggest traps for out-of-state travelers.",
      "Philadelphia has special significance under Pennsylvania firearms law.",
      "School property, courts, federal property, and private property require separate review.",
      "A green reciprocity status does not mean every location or method of carry is lawful."
    ],
    [
      {
        title: "License Required for Concealed Carry / Vehicle Carry",
        risk: "Core Rule",
        body: [
          "STATUTE: 18 Pa.C.S. § 6106.",
          "SUMMARY: Pennsylvania generally prohibits carrying a firearm concealed on or about the person, or carrying a firearm in a vehicle, without a valid and lawfully issued license unless a statutory exception applies.",
          "GUIDANCE: This is the key Pennsylvania travel warning. A Michigan CPL holder must verify recognition and must understand that vehicle carry is treated seriously under Pennsylvania law."
        ],
        source: "18 Pa.C.S. § 6106."
      },
      {
        title: "Pennsylvania License to Carry Firearms",
        risk: "License / Recognition Rule",
        body: [
          "STATUTE: 18 Pa.C.S. § 6109.",
          "SUMMARY: Pennsylvania’s license-to-carry statute governs issuance, eligibility, denial, and the licensing framework for carrying firearms.",
          "GUIDANCE: Out-of-state travelers should verify whether their permit is honored and should carry license/ID documentation when relying on reciprocity."
        ],
        source: "18 Pa.C.S. § 6109."
      },
      {
        title: "Vehicle Carry",
        risk: "High-Risk Travel Issue",
        body: [
          "STATUTE: 18 Pa.C.S. § 6106.",
          "SUMMARY: Carrying a firearm in a vehicle generally requires a valid license unless an exception applies.",
          "GUIDANCE: Do not assume open carry rules on foot apply once entering a vehicle. Pennsylvania vehicle carry should be treated as license-required unless a clear exception applies."
        ],
        source: "18 Pa.C.S. § 6106."
      },
      {
        title: "Philadelphia Carry Warning",
        risk: "City-Specific Risk",
        body: [
          "STATUTE: 18 Pa.C.S. § 6108.",
          "SUMMARY: Pennsylvania law restricts carrying firearms on public streets or public property in Philadelphia unless licensed or exempt.",
          "GUIDANCE: Philadelphia should be treated as a special-risk area. Do not rely on general open-carry assumptions while in Philadelphia."
        ],
        source: "18 Pa.C.S. § 6108."
      },
      {
        title: "Emergency Conditions",
        risk: "Declared Emergency Risk",
        body: [
          "STATUTE: 18 Pa.C.S. § 6107.",
          "SUMMARY: Pennsylvania restricts carrying firearms on public streets or public property during an emergency proclaimed by governmental authorities unless licensed or exempt.",
          "GUIDANCE: During declared emergencies, unrest, disaster conditions, or evacuation events, verify the current legal status before carrying."
        ],
        source: "18 Pa.C.S. § 6107."
      },
      {
        title: "Schools",
        risk: "Extreme Risk Area",
        body: [
          "STATUTE: 18 Pa.C.S. § 912.",
          "SUMMARY: Pennsylvania law restricts possession of weapons on school property, including school buildings, grounds, and conveyances, unless a statutory defense or exception applies.",
          "GUIDANCE: School parking lots, events, and pickup/drop-off should be treated as verify-first situations."
        ],
        source: "18 Pa.C.S. § 912."
      },
      {
        title: "Court Facilities",
        risk: "Hard Stop Area",
        body: [
          "STATUTE: 18 Pa.C.S. § 913.",
          "SUMMARY: Pennsylvania law restricts possession of firearms and dangerous weapons in court facilities, subject to statutory procedures and exceptions.",
          "GUIDANCE: Do not approach courthouse security armed. Plan storage before arrival."
        ],
        source: "18 Pa.C.S. § 913."
      },
      {
        title: "Private Property / Posted Locations",
        risk: "Trespass and Property Control",
        body: [
          "STATUTE / SOURCE: Pennsylvania trespass and property-control framework.",
          "SUMMARY: Private property owners may control access and require people to leave.",
          "GUIDANCE: If posted or asked to leave, leave immediately. Do not turn a carry issue into trespass, disorderly conduct, or a confrontation."
        ],
        source: "Pennsylvania trespass/property law framework."
      },
      {
        title: "Federal Property / Post Offices",
        risk: "Federal Law Overlay",
        body: [
          "STATUTE / SOURCE: Federal facility and postal property framework.",
          "SUMMARY: Pennsylvania carry permission does not override federal property restrictions.",
          "GUIDANCE: Federal buildings, post offices, federal courthouses, and secure federal facilities must be checked separately."
        ],
        source: "Federal facility and postal property framework."
      },
      {
        title: "Use of Force / Self-Defense",
        risk: "Fact-Specific Legal Risk",
        body: [
          "STATUTE / SOURCE: Pennsylvania self-defense framework.",
          "SUMMARY: Defensive force must be justified under the facts. Deadly force is not justified for anger, property disputes, insults, road rage, intimidation, or punishment.",
          "GUIDANCE: Avoid, disengage, call 911, identify evidence/witnesses when necessary, request counsel, and avoid detailed statements under stress."
        ],
        source: "Pennsylvania self-defense law framework."
      }
    ],
    [
      {
        title: "Pennsylvania Travel Checklist",
        steps: [
          "1. Verify Michigan CPL recognition.",
          "2. Check 18 Pa.C.S. § 6106 before vehicle carry.",
          "3. Check Philadelphia restrictions under § 6108.",
          "4. Check emergency restrictions under § 6107.",
          "5. Check school property under § 912.",
          "6. Check court facilities under § 913.",
          "7. Check federal and private property separately."
        ]
      }
    ],
    [
      {
        title: "Driving Through Pennsylvania",
        summary: "Vehicle carry is the biggest Pennsylvania trap for travelers.",
        guidance: [
          "Verify license recognition before entering.",
          "Do not assume open carry rules apply in a vehicle.",
          "Carry license/ID documentation.",
          "Check Philadelphia if your route enters the city."
        ]
      },
      {
        title: "Philadelphia Stop",
        summary: "Philadelphia has special statutory treatment for public carry.",
        guidance: [
          "Check § 6108.",
          "Do not rely on general open carry assumptions.",
          "Avoid unnecessary handling or display."
        ]
      }
    ],
    [
      "Assuming Pennsylvania is permitless carry.",
      "Ignoring vehicle carry under § 6106.",
      "Ignoring Philadelphia restrictions under § 6108.",
      "Ignoring schools under § 912.",
      "Ignoring court facilities under § 913.",
      "Assuming reciprocity overrides location restrictions."
    ],
    [
      "Permit recognition checked.",
      "Vehicle carry under § 6106 checked.",
      "Philadelphia route checked.",
      "School property checked.",
      "Court facilities checked.",
      "Federal property checked.",
      "Private property/signs checked."
    ],
    [
      {
        myth: "If Pennsylvania honors my permit, I can carry anywhere.",
        reality: "No. Recognition does not override vehicle rules, Philadelphia, schools, courts, federal property, or private property."
      }
    ]
  ),

  WI: makeProfile(
    "Wisconsin",
    "Law-Backed Ultra Expanded Travel State",
    "Wisconsin is a high-priority Great Lakes travel state for Michigan CPL holders. Wisconsin has a concealed carry licensing system and recognizes qualifying out-of-state licenses, but users must understand license/ID possession, prohibited places, school zones, vehicles, government buildings, alcohol-related issues, private property, and federal property restrictions.",
    {
      reciprocity: "Michigan CPL recognition should be verified before travel. Wisconsin law controls while physically in Wisconsin.",
      permitlessCarry: "No general permitless concealed carry. Wisconsin generally requires a valid Wisconsin CCW license or recognized out-of-state license for concealed carry.",
      concealedCarry: "Wis. Stat. § 175.60 governs Wisconsin concealed carry licensing and recognition.",
      openCarry: "Open carry may be lawful in some circumstances, but restricted places, vehicles, disorderly conduct, and private property still matter.",
      vehicleCarry: "Vehicle carry must be analyzed under Wisconsin concealed carry and transport laws.",
      dutyToInform: "Wisconsin requires license/ID possession and display upon lawful request when carrying concealed under the license framework.",
      privateSigns: "Private property owners may restrict carry. Leave immediately if asked.",
      forceLaw: "Wisconsin self-defense law is fact-specific and must be verified before relying on any summary."
    },
    [
      "Wisconsin is not a permitless concealed carry state.",
      "A recognized out-of-state license may matter, but users must carry proper documentation.",
      "School zones, government buildings, law enforcement facilities, and posted private property require special caution.",
      "Open carry does not solve concealed carry or restricted-location issues.",
      "Great Lakes travel often involves parks, campgrounds, boats, hotels, and vehicle storage—each should be checked separately."
    ],
    [
      {
        title: "Concealed Carry License Framework",
        risk: "Core Carry Rule",
        body: [
          "STATUTE: Wis. Stat. § 175.60.",
          "SUMMARY: Wisconsin’s concealed carry statute governs issuance of licenses and the concealed carry framework.",
          "GUIDANCE: A Michigan CPL holder should verify Wisconsin recognition and should carry the out-of-state license and photo identification when relying on reciprocity."
        ],
        source: "Wis. Stat. § 175.60."
      },
      {
        title: "Carrying License and Photo ID",
        risk: "Documentation Requirement",
        body: [
          "STATUTE: Wis. Stat. § 175.60(4).",
          "SUMMARY: Wisconsin requires a licensee to have the license document and photographic identification while carrying concealed.",
          "GUIDANCE: Members should carry both permit and photo ID. Do not assume a digital photo or memory of the permit number is enough."
        ],
        source: "Wis. Stat. § 175.60(4)."
      },
      {
        title: "Carrying Concealed Without License",
        risk: "Criminal Exposure",
        body: [
          "STATUTE: Wis. Stat. § 941.23.",
          "SUMMARY: Wisconsin law addresses carrying a concealed weapon and exceptions for lawful carry.",
          "GUIDANCE: Do not treat Wisconsin as permitless concealed carry. Verify license recognition before carrying concealed."
        ],
        source: "Wis. Stat. § 941.23."
      },
      {
        title: "School Zones",
        risk: "Extreme Risk Area",
        body: [
          "STATUTE: Wis. Stat. § 948.605.",
          "SUMMARY: Wisconsin law restricts firearm possession in school zones, subject to exceptions.",
          "GUIDANCE: School buildings, grounds, events, and parking areas should be treated as verify-first areas."
        ],
        source: "Wis. Stat. § 948.605."
      },
      {
        title: "Prohibited / Restricted Locations",
        risk: "Location Restriction",
        body: [
          "STATUTE / SOURCE: Wis. Stat. § 175.60 and related Wisconsin prohibited-place framework.",
          "SUMMARY: Wisconsin law restricts carry in certain locations and allows certain property owners/government facilities to restrict firearms.",
          "GUIDANCE: Check police stations, sheriff offices, jails, courthouses/courtrooms, schools, federal property, secure areas, and posted locations before entering."
        ],
        source: "Wis. Stat. § 175.60; Wisconsin DOJ CCW guidance."
      },
      {
        title: "Private Property / Posted Locations",
        risk: "Trespass / Property Control",
        body: [
          "STATUTE / SOURCE: Wisconsin property and CCW posting framework.",
          "SUMMARY: Property owners may restrict firearms on private property.",
          "GUIDANCE: Posted signs and staff/security instructions should be followed. Leave immediately if asked."
        ],
        source: "Wisconsin DOJ CCW FAQ; Wisconsin property law framework."
      },
      {
        title: "Vehicle Carry",
        risk: "Travel / Storage Risk",
        body: [
          "STATUTE / SOURCE: Wis. Stat. § 941.23; Wis. Stat. § 175.60.",
          "SUMMARY: Vehicle carry must comply with Wisconsin concealed carry and transport rules.",
          "GUIDANCE: If carrying concealed in a vehicle, verify license recognition and avoid unnecessary reaching during police contact."
        ],
        source: "Wis. Stat. § 941.23; Wis. Stat. § 175.60."
      },
      {
        title: "Alcohol / Impairment",
        risk: "Judgment and Legal Risk",
        body: [
          "STATUTE / SOURCE: Wisconsin weapons and intoxication framework.",
          "SUMMARY: Carrying while impaired creates legal and tactical risk.",
          "GUIDANCE: If drinking is part of the plan, carrying should not be. Bars, restaurants, festivals, stadiums, and events should be checked for posted rules."
        ],
        source: "Wisconsin weapons/intoxication framework."
      },
      {
        title: "Federal Property / Post Offices",
        risk: "Federal Law Overlay",
        body: [
          "STATUTE / SOURCE: Federal facility and postal property framework.",
          "SUMMARY: Wisconsin carry permission does not override federal restrictions.",
          "GUIDANCE: Federal buildings, federal courthouses, post offices, and secure federal property must be checked separately."
        ],
        source: "Federal facility and postal property framework."
      },
      {
        title: "Use of Force / Self-Defense",
        risk: "Fact-Specific Legal Risk",
        body: [
          "STATUTE / SOURCE: Wisconsin self-defense framework.",
          "SUMMARY: Wisconsin self-defense law is fact-specific and depends on necessity, reasonableness, and the circumstances.",
          "GUIDANCE: Avoid confrontation, disengage if safely possible, call 911, identify evidence/witnesses, request counsel, and avoid long statements under stress."
        ],
        source: "Wisconsin self-defense law framework."
      }
    ],
    [
      {
        title: "Wisconsin Carry Checklist",
        steps: [
          "1. Verify Michigan CPL recognition.",
          "2. Carry license and photo ID.",
          "3. Check Wis. Stat. § 941.23 concealed carry rules.",
          "4. Check Wis. Stat. § 948.605 school zones.",
          "5. Check posted private property.",
          "6. Check federal and government facilities.",
          "7. Plan safe vehicle storage."
        ]
      }
    ],
    [
      {
        title: "Great Lakes Weekend Trip",
        summary: "Wisconsin travel often involves hotels, parks, restaurants, events, and vehicle storage.",
        guidance: [
          "Carry permit and photo ID.",
          "Check posted locations.",
          "Secure firearms from unauthorized access.",
          "Check parks/federal property separately."
        ]
      }
    ],
    [
      "Assuming Wisconsin is permitless concealed carry.",
      "Failing to carry license and photo ID.",
      "Ignoring school zones.",
      "Ignoring posted private property.",
      "Assuming vehicle carry has no separate rules.",
      "Ignoring federal property."
    ],
    [
      "Recognition checked.",
      "Permit and photo ID carried.",
      "School zones checked.",
      "Vehicle carry checked.",
      "Private signs checked.",
      "Federal property checked."
    ],
    [
      {
        myth: "Wisconsin is close to Michigan, so rules are basically the same.",
        reality: "No. Wisconsin has its own concealed carry, school zone, license/ID, and location rules."
      }
    ]
  ),

  WV: makeProfile(
    "West Virginia",
    "Law-Backed Ultra Expanded Travel State",
    "West Virginia is a permitless carry state for eligible adults 21 and older, but it still has statutory restrictions involving age, prohibited persons, school property, court facilities, campus carry, vehicles, private property, federal property, and use-of-force conduct.",
    {
      reciprocity: "Michigan CPL recognition should be verified, but West Virginia also allows permitless concealed carry for eligible adults 21 and older.",
      permitlessCarry: "W. Va. Code § 61-7-7 allows certain adults 21+ to carry concealed without a license if not prohibited.",
      concealedCarry: "Permitless concealed carry applies only to eligible persons. Younger adults may need a provisional license.",
      openCarry: "Open carry may be lawful for eligible persons, but restricted locations and conduct still matter.",
      vehicleCarry: "Vehicle carry must be analyzed under West Virginia weapons law, school property law, and prohibited-person rules.",
      dutyToInform: "Verify current West Virginia police-contact rules before travel. Keep hands visible and answer lawful questions truthfully.",
      privateSigns: "Private property and posted locations still matter. Leave if asked.",
      forceLaw: "West Virginia self-defense law is fact-specific."
    },
    [
      "West Virginia permitless carry does not mean carry anywhere.",
      "School and court-related premises are major statutory risk points.",
      "Campus carry has detailed rules and exceptions.",
      "A license may still matter for reciprocity outside West Virginia.",
      "Federal property and private property must be checked separately."
    ],
    [
      {
        title: "Permitless Concealed Carry",
        risk: "Core Eligibility Rule",
        body: [
          "STATUTE: W. Va. Code § 61-7-7.",
          "SUMMARY: Certain adults 21 and older may carry a concealed deadly weapon without a license if they are not prohibited under state or federal law.",
          "GUIDANCE: Permitless carry does not apply to prohibited persons and does not override restricted places."
        ],
        source: "W. Va. Code § 61-7-7."
      },
      {
        title: "Under 21 / Provisional License",
        risk: "Age-Based Carry Risk",
        body: [
          "STATUTE: W. Va. Code § 61-7-3; W. Va. Code § 61-7-4.",
          "SUMMARY: Persons under 21 have separate rules and may require a provisional license or other lawful authorization.",
          "GUIDANCE: Do not assume an 18–20-year-old may carry concealed without a license."
        ],
        source: "W. Va. Code § 61-7-3; § 61-7-4."
      },
      {
        title: "Concealed Weapon License",
        risk: "License / Reciprocity Context",
        body: [
          "STATUTE: W. Va. Code § 61-7-4.",
          "SUMMARY: West Virginia law provides a licensing process for concealed deadly weapons, including resident and nonresident licenses.",
          "GUIDANCE: Even with permitless carry inside West Virginia, a license may matter for travel reciprocity in other states."
        ],
        source: "W. Va. Code § 61-7-4."
      },
      {
        title: "Prohibited Persons",
        risk: "Disqualification Risk",
        body: [
          "STATUTE: W. Va. Code § 61-7-7.",
          "SUMMARY: West Virginia law identifies persons prohibited from possessing firearms or carrying under the statutory framework.",
          "GUIDANCE: Protection orders, criminal history, domestic violence issues, substance issues, and federal prohibitions should be checked before carrying."
        ],
        source: "W. Va. Code § 61-7-7."
      },
      {
        title: "Schools / Educational Facilities",
        risk: "Extreme Risk Area",
        body: [
          "STATUTE: W. Va. Code § 61-7-11a.",
          "SUMMARY: West Virginia restricts deadly weapons on premises of educational facilities and court premises, subject to statutory exceptions.",
          "GUIDANCE: Schools, school events, educational property, and court-related premises should be treated as verify-first locations."
        ],
        source: "W. Va. Code § 61-7-11a."
      },
      {
        title: "Courts / Court Premises",
        risk: "Hard Stop Area",
        body: [
          "STATUTE: W. Va. Code § 61-7-11a.",
          "SUMMARY: West Virginia restricts deadly weapons on premises housing courts of law and family law courts.",
          "GUIDANCE: Do not enter courthouse or court-related premises armed unless a clear legal exception applies."
        ],
        source: "W. Va. Code § 61-7-11a."
      },
      {
        title: "Campus Carry",
        risk: "Detailed Campus Rules",
        body: [
          "STATUTE / SOURCE: West Virginia campus carry framework.",
          "SUMMARY: West Virginia law allows certain concealed carry on public college/university campuses, but restrictions, exceptions, storage rules, and specific locations may apply.",
          "GUIDANCE: Campus carry should not be summarized casually. Check the institution, location type, and current rules before carrying."
        ],
        source: "West Virginia campus carry framework; W. Va. Code Chapter 18B / § 61-7 references."
      },
      {
        title: "Brandishing / Threatening Conduct",
        risk: "Display Risk",
        body: [
          "STATUTE: W. Va. Code § 61-7-11.",
          "SUMMARY: West Virginia law addresses brandishing deadly weapons and threatening or causing breach of the peace.",
          "GUIDANCE: Do not display a firearm to intimidate, win an argument, or stop a verbal dispute. If display was necessary due to an immediate threat, call 911 first."
        ],
        source: "W. Va. Code § 61-7-11."
      },
      {
        title: "Private Property / Posted Locations",
        risk: "Property Control",
        body: [
          "STATUTE / SOURCE: West Virginia property and trespass framework.",
          "SUMMARY: Private property owners may control access and restrict firearms on their property.",
          "GUIDANCE: If posted or asked to leave, leave immediately."
        ],
        source: "West Virginia property/trespass framework."
      },
      {
        title: "Federal Property / Post Offices",
        risk: "Federal Law Overlay",
        body: [
          "STATUTE / SOURCE: Federal facility and postal property framework.",
          "SUMMARY: West Virginia carry permission does not override federal restrictions.",
          "GUIDANCE: Federal buildings, post offices, federal courthouses, and secure federal property must be checked separately."
        ],
        source: "Federal facility and postal property framework."
      }
    ],
    [
      {
        title: "West Virginia Carry Checklist",
        steps: [
          "1. Confirm age and eligibility under § 61-7-7.",
          "2. If under 21, check § 61-7-3 and license requirements.",
          "3. Check schools and courts under § 61-7-11a.",
          "4. Check campus carry rules if on college/university property.",
          "5. Check private property and federal property.",
          "6. Avoid display/brandishing conduct under § 61-7-11."
        ]
      }
    ],
    [
      {
        title: "Mountain Trip / Vehicle Travel",
        summary: "West Virginia is permissive, but schools, courts, campuses, and private property remain traps.",
        guidance: [
          "Verify age/eligibility.",
          "Check campus rules.",
          "Check schools and courts.",
          "Do not assume permitless means unrestricted."
        ]
      }
    ],
    [
      "Assuming permitless carry means carry anywhere.",
      "Ignoring under-21 restrictions.",
      "Ignoring schools and courts under § 61-7-11a.",
      "Ignoring campus carry exceptions.",
      "Displaying a firearm in a non-deadly dispute."
    ],
    [
      "Age and eligibility checked.",
      "School/court restrictions checked.",
      "Campus rules checked.",
      "Private property checked.",
      "Federal property checked.",
      "Display/brandishing risk understood."
    ],
    [
      {
        myth: "West Virginia is permitless, so there are no location restrictions.",
        reality: "No. Schools, courts, campuses, private property, federal property, and prohibited-person rules still matter."
      }
    ]
  ),

  GA: makeProfile(
    "Georgia",
    "Law-Backed Ultra Expanded Travel State",
    "Georgia is a high-priority southern travel state with permitless carry for lawful weapons carriers. Georgia law recognizes out-of-state weapons carry licenses, but users must understand lawful weapons carrier status, unauthorized locations, school safety zones, courthouses, government buildings, places of worship, private property, vehicles, and federal property.",
    {
      reciprocity: "Georgia law authorizes persons licensed to carry in another state to carry in Georgia, but they must comply with Georgia law.",
      permitlessCarry: "O.C.G.A. § 16-11-126: lawful weapons carriers may carry weapons as allowed by Georgia law.",
      concealedCarry: "Georgia allows carry by lawful weapons carriers, but unauthorized locations still apply.",
      openCarry: "Georgia carry may be open or concealed for lawful weapons carriers, subject to restricted locations.",
      vehicleCarry: "O.C.G.A. § 16-11-126 addresses carrying in private passenger motor vehicles.",
      dutyToInform: "Verify current Georgia police-contact rules. Keep hands visible and answer lawful questions truthfully.",
      privateSigns: "Private property owners may control access and ask armed persons to leave.",
      forceLaw: "Georgia self-defense law is fact-specific."
    },
    [
      "Georgia permitless carry applies to lawful weapons carriers, not everyone.",
      "Out-of-state license holders must comply with Georgia law.",
      "Unauthorized locations remain in effect.",
      "Schools, courthouses, government buildings, jails/prisons, places of worship, and nuclear power facilities require special caution.",
      "Private property and federal property remain separate issues."
    ],
    [
      {
        title: "Lawful Weapons Carrier / Carry Authority",
        risk: "Core Eligibility Rule",
        body: [
          "STATUTE: O.C.G.A. § 16-11-126.",
          "SUMMARY: Georgia law allows lawful weapons carriers to carry weapons under Georgia’s carry framework.",
          "GUIDANCE: Do not treat Georgia as ruleless. The user must qualify as a lawful weapons carrier and must obey Georgia restricted-location law."
        ],
        source: "O.C.G.A. § 16-11-126."
      },
      {
        title: "Out-of-State License Recognition",
        risk: "Travel Carry Rule",
        body: [
          "STATUTE: O.C.G.A. § 16-11-126(d).",
          "SUMMARY: Georgia authorizes a person licensed to carry a weapon in another state to carry in Georgia, provided the person carries in compliance with Georgia law.",
          "GUIDANCE: Michigan CPL may help with Georgia recognition, but Georgia law controls while in Georgia."
        ],
        source: "O.C.G.A. § 16-11-126(d)."
      },
      {
        title: "Unauthorized Locations",
        risk: "Major Location Restriction",
        body: [
          "STATUTE: O.C.G.A. § 16-11-127.",
          "SUMMARY: Georgia law restricts carrying weapons or long guns in certain unauthorized locations.",
          "GUIDANCE: Check government buildings, courthouses, jails/prisons, places of worship unless permitted, state mental health facilities, nuclear power facilities, and polling places."
        ],
        source: "O.C.G.A. § 16-11-127."
      },
      {
        title: "School Safety Zones",
        risk: "Extreme Risk Area",
        body: [
          "STATUTE: O.C.G.A. § 16-11-127.1.",
          "SUMMARY: Georgia law restricts weapons in school safety zones, subject to statutory exceptions.",
          "GUIDANCE: Schools, school buses, school functions, parking areas, and events should be treated as verify-first areas."
        ],
        source: "O.C.G.A. § 16-11-127.1."
      },
      {
        title: "Courthouses",
        risk: "Hard Stop Area",
        body: [
          "STATUTE: O.C.G.A. § 16-11-127.",
          "SUMMARY: Georgia law treats courthouses as unauthorized locations.",
          "GUIDANCE: Do not approach courthouse security armed. Plan storage before arrival."
        ],
        source: "O.C.G.A. § 16-11-127."
      },
      {
        title: "Government Buildings",
        risk: "Government Facility Risk",
        body: [
          "STATUTE: O.C.G.A. § 16-11-127.",
          "SUMMARY: Georgia restricts weapons in government buildings under the statutory framework, with different treatment depending on lawful weapons carrier status and security screening.",
          "GUIDANCE: Government buildings should be treated as verify-first locations."
        ],
        source: "O.C.G.A. § 16-11-127."
      },
      {
        title: "Places of Worship",
        risk: "Permission Required",
        body: [
          "STATUTE: O.C.G.A. § 16-11-127.",
          "SUMMARY: Georgia restricts carry in places of worship unless the governing body or authority permits carry.",
          "GUIDANCE: Do not assume churches or religious facilities allow carry. Verify policy with the proper authority."
        ],
        source: "O.C.G.A. § 16-11-127."
      },
      {
        title: "Vehicle Carry",
        risk: "Travel / Vehicle Rule",
        body: [
          "STATUTE: O.C.G.A. § 16-11-126.",
          "SUMMARY: Georgia law addresses carrying handguns, long guns, and weapons in private passenger motor vehicles.",
          "GUIDANCE: Vehicle carry should still be paired with calm traffic-stop behavior: hands visible, no reaching, truthful answers."
        ],
        source: "O.C.G.A. § 16-11-126."
      },
      {
        title: "Private Property / Posted Locations",
        risk: "Property Control",
        body: [
          "STATUTE / SOURCE: Georgia trespass/property framework.",
          "SUMMARY: Private property owners may control access and require armed persons to leave.",
          "GUIDANCE: If posted or asked to leave, leave immediately."
        ],
        source: "Georgia property/trespass framework."
      },
      {
        title: "Federal Property / Post Offices",
        risk: "Federal Law Overlay",
        body: [
          "STATUTE / SOURCE: Federal facility and postal property framework.",
          "SUMMARY: Georgia carry permission does not override federal restrictions.",
          "GUIDANCE: Federal buildings, federal courthouses, post offices, and secure federal property must be checked separately."
        ],
        source: "Federal facility and postal property framework."
      }
    ],
    [
      {
        title: "Georgia Carry Checklist",
        steps: [
          "1. Confirm lawful weapons carrier status.",
          "2. Verify out-of-state license recognition if relying on Michigan CPL.",
          "3. Check unauthorized locations under § 16-11-127.",
          "4. Check school safety zones under § 16-11-127.1.",
          "5. Check places of worship policy.",
          "6. Check private and federal property separately."
        ]
      }
    ],
    [
      {
        title: "Atlanta / Event Venue Travel",
        summary: "Georgia is permissive, but city travel often involves government buildings, events, private security, and parking.",
        guidance: [
          "Check unauthorized locations.",
          "Watch for security screening.",
          "Follow private property instructions.",
          "Do not argue with venue staff."
        ]
      }
    ],
    [
      "Assuming lawful weapons carrier means carry anywhere.",
      "Ignoring Georgia unauthorized locations.",
      "Ignoring school safety zones.",
      "Ignoring places of worship rules.",
      "Ignoring private property instructions.",
      "Assuming federal property follows Georgia law."
    ],
    [
      "Lawful weapons carrier status checked.",
      "Recognition checked.",
      "Unauthorized locations checked.",
      "School safety zones checked.",
      "Vehicle carry checked.",
      "Private/federal property checked."
    ],
    [
      {
        myth: "Georgia permitless carry means no restrictions.",
        reality: "No. Georgia still has unauthorized locations, school safety zones, private property rules, and federal restrictions."
      }
    ]
  ),

  NC: makeProfile(
    "North Carolina",
    "Law-Backed Ultra Expanded Travel State",
    "North Carolina is a high-priority southeastern travel state with a concealed handgun permit framework. North Carolina recognizes valid permits, but users must understand permit scope, prohibited places, educational property, assemblies where admission is charged, alcohol-related locations, posted private property, vehicles, parks, and federal property.",
    {
      reciprocity: "North Carolina recognizes valid concealed handgun permits, but users must comply with North Carolina law while physically in the state.",
      permitlessCarry: "No general permitless concealed carry. Concealed handgun carry generally requires a valid permit.",
      concealedCarry: "G.S. 14-415.11: a person with a concealed handgun permit may carry unless otherwise prohibited by law.",
      openCarry: "Open carry may be lawful in some circumstances, but prohibited places, local restrictions, private property, and police contact still matter.",
      vehicleCarry: "Vehicle carry must be analyzed under concealed carry and open carry rules.",
      dutyToInform: "North Carolina permit holders must disclose to law enforcement when approached or addressed by an officer while carrying concealed.",
      privateSigns: "G.S. 14-415.11(c)(8): posted private premises may prohibit concealed carry.",
      forceLaw: "North Carolina self-defense law is fact-specific."
    },
    [
      "North Carolina is not general permitless concealed carry.",
      "Permit recognition does not override prohibited places.",
      "Educational property is a major statutory risk area.",
      "Private posting has explicit statutory significance.",
      "Alcohol-related and event locations need careful review."
    ],
    [
      {
        title: "Concealed Handgun Permit Authority",
        risk: "Core Carry Rule",
        body: [
          "STATUTE: G.S. 14-415.11.",
          "SUMMARY: A person with a concealed handgun permit may carry a concealed handgun unless otherwise specifically prohibited by law.",
          "GUIDANCE: A permit is not blanket authority. Restricted places and posted private property still matter."
        ],
        source: "N.C. Gen. Stat. § 14-415.11."
      },
      {
        title: "Permit Scope / Prohibited Places",
        risk: "Major Carry Restriction",
        body: [
          "STATUTE: G.S. 14-415.11(c).",
          "SUMMARY: North Carolina law identifies areas where a concealed handgun permit does not authorize carry, including areas prohibited by other statutes and posted private premises.",
          "GUIDANCE: Check every destination separately before carrying concealed."
        ],
        source: "N.C. Gen. Stat. § 14-415.11(c)."
      },
      {
        title: "Educational Property",
        risk: "Extreme Risk Area",
        body: [
          "STATUTE: G.S. 14-269.2.",
          "SUMMARY: North Carolina restricts possession or carrying of firearms and other weapons on educational property, subject to statutory exceptions.",
          "GUIDANCE: Schools, colleges, school events, parking lots, and educational property should be treated as verify-first areas."
        ],
        source: "N.C. Gen. Stat. § 14-269.2."
      },
      {
        title: "Assemblies / Admission Charged / Alcohol Sold",
        risk: "Event and Alcohol Location Risk",
        body: [
          "STATUTE: G.S. 14-269.3.",
          "SUMMARY: North Carolina restricts weapons at certain assemblies and establishments where alcoholic beverages are sold and consumed, subject to exceptions.",
          "GUIDANCE: Bars, restaurants, festivals, concerts, stadium events, and ticketed gatherings should be checked carefully."
        ],
        source: "N.C. Gen. Stat. § 14-269.3."
      },
      {
        title: "Private Premises / Posted Notice",
        risk: "Posted Property Rule",
        body: [
          "STATUTE: G.S. 14-415.11(c)(8).",
          "SUMMARY: A concealed handgun permit does not authorize carry on private premises where notice prohibiting concealed handguns is conspicuously posted or stated by the person in control of the premises.",
          "GUIDANCE: Posted signs matter in North Carolina. Leave immediately if asked."
        ],
        source: "N.C. Gen. Stat. § 14-415.11(c)(8)."
      },
      {
        title: "Duty to Disclose During Police Contact",
        risk: "Police Contact Requirement",
        body: [
          "STATUTE / SOURCE: North Carolina concealed handgun permit framework.",
          "SUMMARY: North Carolina permit holders carrying concealed must disclose to law enforcement when approached or addressed by an officer.",
          "GUIDANCE: Use a calm script: Officer, I have a valid permit and I am carrying. How would you like me to proceed?"
        ],
        source: "North Carolina concealed handgun permit guidance; N.C. Gen. Stat. Article 54B."
      },
      {
        title: "State Parks",
        risk: "Parks / Public Lands",
        body: [
          "STATUTE: G.S. 14-415.11(c1).",
          "SUMMARY: North Carolina law allows permit holders to carry concealed handguns on grounds or waters of state parks, subject to other restrictions.",
          "GUIDANCE: State parks are not the same as federal land, visitor centers, schools, posted buildings, or private property. Verify the specific location."
        ],
        source: "N.C. Gen. Stat. § 14-415.11(c1)."
      },
      {
        title: "Vehicle Carry",
        risk: "Vehicle / Concealment Risk",
        body: [
          "STATUTE / SOURCE: G.S. 14-269; G.S. 14-415.11.",
          "SUMMARY: North Carolina concealed weapon law and concealed handgun permit law affect how firearms may be carried in vehicles.",
          "GUIDANCE: If relying on concealment in a vehicle, verify permit validity and disclosure duties before travel."
        ],
        source: "N.C. Gen. Stat. § 14-269; § 14-415.11."
      },
      {
        title: "Federal Property / Post Offices",
        risk: "Federal Law Overlay",
        body: [
          "STATUTE / SOURCE: Federal facility and postal property framework.",
          "SUMMARY: North Carolina carry permission does not override federal property restrictions.",
          "GUIDANCE: Federal buildings, federal courthouses, post offices, and secure federal property must be checked separately."
        ],
        source: "Federal facility and postal property framework."
      },
      {
        title: "Use of Force / Self-Defense",
        risk: "Fact-Specific Legal Risk",
        body: [
          "STATUTE / SOURCE: North Carolina self-defense framework.",
          "SUMMARY: Defensive force must be justified under the facts and applicable North Carolina law.",
          "GUIDANCE: Avoid, disengage, call 911, identify evidence/witnesses when necessary, request counsel, and avoid detailed statements under stress."
        ],
        source: "North Carolina self-defense law framework."
      }
    ],
    [
      {
        title: "North Carolina Carry Checklist",
        steps: [
          "1. Verify permit recognition.",
          "2. Check G.S. 14-415.11 permit scope.",
          "3. Check educational property under G.S. 14-269.2.",
          "4. Check alcohol/event restrictions under G.S. 14-269.3.",
          "5. Check posted private property under G.S. 14-415.11(c)(8).",
          "6. Know police disclosure script.",
          "7. Check federal property separately."
        ]
      }
    ],
    [
      {
        title: "Beach / Vacation Travel",
        summary: "North Carolina travel may include hotels, restaurants, parks, alcohol locations, posted businesses, and federal coastal property.",
        guidance: [
          "Check posted signs.",
          "Check alcohol/event restrictions.",
          "Verify whether land is state, federal, municipal, or private.",
          "Know disclosure duties."
        ]
      }
    ],
    [
      "Assuming North Carolina is permitless concealed carry.",
      "Ignoring posted private property.",
      "Ignoring educational property.",
      "Ignoring alcohol/event restrictions.",
      "Forgetting police disclosure duties.",
      "Assuming state park rules apply to federal property."
    ],
    [
      "Permit recognition checked.",
      "Educational property checked.",
      "Alcohol/event restrictions checked.",
      "Posted private premises checked.",
      "Vehicle carry checked.",
      "Police disclosure script ready.",
      "Federal property checked."
    ],
    [
      {
        myth: "If North Carolina recognizes my permit, I can carry anywhere.",
        reality: "No. Permit recognition does not override educational property, posted private premises, alcohol/event restrictions, federal property, or disclosure duties."
      }
    ]
  ),

  CA: makeProfile(
    "California",
    "High-Risk Law-Backed Ultra Expanded State",
    "California is a high-risk non-recognition state for Michigan CPL holders. A Michigan CPL does not authorize carry in California. California has a restrictive licensing framework, broad sensitive-place restrictions, strict school-zone law, detailed vehicle/transport rules, magazine/equipment restrictions, and significant local and federal overlays. This profile should be treated as a warning-first travel profile.",
    {
      reciprocity: "Michigan CPL is treated as not recognized in this app travel engine. Do not carry in California on a Michigan CPL alone.",
      permitlessCarry: "No general permitless concealed carry. California generally requires a California CCW license for public concealed carry.",
      concealedCarry: "California Penal Code §§ 26150, 26155, and related licensing provisions govern California CCW licenses.",
      openCarry: "Open carry is generally restricted in California and should not be relied upon for travel carry.",
      vehicleCarry: "California vehicle transport must be handled carefully. Treat travel as lawful transport only unless the user has valid California authority.",
      dutyToInform: "Verify current California license conditions and local issuing-agency rules. Keep hands visible and answer lawful questions truthfully.",
      privateSigns: "Private property, sensitive places, posted areas, and local rules may restrict carry.",
      forceLaw: "California self-defense law is fact-specific and should be verified before relying on any summary."
    },
    [
      "California is not a Michigan CPL carry state.",
      "California should be treated as a transport-only state unless the user has lawful California carry authority.",
      "School zones, sensitive places, government property, alcohol locations, parks, casinos, public transit, and federal property require separate review.",
      "California magazine, ammunition, firearm-feature, and local restrictions can create legal exposure even when carry is not occurring.",
      "Do not rely on reciprocity apps alone for California. Verify official law and current injunction/enforcement status."
    ],
    [
      {
        title: "Michigan CPL Not Recognized",
        risk: "Do Not Carry on Michigan CPL",
        body: [
          "STATUTE / SOURCE: California CCW licensing framework; Penal Code §§ 26150 and 26155.",
          "SUMMARY: California requires California-issued carry authority for ordinary public concealed carry. A Michigan CPL does not authorize public carry in California.",
          "GUIDANCE: Treat California as a non-recognition state. Do not carry on a Michigan CPL alone."
        ],
        source: "California Penal Code §§ 26150, 26155; California DOJ CCW guidance."
      },
      {
        title: "California CCW License Framework",
        risk: "State-Issued License Requirement",
        body: [
          "STATUTE: California Penal Code §§ 26150 and 26155.",
          "SUMMARY: California sheriffs and police chiefs may issue licenses to carry concealed firearms under California law and local procedures.",
          "GUIDANCE: A traveler should not assume they can carry without a California license. Local issuing conditions and restrictions may apply."
        ],
        source: "California Penal Code §§ 26150, 26155."
      },
      {
        title: "Sensitive Places / SB 2 Restrictions",
        risk: "Major Location Restriction",
        body: [
          "STATUTE: California Penal Code § 26230.",
          "SUMMARY: California law designates many sensitive places where carry may be restricted, and enforcement status can be affected by litigation.",
          "GUIDANCE: Verify current enforcement status before relying on any California sensitive-place summary."
        ],
        source: "California Penal Code § 26230; California DOJ law-enforcement bulletins."
      },
      {
        title: "School Zones",
        risk: "Extreme Risk Area",
        body: [
          "STATUTE: California Penal Code § 626.9.",
          "SUMMARY: California generally prohibits firearm possession in a school zone unless a statutory exception applies.",
          "GUIDANCE: School property, parking areas, nearby zones, school events, and vehicle presence should be treated as high-risk."
        ],
        source: "California Penal Code § 626.9."
      },
      {
        title: "Vehicle Transport",
        risk: "Transport / Vehicle Trap",
        body: [
          "STATUTE / SOURCE: California firearm transport framework.",
          "SUMMARY: California transport rules are separate from carry rules and should be followed strictly when transporting firearms.",
          "GUIDANCE: Treat firearms as unloaded, locked, and transported only in a lawful manner unless the user has valid California carry authority."
        ],
        source: "California firearm transport framework; California DOJ guidance."
      },
      {
        title: "Open Carry",
        risk: "Do Not Rely on Open Carry",
        body: [
          "STATUTE / SOURCE: California open carry restrictions under Penal Code framework.",
          "SUMMARY: California generally restricts open carry of loaded and unloaded firearms in public places, subject to limited exceptions.",
          "GUIDANCE: Do not rely on open carry as a workaround for lack of California carry authority."
        ],
        source: "California Penal Code open-carry framework."
      },
      {
        title: "Magazines / Ammunition / Equipment",
        risk: "Equipment Restriction Risk",
        body: [
          "STATUTE / SOURCE: California large-capacity magazine, ammunition, and firearm-feature restrictions.",
          "SUMMARY: California regulates certain magazines, ammunition transactions, firearm configurations, and accessories more heavily than many states.",
          "GUIDANCE: Verify firearm, magazine, ammunition, and accessory legality before entering California."
        ],
        source: "California Penal Code firearm-equipment framework."
      },
      {
        title: "Federal Property / Post Offices",
        risk: "Federal Law Overlay",
        body: [
          "STATUTE / SOURCE: Federal facility and postal property framework.",
          "SUMMARY: California carry or transport permission does not override federal restrictions.",
          "GUIDANCE: Federal buildings, federal courthouses, post offices, and secure federal property must be checked separately."
        ],
        source: "Federal facility and postal property framework."
      },
      {
        title: "Private Property / Posted Locations",
        risk: "Property Control",
        body: [
          "STATUTE / SOURCE: California property/trespass framework and sensitive-place law.",
          "SUMMARY: Private property and posted locations can restrict access and carry.",
          "GUIDANCE: If posted or instructed to leave, leave immediately."
        ],
        source: "California property/trespass framework."
      },
      {
        title: "Use of Force / Self-Defense",
        risk: "Fact-Specific Legal Risk",
        body: [
          "STATUTE / SOURCE: California self-defense framework.",
          "SUMMARY: Defensive force must be justified by the facts. Carry legality and use-of-force legality are separate questions.",
          "GUIDANCE: Avoid confrontation, call 911, identify evidence/witnesses when necessary, request counsel, and avoid detailed statements."
        ],
        source: "California self-defense law framework."
      }
    ],
    [
      {
        title: "California Travel Checklist",
        steps: [
          "1. Do not carry on Michigan CPL alone.",
          "2. Verify California CCW authority if applicable.",
          "3. Check Penal Code § 26230 sensitive places.",
          "4. Check Penal Code § 626.9 school zones.",
          "5. Verify locked/unloaded transport rules.",
          "6. Verify magazine, ammunition, and equipment restrictions.",
          "7. Check federal and private property separately."
        ]
      }
    ],
    [
      {
        title: "Driving Into California",
        summary: "California should be treated as a transport-only state unless the user has California carry authority.",
        guidance: [
          "Do not carry on Michigan CPL.",
          "Transport unloaded and locked under California rules.",
          "Verify magazines and ammunition.",
          "Avoid unnecessary handling or stops."
        ]
      }
    ],
    [
      "Carrying on a Michigan CPL.",
      "Ignoring sensitive places.",
      "Ignoring school zones.",
      "Assuming open carry is an option.",
      "Ignoring magazine/ammunition restrictions.",
      "Failing to verify transport rules."
    ],
    [
      "Michigan CPL non-recognition understood.",
      "California CCW authority verified or no carry.",
      "Transport rules checked.",
      "Sensitive places checked.",
      "School zones checked.",
      "Equipment restrictions checked."
    ],
    [
      {
        myth: "I am visiting, so my Michigan CPL should be good enough.",
        reality: "No. California does not recognize Michigan CPL for ordinary carry in this app travel engine."
      }
    ]
  ),

  NY: makeProfile(
    "New York",
    "High-Risk Law-Backed Ultra Expanded State",
    "New York is a high-risk non-recognition state for Michigan CPL holders. A Michigan CPL does not authorize carry in New York. New York has a restrictive licensing framework, a broad sensitive-location statute, separate New York City concerns, strict school rules, public transportation restrictions, and major travel/transport risks.",
    {
      reciprocity: "Michigan CPL is treated as not recognized in this app travel engine. Do not carry in New York on a Michigan CPL alone.",
      permitlessCarry: "No permitless carry. New York requires New York carry authority.",
      concealedCarry: "New York Penal Law § 400.00 governs handgun licensing; Penal Law § 265.01-e restricts sensitive locations.",
      openCarry: "Do not rely on open carry in New York. New York handgun carry is license-based and highly restricted.",
      vehicleCarry: "Vehicle possession/transport must be handled with extreme caution under New York and federal transport rules.",
      dutyToInform: "Verify current New York license conditions and police-contact rules. Keep hands visible and answer lawful questions truthfully.",
      privateSigns: "New York sensitive/restricted location rules and private property rules must be checked.",
      forceLaw: "New York self-defense law is fact-specific and duty/retreat concepts may matter."
    },
    [
      "New York is not a Michigan CPL carry state.",
      "New York City must be treated as a separate high-risk legal environment.",
      "Sensitive-location restrictions are broad and include many common travel destinations.",
      "Transport through New York requires careful planning; casual stops can create risk.",
      "Public transit, Times Square, schools, government locations, parks, and other sensitive places require specific review."
    ],
    [
      {
        title: "Michigan CPL Not Recognized",
        risk: "Do Not Carry on Michigan CPL",
        body: [
          "STATUTE / SOURCE: New York Penal Law Article 400 licensing framework.",
          "SUMMARY: A Michigan CPL does not authorize public handgun carry in New York.",
          "GUIDANCE: Treat New York as a non-recognition state. Do not carry on Michigan CPL alone."
        ],
        source: "N.Y. Penal Law § 400.00."
      },
      {
        title: "New York License Framework",
        risk: "State License Requirement",
        body: [
          "STATUTE: N.Y. Penal Law § 400.00.",
          "SUMMARY: New York handgun possession/carry licensing is governed by New York law and local licensing officers.",
          "GUIDANCE: A traveler should not assume out-of-state licensing creates New York carry authority."
        ],
        source: "N.Y. Penal Law § 400.00."
      },
      {
        title: "Sensitive Locations",
        risk: "Major Location Restriction",
        body: [
          "STATUTE: N.Y. Penal Law § 265.01-e.",
          "SUMMARY: New York prohibits possession of firearms, rifles, or shotguns in sensitive locations as defined by statute unless an exception applies.",
          "GUIDANCE: Treat the sensitive-location list as a major travel warning. Verify before entering any public venue, transportation area, school, government location, or crowded public area."
        ],
        source: "N.Y. Penal Law § 265.01-e."
      },
      {
        title: "Restricted Locations / Private Property",
        risk: "Property and Location Risk",
        body: [
          "STATUTE / SOURCE: New York Concealed Carry Improvement Act framework.",
          "SUMMARY: New York law includes sensitive and restricted location concepts that can affect private property and public-facing locations.",
          "GUIDANCE: Do not assume absence of a sign means carry is lawful. Verify current New York rules before relying."
        ],
        source: "New York CCIA framework; N.Y. Penal Law Article 265."
      },
      {
        title: "New York City",
        risk: "Separate High-Risk Jurisdiction",
        body: [
          "STATUTE / SOURCE: New York City licensing and administrative framework.",
          "SUMMARY: New York City has its own licensing and enforcement environment in addition to state law.",
          "GUIDANCE: Treat NYC, subway/commuter rail, Times Square, airports, and crowded tourist areas as high-risk no-assumption zones."
        ],
        source: "New York State and New York City handgun licensing framework."
      },
      {
        title: "Schools",
        risk: "Extreme Risk Area",
        body: [
          "STATUTE: N.Y. Penal Law § 265.01-e and related school weapons laws.",
          "SUMMARY: Schools and education-related locations are treated as sensitive/high-risk areas under New York law.",
          "GUIDANCE: Do not enter school property, school events, or school-adjacent restricted areas armed unless a clear exception applies."
        ],
        source: "N.Y. Penal Law § 265.01-e; New York school weapons framework."
      },
      {
        title: "Public Transportation",
        risk: "Transit Restriction Risk",
        body: [
          "STATUTE / SOURCE: N.Y. Penal Law § 265.01-e and transit authority restrictions.",
          "SUMMARY: New York sensitive-location restrictions can apply to public transportation and related areas.",
          "GUIDANCE: Subways, buses, commuter rail, terminals, and transit hubs should be treated as restricted unless verified otherwise."
        ],
        source: "N.Y. Penal Law § 265.01-e; New York transit restrictions."
      },
      {
        title: "Vehicle Transport / Passing Through",
        risk: "Transport Trap",
        body: [
          "STATUTE / SOURCE: New York weapons law and federal interstate transport framework.",
          "SUMMARY: Transporting through New York requires strict compliance with state and federal rules.",
          "GUIDANCE: Plan route, avoid unnecessary stops, keep firearms unloaded/locked where applicable, and do not treat transport as carry."
        ],
        source: "New York Penal Law Article 265; federal interstate transport framework."
      },
      {
        title: "Magazines / Ammunition / Equipment",
        risk: "Equipment Restriction Risk",
        body: [
          "STATUTE / SOURCE: New York SAFE Act and Penal Law equipment restrictions.",
          "SUMMARY: New York regulates certain magazines, firearm features, ammunition-related issues, and configurations.",
          "GUIDANCE: Verify firearm, magazine, and ammunition legality before entering New York."
        ],
        source: "New York SAFE Act / Penal Law equipment framework."
      },
      {
        title: "Use of Force / Self-Defense",
        risk: "Fact-Specific Legal Risk",
        body: [
          "STATUTE / SOURCE: New York justification law framework.",
          "SUMMARY: New York self-defense law is fact-specific and can involve necessity, reasonableness, proportionality, and retreat-related issues.",
          "GUIDANCE: Avoid confrontation, disengage when safe, call 911, request counsel, and avoid detailed statements."
        ],
        source: "N.Y. Penal Law Article 35 framework."
      }
    ],
    [
      {
        title: "New York Travel Checklist",
        steps: [
          "1. Do not carry on Michigan CPL alone.",
          "2. Verify New York license authority if applicable.",
          "3. Check Penal Law § 265.01-e sensitive locations.",
          "4. Treat NYC as a separate high-risk environment.",
          "5. Verify transport rules before entry.",
          "6. Verify magazine/equipment restrictions.",
          "7. Avoid casual stops when transporting."
        ]
      }
    ],
    [
      {
        title: "Passing Through New York",
        summary: "New York is one of the highest-risk transport states for travelers.",
        guidance: [
          "Do not carry on Michigan CPL.",
          "Plan route carefully.",
          "Avoid unnecessary stops.",
          "Verify firearm and magazine legality."
        ]
      }
    ],
    [
      "Carrying on Michigan CPL.",
      "Ignoring sensitive locations.",
      "Ignoring New York City rules.",
      "Using public transit while armed.",
      "Ignoring transport limits.",
      "Ignoring magazine/equipment restrictions."
    ],
    [
      "Non-recognition understood.",
      "New York license authority verified or no carry.",
      "Sensitive locations checked.",
      "NYC checked separately.",
      "Transport rules checked.",
      "Equipment restrictions checked."
    ],
    [
      {
        myth: "I am just passing through New York, so it does not matter.",
        reality: "New York travel and transport must be planned carefully. Casual stops and noncompliant equipment can create serious risk."
      }
    ]
  ),

  NJ: makeProfile(
    "New Jersey",
    "High-Risk Law-Backed Ultra Expanded State",
    "New Jersey is a high-risk non-recognition state for Michigan CPL holders. A Michigan CPL does not authorize carry in New Jersey. New Jersey has a restrictive permit-to-carry framework, extensive sensitive-place restrictions, transportation rules, school restrictions, magazine limits, private property issues, and rapidly litigated carry restrictions.",
    {
      reciprocity: "Michigan CPL is treated as not recognized in this app travel engine. Do not carry in New Jersey on a Michigan CPL alone.",
      permitlessCarry: "No permitless carry. New Jersey requires New Jersey carry authority.",
      concealedCarry: "N.J.S.A. 2C:58-4 governs permits to carry handguns; N.J.S.A. 2C:58-4.6 lists many prohibited carry locations.",
      openCarry: "New Jersey permit-to-carry authority should not be treated as open carry authorization.",
      vehicleCarry: "Vehicle possession/transport is tightly regulated and should be treated as transport only unless lawful New Jersey carry authority exists.",
      dutyToInform: "Verify current New Jersey carry-permit duties and police-contact rules. Keep hands visible and answer lawful questions truthfully.",
      privateSigns: "New Jersey sensitive-place and private-property rules must be checked carefully.",
      forceLaw: "New Jersey self-defense law is fact-specific and should be verified before relying on any summary."
    },
    [
      "New Jersey is not a Michigan CPL carry state.",
      "New Jersey sensitive-place law is broad and has been subject to litigation.",
      "Magazine/equipment rules can create legal risk independent of carry.",
      "Transport rules must be followed strictly.",
      "Schools, courthouses, government buildings, parks, beaches, casinos, public gatherings, and private property require careful review."
    ],
    [
      {
        title: "Michigan CPL Not Recognized",
        risk: "Do Not Carry on Michigan CPL",
        body: [
          "STATUTE / SOURCE: New Jersey permit-to-carry framework.",
          "SUMMARY: A Michigan CPL does not authorize public handgun carry in New Jersey.",
          "GUIDANCE: Treat New Jersey as a non-recognition state. Do not carry on Michigan CPL alone."
        ],
        source: "N.J.S.A. 2C:58-4."
      },
      {
        title: "New Jersey Permit to Carry",
        risk: "Permit Requirement",
        body: [
          "STATUTE: N.J.S.A. 2C:58-4.",
          "SUMMARY: New Jersey regulates permits to carry handguns under state law.",
          "GUIDANCE: A traveler should not assume out-of-state permits create New Jersey carry authority."
        ],
        source: "N.J.S.A. 2C:58-4."
      },
      {
        title: "Prohibited Carry Locations / Sensitive Places",
        risk: "Major Location Restriction",
        body: [
          "STATUTE: N.J.S.A. 2C:58-4.6.",
          "SUMMARY: New Jersey lists places where carrying a firearm or destructive device is prohibited, subject to current law and litigation.",
          "GUIDANCE: Verify current enforcement status and location rules before entering any public building, park, beach, casino, school, courthouse, public gathering, or transportation area."
        ],
        source: "N.J.S.A. 2C:58-4.6."
      },
      {
        title: "Schools and Educational Property",
        risk: "Extreme Risk Area",
        body: [
          "STATUTE / SOURCE: N.J.S.A. 2C:58-4.6 and New Jersey school weapons framework.",
          "SUMMARY: Schools and education-related locations are prohibited or highly restricted areas under New Jersey law.",
          "GUIDANCE: Treat school property, buses, events, and parking areas as no-assumption zones."
        ],
        source: "N.J.S.A. 2C:58-4.6; New Jersey school weapons framework."
      },
      {
        title: "Vehicle Transport",
        risk: "Transport Trap",
        body: [
          "STATUTE / SOURCE: New Jersey firearm transport framework.",
          "SUMMARY: New Jersey regulates firearm possession and transport strictly.",
          "GUIDANCE: If transporting, follow lawful transport rules exactly. Do not treat transport as carry."
        ],
        source: "N.J.S.A. 2C:39-6 transport framework."
      },
      {
        title: "Magazine / Ammunition / Equipment Restrictions",
        risk: "Equipment Restriction Risk",
        body: [
          "STATUTE / SOURCE: New Jersey large-capacity magazine and ammunition/firearm framework.",
          "SUMMARY: New Jersey restricts certain magazines, ammunition, firearm types, and configurations.",
          "GUIDANCE: Verify firearm, magazine, ammunition, and accessory legality before entering New Jersey."
        ],
        source: "New Jersey firearm equipment restrictions framework."
      },
      {
        title: "Private Property / Posted Locations",
        risk: "Property Control",
        body: [
          "STATUTE / SOURCE: New Jersey sensitive-place and property law framework.",
          "SUMMARY: Private property and posted locations can restrict carry or access.",
          "GUIDANCE: If posted or instructed to leave, leave immediately."
        ],
        source: "N.J.S.A. 2C:58-4.6; New Jersey property/trespass framework."
      },
      {
        title: "Courts / Government Facilities",
        risk: "Hard Stop Area",
        body: [
          "STATUTE: N.J.S.A. 2C:58-4.6.",
          "SUMMARY: New Jersey sensitive-place law includes government and court-related restrictions.",
          "GUIDANCE: Do not approach courthouse or government security armed."
        ],
        source: "N.J.S.A. 2C:58-4.6."
      },
      {
        title: "Public Gatherings / Parks / Beaches / Casinos",
        risk: "Common Destination Risk",
        body: [
          "STATUTE: N.J.S.A. 2C:58-4.6.",
          "SUMMARY: New Jersey's prohibited-location framework includes many common public destinations.",
          "GUIDANCE: Parks, beaches, casinos, public gatherings, entertainment venues, and transportation areas require direct verification."
        ],
        source: "N.J.S.A. 2C:58-4.6; current litigation/enforcement guidance."
      },
      {
        title: "Use of Force / Self-Defense",
        risk: "Fact-Specific Legal Risk",
        body: [
          "STATUTE / SOURCE: New Jersey self-defense framework.",
          "SUMMARY: Defensive force must be justified by the facts under New Jersey law.",
          "GUIDANCE: Avoid confrontation, disengage when safe, call 911, request counsel, and avoid detailed statements."
        ],
        source: "New Jersey self-defense law framework."
      }
    ],
    [
      {
        title: "New Jersey Travel Checklist",
        steps: [
          "1. Do not carry on Michigan CPL alone.",
          "2. Verify New Jersey permit-to-carry authority if applicable.",
          "3. Check N.J.S.A. 2C:58-4.6 prohibited locations.",
          "4. Verify transport rules under New Jersey law.",
          "5. Verify magazine/equipment restrictions.",
          "6. Check private property and sensitive places.",
          "7. Track current litigation/enforcement updates."
        ]
      }
    ],
    [
      {
        title: "New Jersey Shore / Casino / Public Event Travel",
        summary: "Many common New Jersey destinations fall into sensitive-place or property-controlled categories.",
        guidance: [
          "Do not carry on Michigan CPL.",
          "Check prohibited locations.",
          "Check equipment legality.",
          "Follow transport rules exactly."
        ]
      }
    ],
    [
      "Carrying on Michigan CPL.",
      "Ignoring sensitive places.",
      "Ignoring transport rules.",
      "Ignoring magazine restrictions.",
      "Assuming permit-to-carry means open carry.",
      "Ignoring current litigation status."
    ],
    [
      "Non-recognition understood.",
      "NJ permit authority verified or no carry.",
      "Sensitive places checked.",
      "Transport rules checked.",
      "Magazine/equipment restrictions checked.",
      "Private property checked."
    ],
    [
      {
        myth: "If I am legal in Pennsylvania or Delaware, I am legal in New Jersey.",
        reality: "No. New Jersey has its own restrictive carry, transport, magazine, and sensitive-place laws."
      }
    ]
  ),

  MA: makeProfile(
    "Massachusetts",
    "High-Risk Law-Backed Ultra Expanded State",
    "Massachusetts is a high-risk non-recognition state for Michigan CPL holders. A Michigan CPL does not authorize carry in Massachusetts. Massachusetts has a restrictive licensing framework, vehicle possession rules, ammunition and magazine restrictions, intoxication restrictions, safe storage obligations, and important school/government/federal property concerns.",
    {
      reciprocity: "Michigan CPL is treated as not recognized in this app travel engine. Do not carry in Massachusetts on a Michigan CPL alone.",
      permitlessCarry: "No permitless carry. Massachusetts requires Massachusetts licensing authority.",
      concealedCarry: "Mass. Gen. Laws ch. 140, § 131 governs licenses to carry firearms.",
      openCarry: "Do not rely on open carry in Massachusetts. Massachusetts carry is license-based and highly regulated.",
      vehicleCarry: "Mass. Gen. Laws ch. 269, § 10 addresses possession/control in a vehicle without proper licensing.",
      dutyToInform: "Verify current Massachusetts license conditions and police-contact rules. Keep hands visible and answer lawful questions truthfully.",
      privateSigns: "Private property and posted locations still matter. Leave if asked.",
      forceLaw: "Massachusetts self-defense law is fact-specific."
    },
    [
      "Massachusetts is not a Michigan CPL carry state.",
      "Massachusetts licensing and possession rules are strict.",
      "Vehicle possession without proper Massachusetts authority can create serious exposure.",
      "Magazine, ammunition, safe storage, and equipment rules must be verified.",
      "Schools, courts, government buildings, federal property, and private property require separate review."
    ],
    [
      {
        title: "Massachusetts License to Carry",
        risk: "State License Requirement",
        body: [
          "STATUTE: M.G.L. ch. 140, § 131.",
          "SUMMARY: Massachusetts governs licenses to carry firearms through a state licensing framework.",
          "GUIDANCE: A Michigan CPL does not substitute for Massachusetts carry authority."
        ],
        source: "Mass. Gen. Laws ch. 140, § 131."
      },
      {
        title: "Unlawful Possession / Vehicle Control",
        risk: "Core Criminal Exposure",
        body: [
          "STATUTE: M.G.L. ch. 269, § 10.",
          "SUMMARY: Massachusetts law criminalizes possession or control of a firearm, including in a vehicle, without proper statutory authority or licensing.",
          "GUIDANCE: Treat Massachusetts as a high-risk state for vehicle possession and transport."
        ],
        source: "Mass. Gen. Laws ch. 269, § 10."
      },
      {
        title: "Nonresident Carry / Travel",
        risk: "Nonresident License Risk",
        body: [
          "STATUTE / SOURCE: Massachusetts firearms licensing framework.",
          "SUMMARY: Nonresidents must verify Massachusetts nonresident licensing and temporary carry requirements before possessing or carrying.",
          "GUIDANCE: Do not enter Massachusetts relying on Michigan CPL alone."
        ],
        source: "Massachusetts firearms licensing framework."
      },
      {
        title: "Firearm Identification / Possession Framework",
        risk: "Licensing and Possession Risk",
        body: [
          "STATUTE: M.G.L. ch. 140, §§ 129B and 129C.",
          "SUMMARY: Massachusetts regulates firearm identification, possession, and licensing obligations.",
          "GUIDANCE: Verify possession authority before bringing any firearm into Massachusetts."
        ],
        source: "Mass. Gen. Laws ch. 140, §§ 129B, 129C."
      },
      {
        title: "Large Capacity Weapons / Feeding Devices",
        risk: "Equipment Restriction Risk",
        body: [
          "STATUTE: M.G.L. ch. 269, § 10 and § 10F; ch. 140 definitions.",
          "SUMMARY: Massachusetts restricts large-capacity weapons and large-capacity feeding devices.",
          "GUIDANCE: Verify magazine and firearm configuration before entering Massachusetts."
        ],
        source: "Mass. Gen. Laws ch. 269, §§ 10, 10F; ch. 140 § 121."
      },
      {
        title: "Carrying Loaded While Under Influence",
        risk: "Intoxication Risk",
        body: [
          "STATUTE: M.G.L. ch. 269, § 10H.",
          "SUMMARY: Massachusetts law addresses carrying a loaded firearm while under the influence of liquor, marijuana, narcotic drugs, depressants, stimulant substances, or toxic vapors.",
          "GUIDANCE: If alcohol, marijuana, drugs, or impairment are involved, do not carry."
        ],
        source: "Mass. Gen. Laws ch. 269, § 10H."
      },
      {
        title: "Safe Storage",
        risk: "Storage / Child Access Risk",
        body: [
          "STATUTE / SOURCE: Massachusetts safe storage framework.",
          "SUMMARY: Massachusetts imposes firearm storage obligations.",
          "GUIDANCE: Firearms should be locked, secured, and inaccessible to unauthorized persons when not under direct control."
        ],
        source: "Massachusetts safe storage law framework."
      },
      {
        title: "Schools / Government / Courts",
        risk: "Location Restriction Risk",
        body: [
          "STATUTE / SOURCE: Massachusetts weapons and prohibited-location framework.",
          "SUMMARY: Schools, courts, government buildings, and secured public facilities can create serious location restrictions.",
          "GUIDANCE: Treat educational, court, government, and security-screened buildings as verify-first/no-assumption locations."
        ],
        source: "Massachusetts weapons/prohibited-location framework."
      },
      {
        title: "Federal Property / Post Offices",
        risk: "Federal Law Overlay",
        body: [
          "STATUTE / SOURCE: Federal facility and postal property framework.",
          "SUMMARY: Massachusetts carry or possession authority does not override federal restrictions.",
          "GUIDANCE: Federal buildings, post offices, federal courthouses, and secure federal property must be checked separately."
        ],
        source: "Federal facility and postal property framework."
      },
      {
        title: "Use of Force / Self-Defense",
        risk: "Fact-Specific Legal Risk",
        body: [
          "STATUTE / SOURCE: Massachusetts self-defense framework.",
          "SUMMARY: Massachusetts self-defense law is fact-specific and may involve retreat/avoidance concepts depending on location and facts.",
          "GUIDANCE: Avoid confrontation, disengage when safe, call 911, request counsel, and avoid detailed statements."
        ],
        source: "Massachusetts self-defense law framework."
      }
    ],
    [
      {
        title: "Massachusetts Travel Checklist",
        steps: [
          "1. Do not carry on Michigan CPL alone.",
          "2. Verify Massachusetts licensing/nonresident authority.",
          "3. Check M.G.L. ch. 269 § 10 possession/vehicle rules.",
          "4. Verify magazine/equipment restrictions.",
          "5. Check intoxication law under § 10H.",
          "6. Check safe storage rules.",
          "7. Check schools/courts/government/federal property."
        ]
      }
    ],
    [
      {
        title: "Driving Into Massachusetts",
        summary: "Massachusetts is high risk for possession, vehicle control, magazines, and licensing.",
        guidance: [
          "Do not carry on Michigan CPL.",
          "Verify Massachusetts authority before entry.",
          "Check magazine/equipment legality.",
          "Treat vehicle possession as high risk."
        ]
      }
    ],
    [
      "Carrying on Michigan CPL.",
      "Ignoring vehicle possession/control rules.",
      "Ignoring magazine restrictions.",
      "Ignoring licensing requirements.",
      "Ignoring safe storage.",
      "Carrying while impaired."
    ],
    [
      "Non-recognition understood.",
      "Massachusetts license authority verified or no carry.",
      "Vehicle possession rules checked.",
      "Magazine/equipment checked.",
      "Safe storage checked.",
      "Location restrictions checked."
    ],
    [
      {
        myth: "Massachusetts is just another New England state; my permit should be fine.",
        reality: "No. Massachusetts has its own strict licensing, possession, transport, and equipment rules."
      }
    ]
  ),

  CT: makeProfile(
    "Connecticut",
    "High-Risk Law-Backed Ultra Expanded State",
    "Connecticut is a high-risk non-recognition state for Michigan CPL holders. Connecticut does not honor Michigan CPL for carry. Connecticut has a pistol permit framework, restrictions on carrying without a permit, recent open-carry/display restrictions, school and government location restrictions, magazine/equipment rules, private-property limitations, and federal overlays.",
    {
      reciprocity: "Michigan CPL is treated as not recognized in this app travel engine. Do not carry in Connecticut on a Michigan CPL alone.",
      permitlessCarry: "No permitless handgun carry. Connecticut generally requires a Connecticut pistol/revolver permit for carry.",
      concealedCarry: "Conn. Gen. Stat. §§ 29-28 and 29-35 govern pistol/revolver permits and carry without permit prohibitions.",
      openCarry: "Connecticut now restricts open carry/knowing display concepts. Do not rely on open carry.",
      vehicleCarry: "Vehicle carry/transport must comply with Connecticut permit and transport rules.",
      dutyToInform: "Verify current Connecticut police-contact and permit-display rules. Keep hands visible and answer lawful questions truthfully.",
      privateSigns: "Connecticut permit authority does not override private property prohibitions.",
      forceLaw: "Connecticut self-defense law is fact-specific."
    },
    [
      "Connecticut is not a Michigan CPL carry state.",
      "Connecticut requires Connecticut authority for handgun carry.",
      "Open carry/display is restricted and should not be relied upon.",
      "Schools, legislative buildings, government buildings, parks, private property, and federal property require review.",
      "Magazine/equipment restrictions must be checked before travel."
    ],
    [
      {
        title: "Connecticut Pistol / Revolver Permit",
        risk: "State Permit Requirement",
        body: [
          "STATUTE: Conn. Gen. Stat. § 29-28.",
          "SUMMARY: Connecticut provides a permit framework for carrying pistols and revolvers.",
          "GUIDANCE: A Michigan CPL does not authorize carry in Connecticut."
        ],
        source: "Conn. Gen. Stat. § 29-28."
      },
      {
        title: "Carrying Without Permit Prohibited",
        risk: "Core Criminal Exposure",
        body: [
          "STATUTE: Conn. Gen. Stat. § 29-35.",
          "SUMMARY: Connecticut prohibits carrying a pistol or revolver without a permit, subject to statutory exceptions.",
          "GUIDANCE: Do not carry in Connecticut without valid Connecticut authority."
        ],
        source: "Conn. Gen. Stat. § 29-35."
      },
      {
        title: "Open Carry / Display Restriction",
        risk: "Display Risk",
        body: [
          "STATUTE: Conn. Gen. Stat. § 29-35 and current Connecticut public act framework.",
          "SUMMARY: Connecticut restricts knowingly carrying with intent to display a firearm in public, subject to exceptions.",
          "GUIDANCE: Do not rely on open carry or visible display in Connecticut."
        ],
        source: "Conn. Gen. Stat. § 29-35."
      },
      {
        title: "Permit Must Be Carried",
        risk: "Documentation Requirement",
        body: [
          "STATUTE: Conn. Gen. Stat. § 29-35.",
          "SUMMARY: Connecticut permit holders must carry the permit while carrying the pistol or revolver.",
          "GUIDANCE: A user with Connecticut authority should carry permit documentation and photo identification."
        ],
        source: "Conn. Gen. Stat. § 29-35."
      },
      {
        title: "Schools",
        risk: "Extreme Risk Area",
        body: [
          "STATUTE: Conn. Gen. Stat. § 53a-217b.",
          "SUMMARY: Connecticut restricts possession of firearms and deadly weapons on school grounds, subject to exceptions.",
          "GUIDANCE: Schools, school grounds, events, and parking areas should be treated as verify-first/no-assumption zones."
        ],
        source: "Conn. Gen. Stat. § 53a-217b."
      },
      {
        title: "Private Property / Premises Prohibition",
        risk: "Property Control",
        body: [
          "STATUTE / SOURCE: Connecticut carry-location framework.",
          "SUMMARY: A Connecticut permit does not authorize carry where possession or carrying is prohibited by the person who owns or controls the premises.",
          "GUIDANCE: Posted signs and verbal instructions matter. Leave immediately if asked."
        ],
        source: "Connecticut location restriction framework."
      },
      {
        title: "Legislative / Government Buildings",
        risk: "Government Facility Risk",
        body: [
          "STATUTE / SOURCE: Connecticut location restriction framework.",
          "SUMMARY: Connecticut restricts firearms in certain government and legislative buildings.",
          "GUIDANCE: Treat legislative buildings, courts, government offices, and security-screened facilities as verify-first locations."
        ],
        source: "Connecticut location restriction framework."
      },
      {
        title: "Magazine / Equipment Restrictions",
        risk: "Equipment Restriction Risk",
        body: [
          "STATUTE / SOURCE: Connecticut large-capacity magazine and assault-weapon framework.",
          "SUMMARY: Connecticut regulates certain magazines, firearm types, and equipment.",
          "GUIDANCE: Verify firearm, magazine, ammunition, and accessory legality before entering Connecticut."
        ],
        source: "Connecticut firearm equipment restrictions framework."
      },
      {
        title: "Federal Property / Post Offices",
        risk: "Federal Law Overlay",
        body: [
          "STATUTE / SOURCE: Federal facility and postal property framework.",
          "SUMMARY: Connecticut carry or possession authority does not override federal restrictions.",
          "GUIDANCE: Federal buildings, federal courthouses, post offices, and secure federal property must be checked separately."
        ],
        source: "Federal facility and postal property framework."
      },
      {
        title: "Use of Force / Self-Defense",
        risk: "Fact-Specific Legal Risk",
        body: [
          "STATUTE / SOURCE: Connecticut self-defense framework.",
          "SUMMARY: Connecticut self-defense law is fact-specific and depends on necessity, reasonableness, and statutory justification principles.",
          "GUIDANCE: Avoid confrontation, disengage when safe, call 911, request counsel, and avoid detailed statements."
        ],
        source: "Connecticut self-defense law framework."
      }
    ],
    [
      {
        title: "Connecticut Travel Checklist",
        steps: [
          "1. Do not carry on Michigan CPL alone.",
          "2. Verify Connecticut permit authority if applicable.",
          "3. Check Conn. Gen. Stat. § 29-35 carry prohibition.",
          "4. Avoid open carry/visible display.",
          "5. Check school restrictions under § 53a-217b.",
          "6. Check private property and government buildings.",
          "7. Verify magazine/equipment restrictions."
        ]
      }
    ],
    [
      {
        title: "Traveling Through Connecticut",
        summary: "Connecticut is high risk for nonresident carry, visible display, schools, and equipment restrictions.",
        guidance: [
          "Do not carry on Michigan CPL.",
          "Avoid visible display.",
          "Verify permit authority.",
          "Check equipment restrictions."
        ]
      }
    ],
    [
      "Carrying on Michigan CPL.",
      "Assuming open carry is allowed.",
      "Ignoring schools.",
      "Ignoring private property prohibitions.",
      "Ignoring magazine/equipment rules.",
      "Failing to carry permit documentation if authorized."
    ],
    [
      "Non-recognition understood.",
      "Connecticut permit authority verified or no carry.",
      "Open carry/display restriction understood.",
      "School restrictions checked.",
      "Private property checked.",
      "Equipment restrictions checked."
    ],
    [
      {
        myth: "Connecticut will honor my Michigan CPL because I am only visiting.",
        reality: "No. Connecticut does not honor Michigan CPL in this app travel engine."
      }
    ]
  ),

  IL: makeProfile(
    "Illinois",
    "Law-Backed Ultra Expanded High-Risk State",
    "Illinois is a critical high-risk border state for Michigan CPL holders. Illinois does not treat a Michigan CPL as ordinary public carry authority. Illinois has its own Firearm Concealed Carry Act, strict prohibited areas, vehicle-safe-harbor style rules for nonresidents in limited circumstances, FOID-related framework for residents, local complexity around Chicago/Cook County, and serious transport risks for travelers.",
    {
      reciprocity: "Michigan CPL is not treated as ordinary Illinois public carry authority in this app. Verify any nonresident vehicle exception before travel.",
      permitlessCarry: "No general permitless concealed carry. Illinois concealed carry is license-based.",
      concealedCarry: "430 ILCS 66 governs Illinois concealed carry licensing; nonresident public carry authority is limited and must be verified.",
      openCarry: "Do not rely on open carry in Illinois. Illinois is a high-risk state for public carry without Illinois authority.",
      vehicleCarry: "430 ILCS 66/40 includes limited vehicle-related provisions for certain nonresidents, but this must be handled carefully.",
      dutyToInform: "Illinois licensees/nonresidents should verify current disclosure and police-contact duties; answer lawful questions truthfully and do not reach.",
      privateSigns: "430 ILCS 66/65 and Illinois posting rules make signs and prohibited places important.",
      forceLaw: "Illinois self-defense is fact-specific and does not excuse unlawful carry or unlawful possession."
    },
    [
      "Illinois is not a casual travel state for Michigan CPL holders.",
      "Do not assume Michigan CPL gives ordinary public carry authority in Illinois.",
      "Vehicle handling and transport are major risk areas.",
      "Illinois has many prohibited places under 430 ILCS 66/65.",
      "Chicago/Cook County and local-law/equipment issues require extra verification.",
      "If traveling through Illinois, verify lawful transport before entering the state."
    ],
    [
      { title: "Illinois Concealed Carry Act", risk: "Core Carry Framework", body: ["STATUTE: 430 ILCS 66.", "SUMMARY: Illinois public concealed carry is governed by the Firearm Concealed Carry Act and generally requires Illinois-recognized authority.", "GUIDANCE: A Michigan CPL should not be treated as ordinary Illinois public carry authority. Verify current Illinois State Police guidance before carrying or transporting."], source: "430 ILCS 66." },
      { title: "Nonresident Vehicle Carry / Limited Safe Harbor", risk: "High-Risk Traveler Rule", body: ["STATUTE: 430 ILCS 66/40.", "SUMMARY: Illinois law contains limited provisions for nonresidents who may carry in a vehicle if they are not prohibited and are eligible to carry in their home state, with strict limits when exiting the vehicle.", "GUIDANCE: This is not full reciprocity. Treat Illinois vehicle carry as a narrow, technical exception and verify before relying on it."], source: "430 ILCS 66/40." },
      { title: "Prohibited Areas", risk: "Major Location Restriction", body: ["STATUTE: 430 ILCS 66/65.", "SUMMARY: Illinois lists numerous prohibited areas where firearms may not be carried, including schools, government buildings, courts, correctional facilities, hospitals, public transportation areas, parks/playgrounds, libraries, airports, certain alcohol locations, events, and other listed areas.", "GUIDANCE: Illinois has one of the more detailed prohibited-place lists. Check every stop before entering armed."], source: "430 ILCS 66/65." },
      { title: "Parking Lot / Vehicle Storage", risk: "Technical Compliance Risk", body: ["STATUTE: 430 ILCS 66/65 parking-lot provisions.", "SUMMARY: Illinois allows limited handling in the immediate area around a vehicle for storage/retrieval in certain prohibited parking lot areas under strict conditions.", "GUIDANCE: Do not handle the firearm casually in public. Know the case/trunk/glove-box/console storage requirements before entering a prohibited area."], source: "430 ILCS 66/65." },
      { title: "Schools", risk: "Extreme Risk Area", body: ["STATUTE: 430 ILCS 66/65 and Illinois school weapons framework.", "SUMMARY: Schools and school property are prohibited or highly restricted locations under Illinois law.", "GUIDANCE: Do not assume parking-lot exceptions allow general carry. School property requires specific verification."], source: "430 ILCS 66/65; Illinois school weapons framework." },
      { title: "Public Transportation / Airports", risk: "Travel Infrastructure Risk", body: ["STATUTE: 430 ILCS 66/65.", "SUMMARY: Illinois restricts carry in public transportation facilities and airport secure/passenger areas under the prohibited-place framework.", "GUIDANCE: Travelers using airports, trains, buses, rideshare drop-offs, or transit stations should verify before arrival."], source: "430 ILCS 66/65; federal airport/security framework." },
      { title: "Chicago / Cook County / Local Issues", risk: "Local Complexity", body: ["STATUTE / SOURCE: Illinois preemption and local ordinance framework.", "SUMMARY: Illinois has state firearm preemption in some areas, but Chicago/Cook County history and local equipment restrictions can still create traveler confusion.", "GUIDANCE: Verify magazine, ammunition, local ordinance, and destination-specific rules before entering the Chicago area."], source: "Illinois state/local firearms framework." },
      { title: "Transport Through Illinois", risk: "Interstate Travel Risk", body: ["STATUTE / SOURCE: Illinois transport framework; federal interstate transport framework.", "SUMMARY: Travelers passing through Illinois should understand unloaded/cased/inaccessible transport principles and avoid unnecessary deviations when relying on transport protections.", "GUIDANCE: Plan the route. Avoid unnecessary stops. Do not handle or display firearms during travel."], source: "Illinois transport framework; 18 U.S.C. § 926A framework." },
      { title: "Private Property / Posted Locations", risk: "Posted Property Rule", body: ["STATUTE: 430 ILCS 66/65 posting framework.", "SUMMARY: Illinois recognizes posted prohibited areas and private property restrictions under the concealed carry framework.", "GUIDANCE: If posted or asked to leave, leave immediately. Do not argue with staff or security."], source: "430 ILCS 66/65." },
      { title: "Use of Force / Self-Defense", risk: "Fact-Specific Legal Risk", body: ["STATUTE / SOURCE: Illinois self-defense framework.", "SUMMARY: Self-defense is fact-specific and does not cure unlawful possession or unlawful carry.", "GUIDANCE: Avoid, disengage, call 911, identify evidence/witnesses, request counsel, and avoid detailed statements under stress."], source: "Illinois self-defense law framework." }
    ],
    [ { title: "Illinois Travel Checklist", steps: ["1. Do not assume Michigan CPL equals Illinois carry authority.", "2. Check 430 ILCS 66/40 before relying on any vehicle exception.", "3. Check 430 ILCS 66/65 prohibited areas.", "4. Check Chicago/Cook County equipment/local issues.", "5. Check transport method before entering Illinois.", "6. Avoid unnecessary handling or display."] } ],
    [ { title: "Driving Into Illinois", summary: "Illinois is high risk because a Michigan CPL does not operate like full reciprocity.", guidance: ["Verify vehicle exception.", "Keep firearm secured when required.", "Avoid unnecessary stops.", "Do not enter prohibited locations armed."] } ],
    ["Assuming Michigan CPL is honored for ordinary public carry.", "Ignoring Illinois vehicle limits.", "Ignoring 430 ILCS 66/65 prohibited areas.", "Entering Chicago/Cook County without checking local/equipment rules.", "Handling firearms in parking lots beyond narrow permitted conduct."],
    ["Illinois recognition status understood.", "Vehicle rules checked.", "Prohibited areas checked.", "Chicago/Cook County checked.", "Transport plan confirmed.", "Federal property checked."],
    [ { myth: "Illinois is next to Michigan, so my CPL should work there.", reality: "No. Illinois is a high-risk state and does not treat Michigan CPL as ordinary public carry authority." } ]
  ),

  MD: makeProfile(
    "Maryland",
    "Law-Backed Ultra Expanded High-Risk State",
    "Maryland is a strict non-recognition state for Michigan CPL holders. Maryland requires Maryland wear-and-carry authority for public handgun carry, has extensive sensitive-place restrictions, strict transport expectations, school and government location rules, and significant risk for travelers who assume their home-state permit applies.",
    {
      reciprocity: "Michigan CPL is not recognized for ordinary Maryland public carry in this app.",
      permitlessCarry: "No permitless concealed carry. Maryland requires a Maryland Wear and Carry Permit for public handgun carry.",
      concealedCarry: "Md. Public Safety § 5-306 governs Maryland wear and carry permit issuance.",
      openCarry: "Do not rely on open carry in Maryland. Maryland public handgun carry is permit-based and highly restricted.",
      vehicleCarry: "Maryland transport must be handled carefully under Criminal Law § 4-203 and related exceptions.",
      dutyToInform: "Verify current Maryland police-contact rules; answer lawful questions truthfully and avoid reaching.",
      privateSigns: "Maryland sensitive-place/private-property rules are complex after SB 1 and subsequent litigation; verify before entering.",
      forceLaw: "Maryland self-defense is fact-specific and does not excuse unlawful carry."
    },
    ["Do not carry in Maryland on Michigan CPL alone.", "Maryland transport law is a major traveler trap.", "SB 1 added sensitive-place restrictions effective October 1, 2023.", "Schools, government buildings, hospitals, children/vulnerable-individual locations, and private property can be high risk.", "Maryland is a verify-before-entry state for nearly every destination."],
    [
      { title: "Wear and Carry Permit", risk: "Core Carry Authority", body: ["STATUTE: Md. Public Safety § 5-306.", "SUMMARY: Maryland’s wear-and-carry permit statute controls public handgun carry authority.", "GUIDANCE: A Michigan CPL does not replace a Maryland Wear and Carry Permit. Do not carry publicly in Maryland without Maryland authority."], source: "Md. Public Safety § 5-306; Maryland State Police Wear and Carry Permit guidance." },
      { title: "Handgun Wear / Carry / Transport", risk: "Criminal Exposure", body: ["STATUTE: Md. Criminal Law § 4-203.", "SUMMARY: Maryland restricts wearing, carrying, or transporting a handgun, subject to statutory exceptions.", "GUIDANCE: Transport exceptions are technical. Travel with firearms should be planned before entering Maryland."], source: "Md. Criminal Law § 4-203." },
      { title: "Sensitive Places / SB 1 Restrictions", risk: "Major Location Restriction", body: ["STATUTE / SOURCE: Maryland SB 1 sensitive-place framework; Maryland State Police guidance.", "SUMMARY: Maryland added significant prohibited areas effective October 1, 2023, including areas involving children/vulnerable individuals and other specified locations.", "GUIDANCE: Even Maryland permit holders must check sensitive-place rules before entering."], source: "Maryland State Police Wear and Carry guidance; 2023 SB 1 framework." },
      { title: "Schools and Child-Care Related Areas", risk: "Extreme Risk Area", body: ["STATUTE / SOURCE: Maryland school weapons and SB 1 framework.", "SUMMARY: Schools, child-care areas, and areas for children or vulnerable individuals are high-risk Maryland locations.", "GUIDANCE: Do not treat parking lots, events, or school-adjacent locations casually."], source: "Maryland school weapons framework; Maryland State Police SB 1 guidance." },
      { title: "Private Property / Posted or Restricted Locations", risk: "Property Control", body: ["STATUTE / SOURCE: Maryland sensitive-place/private-property framework.", "SUMMARY: Maryland has complex rules involving private property and locations where firearms are prohibited or restricted.", "GUIDANCE: Check signage, property rules, and current litigation status before entering armed."], source: "Maryland SB 1/private property framework." },
      { title: "Vehicle Transport", risk: "Traveler Trap", body: ["STATUTE: Md. Criminal Law § 4-203.", "SUMMARY: Maryland transport exceptions are limited and should not be treated as general vehicle carry.", "GUIDANCE: When transporting, keep firearms unloaded, secured, inaccessible, and connected to a lawful purpose or destination as required."], source: "Md. Criminal Law § 4-203." },
      { title: "Assault Weapon / Magazine / Equipment Issues", risk: "Equipment Restriction", body: ["STATUTE / SOURCE: Maryland regulated firearms and magazine framework.", "SUMMARY: Maryland regulates certain firearms, magazines, and equipment.", "GUIDANCE: Verify firearm type, magazine capacity, ammunition, and equipment legality before travel."], source: "Maryland regulated firearms/equipment framework." },
      { title: "Federal Property / DC Proximity", risk: "Federal/District Overlay", body: ["STATUTE / SOURCE: Federal facility framework; District of Columbia border risk.", "SUMMARY: Maryland carry/transport authority does not override federal property or Washington, DC law.", "GUIDANCE: Be extremely careful near DC, federal facilities, military installations, monuments, and federal buildings."], source: "Federal facility framework; DC firearms law framework." },
      { title: "Use of Force / Self-Defense", risk: "Fact-Specific Legal Risk", body: ["STATUTE / SOURCE: Maryland self-defense framework.", "SUMMARY: Maryland self-defense is fact-specific and does not cure unlawful carry or transport.", "GUIDANCE: Avoid confrontation, call 911, request counsel, and avoid detailed statements."], source: "Maryland self-defense framework." }
    ],
    [ { title: "Maryland Travel Checklist", steps: ["1. Do not carry on Michigan CPL alone.", "2. Verify Maryland Wear and Carry authority.", "3. Check Md. Criminal Law § 4-203 transport rules.", "4. Check SB 1 sensitive places.", "5. Check school/child-related locations.", "6. Check equipment restrictions.", "7. Check DC/federal property risk."] } ],
    [ { title: "Maryland / DC Road Trip", summary: "Maryland is strict, and DC proximity increases risk.", guidance: ["Do not carry on Michigan CPL.", "Plan transport route.", "Avoid DC unless separately compliant.", "Check sensitive places."] } ],
    ["Carrying on Michigan CPL.", "Treating transport as vehicle carry.", "Ignoring SB 1 sensitive places.", "Crossing into DC with firearms.", "Ignoring magazine/equipment restrictions."],
    ["Maryland non-recognition understood.", "Wear and Carry authority verified or no carry.", "Transport method checked.", "Sensitive places checked.", "Equipment restrictions checked.", "DC/federal risks checked."],
    [ { myth: "My Michigan CPL should work because I am only visiting Maryland.", reality: "No. Maryland does not honor Michigan CPL for ordinary public carry in this app." } ]
  ),

  DE: makeProfile(
    "Delaware",
    "Law-Backed Ultra Expanded High-Risk State",
    "Delaware is a non-recognition/high-risk state for Michigan CPL holders. Delaware uses a concealed deadly weapon license framework, has Safe School and Recreation Zone restrictions, college/university safe-zone rules, courthouse and government-location risks, private property issues, and technical transport concerns for travelers.",
    {
      reciprocity: "Michigan CPL is not treated as recognized for Delaware concealed carry in this app.",
      permitlessCarry: "No permitless concealed carry. Delaware requires a license to carry concealed deadly weapons.",
      concealedCarry: "11 Del. C. § 1441 governs licenses to carry concealed deadly weapons.",
      openCarry: "Open carry may be treated differently than concealed carry, but location and conduct restrictions still matter.",
      vehicleCarry: "Vehicle carry/transport must be verified under Delaware law and school-zone restrictions.",
      dutyToInform: "Verify current Delaware police-contact expectations; answer lawful questions truthfully and avoid reaching.",
      privateSigns: "Private property owners may control access. Leave if asked.",
      forceLaw: "Delaware self-defense is fact-specific and does not excuse unlawful carry."
    },
    ["Do not carry concealed in Delaware on Michigan CPL alone.", "Delaware CCDW licensing is its own process under 11 Del. C. § 1441.", "Safe School and Recreation Zones create major risk.", "College/university safe zones must be checked separately.", "Transport through Delaware should be planned carefully."],
    [
      { title: "Concealed Deadly Weapon License", risk: "Core Carry Authority", body: ["STATUTE: 11 Del. C. § 1441.", "SUMMARY: Delaware licenses concealed deadly weapon carry through its statutory CCDW process.", "GUIDANCE: A Michigan CPL should not be treated as Delaware concealed carry authority."], source: "11 Del. C. § 1441; Delaware Superior Court CCDW rules." },
      { title: "Carrying Concealed Deadly Weapon", risk: "Criminal Exposure", body: ["STATUTE: 11 Del. C. § 1442.", "SUMMARY: Delaware law prohibits carrying a concealed deadly weapon without lawful authority.", "GUIDANCE: Do not conceal carry in Delaware without Delaware-recognized authority."], source: "11 Del. C. § 1442." },
      { title: "Safe School and Recreation Zones", risk: "Extreme Risk Area", body: ["STATUTE: 11 Del. C. § 1457.", "SUMMARY: Delaware restricts weapons in Safe School and Recreation Zones, subject to statutory classifications and exceptions.", "GUIDANCE: Schools, recreation zones, events, parking areas, and youth-related facilities require careful verification."], source: "11 Del. C. § 1457." },
      { title: "College / University Safe Zones", risk: "Campus Risk", body: ["STATUTE: 11 Del. C. § 1457C.", "SUMMARY: Delaware has separate restrictions for college and university safe zones.", "GUIDANCE: Do not assume K-12 school rules are the only educational restrictions."], source: "11 Del. C. § 1457C." },
      { title: "Courthouses / Government Buildings", risk: "Hard Stop Area", body: ["STATUTE / SOURCE: Delaware court/government security framework.", "SUMMARY: Court and government facilities may prohibit weapons and involve screening/security rules.", "GUIDANCE: Do not approach security armed. Plan lawful storage before arrival."], source: "Delaware court/government security framework." },
      { title: "Vehicle / Transport", risk: "Travel Risk", body: ["STATUTE / SOURCE: Delaware concealed weapon and transport framework.", "SUMMARY: Vehicle possession can create concealed-carry issues depending on location, accessibility, and manner of transport.", "GUIDANCE: Verify transport rules before entering Delaware; do not treat a vehicle as a safe carry workaround."], source: "Delaware transport/concealed weapon framework." },
      { title: "Private Property / Posted Locations", risk: "Property Control", body: ["STATUTE / SOURCE: Delaware trespass/property framework.", "SUMMARY: Property owners may control access and require armed persons to leave.", "GUIDANCE: If posted or asked to leave, leave immediately."], source: "Delaware property/trespass framework." },
      { title: "Federal Property / Post Offices", risk: "Federal Law Overlay", body: ["STATUTE / SOURCE: Federal facility and postal property framework.", "SUMMARY: Delaware permission does not override federal restrictions.", "GUIDANCE: Federal buildings, post offices, federal courthouses, and secure federal property must be checked separately."], source: "Federal facility and postal property framework." },
      { title: "Use of Force / Self-Defense", risk: "Fact-Specific Legal Risk", body: ["STATUTE / SOURCE: Delaware justification/self-defense framework.", "SUMMARY: Defensive force must be legally justified under Delaware law and facts.", "GUIDANCE: Avoid confrontation, call 911, request counsel, and do not give detailed statements under stress."], source: "Delaware self-defense/justification framework." }
    ],
    [ { title: "Delaware Travel Checklist", steps: ["1. Do not carry concealed on Michigan CPL alone.", "2. Check 11 Del. C. § 1441 / § 1442.", "3. Check Safe School/Recreation Zones under § 1457.", "4. Check college/university zones under § 1457C.", "5. Check vehicle/transport method.", "6. Check court/government/federal property."] } ],
    [ { title: "Passing Through Delaware", summary: "Delaware is small, but legal mistakes can happen quickly during travel stops.", guidance: ["Plan transport before entry.", "Avoid school/recreation zones.", "Check hotel/private property rules.", "Do not conceal carry on Michigan CPL."] } ],
    ["Carrying concealed on Michigan CPL.", "Ignoring school/recreation zones.", "Ignoring college/university safe zones.", "Using vehicle accessibility as a workaround.", "Ignoring federal/court property."],
    ["Non-recognition understood.", "CCDW authority verified or no carry.", "School/recreation zones checked.", "Campus zones checked.", "Transport checked.", "Federal/court property checked."],
    [ { myth: "Delaware is small, so it is just a pass-through and not a big deal.", reality: "No. Delaware has specific concealed weapon, school-zone, recreation-zone, and campus restrictions." } ]
  ),

  RI: makeProfile(
    "Rhode Island",
    "Law-Backed Ultra Expanded High-Risk State",
    "Rhode Island is a high-risk non-recognition state for Michigan CPL holders. Rhode Island has a permit/license framework for carrying pistols or revolvers, separate municipal and Attorney General permit paths, strong school-ground restrictions, and serious risks for travelers who assume out-of-state carry authority applies.",
    {
      reciprocity: "Michigan CPL is not recognized for ordinary Rhode Island carry in this app.",
      permitlessCarry: "No permitless concealed handgun carry. Rhode Island requires Rhode Island permit authority.",
      concealedCarry: "R.I. Gen. Laws § 11-47-11 and § 11-47-18 address permit/license pathways.",
      openCarry: "Open carry requires careful Rhode Island permit analysis and should not be assumed lawful for visitors.",
      vehicleCarry: "Vehicle carry/transport must be verified under Rhode Island law.",
      dutyToInform: "Verify current Rhode Island police-contact duties; answer lawful questions truthfully and avoid reaching.",
      privateSigns: "Private property and event/location rules still matter.",
      forceLaw: "Rhode Island self-defense is fact-specific and does not excuse unlawful carry."
    },
    ["Do not carry in Rhode Island on Michigan CPL alone.", "Rhode Island permit law is complex because local licensing and Attorney General licensing are distinct.", "School grounds are a major hard-stop risk.", "Open carry should not be assumed lawful without specific Rhode Island authority.", "Transport through Rhode Island should be planned carefully."],
    [
      { title: "License / Permit Required", risk: "Core Carry Rule", body: ["STATUTE: R.I. Gen. Laws § 11-47-8.", "SUMMARY: Rhode Island restricts carrying pistols/revolvers without license or permit authority.", "GUIDANCE: A Michigan CPL does not provide ordinary Rhode Island carry authority."], source: "R.I. Gen. Laws § 11-47-8." },
      { title: "Local Concealed Permit Path", risk: "Permit Framework", body: ["STATUTE: R.I. Gen. Laws § 11-47-11.", "SUMMARY: Rhode Island law provides a local licensing pathway to carry a concealed pistol or revolver.", "GUIDANCE: This is Rhode Island authority, not Michigan reciprocity."], source: "R.I. Gen. Laws § 11-47-11; Rhode Island AG guidance." },
      { title: "Attorney General Permit Path", risk: "Permit Framework", body: ["STATUTE: R.I. Gen. Laws § 11-47-18.", "SUMMARY: Rhode Island law also provides an Attorney General permitting pathway, including carry authority under the statute.", "GUIDANCE: Visitors should not assume this applies without an issued Rhode Island permit."], source: "R.I. Gen. Laws § 11-47-18; Rhode Island AG guidance." },
      { title: "School Grounds", risk: "Extreme Risk Area", body: ["STATUTE: R.I. Gen. Laws § 11-47-60.", "SUMMARY: Rhode Island restricts possession of firearms on school grounds, including property of public/private elementary or secondary schools and school-sponsored activity areas.", "GUIDANCE: Do not enter school grounds armed unless a specific statutory exception clearly applies."], source: "R.I. Gen. Laws § 11-47-60." },
      { title: "Transport to Range / Limited Exceptions", risk: "Technical Transport Rule", body: ["STATUTE: R.I. Gen. Laws § 11-47-10.", "SUMMARY: Rhode Island law includes circumstances where a license or permit is not required for transport to/from target ranges and similar lawful contexts.", "GUIDANCE: Treat these as narrow transport exceptions, not general carry authority."], source: "R.I. Gen. Laws § 11-47-10." },
      { title: "Private Property / Events", risk: "Property and Venue Control", body: ["STATUTE / SOURCE: Rhode Island property/trespass framework.", "SUMMARY: Private property owners and event venues may control access and restrict firearms.", "GUIDANCE: Posted signs, venue rules, and instructions to leave should be followed immediately."], source: "Rhode Island property/trespass framework." },
      { title: "Federal Property / Post Offices", risk: "Federal Law Overlay", body: ["STATUTE / SOURCE: Federal facility and postal property framework.", "SUMMARY: Rhode Island permit authority does not override federal restrictions.", "GUIDANCE: Federal buildings, federal courthouses, post offices, and secure federal property must be checked separately."], source: "Federal facility and postal property framework." },
      { title: "Use of Force / Self-Defense", risk: "Fact-Specific Legal Risk", body: ["STATUTE / SOURCE: Rhode Island self-defense framework.", "SUMMARY: Defensive force must be justified under Rhode Island law and the specific facts.", "GUIDANCE: Avoid confrontation, call 911, request counsel, and avoid detailed statements under stress."], source: "Rhode Island self-defense law framework." }
    ],
    [ { title: "Rhode Island Travel Checklist", steps: ["1. Do not carry on Michigan CPL alone.", "2. Verify Rhode Island permit authority.", "3. Check § 11-47-8, § 11-47-11, and § 11-47-18.", "4. Check school grounds under § 11-47-60.", "5. Check any transport exception under § 11-47-10.", "6. Check private/federal property."] } ],
    [ { title: "New England Road Trip", summary: "Rhode Island is small and easy to enter accidentally while traveling between other states.", guidance: ["Do not carry on Michigan CPL.", "Check route before entry.", "Avoid school grounds.", "Confirm transport method."] } ],
    ["Carrying on Michigan CPL.", "Assuming open carry is available.", "Ignoring school grounds.", "Treating transport exceptions as carry authority.", "Ignoring private/federal property."],
    ["Non-recognition understood.", "RI permit authority verified or no carry.", "School grounds checked.", "Transport method checked.", "Private/federal property checked."],
    [ { myth: "Rhode Island is tiny, so it does not matter if I just pass through.", reality: "No. State lines matter immediately and Rhode Island does not honor Michigan CPL in this app." } ]
  ),

  OR: makeProfile(
    "Oregon",
    "Law-Backed Ultra Expanded High-Risk State",
    "Oregon is a high-risk non-recognition state for Michigan CPL holders. Oregon has an Oregon concealed handgun license framework, public-building restrictions, school/court/government location issues, city/county local loaded-firearm restrictions for non-licensees, and serious vehicle/transport concerns for travelers.",
    {
      reciprocity: "Michigan CPL is not recognized for ordinary Oregon concealed carry in this app.",
      permitlessCarry: "No permitless concealed handgun carry. Oregon requires an Oregon CHL for concealed handgun carry.",
      concealedCarry: "ORS 166.291 and ORS 166.292 govern Oregon CHL issuance and licensing.",
      openCarry: "Open carry may be affected by local loaded-firearm restrictions and public-building rules.",
      vehicleCarry: "Vehicle carry and loaded firearm rules must be checked carefully, especially local ordinances for non-CHL holders.",
      dutyToInform: "Verify current Oregon police-contact rules; answer lawful questions truthfully and avoid reaching.",
      privateSigns: "Private property and posted locations still matter.",
      forceLaw: "Oregon self-defense is fact-specific and does not excuse unlawful carry."
    },
    ["Do not carry concealed in Oregon on Michigan CPL alone.", "Oregon CHL is the key concealed handgun license authority.", "Public buildings, courts, schools, and airport/secure areas require careful review.", "Some localities restrict loaded firearms in public places for people without Oregon CHL authority.", "Vehicle carry should be verified before travel."],
    [
      { title: "Oregon CHL Issuance", risk: "Core Carry Authority", body: ["STATUTE: ORS 166.291; ORS 166.292.", "SUMMARY: Oregon uses a concealed handgun license framework administered by county sheriffs.", "GUIDANCE: A Michigan CPL should not be treated as Oregon concealed carry authority."], source: "ORS 166.291; ORS 166.292." },
      { title: "Public Buildings", risk: "Major Location Restriction", body: ["STATUTE: ORS 166.370.", "SUMMARY: Oregon restricts possession of firearms and dangerous weapons in public buildings, with statutory exceptions.", "GUIDANCE: Government buildings, courts, schools, and public facilities should be checked before entering."], source: "ORS 166.370." },
      { title: "Court Facilities", risk: "Hard Stop Area", body: ["STATUTE / SOURCE: ORS 166.370 and Oregon court security framework.", "SUMMARY: Court facilities are high-risk public building locations under Oregon law.", "GUIDANCE: Do not approach courthouse security armed unless a clear exception applies."], source: "ORS 166.370; Oregon court security framework." },
      { title: "Schools / Campus Issues", risk: "Extreme Risk Area", body: ["STATUTE / SOURCE: ORS 166.370 and Oregon school/campus weapons framework.", "SUMMARY: Schools and campus properties may involve public-building restrictions, school policies, and statutory exceptions.", "GUIDANCE: Do not rely on Michigan CPL. Verify the specific institution and building."], source: "ORS 166.370; Oregon school/campus framework." },
      { title: "Loaded Firearms in Public Places / Local Restrictions", risk: "Local Ordinance Risk", body: ["STATUTE: ORS 166.173.", "SUMMARY: Oregon allows certain cities/counties to regulate possession of loaded firearms in public places, with exceptions including CHL holders.", "GUIDANCE: Portland/Multnomah County and other local rules should be checked before open or vehicle carry."], source: "ORS 166.173." },
      { title: "Vehicle Carry / Loaded Firearm", risk: "Vehicle Trap", body: ["STATUTE / SOURCE: ORS 166.250; ORS 166.173 framework.", "SUMMARY: Oregon vehicle carry can create concealed, loaded, and local-restriction issues.", "GUIDANCE: Verify loaded/unloaded status, accessibility, local ordinances, and lawful transport before entering Oregon."], source: "ORS 166.250; ORS 166.173." },
      { title: "Private Property / Posted Locations", risk: "Property Control", body: ["STATUTE / SOURCE: Oregon property/trespass framework.", "SUMMARY: Private property owners and venues may restrict firearms and require persons to leave.", "GUIDANCE: Follow posted signs and staff/security instructions immediately."], source: "Oregon property/trespass framework." },
      { title: "Federal Property / Post Offices / Public Lands", risk: "Federal/Public Land Overlay", body: ["STATUTE / SOURCE: Federal facility, postal property, and public-land framework.", "SUMMARY: Oregon law does not override federal property restrictions, national park/building rules, or postal property restrictions.", "GUIDANCE: Public lands and federal buildings are different. Verify the specific property."], source: "Federal facility and public land framework." },
      { title: "Use of Force / Self-Defense", risk: "Fact-Specific Legal Risk", body: ["STATUTE / SOURCE: Oregon self-defense framework.", "SUMMARY: Defensive force must be justified under Oregon law and the facts.", "GUIDANCE: Avoid confrontation, call 911, request counsel, and avoid detailed statements under stress."], source: "Oregon self-defense law framework." }
    ],
    [ { title: "Oregon Travel Checklist", steps: ["1. Do not carry concealed on Michigan CPL.", "2. Verify Oregon CHL authority under ORS 166.291/166.292.", "3. Check public buildings under ORS 166.370.", "4. Check loaded/local restrictions under ORS 166.173.", "5. Check vehicle carry/transport.", "6. Check federal/public land rules."] } ],
    [ { title: "Oregon Road Trip", summary: "Oregon travel often involves cities, public buildings, parks, public land, and vehicles.", guidance: ["Do not conceal carry on Michigan CPL.", "Check local loaded-firearm restrictions.", "Check public buildings.", "Verify public land/federal property." ] } ],
    ["Carrying concealed on Michigan CPL.", "Ignoring local loaded-firearm restrictions.", "Ignoring ORS 166.370 public buildings.", "Assuming public land equals carry permission.", "Ignoring vehicle accessibility/loaded issues."],
    ["Oregon non-recognition understood.", "Oregon CHL authority verified or no carry.", "Public buildings checked.", "Local loaded restrictions checked.", "Vehicle transport checked.", "Federal/public land checked."],
    [ { myth: "Oregon is outdoorsy, so carry laws are probably relaxed.", reality: "No. Oregon does not honor Michigan CPL for concealed carry and has public-building/local loaded-firearm issues." } ]
  ),

  NV: makeProfile(
    "Nevada",
    "Law-Backed Ultra Expanded Verify-Status Travel State",
    "Nevada requires special handling because current official Nevada online sources conflict regarding Michigan CPL recognition. Nevada’s official resources page lists Michigan, while the linked 2025 Recognition List PDF does not list Michigan. Because of that conflict, this app flags Nevada as VERIFY BEFORE TRAVEL rather than clean recognized. Nevada has no permitless concealed carry, maintains a recognition-list system under NRS 202.3689, and restricts carry in certain public buildings, airports, schools, child-care facilities, and other locations.",
    {
      reciprocity: "VERIFY BEFORE TRAVEL: official Nevada online sources conflict. One Nevada page lists Michigan, but the 2025 Recognition List PDF does not list Michigan.",
      permitlessCarry: "No permitless concealed carry. Nevada concealed carry requires Nevada permit or a recognized out-of-state permit under Nevada’s list.",
      concealedCarry: "NRS 202.3688 and NRS 202.3689 govern recognition of out-of-state permits.",
      openCarry: "Open carry may be lawful in many places, but restricted locations, vehicle issues, private property, and local rules still matter.",
      vehicleCarry: "Vehicle carry must be evaluated under Nevada concealed/open carry rules and prohibited locations.",
      dutyToInform: "Verify current Nevada police-contact rules; permit must be in possession when carrying concealed under recognized authority.",
      privateSigns: "Private property, casinos, hotels, resorts, event venues, and security instructions matter.",
      forceLaw: "Nevada self-defense is fact-specific and does not excuse unlawful carry."
    },
    ["Nevada reciprocity is flagged VERIFY, not clean green, because Nevada official pages conflict regarding Michigan.", "Do not assume Michigan CPL is honored without checking Nevada’s current recognition list immediately before travel.", "Nevada does not have permitless concealed carry.", "Casinos/hotels/resorts are private property and can remove or trespass armed persons.", "Public airports, schools, child-care facilities, and public buildings have specific restrictions."],
    [
      { title: "Out-of-State Permit Recognition", risk: "Conflicting Official Source Warning", body: ["STATUTE: NRS 202.3688; NRS 202.3689.", "SUMMARY: Nevada recognizes permits from states included on the list prepared under NRS 202.3689. Official Nevada web materials currently conflict about whether Michigan appears on the active list.", "GUIDANCE: Treat Nevada as VERIFY BEFORE TRAVEL. Check Nevada State Police/RCCD recognition list and call if necessary before carrying concealed."], source: "NRS 202.3688; NRS 202.3689; Nevada RCCD Out-of-State CCW Recognition pages." },
      { title: "No Permitless Concealed Carry", risk: "Core Carry Rule", body: ["STATUTE / SOURCE: Nevada concealed firearm permit framework.", "SUMMARY: Nevada requires a Nevada permit or recognized out-of-state permit for concealed firearm carry.", "GUIDANCE: If Michigan is not on the active Nevada list at the time of travel, do not concealed carry on Michigan CPL."], source: "NRS 202.3653 to NRS 202.369; NRS 202.3688." },
      { title: "Permit Must Be Possessed", risk: "Documentation Requirement", body: ["STATUTE / SOURCE: Nevada RCCD recognition guidance.", "SUMMARY: Nevada states that permit holders from recognized states must have the permit in their possession while carrying.", "GUIDANCE: Carry physical permit and ID. Do not rely on memory, screenshots, or assumptions."], source: "Nevada RCCD Out-of-State CCW Recognition guidance." },
      { title: "Public Buildings / Airports / Schools / Child-Care", risk: "Major Location Restriction", body: ["STATUTE: NRS 202.3673.", "SUMMARY: Nevada restricts concealed firearms in certain public buildings, airport property, public schools, child-care facilities, and other listed locations.", "GUIDANCE: Airports, schools, government buildings, child-care facilities, and posted/security-controlled buildings should be checked before entering."], source: "NRS 202.3673." },
      { title: "Schools and Child-Care Facilities", risk: "Extreme Risk Area", body: ["STATUTE: NRS 202.265; NRS 202.3673.", "SUMMARY: Nevada restricts weapons on school property and child-care related premises, subject to exceptions.", "GUIDANCE: Do not treat parking lots, events, or child-care locations casually."], source: "NRS 202.265; NRS 202.3673." },
      { title: "Casinos / Hotels / Resorts", risk: "Private Property / Security Risk", body: ["STATUTE / SOURCE: Nevada private property and trespass framework.", "SUMMARY: Nevada casinos, hotels, resorts, convention centers, and event venues can impose private property/security rules even when state carry would otherwise be lawful.", "GUIDANCE: Follow security instructions. If asked to leave or disarm, leave calmly."], source: "Nevada private property/trespass framework." },
      { title: "Las Vegas Strip / Event Venues", risk: "High-Contact Environment", body: ["STATUTE / SOURCE: Nevada private property/event/security framework.", "SUMMARY: Las Vegas travel involves casinos, hotels, concerts, stadiums, clubs, alcohol, rideshare areas, and security screening.", "GUIDANCE: Plan storage and venue rules before leaving the hotel. Do not argue with security."], source: "Nevada private property and event security framework." },
      { title: "Vehicle Carry", risk: "Travel Carry Risk", body: ["STATUTE / SOURCE: Nevada open/concealed carry and vehicle framework.", "SUMMARY: Vehicle possession can involve concealed carry, open carry, accessibility, and local/private-property issues.", "GUIDANCE: Verify whether your method of carry is concealed or open under Nevada law and whether your permit status is valid."], source: "Nevada firearm/vehicle carry framework." },
      { title: "Federal Property / Post Offices / National Parks", risk: "Federal/Public Land Overlay", body: ["STATUTE / SOURCE: Federal facility and public land framework.", "SUMMARY: Nevada carry permission does not override federal buildings, post offices, secure federal facilities, or specific federal-property rules.", "GUIDANCE: National parks may follow state carry rules generally, but buildings/facilities remain restricted. Verify specific property."], source: "Federal facility and public land framework." },
      { title: "Use of Force / Self-Defense", risk: "Fact-Specific Legal Risk", body: ["STATUTE / SOURCE: Nevada self-defense framework.", "SUMMARY: Defensive force must be justified under Nevada law and the facts.", "GUIDANCE: Avoid confrontation, call 911, request counsel, and avoid detailed statements under stress."], source: "Nevada self-defense law framework." }
    ],
    [ { title: "Nevada Travel Checklist", steps: ["1. Verify Nevada’s current recognition list immediately before travel.", "2. If Michigan is absent or unclear, do not concealed carry on Michigan CPL.", "3. Check NRS 202.3673 prohibited locations.", "4. Check schools/child-care under NRS 202.265 and NRS 202.3673.", "5. Check casino/hotel/private property rules.", "6. Carry permit and ID if legally carrying.", "7. Check federal property/public land rules."] } ],
    [ { title: "Las Vegas Trip", summary: "Nevada travel often means casinos, hotels, alcohol, security screening, rideshare areas, and event venues.", guidance: ["Verify reciprocity before travel.", "Check hotel/casino policy.", "Do not argue with security.", "Plan lawful storage before events."] } ],
    ["Assuming Nevada cleanly honors Michigan without checking current official list.", "Ignoring official-source conflict.", "Carrying concealed without recognized permit authority.", "Ignoring NRS 202.3673 locations.", "Ignoring casino/hotel private property rules.", "Ignoring schools/child-care facilities."],
    ["Nevada recognition verified within 24-48 hours of travel.", "Permit/ID carried if legally carrying.", "NRS 202.3673 locations checked.", "Casino/hotel/event rules checked.", "Vehicle carry method checked.", "Federal property checked."],
    [ { myth: "Nevada definitely honors Michigan CPL, so I can just carry in Vegas.", reality: "Nevada official sources conflict. This app flags Nevada as VERIFY BEFORE TRAVEL until the active recognition list is confirmed." } ]
  ),
  AL: makeProfile(
    "Alabama",
    "Law-Backed Ultra Expanded Travel State",
    "Alabama is a common southern travel state and a useful state for members because it has permitless carry, optional permits, broad recognition of out-of-state permits, and important restrictions involving prohibited persons, schools, law enforcement facilities, courthouses, secure government buildings, private property, federal property, and defensive conduct. Alabama is generally permissive, but it is not rule-free.",
    {
      reciprocity: "Alabama recognizes any valid out-of-state permit under Alabama Code § 13A-11-85. Michigan CPL should be treated as recognized, but Alabama law controls while physically in Alabama.",
      permitlessCarry: "Alabama Code § 13A-11-74.1: Alabama does not impose a general prohibition on carrying a pistol without a permit.",
      concealedCarry: "Alabama allows permitless carry for eligible persons, but prohibited-person rules and location restrictions still apply.",
      openCarry: "Open carry may be lawful for eligible persons, but restricted locations, disorderly conduct, private property, and police contact still matter.",
      vehicleCarry: "Alabama permitless carry includes vehicle carry considerations, but federal property, schools, courthouses, and restricted premises remain separate issues.",
      dutyToInform: "Verify current Alabama police-contact duties. Keep hands visible and answer lawful questions truthfully.",
      privateSigns: "Private property owners may restrict firearms and require persons to leave.",
      forceLaw: "Alabama self-defense law is fact-specific and does not excuse unlawful possession, unlawful carry, or reckless conduct."
    },
    [
      "Alabama is generally permissive, but permitless carry does not mean carry anywhere.",
      "Alabama recognizes valid out-of-state permits, but users must still follow Alabama law.",
      "Schools, courthouses, law enforcement facilities, detention facilities, secure government buildings, federal property, and private property remain major warning areas.",
      "A permit may still matter for reciprocity when leaving Alabama, documentation, and certain practical interactions.",
      "Travelers should treat event venues, beaches, bars, stadiums, government property, and posted private locations as verify-first areas."
    ],
    [
      {
        title: "Permitless Carry / Carrying Without Permit",
        risk: "Core Carry Rule",
        body: [
          "STATUTE: Alabama Code § 13A-11-74.1.",
          "SUMMARY: Alabama law states that the availability of a pistol permit or recognition of a nonresident license does not impose a general prohibition on otherwise lawful carrying of a pistol without a permit.",
          "GUIDANCE: Permitless carry only helps people who may lawfully possess and carry. Prohibited persons, restricted places, intoxication, criminal activity, and federal restrictions can still make carry unlawful."
        ],
        source: "Alabama Code § 13A-11-74.1."
      },
      {
        title: "Optional Alabama Pistol Permit",
        risk: "Permit / Reciprocity Context",
        body: [
          "STATUTE: Alabama Code § 13A-11-75.",
          "SUMMARY: Alabama maintains an optional pistol permit system through county sheriffs.",
          "GUIDANCE: Even in a permitless carry state, a permit can still matter for reciprocity outside Alabama, documentation, and proving permit status when traveling."
        ],
        source: "Alabama Code § 13A-11-75; Alabama Law Enforcement Agency gun laws guidance."
      },
      {
        title: "Out-of-State Permit Recognition",
        risk: "Travel Recognition Rule",
        body: [
          "STATUTE: Alabama Code § 13A-11-85.",
          "SUMMARY: Alabama recognizes any valid permit or license issued by another state.",
          "GUIDANCE: Michigan CPL should be treated as recognized in Alabama, but recognition does not override Alabama restricted places, federal law, or private property control."
        ],
        source: "Alabama Code § 13A-11-85; Alabama Law Enforcement Agency gun laws guidance."
      },
      {
        title: "Prohibited Persons / Persons Forbidden to Possess",
        risk: "Disqualification Risk",
        body: [
          "STATUTE: Alabama Code § 13A-11-72.",
          "SUMMARY: Alabama law identifies categories of people prohibited from owning, possessing, or controlling pistols or firearms in certain circumstances.",
          "GUIDANCE: Domestic violence issues, felony history, protection orders, mental health adjudications, pending cases, bond conditions, or federal prohibitions require legal review before possession or carry."
        ],
        source: "Alabama Code § 13A-11-72."
      },
      {
        title: "Schools / K-12 Premises",
        risk: "Extreme Risk Area",
        body: [
          "STATUTE: Alabama Code § 13A-11-72(d) and related school weapons framework.",
          "SUMMARY: Alabama restricts possession of deadly weapons on school premises under statutory conditions and exceptions.",
          "GUIDANCE: School buildings, buses, school property, events, pickup/drop-off, and athletic activities should be treated as verify-first areas. Do not assume permitless carry solves a school issue."
        ],
        source: "Alabama Code § 13A-11-72(d); Alabama school weapons framework."
      },
      {
        title: "Courthouses / Court Facilities",
        risk: "Hard Stop Area",
        body: [
          "STATUTE / SOURCE: Alabama court security and prohibited-location framework.",
          "SUMMARY: Courthouses and court facilities are high-risk restricted locations and may be controlled by court order, security screening, and local facility rules.",
          "GUIDANCE: Do not approach court security armed. Secure lawfully before arrival or do not bring the firearm."
        ],
        source: "Alabama court security/prohibited premises framework."
      },
      {
        title: "Law Enforcement / Detention / Correctional Facilities",
        risk: "Restricted Facility Risk",
        body: [
          "STATUTE / SOURCE: Alabama prohibited-location and correctional facility framework.",
          "SUMMARY: Police stations, sheriff offices, jails, detention facilities, prisons, and correctional settings create serious legal and security risk.",
          "GUIDANCE: Treat these locations as restricted unless a clear legal exception applies. Do not walk into a police or jail facility armed without verifying."
        ],
        source: "Alabama law enforcement/detention facility framework."
      },
      {
        title: "Private Property / Posted Locations",
        risk: "Property Control",
        body: [
          "STATUTE / SOURCE: Alabama property and trespass framework.",
          "SUMMARY: Private property owners may restrict firearms and require a person to leave.",
          "GUIDANCE: Posted businesses, event venues, churches, hotels, beaches, stadiums, and private properties should be respected. If asked to leave, leave immediately."
        ],
        source: "Alabama property/trespass framework."
      },
      {
        title: "Vehicle Carry / Road Trip Issues",
        risk: "Travel Carry Risk",
        body: [
          "STATUTE / SOURCE: Alabama Code § 13A-11-74.1; Alabama pistol carry framework.",
          "SUMMARY: Alabama permitless carry reduces the old permit barrier for pistol carry, but vehicle carry still interacts with eligibility, location restrictions, officer safety, and federal property.",
          "GUIDANCE: Keep hands visible during police contact, avoid reaching, answer lawful questions truthfully, and do not assume a vehicle cures a school, court, or federal property problem."
        ],
        source: "Alabama Code § 13A-11-74.1; Alabama firearm travel framework."
      },
      {
        title: "Federal Property / Post Offices / Military Installations",
        risk: "Federal Law Overlay",
        body: [
          "STATUTE / SOURCE: Federal facility, postal property, and military installation framework.",
          "SUMMARY: Alabama carry permission does not override federal buildings, post offices, secure federal facilities, military bases, or federal court rules.",
          "GUIDANCE: Check federal property separately. Military installations and federal facilities are not controlled by Alabama permitless carry."
        ],
        source: "Federal facility, postal property, and military installation framework."
      },
      {
        title: "Use of Force / Self-Defense",
        risk: "Fact-Specific Legal Risk",
        body: [
          "STATUTE / SOURCE: Alabama self-defense framework.",
          "SUMMARY: Defensive force must be justified under Alabama law and the facts. Carry law does not decide whether force was lawful.",
          "GUIDANCE: Avoid confrontation, call 911, identify evidence/witnesses when necessary, request counsel, and avoid detailed statements under stress."
        ],
        source: "Alabama self-defense law framework."
      }
    ],
    [
      {
        title: "Alabama Carry Checklist",
        steps: [
          "1. Confirm legal eligibility to possess and carry.",
          "2. Confirm Alabama recognition/permitless status under §§ 13A-11-74.1 and 13A-11-85.",
          "3. Check schools under § 13A-11-72 and related rules.",
          "4. Check courts, law enforcement facilities, and secure government buildings.",
          "5. Check private property, hotels, beaches, stadiums, and event rules.",
          "6. Check federal property and military installations separately."
        ]
      }
    ],
    [
      {
        title: "Gulf Coast / Vacation Travel",
        summary: "Alabama travel often includes beaches, hotels, restaurants, events, alcohol, and vehicle storage.",
        guidance: [
          "Check hotel and venue policy.",
          "Do not leave firearms unsecured in vehicles.",
          "Check federal property and military-area rules.",
          "Do not mix alcohol and carry."
        ]
      }
    ],
    [
      "Assuming permitless carry means no prohibited places.",
      "Ignoring school premises.",
      "Ignoring federal property or military installations.",
      "Arguing with private property/security staff.",
      "Leaving firearms unsecured in vehicles during travel.",
      "Assuming recognition overrides Alabama law."
    ],
    [
      "Eligibility checked.",
      "Permitless/recognition rule checked.",
      "School property checked.",
      "Court/government/law enforcement facilities checked.",
      "Private property checked.",
      "Federal/military property checked.",
      "Vehicle storage plan ready."
    ],
    [
      {
        myth: "Alabama is permitless, so there are no restrictions.",
        reality: "No. Permitless carry does not override prohibited persons, schools, courts, federal property, private property, or other restricted locations."
      }
    ]
  ),

  SC: makeProfile(
    "South Carolina",
    "Law-Backed Ultra Expanded Travel State",
    "South Carolina is an important southern travel state because it recently adopted constitutional carry while still keeping significant location restrictions. South Carolina law no longer requires a CWP for ordinary carry by eligible persons, but firearms remain prohibited in many places, including schools, churches unless allowed, law enforcement and correctional facilities, medical procedure areas, courthouses, public buildings, and posted locations.",
    {
      reciprocity: "South Carolina should be treated as recognized/permitless for eligible Michigan travelers, but South Carolina law controls while physically in the state.",
      permitlessCarry: "South Carolina constitutional carry took effect in 2024; eligible persons may carry without a CWP subject to restrictions.",
      concealedCarry: "CWP is no longer required for ordinary eligible carry, but CWP remains useful for reciprocity/training and some legal contexts.",
      openCarry: "Open carry is allowed for eligible persons, subject to prohibited locations and property restrictions.",
      vehicleCarry: "Vehicle carry is generally more permissive after constitutional carry, but restricted places, private property, and officer safety still matter.",
      dutyToInform: "SLED guidance states a CWP holder is not required to disclose CWP status to law enforcement under the new law.",
      privateSigns: "S.C. Code § 23-31-235 controls signage requirements for premises where concealed weapons are prohibited.",
      forceLaw: "South Carolina self-defense law is fact-specific and does not excuse unlawful carry or reckless display."
    },
    [
      "South Carolina constitutional carry does not mean carry anywhere.",
      "SLED specifically warns that firearms remain prohibited in many locations after constitutional carry.",
      "Schools, churches, law enforcement facilities, correctional facilities, medical procedure areas, courthouses, public buildings, and posted locations need special caution.",
      "A CWP may still matter for reciprocity when traveling outside South Carolina.",
      "Private property and event security rules should be treated seriously."
    ],
    [
      {
        title: "Constitutional Carry / Permitless Carry",
        risk: "Core Carry Rule",
        body: [
          "STATUTE / SOURCE: South Carolina constitutional carry law; SLED constitutional carry guidance.",
          "SUMMARY: South Carolina no longer requires a CWP for ordinary eligible carry, but firearm restrictions still apply in many locations.",
          "GUIDANCE: Do not teach South Carolina as ruleless. Eligible carry still requires location awareness and lawful conduct."
        ],
        source: "South Carolina Law Enforcement Division constitutional carry guidance."
      },
      {
        title: "SLED Prohibited Location Warning",
        risk: "Major Location Restriction",
        body: [
          "STATUTE / SOURCE: SLED constitutional carry guidance; S.C. Code Title 16 and Title 23 firearms framework.",
          "SUMMARY: SLED states firearms are still prohibited in many locations, including schools, churches, law enforcement facilities, detention/correctional facilities, places where medical procedures are performed, courthouses, public buildings, and clearly marked places prohibiting firearms.",
          "GUIDANCE: Treat these as high-risk verify-first locations before entering armed."
        ],
        source: "South Carolina Law Enforcement Division constitutional carry guidance."
      },
      {
        title: "Carrying Weapon on School Property",
        risk: "Extreme Risk Area",
        body: [
          "STATUTE: S.C. Code § 16-23-430.",
          "SUMMARY: South Carolina law restricts carrying weapons on elementary or secondary school property, subject to statutory exceptions.",
          "GUIDANCE: School buildings, school grounds, buses, parking lots, events, and student activities should be treated as verify-first areas."
        ],
        source: "S.C. Code § 16-23-430."
      },
      {
        title: "Prohibited Locations / CWP Restrictions",
        risk: "Location Restriction",
        body: [
          "STATUTE: S.C. Code § 23-31-215(M) and related 2024 changes.",
          "SUMMARY: South Carolina law has historically identified locations where concealed weapons may not be carried, and 2024 guidance confirms many location restrictions remain.",
          "GUIDANCE: Review schools, churches unless allowed, courthouses, public buildings, detention/correctional facilities, medical-procedure locations, and posted areas before entry."
        ],
        source: "S.C. Code § 23-31-215; SLED constitutional carry guidance."
      },
      {
        title: "Places of Worship",
        risk: "Permission Required",
        body: [
          "STATUTE / SOURCE: SLED constitutional carry guidance and South Carolina location-restriction framework.",
          "SUMMARY: SLED lists churches among locations where firearms remain prohibited unless carry is allowed by the appropriate authority or exception.",
          "GUIDANCE: Do not assume church carry is allowed. Verify with the governing authority or security policy."
        ],
        source: "SLED constitutional carry guidance; South Carolina location-restriction framework."
      },
      {
        title: "Courthouses / Public Buildings",
        risk: "Hard Stop Area",
        body: [
          "STATUTE / SOURCE: SLED guidance and South Carolina public building/court security framework.",
          "SUMMARY: Courthouses and public buildings remain high-risk restricted locations under South Carolina law and policy.",
          "GUIDANCE: Do not approach courthouse or public-building security armed unless a clear legal exception applies."
        ],
        source: "SLED constitutional carry guidance; South Carolina court/public building framework."
      },
      {
        title: "Private Property / Signage",
        risk: "Posted Premises Rule",
        body: [
          "STATUTE: S.C. Code § 23-31-235.",
          "SUMMARY: South Carolina law specifies signage requirements for premises where concealed weapons are prohibited.",
          "GUIDANCE: Posted signs and property-owner instructions should be followed. Leave immediately if asked."
        ],
        source: "S.C. Code § 23-31-235."
      },
      {
        title: "Law Enforcement / Correctional Facilities",
        risk: "Restricted Facility Risk",
        body: [
          "STATUTE / SOURCE: SLED constitutional carry guidance and South Carolina facility restrictions.",
          "SUMMARY: SLED specifically lists law enforcement facilities, detention facilities, and correctional facilities as prohibited locations.",
          "GUIDANCE: Do not enter police, jail, detention, or correctional facilities armed unless a clear exception applies."
        ],
        source: "SLED constitutional carry guidance."
      },
      {
        title: "Medical Procedure Locations",
        risk: "Healthcare Location Risk",
        body: [
          "STATUTE / SOURCE: SLED constitutional carry guidance.",
          "SUMMARY: SLED includes places where medical procedures are performed among prohibited areas.",
          "GUIDANCE: Hospitals, surgery centers, clinics, procedure areas, and medical campuses should be verified before entry."
        ],
        source: "SLED constitutional carry guidance."
      },
      {
        title: "Federal Property / Post Offices / Military Bases",
        risk: "Federal Law Overlay",
        body: [
          "STATUTE / SOURCE: Federal facility and postal property framework.",
          "SUMMARY: South Carolina carry permission does not override federal buildings, post offices, secure federal facilities, or military installations.",
          "GUIDANCE: Federal property must be checked separately from South Carolina law."
        ],
        source: "Federal facility, postal property, and military installation framework."
      },
      {
        title: "Use of Force / Self-Defense",
        risk: "Fact-Specific Legal Risk",
        body: [
          "STATUTE / SOURCE: South Carolina Protection of Persons and Property Act / self-defense framework.",
          "SUMMARY: Defensive force must be justified under South Carolina law and the facts. Carry permission does not decide whether force was lawful.",
          "GUIDANCE: Avoid confrontation, call 911, identify evidence/witnesses when necessary, request counsel, and avoid detailed statements under stress."
        ],
        source: "South Carolina self-defense law framework."
      }
    ],
    [
      {
        title: "South Carolina Carry Checklist",
        steps: [
          "1. Confirm eligibility to possess and carry.",
          "2. Confirm constitutional carry status and remaining location restrictions.",
          "3. Check S.C. Code § 16-23-430 for school property.",
          "4. Check churches, law enforcement, correctional facilities, medical-procedure locations, courthouses, and public buildings.",
          "5. Check signs under § 23-31-235.",
          "6. Check federal property separately."
        ]
      }
    ],
    [
      {
        title: "Myrtle Beach / Charleston Travel",
        summary: "South Carolina travel often includes hotels, beaches, bars, churches, public events, medical facilities, and private security.",
        guidance: [
          "Check posted properties.",
          "Do not carry into prohibited public buildings.",
          "Avoid alcohol/carry combinations.",
          "Follow private security instructions."
        ]
      }
    ],
    [
      "Assuming constitutional carry means carry anywhere.",
      "Ignoring SLED prohibited-location guidance.",
      "Ignoring school property.",
      "Ignoring churches and medical-procedure locations.",
      "Ignoring posted private property signs.",
      "Assuming federal property follows South Carolina law."
    ],
    [
      "Eligibility checked.",
      "SLED prohibited locations checked.",
      "School property checked.",
      "Church policy checked.",
      "Medical/courthouse/public building checked.",
      "Private signs checked.",
      "Federal property checked."
    ],
    [
      {
        myth: "South Carolina constitutional carry means I can carry anywhere.",
        reality: "No. SLED guidance makes clear that many locations remain prohibited even after constitutional carry."
      }
    ]
  ),

  VA: makeProfile(
    "Virginia",
    "Law-Backed Ultra Expanded Travel State",
    "Virginia is a common travel state for Michigan CPL holders and has a recognized concealed handgun permit framework with permit reciprocity, strict school rules, public/capitol area restrictions, courthouse concerns, airport/secure-area issues, alcohol and restaurant issues, private property rules, and local government/event limitations. Virginia law controls while physically in Virginia.",
    {
      reciprocity: "Virginia recognizes out-of-state concealed handgun permits that meet Virginia statutory conditions under Va. Code § 18.2-308.014.",
      permitlessCarry: "No general permitless concealed handgun carry. Concealed handgun carry generally requires a valid permit or statutory exception.",
      concealedCarry: "Va. Code § 18.2-308 and Article 6.1 govern concealed weapons and permits.",
      openCarry: "Open carry may be lawful in many circumstances, but local restrictions, schools, courthouses, private property, and public-event rules matter.",
      vehicleCarry: "Vehicle carry must be analyzed under Virginia concealed-carry rules and exceptions.",
      dutyToInform: "Virginia does not generally use Michigan-style automatic disclosure, but permit/ID must be displayed upon demand under reciprocity conditions.",
      privateSigns: "Private property owners can restrict firearms and require persons to leave.",
      forceLaw: "Virginia self-defense law is fact-specific and rooted substantially in case-law principles."
    },
    [
      "Virginia recognizes out-of-state permits if statutory conditions are met, but the person must carry permit and photo ID and display them upon demand.",
      "Virginia is not permitless concealed carry.",
      "School property, courthouses, airport terminals/secure areas, capitol/government areas, and certain public events require careful review.",
      "Open carry is not the same as lawful carry everywhere.",
      "Private property, employer rules, and local ordinances can create separate consequences."
    ],
    [
      {
        title: "Concealed Carry Permit / Reciprocity",
        risk: "Core Recognition Rule",
        body: [
          "STATUTE: Va. Code § 18.2-308.014.",
          "SUMMARY: Virginia recognizes valid out-of-state concealed handgun permits if statutory conditions are satisfied, including permit and photo identification display upon demand and no prior Virginia permit revocation.",
          "GUIDANCE: Michigan CPL holders should carry physical permit and government photo ID and be prepared to display them upon lawful demand."
        ],
        source: "Va. Code § 18.2-308.014."
      },
      {
        title: "Concealed Weapons General Rule",
        risk: "Core Carry Rule",
        body: [
          "STATUTE: Va. Code § 18.2-308.",
          "SUMMARY: Virginia restricts carrying concealed weapons, including handguns, unless a permit or statutory exception applies.",
          "GUIDANCE: Do not treat Virginia as permitless concealed carry. Verify permit recognition and carry documentation."
        ],
        source: "Va. Code § 18.2-308."
      },
      {
        title: "Permit Must Be Carried / Displayed",
        risk: "Documentation Requirement",
        body: [
          "STATUTE: Va. Code § 18.2-308.014 and Article 6.1 framework.",
          "SUMMARY: Virginia’s reciprocity statute requires the permit holder to carry the permit/license and photo identification and display them upon demand by law enforcement.",
          "GUIDANCE: Carry physical permit and photo ID. Do not rely on screenshots or memory."
        ],
        source: "Va. Code § 18.2-308.014."
      },
      {
        title: "Schools / School Property",
        risk: "Extreme Risk Area",
        body: [
          "STATUTE: Va. Code § 18.2-308.1.",
          "SUMMARY: Virginia restricts possession of firearms and weapons on school property and school buses, subject to statutory exceptions.",
          "GUIDANCE: Schools, school events, buses, parking areas, and activities should be treated as verify-first locations."
        ],
        source: "Va. Code § 18.2-308.1."
      },
      {
        title: "Courthouses",
        risk: "Hard Stop Area",
        body: [
          "STATUTE: Va. Code § 18.2-283.1.",
          "SUMMARY: Virginia restricts weapons in courthouses and courtrooms, subject to exceptions.",
          "GUIDANCE: Do not approach courthouse security armed. Plan lawful storage before arrival."
        ],
        source: "Va. Code § 18.2-283.1."
      },
      {
        title: "Air Carrier Airport Terminal",
        risk: "Airport / Transportation Risk",
        body: [
          "STATUTE: Va. Code § 18.2-287.01.",
          "SUMMARY: Virginia restricts carrying weapons in air carrier airport terminals, subject to statutory details and exceptions.",
          "GUIDANCE: Airport carry and airline checked transport are different. Know TSA/airline procedures before arrival."
        ],
        source: "Va. Code § 18.2-287.01."
      },
      {
        title: "Capitol Square / Government Buildings / Local Events",
        risk: "Government and Local Restriction Risk",
        body: [
          "STATUTE / SOURCE: Virginia state/local government firearms restrictions framework, including Va. Code § 15.2-915 authority in certain public spaces/events.",
          "SUMMARY: Virginia allows certain local firearm restrictions in government buildings, parks, recreation/community centers, and permitted events under statutory limits.",
          "GUIDANCE: Public buildings, city events, protests, parades, parks, and community centers should be checked before carrying."
        ],
        source: "Va. Code § 15.2-915; Virginia local firearms restrictions framework."
      },
      {
        title: "Restaurants / Alcohol",
        risk: "Alcohol Location Risk",
        body: [
          "STATUTE / SOURCE: Virginia concealed handgun and alcohol-related restrictions framework.",
          "SUMMARY: Virginia has rules involving concealed handguns, alcohol consumption, and restaurants/clubs where alcohol is served.",
          "GUIDANCE: If drinking is part of the plan, carrying should not be. Verify alcohol-related restrictions before entering bars, restaurants, clubs, stadiums, or events."
        ],
        source: "Virginia alcohol/firearm restrictions framework."
      },
      {
        title: "Private Property / Posted Locations",
        risk: "Property Control",
        body: [
          "STATUTE / SOURCE: Virginia property and trespass framework.",
          "SUMMARY: Private property owners may restrict firearms and require a person to leave.",
          "GUIDANCE: If posted or instructed to leave, leave immediately. Do not debate staff or security."
        ],
        source: "Virginia property/trespass framework."
      },
      {
        title: "Federal Property / Post Offices / Military Installations",
        risk: "Federal Law Overlay",
        body: [
          "STATUTE / SOURCE: Federal facility, postal property, and military installation framework.",
          "SUMMARY: Virginia carry permission does not override federal property, military installation, federal courthouse, postal, or secure federal facility restrictions.",
          "GUIDANCE: Federal property must be checked separately. Northern Virginia travel often involves federal facilities and secure government areas."
        ],
        source: "Federal facility, postal property, and military installation framework."
      },
      {
        title: "Use of Force / Self-Defense",
        risk: "Fact-Specific Legal Risk",
        body: [
          "STATUTE / SOURCE: Virginia self-defense case-law and statutory framework.",
          "SUMMARY: Virginia self-defense is fact-specific and depends on reasonableness, fault, necessity, proportionality, and circumstances.",
          "GUIDANCE: Avoid confrontation, disengage if safely possible, call 911, request counsel, and avoid detailed statements under stress."
        ],
        source: "Virginia self-defense law framework."
      }
    ],
    [
      {
        title: "Virginia Carry Checklist",
        steps: [
          "1. Verify permit recognition under § 18.2-308.014.",
          "2. Carry physical permit and government photo ID.",
          "3. Check schools under § 18.2-308.1.",
          "4. Check courthouses under § 18.2-283.1.",
          "5. Check airports under § 18.2-287.01.",
          "6. Check local government/event restrictions.",
          "7. Check alcohol, private property, and federal property."
        ]
      }
    ],
    [
      {
        title: "Northern Virginia / DC Border Travel",
        summary: "Virginia travel near DC creates major risk because federal property and DC law may be nearby.",
        guidance: [
          "Know whether you are in Virginia, DC, federal property, or private property.",
          "Carry permit and photo ID.",
          "Do not cross into DC armed without separate legal review.",
          "Check federal buildings and parking areas."
        ]
      }
    ],
    [
      "Assuming Virginia is permitless concealed carry.",
      "Failing to carry permit and photo ID.",
      "Ignoring schools, courthouses, airports, and government/event restrictions.",
      "Crossing into DC accidentally while armed.",
      "Ignoring private property and employer policies."
    ],
    [
      "Permit recognition checked.",
      "Permit and photo ID carried.",
      "School property checked.",
      "Courthouse/airport checked.",
      "Local government/event rules checked.",
      "Federal/DC boundary risks checked."
    ],
    [
      {
        myth: "Virginia honors my permit, so I can carry anywhere in Virginia.",
        reality: "No. Permit recognition does not override schools, courthouses, airports, government/event restrictions, private property, federal property, or DC boundary risks."
      }
    ]
  ),

  MO: makeProfile(
    "Missouri",
    "Law-Backed Ultra Expanded Travel State",
    "Missouri is a major Midwest travel state with permitless concealed carry for many eligible persons, but the state still maintains a detailed prohibited-location framework, local open-carry issues, school restrictions, court/government restrictions, private property signage, vehicle/employer rules, alcohol/event concerns, and self-defense considerations. Missouri is generally permissive but not unrestricted.",
    {
      reciprocity: "Missouri generally recognizes valid permits and also has permitless carry, but Missouri law controls while physically in Missouri.",
      permitlessCarry: "Missouri has allowed permitless concealed carry for eligible persons since 2017, subject to prohibited locations and other laws.",
      concealedCarry: "RSMo § 571.107 lists locations where concealed carry authorization does not apply.",
      openCarry: "Open carry may be affected by local ordinances, especially for persons without a permit Missouri honors.",
      vehicleCarry: "Missouri permitless carry and permit rules can apply in vehicles, but employer-owned vehicles and prohibited locations require review.",
      dutyToInform: "Verify current Missouri police-contact rules. Keep hands visible and answer lawful questions truthfully.",
      privateSigns: "RSMo § 571.107 includes private-property signage rules and vehicle-on-premises language.",
      forceLaw: "Missouri self-defense law is fact-specific and does not excuse unlawful carry or reckless display."
    },
    [
      "Missouri is permitless carry, but § 571.107 remains the core prohibited-location warning statute.",
      "Private property signage has detailed rules, including vehicle-on-premises treatment.",
      "Local open-carry restrictions may matter for persons without a valid permit recognized by Missouri.",
      "Schools, courts, law enforcement facilities, polling places, government meetings, bars, hospitals, amusement parks, casinos, and churches require careful review.",
      "Permitless carry does not mean no consequences."
    ],
    [
      {
        title: "Permitless Carry / Missouri Carry Framework",
        risk: "Core Carry Rule",
        body: [
          "STATUTE / SOURCE: Missouri weapons statutes, including RSMo Chapter 571.",
          "SUMMARY: Missouri allows permitless concealed carry for eligible persons, while still issuing permits for reciprocity and other purposes.",
          "GUIDANCE: Permitless carry does not override prohibited places, private property signs, local open-carry rules, or prohibited-person laws."
        ],
        source: "RSMo Chapter 571; Missouri permitless carry framework."
      },
      {
        title: "Prohibited Locations",
        risk: "Major Location Restriction",
        body: [
          "STATUTE: RSMo § 571.107.",
          "SUMMARY: Missouri law lists locations where concealed carry authorization does not apply, including law enforcement facilities, polling places, correctional facilities, courthouses, government meetings, schools, child care facilities, bars, airports, hospitals, amusement parks, churches, private posted property, stadiums/arenas, casinos, and higher education premises, subject to statutory details and exceptions.",
          "GUIDANCE: Treat § 571.107 as the main Missouri location checklist before entering armed."
        ],
        source: "RSMo § 571.107."
      },
      {
        title: "Private Property / Posted Locations",
        risk: "Posted Property Rule",
        body: [
          "STATUTE: RSMo § 571.107(15).",
          "SUMMARY: Missouri allows private property owners to post premises as off-limits to concealed firearms with signs meeting statutory requirements; the statute also addresses firearms in vehicles on posted premises.",
          "GUIDANCE: If posted or asked to leave, leave immediately. Do not remove or brandish a firearm from a vehicle on posted premises."
        ],
        source: "RSMo § 571.107(15)."
      },
      {
        title: "Schools / Child Care Facilities",
        risk: "Extreme Risk Area",
        body: [
          "STATUTE: RSMo § 571.107 and Missouri school weapons framework.",
          "SUMMARY: Missouri restricts carry in schools and child care facilities under § 571.107 and related laws, subject to statutory details and exceptions.",
          "GUIDANCE: School buildings, grounds, buses, events, child care facilities, and parking areas should be treated as verify-first locations."
        ],
        source: "RSMo § 571.107; Missouri school weapons framework."
      },
      {
        title: "Courts / Government Meetings / Polling Places",
        risk: "Government Function Risk",
        body: [
          "STATUTE: RSMo § 571.107.",
          "SUMMARY: Missouri restricts carry in courthouses, courtrooms, government meetings, and polling places under the prohibited-location framework.",
          "GUIDANCE: Do not approach court security or polling places armed without checking current law and facility rules."
        ],
        source: "RSMo § 571.107."
      },
      {
        title: "Law Enforcement / Correctional Facilities",
        risk: "Restricted Facility Risk",
        body: [
          "STATUTE: RSMo § 571.107.",
          "SUMMARY: Missouri restricts carry in police, sheriff, highway patrol, and correctional/detention facilities under the prohibited-location framework.",
          "GUIDANCE: Treat police stations, jails, detention centers, and correctional facilities as restricted unless a clear exception applies."
        ],
        source: "RSMo § 571.107."
      },
      {
        title: "Bars / Alcohol / Casinos / Amusement Parks",
        risk: "Entertainment and Alcohol Risk",
        body: [
          "STATUTE: RSMo § 571.107.",
          "SUMMARY: Missouri’s prohibited-location statute includes restrictions involving bars, amusement parks, gambling facilities, stadiums, and similar venues under statutory details.",
          "GUIDANCE: Entertainment venues, casinos, stadiums, bars, and alcohol-centered locations should be checked carefully. Do not carry while impaired."
        ],
        source: "RSMo § 571.107."
      },
      {
        title: "Open Carry / Local Ordinances",
        risk: "Local Rule Risk",
        body: [
          "STATUTE / SOURCE: Missouri open carry and local ordinance framework.",
          "SUMMARY: Missouri generally permits open carry, but local governments may restrict open carry for persons without a valid permit recognized by Missouri.",
          "GUIDANCE: Do not assume open carry is uniformly accepted statewide. Check local ordinances, especially in cities and event areas."
        ],
        source: "Missouri local open-carry framework; RSMo Chapter 21/571 preemption framework."
      },
      {
        title: "Vehicle Carry / Employer Vehicles",
        risk: "Vehicle and Employment Risk",
        body: [
          "STATUTE: RSMo § 571.107 and Missouri vehicle/employer framework.",
          "SUMMARY: Missouri law includes vehicle-related rules in the private-property subsection and allows employers to restrict firearms in employer-owned vehicles.",
          "GUIDANCE: Company vehicles, job sites, posted premises, and customer locations should be checked separately from ordinary public carry."
        ],
        source: "RSMo § 571.107(15)."
      },
      {
        title: "Federal Property / Post Offices",
        risk: "Federal Law Overlay",
        body: [
          "STATUTE / SOURCE: Federal facility and postal property framework.",
          "SUMMARY: Missouri carry permission does not override federal buildings, post offices, federal courthouses, or secure federal facilities.",
          "GUIDANCE: Federal property must be checked separately from Missouri law."
        ],
        source: "Federal facility and postal property framework."
      },
      {
        title: "Use of Force / Self-Defense",
        risk: "Fact-Specific Legal Risk",
        body: [
          "STATUTE / SOURCE: Missouri self-defense framework.",
          "SUMMARY: Defensive force must be justified under Missouri law and the facts. Permitless carry does not decide whether force was lawful.",
          "GUIDANCE: Avoid confrontation, call 911, identify evidence/witnesses when necessary, request counsel, and avoid detailed statements under stress."
        ],
        source: "Missouri self-defense law framework."
      }
    ],
    [
      {
        title: "Missouri Carry Checklist",
        steps: [
          "1. Confirm legal eligibility to possess and carry.",
          "2. Check RSMo § 571.107 before entering any location.",
          "3. Check posted property under § 571.107(15).",
          "4. Check schools, child care, courts, government meetings, law enforcement facilities, and polling places.",
          "5. Check bars, casinos, amusement parks, stadiums, hospitals, and churches.",
          "6. Check local open carry rules and federal property."
        ]
      }
    ],
    [
      {
        title: "St. Louis / Kansas City Travel",
        summary: "Large-city travel may involve local open-carry rules, stadiums, hospitals, casinos, bars, posted private property, and government buildings.",
        guidance: [
          "Check § 571.107.",
          "Check local open carry rules.",
          "Watch for posted premises.",
          "Do not carry while impaired."
        ]
      }
    ],
    [
      "Assuming permitless carry means no prohibited places.",
      "Ignoring § 571.107.",
      "Ignoring posted private property signs.",
      "Ignoring local open carry ordinances.",
      "Carrying into bars, casinos, stadiums, schools, courts, or government meetings without checking.",
      "Assuming employer-owned vehicles are treated like personal vehicles."
    ],
    [
      "Eligibility checked.",
      "RSMo § 571.107 checked.",
      "Private signs checked.",
      "Local open carry checked.",
      "School/court/government functions checked.",
      "Federal property checked.",
      "Vehicle/employer policy checked."
    ],
    [
      {
        myth: "Missouri permitless carry means I can carry anywhere.",
        reality: "No. RSMo § 571.107 lists many prohibited/restricted locations and private property rules still apply."
      }
    ]
  ),

  IA: makeProfile(
    "Iowa",
    "Law-Backed Ultra Expanded Travel State",
    "Iowa is a Midwest travel state with permitless carry for otherwise lawful persons, but it still has important restrictions involving schools, weapons-free zones, intoxication, minors, prohibited persons, permits for reciprocity, private property, state capitol rules, vehicles, and federal property. Iowa is permissive, but not consequence-free.",
    {
      reciprocity: "Iowa recognizes valid permits/licenses issued by other states for nonresidents under Iowa Code § 724.11A, and Iowa also has permitless carry under § 724.5.",
      permitlessCarry: "Iowa Code § 724.5 states that permit availability shall not be construed to prohibit otherwise lawful unlicensed carrying or transport, openly or concealed, including a loaded firearm.",
      concealedCarry: "Permitless carry exists for otherwise lawful persons, but prohibited places and disqualifications still apply.",
      openCarry: "Open carry may be lawful for eligible persons, but state capitol rules, local/property rules, schools, and disorderly conduct concerns matter.",
      vehicleCarry: "Iowa Code § 724.5 includes otherwise lawful unlicensed carrying or transport, including a loaded firearm, but other restrictions still apply.",
      dutyToInform: "Iowa has a duty-to-cooperate statute in Iowa Code § 724.4D; keep hands visible and answer lawful questions truthfully.",
      privateSigns: "Private property and trespass rules matter. Leave if asked.",
      forceLaw: "Iowa self-defense law is fact-specific and does not excuse unlawful carry or reckless display."
    },
    [
      "Iowa permitless carry took effect through 2021 law changes and is reflected in § 724.5.",
      "Permitless carry applies only when the carry or transport is otherwise lawful.",
      "Schools, weapons-free zones, intoxication, minors, and prohibited-person rules still matter.",
      "Iowa permits remain useful for reciprocity outside Iowa and documentation.",
      "State capitol, public buildings, posted private property, federal property, and event security should be checked separately."
    ],
    [
      {
        title: "Permitless Carry / Availability of Permit Not a Ban",
        risk: "Core Carry Rule",
        body: [
          "STATUTE: Iowa Code § 724.5.",
          "SUMMARY: Iowa law states that the availability of a professional or nonprofessional permit shall not be construed to impose a general prohibition on otherwise lawful unlicensed carrying or transport, whether openly or concealed, of a dangerous weapon, including a loaded firearm.",
          "GUIDANCE: The key phrase is otherwise lawful. Permitless carry does not protect prohibited persons, restricted locations, intoxication, minors, or criminal conduct."
        ],
        source: "Iowa Code § 724.5; Iowa Department of Public Safety weapon permit guidance."
      },
      {
        title: "Out-of-State Permit Recognition",
        risk: "Travel Recognition Rule",
        body: [
          "STATUTE: Iowa Code § 724.11A.",
          "SUMMARY: Iowa recognizes a valid permit or license issued by another state to a nonresident of Iowa, subject to Iowa law.",
          "GUIDANCE: Michigan CPL should be treated as recognized for Iowa travel, but Iowa law controls while physically in Iowa."
        ],
        source: "Iowa Code § 724.11A."
      },
      {
        title: "Nonprofessional Permit / Permit Still Useful",
        risk: "Permit / Reciprocity Context",
        body: [
          "STATUTE: Iowa Code § 724.7; § 724.11.",
          "SUMMARY: Iowa still issues nonprofessional permits to carry weapons even after permitless carry law changes.",
          "GUIDANCE: A permit may matter for reciprocity outside Iowa, documentation, and certain federal or interstate issues."
        ],
        source: "Iowa Code §§ 724.7, 724.11; Iowa DPS weapon permits guidance."
      },
      {
        title: "Carrying Firearms on School Grounds",
        risk: "Extreme Risk Area",
        body: [
          "STATUTE: Iowa Code § 724.4B.",
          "SUMMARY: Iowa law restricts carrying firearms on school grounds, subject to statutory exceptions.",
          "GUIDANCE: School buildings, grounds, buses, parking areas, and events should be treated as verify-first areas. Do not assume permitless carry solves school issues."
        ],
        source: "Iowa Code § 724.4B."
      },
      {
        title: "Weapons-Free Zones / Enhanced Penalties",
        risk: "Enhanced Penalty Area",
        body: [
          "STATUTE: Iowa Code § 724.4A.",
          "SUMMARY: Iowa law provides enhanced penalties for certain weapons offenses committed in weapons-free zones.",
          "GUIDANCE: Schools and other designated areas can increase legal exposure even when the user thinks the underlying conduct is minor."
        ],
        source: "Iowa Code § 724.4A."
      },
      {
        title: "Carrying While Under the Influence",
        risk: "Intoxication Risk",
        body: [
          "STATUTE: Iowa Code § 724.4C.",
          "SUMMARY: Iowa law addresses possession or carrying of dangerous weapons while under the influence.",
          "GUIDANCE: If alcohol or drugs are part of the plan, carrying should not be part of the plan. Impairment can destroy an otherwise lawful carry situation."
        ],
        source: "Iowa Code § 724.4C."
      },
      {
        title: "Duty to Cooperate / Police Contact",
        risk: "Police Contact Risk",
        body: [
          "STATUTE: Iowa Code § 724.4D.",
          "SUMMARY: Iowa law includes a duty-to-cooperate provision involving dangerous weapons and reasonable suspicion.",
          "GUIDANCE: During police contact, keep hands visible, do not reach, and answer lawful questions truthfully. Do not argue roadside about the statute."
        ],
        source: "Iowa Code § 724.4D."
      },
      {
        title: "Minors / Age Issues",
        risk: "Age-Based Risk",
        body: [
          "STATUTE: Iowa Code § 724.4E and related age/prohibited person framework.",
          "SUMMARY: Iowa law addresses possession of dangerous weapons and loaded firearms by minors and related restrictions.",
          "GUIDANCE: Do not assume permitless carry applies the same to minors or younger adults. Verify age and eligibility."
        ],
        source: "Iowa Code § 724.4E."
      },
      {
        title: "State Capitol / Government Buildings",
        risk: "Government Facility Risk",
        body: [
          "STATUTE / SOURCE: Iowa state capitol and public-building firearms framework.",
          "SUMMARY: Iowa government buildings, the capitol complex, and security-controlled public buildings may have special rules.",
          "GUIDANCE: Treat capitol grounds, government buildings, courthouses, and public meetings as verify-first locations."
        ],
        source: "Iowa public-building/state capitol firearms framework."
      },
      {
        title: "Private Property / Posted Locations",
        risk: "Property Control",
        body: [
          "STATUTE / SOURCE: Iowa property and trespass framework.",
          "SUMMARY: Private property owners can control access and require persons to leave.",
          "GUIDANCE: If posted or asked to leave, leave immediately. Do not turn a carry question into a trespass or disorderly conduct issue."
        ],
        source: "Iowa property/trespass framework."
      },
      {
        title: "Federal Property / Post Offices",
        risk: "Federal Law Overlay",
        body: [
          "STATUTE / SOURCE: Federal facility and postal property framework.",
          "SUMMARY: Iowa carry permission does not override federal buildings, post offices, federal courthouses, or secure federal facilities.",
          "GUIDANCE: Federal property must be checked separately from Iowa law."
        ],
        source: "Federal facility and postal property framework."
      },
      {
        title: "Use of Force / Self-Defense",
        risk: "Fact-Specific Legal Risk",
        body: [
          "STATUTE / SOURCE: Iowa self-defense framework.",
          "SUMMARY: Defensive force must be justified under Iowa law and the facts. Permitless carry does not decide whether force was lawful.",
          "GUIDANCE: Avoid confrontation, call 911, identify evidence/witnesses when necessary, request counsel, and avoid detailed statements under stress."
        ],
        source: "Iowa self-defense law framework."
      }
    ],
    [
      {
        title: "Iowa Carry Checklist",
        steps: [
          "1. Confirm the carry or transport is otherwise lawful under § 724.5.",
          "2. Verify recognition under § 724.11A if relying on Michigan CPL.",
          "3. Check school grounds under § 724.4B.",
          "4. Check weapons-free zones under § 724.4A.",
          "5. Check intoxication under § 724.4C.",
          "6. Check police contact/duty to cooperate under § 724.4D.",
          "7. Check private, government, and federal property."
        ]
      }
    ],
    [
      {
        title: "Iowa Road Trip / College Town",
        summary: "Iowa travel can involve colleges, schools, state property, restaurants, and rural vehicle travel.",
        guidance: [
          "Check school grounds.",
          "Check government/capitol rules.",
          "Do not carry while impaired.",
          "Treat college-town events as verify-first."
        ]
      }
    ],
    [
      "Assuming otherwise lawful in § 724.5 means everything is allowed.",
      "Ignoring school grounds under § 724.4B.",
      "Ignoring intoxication under § 724.4C.",
      "Ignoring weapons-free zone enhanced penalties.",
      "Ignoring state capitol/government rules.",
      "Assuming private property signs or instructions do not matter."
    ],
    [
      "Eligibility checked.",
      "§ 724.5 otherwise-lawful status checked.",
      "School grounds checked.",
      "Weapons-free zones checked.",
      "Intoxication risk checked.",
      "Private/government/federal property checked.",
      "Police-contact behavior plan ready."
    ],
    [
      {
        myth: "Iowa permitless carry means I can carry anywhere.",
        reality: "No. § 724.5 only protects otherwise lawful carry or transport. Schools, intoxication, weapons-free zones, prohibited persons, private property, and federal property still matter."
      }
    ]
  ),

  MN: makeProfile(
    "Minnesota",
    "Law-Backed Ultra Expanded Travel State",
    "Minnesota is a high-priority Great Lakes travel state for Michigan CPL holders because it generally requires a valid permit to carry a pistol in public, has detailed school-property rules, police disclosure upon request, private-posted-premises rules, public-building/employer policy issues, vehicle transport rules without a permit, and strict caution around alcohol, federal property, parks, and government facilities.",
    {
      reciprocity: "Minnesota honors certain out-of-state permits only if listed by Minnesota. Michigan CPL recognition must be verified before travel.",
      permitlessCarry: "No general permitless public pistol carry. Minnesota generally requires a valid permit to carry a pistol in public under Minn. Stat. § 624.714.",
      concealedCarry: "Minnesota’s permit to carry applies to carrying a pistol; it is not limited to concealed carry.",
      openCarry: "Open carry of a pistol in public generally requires a valid permit unless an exception applies.",
      vehicleCarry: "Without a valid permit, Minnesota vehicle transport generally requires unloaded and properly cased/trunk transport under statutory exceptions.",
      dutyToInform: "Minn. Stat. § 624.714 requires permit holders to disclose whether they are carrying if requested by a peace officer.",
      privateSigns: "Minnesota has posted-premises rules under § 624.714 and private property/employer policy concerns.",
      forceLaw: "Minnesota self-defense law is fact-specific and does not excuse unlawful carry."
    },
    [
      "Minnesota is not permitless public pistol carry.",
      "Out-of-state permit recognition must be checked against Minnesota’s current list.",
      "A permit holder must disclose whether they are carrying if a peace officer requests it.",
      "School property is a major statutory risk area.",
      "Vehicle transport without a permit requires careful compliance."
    ],
    [
      {
        title: "Permit to Carry Requirement",
        risk: "Core Carry Rule",
        body: [
          "STATUTE: Minn. Stat. § 624.714.",
          "SUMMARY: Minnesota’s permit-to-carry statute governs who may carry a pistol in public and the process for obtaining a permit.",
          "GUIDANCE: Do not treat Minnesota as permitless carry. Verify Michigan CPL recognition before travel and carry permit/ID documentation."
        ],
        source: "Minn. Stat. § 624.714."
      },
      {
        title: "Out-of-State Permit Recognition",
        risk: "Recognition List Risk",
        body: [
          "STATUTE / SOURCE: Minn. Stat. § 624.714 and Minnesota permit reciprocity framework.",
          "SUMMARY: Minnesota honors out-of-state permits only when the state is recognized by Minnesota under its permit standards.",
          "GUIDANCE: Verify current Minnesota reciprocity before travel. Do not assume Michigan CPL is honored without checking the active list."
        ],
        source: "Minn. Stat. § 624.714; Minnesota DPS/BCA permit reciprocity framework."
      },
      {
        title: "Disclosure Upon Request by Peace Officer",
        risk: "Police Contact Requirement",
        body: [
          "STATUTE: Minn. Stat. § 624.714, subd. 1b(d).",
          "SUMMARY: Upon request of a peace officer, a permit holder shall disclose whether or not the permit holder is currently carrying a firearm.",
          "GUIDANCE: Minnesota is not automatic Michigan-style disclosure, but if asked, answer truthfully. Keep hands visible and do not reach."
        ],
        source: "Minn. Stat. § 624.714, subd. 1b(d)."
      },
      {
        title: "Permit / ID Display Upon Demand",
        risk: "Documentation Requirement",
        body: [
          "STATUTE: Minn. Stat. § 624.714.",
          "SUMMARY: Minnesota permit holders must comply with statutory permit/identification display requirements when lawfully demanded by a peace officer.",
          "GUIDANCE: Carry physical permit and government photo ID. Do not rely on a screenshot."
        ],
        source: "Minn. Stat. § 624.714."
      },
      {
        title: "Carrying Without a Permit / Exceptions",
        risk: "Unlicensed Carry Risk",
        body: [
          "STATUTE: Minn. Stat. § 624.714, subd. 9 and related transport statutes.",
          "SUMMARY: Minnesota has specific exceptions where a permit is not required, but these are limited and fact-specific.",
          "GUIDANCE: Do not treat exceptions as a general carry right. Verify home/business, transport, hunting/range, and vehicle exceptions carefully."
        ],
        source: "Minn. Stat. § 624.714, subd. 9."
      },
      {
        title: "School Property",
        risk: "Extreme Risk Area",
        body: [
          "STATUTE: Minn. Stat. § 609.66, subd. 1d.",
          "SUMMARY: Minnesota restricts possession, storage, and keeping of firearms while knowingly on school property, subject to statutory exceptions.",
          "GUIDANCE: Schools, school parking areas, buses, events, and school-controlled property should be treated as verify-first areas."
        ],
        source: "Minn. Stat. § 609.66, subd. 1d."
      },
      {
        title: "Vehicle Transport Without Permit",
        risk: "Transport Trap",
        body: [
          "STATUTE / SOURCE: Minn. Stat. § 624.714, subd. 9; Minnesota transport framework.",
          "SUMMARY: Without a valid permit, Minnesota transport rules generally require careful unloaded/cased/trunk or otherwise lawful transport methods depending on the facts.",
          "GUIDANCE: If permit recognition is uncertain, do not carry loaded/accessible in a vehicle. Treat it as transport and verify the exact rule."
        ],
        source: "Minn. Stat. § 624.714, subd. 9; Minnesota transport law framework."
      },
      {
        title: "Posted Private Establishments",
        risk: "Posted Premises / Trespass Risk",
        body: [
          "STATUTE: Minn. Stat. § 624.714, subd. 17.",
          "SUMMARY: Minnesota law addresses private establishments posting against firearms and the legal effect of notice and refusal to leave.",
          "GUIDANCE: Posted signs and direct instructions should be followed. If asked to leave, leave immediately."
        ],
        source: "Minn. Stat. § 624.714, subd. 17."
      },
      {
        title: "Employer Policies / Public Employers",
        risk: "Employment and Policy Risk",
        body: [
          "STATUTE: Minn. Stat. § 624.714, subd. 18.",
          "SUMMARY: Minnesota law addresses employer policies restricting carry or possession by employees while acting in the course and scope of employment.",
          "GUIDANCE: Criminal carry legality and employment consequences are separate. Company vehicles, job sites, and government employment settings require separate review."
        ],
        source: "Minn. Stat. § 624.714, subd. 18."
      },
      {
        title: "State Colleges / Universities",
        risk: "Campus Policy Risk",
        body: [
          "STATUTE / SOURCE: Minn. Stat. § 624.714 and Minnesota State Colleges and Universities policy framework.",
          "SUMMARY: Minnesota campus carry can involve state law, institutional policy, employment status, dormitory/residence issues, and event security.",
          "GUIDANCE: Do not assume a permit allows carry everywhere on campus. Verify the institution and location."
        ],
        source: "Minn. Stat. § 624.714; Minnesota State 5.21 firearms policy framework."
      },
      {
        title: "Alcohol / Impairment",
        risk: "Impairment Risk",
        body: [
          "STATUTE / SOURCE: Minnesota weapons and impairment framework.",
          "SUMMARY: Carrying while impaired creates legal, tactical, and evidentiary risk.",
          "GUIDANCE: If drinking or impairment is part of the plan, carrying should not be. Bars, restaurants, stadiums, and festivals should also be checked for posted rules."
        ],
        source: "Minnesota weapons/intoxication framework."
      },
      {
        title: "Federal Property / Post Offices / Public Land",
        risk: "Federal/Public Land Overlay",
        body: [
          "STATUTE / SOURCE: Federal facility, postal property, and public land framework.",
          "SUMMARY: Minnesota carry permission does not override federal buildings, post offices, federal courthouses, secure federal facilities, or federal land/building rules.",
          "GUIDANCE: Check federal property separately. National parks/forests and federal buildings are not the same analysis."
        ],
        source: "Federal facility, postal property, and public land framework."
      },
      {
        title: "Use of Force / Self-Defense",
        risk: "Fact-Specific Legal Risk",
        body: [
          "STATUTE / SOURCE: Minnesota self-defense framework.",
          "SUMMARY: Defensive force must be justified under Minnesota law and the facts. A permit to carry does not decide whether force was lawful.",
          "GUIDANCE: Avoid confrontation, disengage when safe, call 911, identify evidence/witnesses when necessary, request counsel, and avoid detailed statements under stress."
        ],
        source: "Minnesota self-defense law framework."
      }
    ],
    [
      {
        title: "Minnesota Carry Checklist",
        steps: [
          "1. Verify Michigan CPL recognition on Minnesota’s current list.",
          "2. Carry permit and government photo ID.",
          "3. Know disclosure upon request under § 624.714.",
          "4. Check school property under § 609.66, subd. 1d.",
          "5. Check posted premises under § 624.714, subd. 17.",
          "6. Check employer/campus/public building policies.",
          "7. If recognition is uncertain, use lawful transport rules instead of carry."
        ]
      }
    ],
    [
      {
        title: "Minnesota Road Trip / Twin Cities Visit",
        summary: "Minnesota travel often involves schools, campuses, public buildings, posted businesses, stadiums, restaurants, and federal/public land.",
        guidance: [
          "Verify reciprocity first.",
          "Know the disclosure-upon-request rule.",
          "Check posted premises and schools.",
          "Do not assume vehicle carry is lawful without a recognized permit."
        ]
      }
    ],
    [
      "Assuming Minnesota is permitless carry.",
      "Assuming Michigan CPL is honored without checking Minnesota’s current list.",
      "Failing to disclose when asked by a peace officer.",
      "Ignoring school property under § 609.66.",
      "Ignoring posted premises under § 624.714.",
      "Ignoring vehicle transport rules if permit recognition is uncertain.",
      "Assuming campus/employer policies do not matter."
    ],
    [
      "Recognition checked.",
      "Permit and ID carried.",
      "Disclosure-upon-request rule understood.",
      "School property checked.",
      "Vehicle transport checked.",
      "Posted premises checked.",
      "Campus/employer/federal property checked."
    ],
    [
      {
        myth: "Minnesota is close to Michigan, so my CPL should be fine everywhere.",
        reality: "No. Minnesota uses its own permit recognition rules and has specific disclosure, school, posted-premises, and transport requirements."
      }
    ]
  ),


  AZ: makeProfile(
    "Arizona",
    "Law-Backed Ultra Expanded Travel State",
    "Arizona is a high-priority western travel state with broad lawful carry for eligible adults and a state concealed weapons permit program. Arizona is generally permitless for adults who may lawfully possess and carry, but members must understand age limits, police-contact truthfulness, school grounds, alcohol-serving establishments, polling places, prohibited possessors, tribal/federal property, vehicle carry, and defensive display risk.",
    {
      reciprocity: "Michigan CPL should be verified before travel, but Arizona generally recognizes valid permits and also has permitless carry for eligible adults.",
      permitlessCarry: "A.R.S. § 13-3102 is the main misconduct-involving-weapons statute. Arizona broadly permits carry for eligible adults, with restrictions and age limits.",
      concealedCarry: "A.R.S. § 13-3102 and § 13-3112: Arizona issues concealed weapons permits, but eligible adults may have permitless carry authority subject to restrictions.",
      openCarry: "Open carry is generally lawful for eligible adults, but restricted places, tribal/federal property, private property, and police-contact issues still matter.",
      vehicleCarry: "A.R.S. § 13-3102 addresses concealed weapons within immediate control in or on a means of transportation and includes important police-contact requirements.",
      dutyToInform: "Arizona requires accurate answer if a law enforcement officer asks whether the person is carrying a concealed deadly weapon.",
      privateSigns: "Private property owners may restrict firearms and ask a person to leave. Posted alcohol establishments require special caution.",
      forceLaw: "Arizona self-defense law is fact-specific. Defensive force must be legally justified by the circumstances."
    },
    [
      "Arizona is permissive, but not rule-free.",
      "A.R.S. § 13-3102 is a core statute for prohibited conduct, including concealed carry issues, vehicle-related issues, and answering law enforcement accurately when asked.",
      "Arizona schools, alcohol-serving establishments, polling places, federal property, tribal lands, and private property can create carry restrictions.",
      "Arizona travel often involves tribal land, national parks, federal facilities, border areas, and desert recreation; each may change the legal analysis.",
      "Do not assume permitless carry means carry anywhere or ignore posted property."
    ],
    [
      {
        title: "Permitless Carry / Concealed Weapons Framework",
        risk: "Core Carry Rule",
        body: [
          "STATUTE: A.R.S. § 13-3102; A.R.S. § 13-3112.",
          "SUMMARY: Arizona broadly allows eligible adults to carry, and Arizona also maintains a concealed weapons permit program under § 13-3112.",
          "GUIDANCE: Permitless carry does not apply to prohibited possessors, underage persons, restricted locations, tribal/federal property, or situations involving unlawful conduct."
        ],
        source: "A.R.S. § 13-3102; A.R.S. § 13-3112; Arizona DPS concealed weapons permit program."
      },
      {
        title: "Police Contact / Accurate Answer Requirement",
        risk: "Officer Contact Risk",
        body: [
          "STATUTE: A.R.S. § 13-3102.",
          "SUMMARY: Arizona law includes misconduct for failing to accurately answer a law enforcement officer if asked whether the person is carrying a concealed deadly weapon.",
          "GUIDANCE: If asked, answer truthfully and calmly. Keep hands visible and do not reach. Recommended wording: Officer, I am lawfully carrying. How would you like me to proceed?"
        ],
        source: "A.R.S. § 13-3102."
      },
      {
        title: "Under 21 Concealed Carry Risk",
        risk: "Age-Based Restriction",
        body: [
          "STATUTE: A.R.S. § 13-3102.",
          "SUMMARY: Arizona's misconduct statute includes restrictions involving persons under 21 carrying concealed deadly weapons on the person or within immediate control in or on transportation, subject to statutory details and exceptions.",
          "GUIDANCE: Do not assume an 18–20-year-old can concealed carry in Arizona the same way a 21+ eligible adult can."
        ],
        source: "A.R.S. § 13-3102."
      },
      {
        title: "School Grounds",
        risk: "Extreme Risk Area",
        body: [
          "STATUTE: A.R.S. § 13-3102.",
          "SUMMARY: Arizona law restricts firearms on school grounds, subject to statutory exceptions.",
          "GUIDANCE: School buildings, parking areas, school events, and pickup/drop-off situations should be treated as verify-first locations."
        ],
        source: "A.R.S. § 13-3102."
      },
      {
        title: "Alcohol-Serving Establishments",
        risk: "Posted Premises / Alcohol Risk",
        body: [
          "STATUTE: A.R.S. § 13-3102; Arizona liquor/firearms framework.",
          "SUMMARY: Arizona law includes restrictions involving firearms in establishments licensed to serve alcohol and specific treatment of posted premises and permit holders.",
          "GUIDANCE: Bars, restaurants, breweries, events, and posted alcohol establishments require careful checking. Do not consume alcohol while carrying."
        ],
        source: "A.R.S. § 13-3102; Arizona liquor/firearms framework."
      },
      {
        title: "Polling Places and Public Events",
        risk: "Election / Public Gathering Risk",
        body: [
          "STATUTE: A.R.S. § 13-3102 and Arizona election/public-place framework.",
          "SUMMARY: Arizona law includes restrictions related to polling places on election day and certain public locations or events.",
          "GUIDANCE: Voting locations, government-controlled event spaces, and security-screened public events should be checked before entering armed."
        ],
        source: "A.R.S. § 13-3102; Arizona election/public-place framework."
      },
      {
        title: "Tribal Land / Federal Property",
        risk: "Separate Sovereign / Federal Overlay",
        body: [
          "STATUTE / SOURCE: Tribal law and federal facility framework.",
          "SUMMARY: Arizona state carry permission does not automatically control tribal land, federal buildings, post offices, federal courthouses, military installations, or secure federal facilities.",
          "GUIDANCE: Arizona travel often crosses tribal land and federal land. Verify the specific jurisdiction before carrying."
        ],
        source: "Tribal law; federal facility and postal property framework."
      },
      {
        title: "Vehicle Carry",
        risk: "Vehicle / Police Contact Risk",
        body: [
          "STATUTE: A.R.S. § 13-3102.",
          "SUMMARY: Arizona law addresses concealed weapons within immediate control in or on a means of transportation, including age and police-contact issues.",
          "GUIDANCE: Keep hands visible during traffic stops, answer accurately if asked, and do not reach for documents near a firearm without instruction."
        ],
        source: "A.R.S. § 13-3102."
      },
      {
        title: "Prohibited Possessors",
        risk: "Disqualification Risk",
        body: [
          "STATUTE / SOURCE: A.R.S. § 13-3101; A.R.S. § 13-3102.",
          "SUMMARY: Arizona law defines prohibited possessors and criminalizes certain weapons conduct by disqualified persons.",
          "GUIDANCE: Court orders, felony history, domestic violence issues, mental health restrictions, drug-related disqualifiers, and federal prohibitions must be checked before carrying."
        ],
        source: "A.R.S. § 13-3101; A.R.S. § 13-3102."
      },
      {
        title: "Use of Force / Defensive Display",
        risk: "Fact-Specific Legal Risk",
        body: [
          "STATUTE / SOURCE: Arizona justification and criminal-threat framework.",
          "SUMMARY: Defensive force and defensive display must be justified by the facts; displaying to intimidate or win an argument can create criminal exposure.",
          "GUIDANCE: If a defensive display was necessary due to an immediate threat, call 911 first, identify the threat, identify evidence and witnesses, request counsel, and avoid long statements."
        ],
        source: "Arizona justification law framework; Prime Defense aftermath protocol."
      }
    ],
    [
      {
        title: "Arizona Carry Checklist",
        steps: [
          "1. Confirm eligibility and age.",
          "2. Check A.R.S. § 13-3102 restricted conduct.",
          "3. Check school grounds.",
          "4. Check alcohol-serving/posting rules.",
          "5. Check tribal and federal property separately.",
          "6. Know the accurate-answer rule for police contact.",
          "7. Verify vehicle carry before travel."
        ]
      }
    ],
    [
      {
        title: "Traffic Stop in Arizona",
        summary: "Arizona requires accurate answers if law enforcement asks about a concealed deadly weapon.",
        guidance: [
          "Keep hands visible.",
          "Do not reach.",
          "Answer accurately if asked.",
          "Ask how the officer wants you to proceed."
        ]
      },
      {
        title: "Restaurant or Bar",
        summary: "Arizona alcohol-serving establishments can involve posting and permit-related rules.",
        guidance: [
          "Check for signs.",
          "Do not drink while armed.",
          "Leave if asked.",
          "Do not assume permitless carry solves alcohol-location issues."
        ]
      }
    ],
    [
      "Assuming Arizona permitless carry means carry anywhere.",
      "Failing to answer accurately if asked by law enforcement.",
      "Ignoring school grounds.",
      "Ignoring posted alcohol establishments.",
      "Assuming Arizona law controls tribal land or federal property.",
      "Assuming an 18–20-year-old may concealed carry the same as a 21+ adult."
    ],
    [
      "Eligibility and age checked.",
      "A.R.S. § 13-3102 checked.",
      "School grounds checked.",
      "Alcohol/posting rules checked.",
      "Tribal/federal property checked.",
      "Police-contact script ready."
    ],
    [
      {
        myth: "Arizona is permitless, so there are no restrictions.",
        reality: "No. Arizona still has restricted places, age issues, prohibited-person rules, alcohol-location rules, tribal/federal overlays, and police-contact requirements."
      }
    ]
  ),

  CO: makeProfile(
    "Colorado",
    "Law-Backed Ultra Expanded Travel State",
    "Colorado is a high-priority western travel state with a concealed handgun permit system, resident-permit reciprocity limitations, school and college restrictions, magazine limits, and increasing local-law complexity. Michigan travelers must understand that Colorado is not permitless concealed carry and that local restrictions may exist in addition to state law.",
    {
      reciprocity: "Colorado reciprocity must be verified carefully. Colorado generally honors only resident permits from states with reciprocity agreements.",
      permitlessCarry: "No general permitless concealed carry. C.R.S. § 18-12-105 restricts carrying concealed without legal authority.",
      concealedCarry: "Colorado concealed handgun permits are governed by C.R.S. § 18-12-203 and related sections; reciprocity is limited.",
      openCarry: "Open carry may be lawful in many areas, but local restrictions, Denver-area issues, schools, government buildings, and private property matter.",
      vehicleCarry: "Vehicle carry must be analyzed under Colorado concealed/open carry and local-law framework.",
      dutyToInform: "Verify current Colorado police-contact rules. Keep hands visible and answer lawful questions truthfully.",
      privateSigns: "Private property and local rules can restrict carry. Leave immediately if asked.",
      forceLaw: "Colorado self-defense is fact-specific and must be legally justified."
    },
    [
      "Colorado is not permitless concealed carry.",
      "Colorado reciprocity is more limited than many states and may depend on resident permits.",
      "Schools, colleges/universities, public buildings, polling places, private property, and federal lands require separate review.",
      "Colorado has magazine capacity restrictions under state law.",
      "Local ordinances can create traps, especially for travelers who assume statewide uniformity."
    ],
    [
      {
        title: "Concealed Carry Without Permit",
        risk: "Core Carry Rule",
        body: [
          "STATUTE: C.R.S. § 18-12-105.",
          "SUMMARY: Colorado law restricts carrying a concealed weapon without legal authority.",
          "GUIDANCE: Do not treat Colorado as permitless concealed carry. Verify Michigan CPL recognition and whether Colorado honors the user’s specific permit."
        ],
        source: "C.R.S. § 18-12-105."
      },
      {
        title: "Colorado Permit / Reciprocity Framework",
        risk: "Recognition Risk",
        body: [
          "STATUTE / SOURCE: C.R.S. § 18-12-203; Colorado Bureau of Investigation reciprocity guidance.",
          "SUMMARY: Colorado maintains a concealed handgun permit framework and generally honors resident permits from states with reciprocity agreements.",
          "GUIDANCE: Michigan travelers should verify recognition before travel and should not assume nonresident permits are honored."
        ],
        source: "C.R.S. § 18-12-203; Colorado CBI reciprocity guidance."
      },
      {
        title: "Schools / Colleges / Universities",
        risk: "Extreme Risk Area",
        body: [
          "STATUTE: C.R.S. § 18-12-105.5.",
          "SUMMARY: Colorado restricts unlawfully carrying or possessing weapons on school, college, or university grounds, subject to statutory exceptions.",
          "GUIDANCE: K-12 schools, colleges, universities, campus buildings, events, and parking areas require careful review before carrying."
        ],
        source: "C.R.S. § 18-12-105.5."
      },
      {
        title: "Local Restrictions / Denver Warning",
        risk: "Local Law Risk",
        body: [
          "STATUTE / SOURCE: Colorado state and local firearms regulation framework.",
          "SUMMARY: Colorado has local-law complexity, and certain municipalities may regulate aspects of firearms possession or carry.",
          "GUIDANCE: Treat Denver and other local jurisdictions as verify-first areas. Do not assume statewide rules are the only rules."
        ],
        source: "Colorado local firearms regulation framework."
      },
      {
        title: "Magazine Capacity Restriction",
        risk: "Equipment Risk",
        body: [
          "STATUTE: C.R.S. § 18-12-302.",
          "SUMMARY: Colorado restricts large-capacity magazines under state law.",
          "GUIDANCE: Check magazine capacity before travel. Equipment legal in Michigan may create risk in Colorado."
        ],
        source: "C.R.S. § 18-12-302."
      },
      {
        title: "Vehicle Carry",
        risk: "Vehicle / Local Law Risk",
        body: [
          "STATUTE / SOURCE: C.R.S. § 18-12-105 and Colorado vehicle/open carry framework.",
          "SUMMARY: Colorado vehicle carry can differ depending on whether the firearm is concealed, loaded, carried on the person, or stored in the vehicle.",
          "GUIDANCE: Verify vehicle carry before travel, especially if entering Denver or local jurisdictions with special rules."
        ],
        source: "C.R.S. § 18-12-105; Colorado firearms transport framework."
      },
      {
        title: "Public Buildings / Security Screening",
        risk: "Government Facility Risk",
        body: [
          "STATUTE / SOURCE: Colorado restricted-location and public-building framework.",
          "SUMMARY: Public buildings, government facilities, courthouses, and security-screened locations may restrict firearms.",
          "GUIDANCE: Do not approach screening armed. Verify before entering any government building, court facility, or posted public property."
        ],
        source: "Colorado public-building firearms framework."
      },
      {
        title: "Federal Land / National Parks",
        risk: "Federal Overlay",
        body: [
          "STATUTE / SOURCE: Federal facility and public lands framework.",
          "SUMMARY: Colorado has extensive federal land; state carry permission does not override federal buildings, visitor centers, federal courthouses, post offices, or secure facilities.",
          "GUIDANCE: Distinguish outdoor land rules from federal buildings and visitor centers."
        ],
        source: "Federal facility and public lands framework."
      },
      {
        title: "Private Property / Posted Locations",
        risk: "Property Control",
        body: [
          "STATUTE / SOURCE: Colorado property/trespass framework.",
          "SUMMARY: Private property owners may restrict firearms and require people to leave.",
          "GUIDANCE: Posted signs and staff/security instructions should be followed immediately."
        ],
        source: "Colorado property/trespass framework."
      },
      {
        title: "Use of Force / Self-Defense",
        risk: "Fact-Specific Legal Risk",
        body: [
          "STATUTE / SOURCE: Colorado self-defense and defense-of-premises framework.",
          "SUMMARY: Colorado defensive force law is fact-specific and depends on reasonableness, necessity, and the circumstances.",
          "GUIDANCE: Avoid escalation, disengage when safely possible, call 911, identify evidence/witnesses, request counsel, and avoid detailed statements under stress."
        ],
        source: "Colorado self-defense law framework."
      }
    ],
    [
      {
        title: "Colorado Carry Checklist",
        steps: [
          "1. Verify Colorado honors the permit being used.",
          "2. Check C.R.S. § 18-12-105 concealed carry restrictions.",
          "3. Check C.R.S. § 18-12-105.5 schools/colleges.",
          "4. Check magazine capacity under § 18-12-302.",
          "5. Check Denver/local restrictions.",
          "6. Check federal property and national park buildings separately.",
          "7. Check vehicle carry before travel."
        ]
      }
    ],
    [
      {
        title: "Colorado Road Trip",
        summary: "Colorado travel often involves Denver, mountain towns, national parks, college campuses, and local ordinances.",
        guidance: [
          "Verify reciprocity before entering.",
          "Check magazine capacity.",
          "Check Denver/local restrictions.",
          "Separate outdoor public land from federal buildings."
        ]
      }
    ],
    [
      "Assuming Colorado is permitless concealed carry.",
      "Ignoring resident-permit reciprocity limitations.",
      "Ignoring Denver/local rules.",
      "Ignoring magazine capacity limits.",
      "Ignoring schools/college grounds.",
      "Assuming national park land equals federal building permission."
    ],
    [
      "Reciprocity checked.",
      "Concealed carry statute checked.",
      "Schools/colleges checked.",
      "Magazine capacity checked.",
      "Denver/local law checked.",
      "Federal property checked."
    ],
    [
      {
        myth: "Colorado is western and gun-friendly, so my permit automatically works everywhere.",
        reality: "No. Colorado has permit recognition limits, local-law issues, school restrictions, and magazine restrictions."
      }
    ]
  ),

  UT: makeProfile(
    "Utah",
    "Law-Backed Ultra Expanded Travel State",
    "Utah is a high-priority western travel state with permitless carry for qualifying adults and a well-known concealed firearm permit system. Utah is generally friendly to lawful carry, but users must understand age rules, loaded firearm rules, school premises, secure areas, churches/places of worship, private property, vehicles, federal property, and use-of-force realities.",
    {
      reciprocity: "Utah generally recognizes permits and also allows permitless concealed carry for qualifying adults, but Utah law controls while physically in Utah.",
      permitlessCarry: "Utah allows permitless carry for qualifying adults, but age, loaded firearm, school, secure-area, and restricted-person rules still apply.",
      concealedCarry: "Utah concealed firearm permits are governed by Utah Code Title 53, Chapter 5, Part 7, and carry rules are in Utah Code Title 76, Chapter 10.",
      openCarry: "Open carry may be lawful in many circumstances, but loaded/unloaded status, vehicles, schools, secure areas, and private property matter.",
      vehicleCarry: "Utah Code § 76-10-505 addresses loaded firearms in vehicles and on streets, with exceptions for vehicle possession/consent.",
      dutyToInform: "Verify current Utah police-contact rules. Keep hands visible and answer lawful questions truthfully.",
      privateSigns: "Private property and posted/restricted locations can matter. Leave if asked.",
      forceLaw: "Utah self-defense law is fact-specific and must be legally justified."
    },
    [
      "Utah is permissive, but not rule-free.",
      "Loaded firearm rules, school premises, secure areas, and restricted-person laws are key Utah issues.",
      "Utah permits can still matter for reciprocity and for exceptions in certain contexts.",
      "Outdoor recreation, national parks, federal buildings, churches, and universities require separate review.",
      "Do not assume permitless carry eliminates location restrictions."
    ],
    [
      {
        title: "Permitless Carry / Concealed Firearm Framework",
        risk: "Core Carry Rule",
        body: [
          "STATUTE / SOURCE: Utah Code Title 76, Chapter 10; Utah Concealed Firearm Act framework.",
          "SUMMARY: Utah allows permitless carry for qualifying adults, while still issuing concealed firearm permits for reciprocity and other legal advantages.",
          "GUIDANCE: Confirm age, eligibility, restricted-person status, location, loaded status, and whether a permit creates an exception in the specific context."
        ],
        source: "Utah Code Title 76, Chapter 10; Utah Code Title 53, Chapter 5, Part 7."
      },
      {
        title: "Loaded Firearm in Vehicle or on Street",
        risk: "Vehicle / Loaded Carry Rule",
        body: [
          "STATUTE: Utah Code § 76-10-505.",
          "SUMMARY: Utah law regulates carrying loaded firearms in or on vehicles and on streets, with statutory exceptions including lawful possession/consent of the vehicle.",
          "GUIDANCE: Vehicle carry is not just a concealed carry question. Verify loaded status and vehicle authority before relying on permitless carry."
        ],
        source: "Utah Code § 76-10-505."
      },
      {
        title: "School Premises",
        risk: "Extreme Risk Area",
        body: [
          "STATUTE: Utah Code § 76-10-505.5.",
          "SUMMARY: Utah law restricts dangerous weapons and firearms on or about school premises, subject to statutory exceptions.",
          "GUIDANCE: K-12 schools, higher education, school grounds, events, and parking areas require careful review. Do not assume permitless carry solves school premises."
        ],
        source: "Utah Code § 76-10-505.5."
      },
      {
        title: "Persons Exempt / Permit Advantages",
        risk: "Exception Framework",
        body: [
          "STATUTE: Utah Code § 76-10-523.",
          "SUMMARY: Utah law identifies persons exempt from certain weapons laws, including permit-related exceptions and law enforcement categories.",
          "GUIDANCE: A Utah or recognized permit may still matter for specific exceptions even though Utah allows permitless carry."
        ],
        source: "Utah Code § 76-10-523."
      },
      {
        title: "Secure Areas / Airports / Correctional Facilities",
        risk: "Restricted Facility Risk",
        body: [
          "STATUTE / SOURCE: Utah secure-area and federal transportation framework.",
          "SUMMARY: Secure areas of airports, correctional facilities, mental health facilities, law enforcement/courthouse environments, and posted secure areas may restrict carry.",
          "GUIDANCE: Do not approach security screening armed. Verify secure-area rules before entering."
        ],
        source: "Utah secure area and federal transportation framework."
      },
      {
        title: "Churches / Houses of Worship",
        risk: "Notice / Property Control",
        body: [
          "STATUTE / SOURCE: Utah church and private-property firearm framework.",
          "SUMMARY: Utah law includes special treatment for houses of worship and private property notices in certain contexts.",
          "GUIDANCE: Verify church policy before carrying. Do not assume a place of worship allows carry."
        ],
        source: "Utah church/private property firearms framework."
      },
      {
        title: "National Parks / Federal Property",
        risk: "Federal Overlay",
        body: [
          "STATUTE / SOURCE: Federal facility and public lands framework.",
          "SUMMARY: Utah has extensive federal land. State carry permission does not override federal buildings, visitor centers, post offices, courthouses, or secure federal facilities.",
          "GUIDANCE: Distinguish outdoor land rules from buildings, visitor centers, ranger stations, and secure facilities."
        ],
        source: "Federal facility and public lands framework."
      },
      {
        title: "Alcohol / Impairment",
        risk: "Impairment Risk",
        body: [
          "STATUTE / SOURCE: Utah weapons and impairment framework.",
          "SUMMARY: Carrying while impaired or using a firearm while intoxicated can create serious criminal and civil risk.",
          "GUIDANCE: If alcohol or impairing substances are part of the plan, carrying should not be."
        ],
        source: "Utah weapons/intoxication framework."
      },
      {
        title: "Private Property / Posted Locations",
        risk: "Property Control",
        body: [
          "STATUTE / SOURCE: Utah private property and trespass framework.",
          "SUMMARY: Private property owners can control access and may restrict firearms.",
          "GUIDANCE: If posted or instructed to leave, leave immediately. Do not argue with staff/security."
        ],
        source: "Utah private property/trespass framework."
      },
      {
        title: "Use of Force / Self-Defense",
        risk: "Fact-Specific Legal Risk",
        body: [
          "STATUTE / SOURCE: Utah self-defense law framework.",
          "SUMMARY: Utah defensive force law is fact-specific and requires legal justification under the circumstances.",
          "GUIDANCE: Avoid escalation, disengage when safe, call 911, identify evidence/witnesses, request counsel, and avoid detailed statements under stress."
        ],
        source: "Utah self-defense law framework."
      }
    ],
    [
      {
        title: "Utah Carry Checklist",
        steps: [
          "1. Confirm eligibility and age.",
          "2. Check loaded firearm rules under § 76-10-505.",
          "3. Check school premises under § 76-10-505.5.",
          "4. Check whether permit-based exceptions apply under § 76-10-523.",
          "5. Check secure areas and airports.",
          "6. Check church/private property policy.",
          "7. Check federal land/buildings separately."
        ]
      }
    ],
    [
      {
        title: "Utah National Park Trip",
        summary: "Utah travel often involves federal land, visitor centers, trailheads, hotels, and vehicles.",
        guidance: [
          "Separate outdoor federal land from federal buildings.",
          "Check visitor centers and ranger stations.",
          "Check vehicle loaded status.",
          "Secure firearms from unauthorized access."
        ]
      }
    ],
    [
      "Assuming Utah permitless carry means carry anywhere.",
      "Ignoring loaded firearm rules in vehicles/on streets.",
      "Ignoring school premises.",
      "Ignoring church/private property notices.",
      "Assuming national park land means federal building carry is allowed.",
      "Ignoring secure airport areas."
    ],
    [
      "Eligibility and age checked.",
      "Loaded firearm rules checked.",
      "School premises checked.",
      "Permit exceptions checked.",
      "Secure areas checked.",
      "Federal property checked."
    ],
    [
      {
        myth: "Utah is permitless, so there are no rules.",
        reality: "No. Loaded firearm rules, school premises, secure areas, private property, and federal property still matter."
      }
    ]
  ),

  NM: makeProfile(
    "New Mexico",
    "Law-Backed Ultra Expanded Travel State",
    "New Mexico is a high-priority southwestern travel state with a concealed handgun license system and no general permitless concealed carry. Open carry may be lawful for eligible persons, but concealed carry requires a license, and travelers must understand license possession, reciprocity, schools, universities, liquor establishments, vehicles, tribal/federal land, private property, and self-defense issues.",
    {
      reciprocity: "New Mexico reciprocity must be verified through New Mexico DPS. New Mexico law controls while physically in New Mexico.",
      permitlessCarry: "No general permitless concealed handgun carry. New Mexico requires a concealed handgun license for concealed carry.",
      concealedCarry: "NMSA 1978, § 29-19-9 requires the licensee to have the concealed handgun license in possession while carrying concealed.",
      openCarry: "Open carry may be lawful for eligible persons, but prohibited places, private property, tribal land, federal property, and disorderly conduct issues still matter.",
      vehicleCarry: "New Mexico vehicle carry has separate treatment from concealed carry on the person and should be verified before travel.",
      dutyToInform: "Verify current New Mexico police-contact rules. Carry physical license when carrying concealed and answer lawful questions truthfully.",
      privateSigns: "Private property owners may restrict firearms. Leave if asked.",
      forceLaw: "New Mexico self-defense law is fact-specific and should be verified before relying on any summary."
    },
    [
      "New Mexico is not permitless concealed carry.",
      "New Mexico DPS states concealed carry is not permitted without the physical license on your person.",
      "New Mexico has tribal land, federal land, national parks, border areas, and rural travel considerations that can change the legal analysis.",
      "Schools, universities, liquor establishments, and posted private property require special caution.",
      "Reciprocity should be verified directly with New Mexico DPS before travel."
    ],
    [
      {
        title: "Concealed Handgun License Required",
        risk: "Core Carry Rule",
        body: [
          "STATUTE: NMSA 1978, § 29-19-9; New Mexico Concealed Handgun Carry Act.",
          "SUMMARY: New Mexico requires a concealed handgun license for concealed carry, and licensees must have the license in possession while carrying concealed.",
          "GUIDANCE: Do not treat New Mexico as permitless concealed carry. Carry the physical license and photo ID when relying on reciprocity."
        ],
        source: "NMSA 1978, § 29-19-9; New Mexico DPS concealed carry guidance."
      },
      {
        title: "Reciprocity / Recognition",
        risk: "Recognition Risk",
        body: [
          "STATUTE: NMSA 1978, § 29-19-12.",
          "SUMMARY: New Mexico DPS administers reciprocity and recognition of other states’ concealed handgun licenses under the Concealed Handgun Carry Act framework.",
          "GUIDANCE: Verify reciprocity before travel and do not rely on outdated maps."
        ],
        source: "NMSA 1978, § 29-19-12; New Mexico DPS concealed carry licenses."
      },
      {
        title: "Physical License Possession",
        risk: "Documentation Risk",
        body: [
          "STATUTE: NMSA 1978, § 29-19-9.",
          "SUMMARY: A licensee must have the concealed handgun license in possession at all times while carrying a concealed handgun.",
          "GUIDANCE: Do not rely on a photo, email, or memory of the permit number. Carry the physical license."
        ],
        source: "NMSA 1978, § 29-19-9; New Mexico DPS guidance."
      },
      {
        title: "Schools",
        risk: "Extreme Risk Area",
        body: [
          "STATUTE: NMSA 1978, § 30-7-2.1.",
          "SUMMARY: New Mexico restricts unlawful carrying of deadly weapons on school premises, subject to statutory exceptions.",
          "GUIDANCE: School buildings, school grounds, events, and parking areas should be treated as verify-first locations."
        ],
        source: "NMSA 1978, § 30-7-2.1."
      },
      {
        title: "University Premises",
        risk: "Higher Education Risk",
        body: [
          "STATUTE: NMSA 1978, § 30-7-2.4.",
          "SUMMARY: New Mexico restricts carrying firearms on university premises, subject to statutory exceptions.",
          "GUIDANCE: Treat college/university campuses, events, buildings, and parking areas as verify-first locations."
        ],
        source: "NMSA 1978, § 30-7-2.4."
      },
      {
        title: "Liquor Establishments / Alcohol",
        risk: "Alcohol Location Risk",
        body: [
          "STATUTE: NMSA 1978, § 30-7-3 and New Mexico alcohol/firearms framework.",
          "SUMMARY: New Mexico restricts firearms in certain establishments licensed to dispense alcoholic beverages, subject to exceptions.",
          "GUIDANCE: Bars, restaurants, breweries, casinos, resorts, and events with alcohol require careful checking. Do not drink while carrying."
        ],
        source: "NMSA 1978, § 30-7-3; New Mexico alcohol/firearms framework."
      },
      {
        title: "One Concealed Handgun Limitation / License Scope",
        risk: "License Scope Risk",
        body: [
          "STATUTE / SOURCE: New Mexico Administrative Code concealed handgun carry rules.",
          "SUMMARY: New Mexico license rules include scope and carry limitations that may affect how many concealed handguns may be carried and what is covered by the license.",
          "GUIDANCE: Verify license scope before carrying multiple concealed handguns or non-handgun weapons."
        ],
        source: "N.M. Admin. Code concealed handgun carry rules; New Mexico DPS guidance."
      },
      {
        title: "Vehicle Carry",
        risk: "Vehicle / Transport Risk",
        body: [
          "STATUTE / SOURCE: New Mexico firearms and vehicle carry framework.",
          "SUMMARY: New Mexico vehicle carry may be treated differently from concealed carry on the person.",
          "GUIDANCE: Verify vehicle carry rules before travel. Keep hands visible during police contact and do not reach near a firearm without instruction."
        ],
        source: "New Mexico vehicle carry/firearms framework."
      },
      {
        title: "Tribal Land / Federal Property",
        risk: "Separate Jurisdiction Overlay",
        body: [
          "STATUTE / SOURCE: Tribal law and federal facility/public lands framework.",
          "SUMMARY: New Mexico state carry permission does not automatically control tribal land, federal buildings, post offices, military installations, federal courthouses, or secure federal facilities.",
          "GUIDANCE: New Mexico travel often crosses tribal and federal land. Verify the specific jurisdiction before carrying."
        ],
        source: "Tribal law; federal facility and public lands framework."
      },
      {
        title: "Use of Force / Self-Defense",
        risk: "Fact-Specific Legal Risk",
        body: [
          "STATUTE / SOURCE: New Mexico self-defense law framework.",
          "SUMMARY: Defensive force must be legally justified under the facts and circumstances.",
          "GUIDANCE: Avoid escalation, disengage when safe, call 911, identify evidence/witnesses, request counsel, and avoid detailed statements under stress."
        ],
        source: "New Mexico self-defense law framework."
      }
    ],
    [
      {
        title: "New Mexico Carry Checklist",
        steps: [
          "1. Verify reciprocity with New Mexico DPS.",
          "2. Carry physical concealed handgun license.",
          "3. Check school premises under § 30-7-2.1.",
          "4. Check university premises under § 30-7-2.4.",
          "5. Check liquor establishments under § 30-7-3.",
          "6. Check tribal and federal land separately.",
          "7. Verify vehicle carry before travel."
        ]
      }
    ],
    [
      {
        title: "Southwest Road Trip",
        summary: "New Mexico travel often involves tribal land, federal land, parks, casinos, hotels, and long vehicle routes.",
        guidance: [
          "Verify reciprocity first.",
          "Carry physical license.",
          "Check tribal/federal property.",
          "Check alcohol/casino locations."
        ]
      }
    ],
    [
      "Assuming New Mexico is permitless concealed carry.",
      "Failing to carry the physical license.",
      "Ignoring schools and university premises.",
      "Ignoring liquor establishment rules.",
      "Assuming state law controls tribal land.",
      "Assuming national park land equals federal building permission."
    ],
    [
      "Reciprocity checked with DPS.",
      "Physical license carried.",
      "Schools checked.",
      "Universities checked.",
      "Liquor establishments checked.",
      "Tribal/federal property checked."
    ],
    [
      {
        myth: "New Mexico open carry means concealed carry is permitless too.",
        reality: "No. New Mexico requires a concealed handgun license for concealed carry."
      }
    ]
  ),

  WY: makeProfile(
    "Wyoming",
    "Law-Backed Ultra Expanded Travel State",
    "Wyoming is a permissive carry state that allows permitless concealed carry for U.S. residents who may legally possess firearms, but travelers must still understand eligibility, restricted locations, schools, universities/campus rules, vehicles, federal land, national parks, private property, and self-defense realities.",
    {
      reciprocity: "Michigan CPL recognition should be verified, but Wyoming also allows permitless concealed carry for qualifying U.S. residents.",
      permitlessCarry: "Wyo. Stat. § 6-8-104 and Wyoming DCI guidance: Wyoming allows qualifying U.S. residents to carry concealed without a permit.",
      concealedCarry: "Wyoming maintains a concealed firearm permit system under § 6-8-104, but permitless carry may apply to eligible U.S. residents.",
      openCarry: "Open carry may be lawful for eligible persons, but restricted places, private property, federal property, and police contact still matter.",
      vehicleCarry: "Vehicle carry must be analyzed under Wyoming concealed/open carry and restricted-location rules.",
      dutyToInform: "Verify current Wyoming police-contact rules. Keep hands visible and answer lawful questions truthfully.",
      privateSigns: "Private property owners may restrict firearms. Leave if asked.",
      forceLaw: "Wyoming self-defense law is fact-specific and must be legally justified."
    },
    [
      "Wyoming is permissive, but not rule-free.",
      "Wyoming DCI states that effective July 1, 2021, any U.S. resident legally allowed to possess firearms may carry concealed in Wyoming without a concealed firearms permit.",
      "A Wyoming permit may still matter for reciprocity outside Wyoming.",
      "Federal land, national parks, visitor centers, post offices, schools, universities, and private property require separate review.",
      "Outdoor recreation does not eliminate secure-building or federal-facility restrictions."
    ],
    [
      {
        title: "Permitless Concealed Carry",
        risk: "Core Eligibility Rule",
        body: [
          "STATUTE: Wyo. Stat. § 6-8-104; Wyoming DCI guidance.",
          "SUMMARY: Wyoming allows qualifying U.S. residents who are legally allowed to possess firearms to carry concealed without a concealed firearms permit.",
          "GUIDANCE: Confirm eligibility, residency/status, prohibited-person status, age, and restricted locations before carrying."
        ],
        source: "Wyo. Stat. § 6-8-104; Wyoming DCI CFP FAQ."
      },
      {
        title: "Concealed Firearm Permit / Reciprocity Context",
        risk: "License / Travel Rule",
        body: [
          "STATUTE: Wyo. Stat. § 6-8-104.",
          "SUMMARY: Wyoming still issues concealed firearm permits and recognizes permits under the statutory framework.",
          "GUIDANCE: Even if permitless carry applies in Wyoming, a permit can matter when traveling to other states."
        ],
        source: "Wyo. Stat. § 6-8-104."
      },
      {
        title: "Eligibility / Prohibited Persons",
        risk: "Disqualification Risk",
        body: [
          "STATUTE: Wyo. Stat. § 6-8-104 and federal prohibited-person framework.",
          "SUMMARY: Permitless carry only helps people who may legally possess firearms and are not disqualified.",
          "GUIDANCE: Criminal history, protection orders, domestic violence issues, controlled-substance issues, mental health adjudications, and federal prohibitions should be checked before carrying."
        ],
        source: "Wyo. Stat. § 6-8-104; federal prohibited-person framework."
      },
      {
        title: "Schools / Universities / Campus Rules",
        risk: "Extreme Risk Area",
        body: [
          "STATUTE / SOURCE: Wyoming school and campus carry framework; Wyo. Stat. § 6-8-104 references.",
          "SUMMARY: Wyoming schools, university facilities, and campus rules can involve specific restrictions and exceptions.",
          "GUIDANCE: Check K-12 schools, universities, events, buildings, parking, and posted campus rules before carrying."
        ],
        source: "Wyoming school/campus carry framework; University of Wyoming campus carry guidance."
      },
      {
        title: "Federal Land / National Parks",
        risk: "Federal Overlay",
        body: [
          "STATUTE / SOURCE: Federal facility and public lands framework.",
          "SUMMARY: Wyoming has extensive federal land and national parks. State carry permission does not override federal buildings, visitor centers, post offices, federal courthouses, or secure facilities.",
          "GUIDANCE: Distinguish outdoor land from federal buildings and visitor centers. Yellowstone/Grand Teton travel requires careful building-by-building awareness."
        ],
        source: "Federal facility and public lands framework."
      },
      {
        title: "Vehicle Carry",
        risk: "Road Trip / Wildlife Area Risk",
        body: [
          "STATUTE / SOURCE: Wyo. Stat. § 6-8-104 and Wyoming vehicle/firearms framework.",
          "SUMMARY: Vehicle carry may be lawful for eligible persons but still interacts with restricted locations, federal lands, wildlife/hunting rules, and police contact.",
          "GUIDANCE: Keep hands visible during traffic stops and check DNR/game rules when hunting, camping, or transporting firearms in the field."
        ],
        source: "Wyo. Stat. § 6-8-104; Wyoming vehicle/firearms framework."
      },
      {
        title: "Private Property / Posted Locations",
        risk: "Property Control",
        body: [
          "STATUTE / SOURCE: Wyoming property/trespass framework.",
          "SUMMARY: Private property owners may control access and restrict firearms.",
          "GUIDANCE: If posted or asked to leave, leave immediately. Ranches, lodges, events, and private recreation properties may have their own rules."
        ],
        source: "Wyoming property/trespass framework."
      },
      {
        title: "Alcohol / Impairment",
        risk: "Impairment Risk",
        body: [
          "STATUTE / SOURCE: Wyoming weapons and intoxication framework.",
          "SUMMARY: Carrying while impaired creates legal, tactical, and evidentiary risk.",
          "GUIDANCE: If drinking or impairing substances are part of the plan, carrying should not be."
        ],
        source: "Wyoming weapons/intoxication framework."
      },
      {
        title: "Use of Force / Self-Defense",
        risk: "Fact-Specific Legal Risk",
        body: [
          "STATUTE / SOURCE: Wyoming self-defense law framework.",
          "SUMMARY: Defensive force must be justified under the facts and applicable Wyoming law.",
          "GUIDANCE: Avoid escalation, disengage when safe, call 911, identify evidence/witnesses, request counsel, and avoid detailed statements under stress."
        ],
        source: "Wyoming self-defense law framework."
      }
    ],
    [
      {
        title: "Wyoming Carry Checklist",
        steps: [
          "1. Confirm eligibility and prohibited-person status.",
          "2. Check Wyo. Stat. § 6-8-104.",
          "3. Check school/campus rules.",
          "4. Check federal land/buildings separately.",
          "5. Check private property and lodges/events.",
          "6. Check hunting/DNR rules if outdoors.",
          "7. Plan safe vehicle storage."
        ]
      }
    ],
    [
      {
        title: "Yellowstone / Grand Teton Trip",
        summary: "Wyoming travel often involves federal land, visitor centers, hotels, vehicles, and outdoor recreation.",
        guidance: [
          "Separate park land from federal buildings.",
          "Check visitor centers and ranger stations.",
          "Secure firearms in vehicles/hotels.",
          "Check hunting and wildlife rules separately."
        ]
      }
    ],
    [
      "Assuming Wyoming permitless carry means carry anywhere.",
      "Ignoring federal buildings in national parks.",
      "Ignoring campus/school rules.",
      "Ignoring hunting/DNR rules.",
      "Ignoring private lodge/event property.",
      "Assuming a permit is useless just because Wyoming is permitless."
    ],
    [
      "Eligibility checked.",
      "§ 6-8-104 checked.",
      "School/campus rules checked.",
      "Federal property checked.",
      "Private property checked.",
      "Vehicle/outdoor rules checked."
    ],
    [
      {
        myth: "Wyoming is permitless, so a permit never matters.",
        reality: "No. Permitless carry may apply inside Wyoming, but a permit can still matter for reciprocity and specific exceptions outside Wyoming."
      }
    ]
  ),

  MT: makeProfile(
    "Montana",
    "Law-Backed Ultra Expanded Travel State",
    "Montana is a permissive carry state with permitless concealed carry, but members must still understand school buildings, local public-building authority, private property, federal land, national parks, tribal land, vehicles, alcohol/impairment, and self-defense realities. Montana is especially important for travelers because outdoor recreation and federal/public lands can create jurisdictional confusion.",
    {
      reciprocity: "Michigan CPL recognition should be verified, but Montana also has permitless concealed carry for eligible persons.",
      permitlessCarry: "MCA § 45-8-316 and Montana carry framework: Montana no longer generally requires a permit for eligible persons to carry concealed, subject to restrictions.",
      concealedCarry: "Montana still issues permits for reciprocity and certain legal advantages, but permitless carry may apply inside Montana.",
      openCarry: "Open carry may be lawful for eligible persons, but school buildings, publicly owned buildings, private property, federal/tribal land, and conduct still matter.",
      vehicleCarry: "Vehicle carry must be analyzed with Montana carry rules, school/property restrictions, federal/tribal land, and hunting/outdoor rules.",
      dutyToInform: "Verify current Montana police-contact rules. Keep hands visible and answer lawful questions truthfully.",
      privateSigns: "Private property owners may restrict firearms. Leave immediately if asked.",
      forceLaw: "Montana self-defense law is fact-specific and must be legally justified."
    },
    [
      "Montana is permissive, but not rule-free.",
      "MCA § 45-8-361 restricts weapons in school buildings, subject to exceptions.",
      "MCA § 45-8-351 addresses local-government regulation and public-building authority.",
      "Montana travel often involves national parks, federal lands, tribal lands, hunting, camping, lodges, and vehicles.",
      "Federal/tribal property and school buildings are the most important carry traps for travelers."
    ],
    [
      {
        title: "Permitless Concealed Carry",
        risk: "Core Carry Rule",
        body: [
          "STATUTE: MCA § 45-8-316; Montana carry framework.",
          "SUMMARY: Montana no longer generally requires a permit for eligible persons to carry concealed, subject to restrictions and exceptions.",
          "GUIDANCE: Confirm eligibility and restricted locations. Permitless carry does not override school buildings, private property, public-building rules, federal property, or tribal land."
        ],
        source: "MCA § 45-8-316; Montana carry framework."
      },
      {
        title: "Permit / Reciprocity Context",
        risk: "Travel License Rule",
        body: [
          "STATUTE / SOURCE: Montana concealed weapon permit framework.",
          "SUMMARY: Montana still issues concealed weapon permits that may matter for reciprocity outside Montana and certain legal advantages.",
          "GUIDANCE: A permit can still be useful even in a permitless carry state. Do not discard permit considerations for multi-state travel."
        ],
        source: "Montana concealed weapon permit framework."
      },
      {
        title: "School Buildings",
        risk: "Extreme Risk Area",
        body: [
          "STATUTE: MCA § 45-8-361.",
          "SUMMARY: Montana restricts possession, carrying, or storage of weapons in school buildings, subject to exceptions.",
          "GUIDANCE: K-12 school buildings and school activities should be treated as hard verify-first areas. Do not assume permitless carry applies inside a school building."
        ],
        source: "MCA § 45-8-361."
      },
      {
        title: "Local Public Buildings / Preemption",
        risk: "Public Building Risk",
        body: [
          "STATUTE: MCA § 45-8-351.",
          "SUMMARY: Montana restricts local government firearms regulation but allows certain local authority involving discharge and carrying in publicly owned and occupied buildings under local jurisdiction.",
          "GUIDANCE: City/county buildings, parks, public assemblies, and posted public facilities require verification."
        ],
        source: "MCA § 45-8-351."
      },
      {
        title: "Federal Land / National Parks",
        risk: "Federal Overlay",
        body: [
          "STATUTE / SOURCE: Federal facility and public lands framework.",
          "SUMMARY: Montana has extensive federal land and national parks. State carry permission does not override federal buildings, visitor centers, post offices, federal courthouses, or secure federal facilities.",
          "GUIDANCE: Glacier and Yellowstone-region travel requires awareness of federal building boundaries, visitor centers, ranger stations, and park facilities."
        ],
        source: "Federal facility and public lands framework."
      },
      {
        title: "Tribal Land",
        risk: "Separate Sovereign Overlay",
        body: [
          "STATUTE / SOURCE: Tribal law framework.",
          "SUMMARY: Montana state carry rules do not automatically control tribal lands or tribal facilities.",
          "GUIDANCE: Verify tribal law before carrying on reservations, tribal casinos, tribal offices, and tribal events."
        ],
        source: "Tribal law framework."
      },
      {
        title: "Vehicle Carry / Outdoor Travel",
        risk: "Vehicle / Hunting / Recreation Risk",
        body: [
          "STATUTE / SOURCE: Montana carry, hunting, and vehicle framework.",
          "SUMMARY: Vehicle carry may be lawful for eligible persons, but hunting, wildlife, public land, private land, tribal land, and federal facility rules may change the analysis.",
          "GUIDANCE: Check Montana FWP/hunting rules when carrying while hunting, camping, fishing, boating, or crossing public/private land."
        ],
        source: "Montana carry and outdoor recreation framework."
      },
      {
        title: "Private Property / Posted Locations",
        risk: "Property Control",
        body: [
          "STATUTE / SOURCE: Montana property/trespass framework.",
          "SUMMARY: Private property owners may control access and restrict firearms.",
          "GUIDANCE: If posted or asked to leave, leave immediately. Ranches, lodges, outfitters, hotels, private events, and leased lands may have their own rules."
        ],
        source: "Montana property/trespass framework."
      },
      {
        title: "Alcohol / Impairment",
        risk: "Impairment Risk",
        body: [
          "STATUTE / SOURCE: Montana weapons and impairment framework.",
          "SUMMARY: Carrying while impaired can create legal, tactical, and evidentiary risk.",
          "GUIDANCE: If alcohol or impairing substances are part of the plan, carrying should not be."
        ],
        source: "Montana weapons/intoxication framework."
      },
      {
        title: "Use of Force / Self-Defense",
        risk: "Fact-Specific Legal Risk",
        body: [
          "STATUTE / SOURCE: Montana self-defense law framework.",
          "SUMMARY: Defensive force must be legally justified under the facts and applicable Montana law.",
          "GUIDANCE: Avoid escalation, disengage when safe, call 911, identify evidence/witnesses, request counsel, and avoid detailed statements under stress."
        ],
        source: "Montana self-defense law framework."
      }
    ],
    [
      {
        title: "Montana Carry Checklist",
        steps: [
          "1. Confirm eligibility.",
          "2. Check MCA § 45-8-316 carry framework.",
          "3. Check school buildings under § 45-8-361.",
          "4. Check public buildings/local rules under § 45-8-351.",
          "5. Check federal and tribal land separately.",
          "6. Check private property and lodge/event rules.",
          "7. Check hunting/outdoor rules if applicable."
        ]
      }
    ],
    [
      {
        title: "Glacier / Yellowstone Region Travel",
        summary: "Montana travel often involves federal land, tribal land, park facilities, lodges, vehicles, and outdoor recreation.",
        guidance: [
          "Separate outdoor land from federal buildings.",
          "Verify tribal land rules.",
          "Check school/public building rules.",
          "Check hunting/outdoor regulations."
        ]
      }
    ],
    [
      "Assuming Montana permitless carry means carry anywhere.",
      "Ignoring school buildings under § 45-8-361.",
      "Ignoring public building/local authority under § 45-8-351.",
      "Assuming state law controls tribal land.",
      "Assuming national park land equals visitor center permission.",
      "Ignoring hunting/outdoor rules."
    ],
    [
      "Eligibility checked.",
      "Carry framework checked.",
      "School buildings checked.",
      "Public buildings/local rules checked.",
      "Federal/tribal property checked.",
      "Outdoor/hunting rules checked."
    ],
    [
      {
        myth: "Montana permitless carry means there are no restrictions.",
        reality: "No. School buildings, public buildings, private property, federal land, tribal land, and outdoor rules still matter."
      }
    ]
  ),

  ID: makeProfile(
    "Idaho",
    "Law-Backed Ultra Expanded Travel State",
    "Idaho is a generally permitless-carry state for eligible adults, but Idaho still has important restrictions involving school property, courthouses, jails, private property, alcohol/impairment, tribal land, federal property, vehicles, and enhanced-license reciprocity. Michigan members should not treat Idaho as rule-free simply because it is firearm-friendly.",
    {
      reciprocity: "Michigan CPL recognition should be verified before travel. Idaho also allows permitless carry for eligible persons under Idaho Code § 18-3302.",
      permitlessCarry: "Idaho Code § 18-3302: eligible persons may carry concealed without a license in many circumstances, subject to statutory restrictions.",
      concealedCarry: "Idaho recognizes concealed carry licenses and also has standard and enhanced concealed weapon license systems.",
      openCarry: "Open carry is generally lawful for eligible persons, but prohibited places, private property, and public conduct still matter.",
      vehicleCarry: "Vehicle carry must still comply with Idaho law, school restrictions, private property, and federal/tribal land overlays.",
      dutyToInform: "Verify current Idaho police-contact rules. Keep hands visible and answer lawful questions truthfully.",
      privateSigns: "Private property owners may restrict firearms. Leave immediately if asked.",
      forceLaw: "Idaho self-defense law is fact-specific and must be evaluated under the circumstances."
    },
    [
      "Idaho is generally permissive, but not unrestricted.",
      "Schools, courthouses, jails, juvenile detention facilities, private property, federal buildings, and tribal land require separate analysis.",
      "An Idaho enhanced license can matter for reciprocity outside Idaho, but permitless carry inside Idaho does not automatically travel to other states.",
      "Federal school-zone law may still matter, especially for unlicensed carry near schools.",
      "Outdoor travel can involve state land, federal land, tribal land, hunting rules, and private ranch/property restrictions."
    ],
    [
      {
        title: "Permitless Concealed Carry",
        risk: "Core Eligibility Rule",
        body: [
          "STATUTE: Idaho Code § 18-3302.",
          "SUMMARY: Idaho law includes exceptions to the concealed-weapon license requirement and generally permits concealed carry by eligible persons under the statutory framework.",
          "GUIDANCE: Do not teach Idaho as no-rules carry. Eligibility, age, prohibited-person status, prohibited locations, school zones, private property, and federal/tribal overlays still matter."
        ],
        source: "Idaho Code § 18-3302."
      },
      {
        title: "Standard and Enhanced Concealed Weapon Licenses",
        risk: "License / Reciprocity Context",
        body: [
          "STATUTE: Idaho Code § 18-3302 and § 18-3302K.",
          "SUMMARY: Idaho has concealed weapon license provisions, including enhanced license provisions that may affect reciprocity outside Idaho.",
          "GUIDANCE: Even in a permitless state, a license can matter for travel, reciprocity, federal school-zone exceptions, and documentation."
        ],
        source: "Idaho Code § 18-3302; Idaho Code § 18-3302K."
      },
      {
        title: "Schools / Federal School Zone Overlay",
        risk: "Extreme Risk Area",
        body: [
          "STATUTE / SOURCE: Idaho school weapons framework; federal Gun-Free School Zones Act.",
          "SUMMARY: School property and school-zone areas are high-risk locations. Federal law can add restrictions separate from Idaho carry permission.",
          "GUIDANCE: Do not assume permitless carry resolves school-zone issues. School pickup, events, parking lots, and school-adjacent travel should be verify-first situations."
        ],
        source: "Idaho school weapons framework; 18 U.S.C. § 922(q)."
      },
      {
        title: "Courthouses / Jails / Detention Facilities",
        risk: "Hard Stop Area",
        body: [
          "STATUTE / SOURCE: Idaho prohibited-place and facility framework.",
          "SUMMARY: Courthouses, jails, juvenile detention facilities, correctional facilities, and secure government facilities may restrict weapons.",
          "GUIDANCE: Do not approach screening or controlled facility entrances armed unless a clear legal exception applies."
        ],
        source: "Idaho weapons/prohibited-place framework."
      },
      {
        title: "Private Property / Posted Locations",
        risk: "Property Control",
        body: [
          "STATUTE / SOURCE: Idaho property/trespass framework.",
          "SUMMARY: Private property owners and businesses may restrict firearms and require people to leave.",
          "GUIDANCE: If posted or asked to leave, leave immediately. Do not argue with staff, security, landowners, or event personnel."
        ],
        source: "Idaho property/trespass framework."
      },
      {
        title: "Federal / Tribal / Outdoor Land",
        risk: "Land Jurisdiction Risk",
        body: [
          "STATUTE / SOURCE: Federal facility, national park, tribal, and public land framework.",
          "SUMMARY: Idaho carry permission does not override federal buildings, tribal law, national park facility rules, visitor centers, post offices, or private ranch/property restrictions.",
          "GUIDANCE: Separate the land you are on from the building you enter. Federal land, tribal land, and private land can change the legal analysis."
        ],
        source: "Federal facility framework; tribal law framework; Idaho public/private land framework."
      },
      {
        title: "Alcohol / Impairment",
        risk: "Impairment Risk",
        body: [
          "STATUTE / SOURCE: Idaho weapons and impairment framework.",
          "SUMMARY: Carrying while intoxicated or impaired can create legal, tactical, and evidentiary risk.",
          "GUIDANCE: If alcohol or impairing substances are part of the plan, carrying should not be."
        ],
        source: "Idaho weapons/intoxication framework."
      },
      {
        title: "Use of Force / Self-Defense",
        risk: "Fact-Specific Legal Risk",
        body: [
          "STATUTE / SOURCE: Idaho self-defense law framework.",
          "SUMMARY: Defensive force must be legally justified under the facts and applicable Idaho law.",
          "GUIDANCE: Avoid escalation, disengage when safe, call 911, identify evidence/witnesses, request counsel, and avoid detailed statements under stress."
        ],
        source: "Idaho self-defense law framework."
      }
    ],
    [
      {
        title: "Idaho Carry Checklist",
        steps: [
          "1. Confirm eligibility under Idaho Code § 18-3302.",
          "2. Check whether a license is needed for reciprocity or federal school-zone purposes.",
          "3. Check school property and school-zone issues.",
          "4. Check courthouses, jails, and secure government facilities.",
          "5. Check private property, tribal land, federal buildings, and outdoor land rules.",
          "6. Avoid carry while impaired."
        ]
      }
    ],
    [
      {
        title: "Idaho Outdoor / Mountain Travel",
        summary: "Idaho travel often involves highways, parks, federal land, tribal land, private ranches, and outdoor recreation.",
        guidance: [
          "Verify the jurisdiction of the land and building.",
          "Check school-zone issues near towns.",
          "Check private property and ranch/lodge policies.",
          "Do not assume federal or tribal property follows Idaho law."
        ]
      }
    ],
    [
      "Assuming Idaho permitless carry means carry anywhere.",
      "Ignoring federal school-zone issues.",
      "Ignoring courthouses, jails, and detention facilities.",
      "Assuming state law controls tribal land.",
      "Assuming national park land equals visitor center permission.",
      "Ignoring private property and ranch/lodge rules."
    ],
    [
      "Eligibility checked.",
      "License/reciprocity needs checked.",
      "School-zone issues checked.",
      "Court/jail/government facilities checked.",
      "Federal/tribal/private property checked.",
      "Outdoor/hunting rules checked."
    ],
    [
      {
        myth: "Idaho is permitless, so there are no restrictions.",
        reality: "No. Idaho is permissive, but schools, federal property, tribal land, private property, jails, courts, and impairment rules still matter."
      }
    ]
  ),

  ND: makeProfile(
    "North Dakota",
    "Law-Backed Ultra Expanded Travel State",
    "North Dakota allows constitutional concealed carry for eligible individuals within North Dakota, but the state still has important requirements involving eligibility, identification, police notification, restricted locations, school property, private property, vehicles, and reciprocity outside North Dakota.",
    {
      reciprocity: "Michigan CPL recognition should be verified before travel. North Dakota also has constitutional concealed carry for eligible individuals within North Dakota.",
      permitlessCarry: "N.D. constitutional carry allows concealed carry by eligible individuals within North Dakota, subject to identification and eligibility requirements.",
      concealedCarry: "N.D.C.C. Chapter 62.1-04 governs concealed weapons and concealed weapon licenses.",
      openCarry: "Open carry and firearm possession must still comply with North Dakota weapons law and restricted-location rules.",
      vehicleCarry: "Vehicle carry must be analyzed under North Dakota weapons law and police-contact requirements.",
      dutyToInform: "North Dakota constitutional carry has a law-enforcement notification requirement for permitless concealed carry.",
      privateSigns: "Private property owners may restrict firearms. Leave if asked.",
      forceLaw: "North Dakota self-defense law is fact-specific."
    },
    [
      "North Dakota constitutional carry is within North Dakota only and does not create reciprocity in other states.",
      "The Attorney General warns that a concealed weapon license is needed for reciprocity outside North Dakota.",
      "Eligible permitless carriers must understand identification and law-enforcement notification requirements.",
      "Schools, courts, posted private property, federal property, and tribal property require separate analysis.",
      "A North Dakota license may still matter for travel even if permitless carry exists inside North Dakota."
    ],
    [
      {
        title: "Constitutional Concealed Carry",
        risk: "Core Eligibility Rule",
        body: [
          "STATUTE / SOURCE: N.D.C.C. Chapter 62.1-04; North Dakota Attorney General constitutional carry guidance.",
          "SUMMARY: North Dakota allows constitutional concealed carry by eligible individuals within North Dakota, subject to statutory requirements.",
          "GUIDANCE: Constitutional carry does not apply outside North Dakota and does not replace a license for reciprocity in other states."
        ],
        source: "N.D.C.C. Chapter 62.1-04; North Dakota Attorney General constitutional carry guidance."
      },
      {
        title: "Identification and Police Notification",
        risk: "Police Contact Requirement",
        body: [
          "STATUTE / SOURCE: N.D.C.C. § 62.1-04-02 and Attorney General guidance.",
          "SUMMARY: North Dakota permitless concealed carry requires eligible individuals to carry qualifying identification and notify law enforcement during stops under the constitutional carry framework.",
          "GUIDANCE: Keep hands visible and disclose calmly if stopped while carrying under permitless carry. Do not reach for ID or the firearm until instructed."
        ],
        source: "N.D.C.C. § 62.1-04-02; North Dakota Attorney General guidance."
      },
      {
        title: "Concealed Weapon License / Reciprocity",
        risk: "Travel Outside State",
        body: [
          "STATUTE: N.D.C.C. § 62.1-04-03.",
          "SUMMARY: North Dakota issues concealed weapon licenses, including Class 1 and Class 2 licenses, under the statutory framework.",
          "GUIDANCE: A license may be necessary for reciprocity outside North Dakota. Permitless carry inside North Dakota does not travel with the user."
        ],
        source: "N.D.C.C. § 62.1-04-03; North Dakota Attorney General concealed weapon license guidance."
      },
      {
        title: "Schools / Educational Property",
        risk: "Extreme Risk Area",
        body: [
          "STATUTE / SOURCE: North Dakota school weapons framework; federal school-zone framework.",
          "SUMMARY: Schools and school-related property are high-risk areas under state and federal law.",
          "GUIDANCE: Do not rely on a short reciprocity or permitless carry summary for school pickup, events, or campus areas. Verify before entering armed."
        ],
        source: "North Dakota weapons/school framework; 18 U.S.C. § 922(q)."
      },
      {
        title: "Restricted Locations / Government Facilities",
        risk: "Location Restriction",
        body: [
          "STATUTE / SOURCE: North Dakota weapons and facility framework.",
          "SUMMARY: Courts, jails, law-enforcement facilities, government buildings, schools, federal property, and tribal property may restrict firearms.",
          "GUIDANCE: Treat controlled facilities and screened entrances as verify-first locations."
        ],
        source: "North Dakota weapons/prohibited-place framework."
      },
      {
        title: "Private Property / Posted Locations",
        risk: "Property Control",
        body: [
          "STATUTE / SOURCE: North Dakota property/trespass framework.",
          "SUMMARY: Private property owners may restrict firearms and require armed persons to leave.",
          "GUIDANCE: If posted or asked to leave, leave immediately."
        ],
        source: "North Dakota property/trespass framework."
      },
      {
        title: "Tribal Land / Federal Property",
        risk: "Jurisdiction Overlay",
        body: [
          "STATUTE / SOURCE: Federal facility, postal property, tribal law, and North Dakota public land framework.",
          "SUMMARY: North Dakota carry permission does not override federal buildings, post offices, tribal law, or other jurisdictional restrictions.",
          "GUIDANCE: Verify tribal law and federal rules before carrying on reservations, tribal casinos, federal buildings, or posted federal property."
        ],
        source: "Federal facility framework; tribal law framework."
      },
      {
        title: "Use of Force / Self-Defense",
        risk: "Fact-Specific Legal Risk",
        body: [
          "STATUTE / SOURCE: North Dakota self-defense law framework.",
          "SUMMARY: Defensive force must be legally justified under the facts and applicable North Dakota law.",
          "GUIDANCE: Avoid escalation, disengage when safe, call 911, identify evidence/witnesses, request counsel, and avoid detailed statements under stress."
        ],
        source: "North Dakota self-defense law framework."
      }
    ],
    [
      {
        title: "North Dakota Carry Checklist",
        steps: [
          "1. Confirm eligibility for constitutional carry.",
          "2. Carry qualifying ID if relying on permitless carry.",
          "3. Know the law-enforcement notification rule.",
          "4. Check schools, courts, jails, and government facilities.",
          "5. Check tribal and federal property separately.",
          "6. Remember permitless carry does not create out-of-state reciprocity."
        ]
      }
    ],
    [
      {
        title: "Rural / Tribal Land Travel",
        summary: "North Dakota travel may involve rural highways, tribal land, federal facilities, and long-distance vehicle travel.",
        guidance: [
          "Verify tribal jurisdiction.",
          "Carry ID if permitless carrying.",
          "Know notification requirements.",
          "Check federal and private property."
        ]
      }
    ],
    [
      "Assuming constitutional carry works outside North Dakota.",
      "Failing to carry ID while permitless carrying.",
      "Failing to notify law enforcement when required.",
      "Ignoring tribal land.",
      "Ignoring federal property.",
      "Assuming permitless carry replaces a license for reciprocity."
    ],
    [
      "Eligibility checked.",
      "ID carried.",
      "Police notification rule understood.",
      "Schools/courts/government facilities checked.",
      "Tribal/federal property checked.",
      "Reciprocity outside ND checked."
    ],
    [
      {
        myth: "North Dakota constitutional carry lets me carry in other states.",
        reality: "No. North Dakota Attorney General guidance says constitutional carry is within North Dakota; reciprocity outside the state requires a valid license."
      }
    ]
  ),

  SD: makeProfile(
    "South Dakota",
    "Law-Backed Ultra Expanded Travel State",
    "South Dakota is a permitless carry state for eligible persons, but it still has important restrictions involving schools, county courthouses, the State Capitol, vehicles, private property, tribal land, federal property, and self-defense conduct. South Dakota also issues regular, gold card, and enhanced permits that may matter for reciprocity outside the state.",
    {
      reciprocity: "Michigan CPL recognition should be verified before travel. South Dakota also allows permitless carry for eligible persons.",
      permitlessCarry: "S.D. Codified Laws Chapter 23-7: South Dakota does not impose a general permit requirement for carrying a concealed pistol.",
      concealedCarry: "South Dakota issues concealed pistol permits, including enhanced permits, but eligible persons may carry without a permit inside the state subject to restrictions.",
      openCarry: "Open carry may be lawful for eligible persons, but restricted locations and conduct still matter.",
      vehicleCarry: "Vehicle carry is generally permissive for eligible persons, but schools, courthouses, tribal land, and federal property still require analysis.",
      dutyToInform: "Verify current South Dakota police-contact rules. Keep hands visible and answer lawful questions truthfully.",
      privateSigns: "Private property and posted locations still matter. Leave if asked.",
      forceLaw: "South Dakota self-defense law is fact-specific."
    },
    [
      "South Dakota permitless carry does not mean unrestricted carry.",
      "County courthouses, the State Capitol, and elementary/secondary schools are key restricted areas.",
      "Tribal land can have separate rules and should be verified before carry.",
      "South Dakota permits may still matter for reciprocity in other states.",
      "Outdoor travel, hunting, federal land, and private ranch/property rules should be checked separately."
    ],
    [
      {
        title: "Permitless Carry / Concealed Pistol Framework",
        risk: "Core Eligibility Rule",
        body: [
          "STATUTE: S.D. Codified Laws Chapter 23-7.",
          "SUMMARY: South Dakota law does not impose a general prohibition on carrying a concealed pistol without a permit, subject to legal eligibility and location restrictions.",
          "GUIDANCE: Do not treat permitless carry as carry anywhere. Restricted locations and prohibited-person rules still matter."
        ],
        source: "S.D. Codified Laws Chapter 23-7."
      },
      {
        title: "Concealed Pistol Permits / Reciprocity",
        risk: "Travel Outside State",
        body: [
          "STATUTE: S.D. Codified Laws § 23-7-7 and related permit statutes.",
          "SUMMARY: South Dakota issues concealed pistol permits through county sheriffs, including enhanced permit options.",
          "GUIDANCE: A South Dakota permit may matter for reciprocity outside the state even if permitless carry applies inside South Dakota."
        ],
        source: "S.D. Codified Laws § 23-7-7; South Dakota Secretary of State concealed pistol permit guidance."
      },
      {
        title: "Schools",
        risk: "Extreme Risk Area",
        body: [
          "STATUTE: S.D. Codified Laws § 13-32-7.",
          "SUMMARY: South Dakota restricts firearms on elementary and secondary school premises, subject to statutory provisions and exceptions.",
          "GUIDANCE: School buildings, school events, school vehicles, and school property should be treated as verify-first locations."
        ],
        source: "S.D. Codified Laws § 13-32-7."
      },
      {
        title: "County Courthouses and State Capitol",
        risk: "Hard Stop Area",
        body: [
          "STATUTE: S.D. Codified Laws § 22-14-22 and related Capitol rules.",
          "SUMMARY: South Dakota restricts firearms in county courthouses and has specific requirements for carry in the State Capitol.",
          "GUIDANCE: Do not enter courthouse or Capitol-controlled areas armed unless the current law clearly allows the exact conduct."
        ],
        source: "S.D. Codified Laws § 22-14-22; S.D. Codified Laws § 22-14-24."
      },
      {
        title: "Vehicle Carry",
        risk: "Travel / Vehicle Rule",
        body: [
          "STATUTE / SOURCE: S.D. Codified Laws Chapter 23-7 and South Dakota vehicle carry framework.",
          "SUMMARY: Vehicle carry is generally permissive for eligible persons, but location restrictions and jurisdiction overlays still apply.",
          "GUIDANCE: Vehicle carry does not override schools, courthouses, tribal land, federal property, or private property rules."
        ],
        source: "S.D. Codified Laws Chapter 23-7; South Dakota vehicle carry framework."
      },
      {
        title: "Tribal Land / Federal Property",
        risk: "Jurisdiction Overlay",
        body: [
          "STATUTE / SOURCE: Tribal law; federal facility and postal property framework.",
          "SUMMARY: South Dakota carry permission does not override tribal law or federal property restrictions.",
          "GUIDANCE: Verify tribal law before carrying on reservations, tribal casinos, tribal offices, and tribal events. Federal buildings and post offices must be checked separately."
        ],
        source: "Tribal law framework; federal facility framework."
      },
      {
        title: "Private Property / Posted Locations",
        risk: "Property Control",
        body: [
          "STATUTE / SOURCE: South Dakota property/trespass framework.",
          "SUMMARY: Private property owners may restrict access and require armed persons to leave.",
          "GUIDANCE: If posted or asked to leave, leave immediately."
        ],
        source: "South Dakota property/trespass framework."
      },
      {
        title: "Use of Force / Self-Defense",
        risk: "Fact-Specific Legal Risk",
        body: [
          "STATUTE / SOURCE: South Dakota self-defense law framework.",
          "SUMMARY: Defensive force must be legally justified under the facts and applicable South Dakota law.",
          "GUIDANCE: Avoid escalation, disengage when safe, call 911, identify evidence/witnesses, request counsel, and avoid detailed statements under stress."
        ],
        source: "South Dakota self-defense law framework."
      }
    ],
    [
      {
        title: "South Dakota Carry Checklist",
        steps: [
          "1. Confirm eligibility.",
          "2. Check schools under § 13-32-7.",
          "3. Check county courthouse and State Capitol restrictions.",
          "4. Check tribal land and federal property separately.",
          "5. Check private property and event rules.",
          "6. Consider whether a permit is needed for reciprocity outside South Dakota."
        ]
      }
    ],
    [
      {
        title: "Black Hills / Tribal Land Travel",
        summary: "South Dakota travel may involve tribal land, national parks, state parks, private tourist properties, and long vehicle trips.",
        guidance: [
          "Separate state land, federal land, and tribal land.",
          "Check park buildings and visitor centers separately.",
          "Check courthouse and school restrictions.",
          "Check private property and lodging policies."
        ]
      }
    ],
    [
      "Assuming South Dakota permitless carry means carry anywhere.",
      "Ignoring schools under § 13-32-7.",
      "Ignoring county courthouses and Capitol rules.",
      "Assuming state law controls tribal land.",
      "Assuming national park land equals visitor center permission.",
      "Ignoring reciprocity needs outside South Dakota."
    ],
    [
      "Eligibility checked.",
      "School restrictions checked.",
      "Courthouse/Capitol rules checked.",
      "Federal/tribal property checked.",
      "Private property checked.",
      "Out-of-state reciprocity needs checked."
    ],
    [
      {
        myth: "South Dakota is permitless, so all public places are okay.",
        reality: "No. Schools, courthouses, Capitol rules, tribal land, federal property, and private property still matter."
      }
    ]
  ),

  NE: makeProfile(
    "Nebraska",
    "Law-Backed Ultra Expanded Travel State",
    "Nebraska adopted permitless concealed carry effective September 2, 2023, but the state still has detailed prohibited-location rules, school restrictions, public-building issues, alcohol-location restrictions, private property rules, local-preemption history, and vehicle/travel concerns. Nebraska remains a state where users must carefully separate general carry permission from prohibited places.",
    {
      reciprocity: "Michigan CPL recognition should be verified before travel. Nebraska also has permitless concealed carry for eligible persons 21 and older under LB 77 framework.",
      permitlessCarry: "Nebraska permitless carry took effect September 2, 2023, but prohibited places remain extensive.",
      concealedCarry: "Nebraska concealed handgun permit law remains important for reciprocity, federal school-zone issues, and documentation.",
      openCarry: "Open carry may be lawful for eligible persons, but location restrictions, vehicle visibility, and local/public-building issues still matter.",
      vehicleCarry: "Vehicle carry must be analyzed under Nebraska concealed handgun and prohibited-place rules.",
      dutyToInform: "Verify current Nebraska police-contact rules. Keep hands visible and answer lawful questions truthfully.",
      privateSigns: "Private property owners may restrict firearms. Leave if asked.",
      forceLaw: "Nebraska self-defense law is fact-specific."
    },
    [
      "Nebraska permitless carry did not erase prohibited places.",
      "Nebraska has a detailed statutory list of places where concealed handguns remain prohibited.",
      "Schools, courts, law-enforcement facilities, banks, hospitals, places of worship, polling places, athletic events, and alcohol-heavy locations require careful review.",
      "A Nebraska permit may still matter for reciprocity and federal school-zone considerations.",
      "Recent Nebraska local/public-building controversies make current verification important."
    ],
    [
      {
        title: "Permitless Carry / LB 77 Framework",
        risk: "Core Eligibility Rule",
        body: [
          "STATUTE / SOURCE: Nebraska LB 77 framework; Nebraska State Patrol CHP guidance.",
          "SUMMARY: Nebraska permitless concealed carry took effect September 2, 2023, allowing eligible persons to carry concealed without a Nebraska concealed handgun permit, subject to restrictions.",
          "GUIDANCE: Do not treat Nebraska as unrestricted. The prohibited-place list remains critical."
        ],
        source: "Nebraska State Patrol CHP FAQ; Nebraska LB 77 framework."
      },
      {
        title: "Prohibited Places",
        risk: "Major Location Restriction",
        body: [
          "STATUTE: Neb. Rev. Stat. § 28-1202.01.",
          "SUMMARY: Nebraska law identifies many places where concealed handguns remain prohibited, including law-enforcement offices, detention facilities, courtrooms/courthouse buildings, polling places, public meetings, financial institutions, athletic events, schools, places of worship, hospitals, political events, certain alcohol establishments, and places prohibited by state or federal law.",
          "GUIDANCE: Nebraska's prohibited-place list is one of the most important parts of the state profile. Users should check destination type before carrying."
        ],
        source: "Neb. Rev. Stat. § 28-1202.01."
      },
      {
        title: "Schools / School Activities",
        risk: "Extreme Risk Area",
        body: [
          "STATUTE: Neb. Rev. Stat. § 28-1202.01 and Nebraska school weapons framework.",
          "SUMMARY: Nebraska restricts concealed handguns in or on school buildings, grounds, vehicles, sponsored activities, and athletic events.",
          "GUIDANCE: School pickup, school sports, parking lots, events, and school vehicles should be treated as verify-first areas."
        ],
        source: "Neb. Rev. Stat. § 28-1202.01."
      },
      {
        title: "Courts / Law Enforcement / Detention Facilities",
        risk: "Hard Stop Area",
        body: [
          "STATUTE: Neb. Rev. Stat. § 28-1202.01.",
          "SUMMARY: Nebraska restricts concealed handguns in police/sheriff/State Patrol offices, detention facilities, prisons, jails, courtrooms, and buildings containing courtrooms.",
          "GUIDANCE: Do not approach courthouse, jail, or law-enforcement entrances armed unless a clear exception applies."
        ],
        source: "Neb. Rev. Stat. § 28-1202.01."
      },
      {
        title: "Banks / Hospitals / Churches / Athletic Events",
        risk: "Common Destination Trap",
        body: [
          "STATUTE: Neb. Rev. Stat. § 28-1202.01.",
          "SUMMARY: Nebraska's prohibited-place list includes financial institutions, hospitals/emergency rooms/trauma centers, places of worship, and professional or semiprofessional athletic events.",
          "GUIDANCE: These everyday destinations are easy to overlook. Do not assume permitless carry makes routine errands lawful."
        ],
        source: "Neb. Rev. Stat. § 28-1202.01."
      },
      {
        title: "Alcohol Establishments",
        risk: "Alcohol Location Risk",
        body: [
          "STATUTE: Neb. Rev. Stat. § 28-1202.01.",
          "SUMMARY: Nebraska prohibits concealed handguns in establishments licensed under the Nebraska Liquor Control Act that derive over one-half of total income from alcoholic liquor sales.",
          "GUIDANCE: Bars and alcohol-heavy venues should be treated as verify-first locations. If drinking is part of the plan, carrying should not be."
        ],
        source: "Neb. Rev. Stat. § 28-1202.01."
      },
      {
        title: "Vehicle Carry / Open Carry Visibility",
        risk: "Vehicle / Travel Risk",
        body: [
          "STATUTE / SOURCE: Nebraska carry and vehicle framework.",
          "SUMMARY: Vehicle carry must be analyzed under Nebraska concealed carry and open carry rules, plus prohibited-place rules.",
          "GUIDANCE: Do not assume vehicle carry is simple. Check prohibited destinations, school zones, and police-contact behavior."
        ],
        source: "Nebraska vehicle/carry framework; Neb. Rev. Stat. § 28-1202.01."
      },
      {
        title: "Private Property / Posted Locations",
        risk: "Property Control",
        body: [
          "STATUTE / SOURCE: Nebraska property/trespass framework.",
          "SUMMARY: Private property owners may restrict firearms and require people to leave.",
          "GUIDANCE: If posted or asked to leave, leave immediately."
        ],
        source: "Nebraska property/trespass framework."
      },
      {
        title: "Federal Property / Post Offices",
        risk: "Federal Law Overlay",
        body: [
          "STATUTE / SOURCE: Federal facility and postal property framework.",
          "SUMMARY: Nebraska carry permission does not override federal restrictions.",
          "GUIDANCE: Federal buildings, federal courthouses, post offices, and secure federal property must be checked separately."
        ],
        source: "Federal facility and postal property framework."
      },
      {
        title: "Use of Force / Self-Defense",
        risk: "Fact-Specific Legal Risk",
        body: [
          "STATUTE / SOURCE: Nebraska self-defense law framework.",
          "SUMMARY: Defensive force must be legally justified under the facts and applicable Nebraska law.",
          "GUIDANCE: Avoid escalation, disengage when safe, call 911, identify evidence/witnesses, request counsel, and avoid detailed statements under stress."
        ],
        source: "Nebraska self-defense law framework."
      }
    ],
    [
      {
        title: "Nebraska Carry Checklist",
        steps: [
          "1. Confirm eligibility under Nebraska permitless carry/LB 77 framework.",
          "2. Check Neb. Rev. Stat. § 28-1202.01 prohibited places.",
          "3. Check schools, courts, law-enforcement facilities, hospitals, churches, banks, athletic events, and alcohol-heavy locations.",
          "4. Check private property and signs.",
          "5. Check federal property separately.",
          "6. Consider whether a permit is needed for reciprocity or federal school-zone purposes."
        ]
      }
    ],
    [
      {
        title: "Omaha / Lincoln / Public Building Travel",
        summary: "Nebraska permitless carry exists, but public buildings and prohibited-location issues still require careful review.",
        guidance: [
          "Check current state law and local/public-building rules.",
          "Check the § 28-1202.01 prohibited-place list.",
          "Do not assume routine errands are lawful.",
          "Plan storage before entering restricted buildings."
        ]
      }
    ],
    [
      "Assuming Nebraska permitless carry means unrestricted carry.",
      "Ignoring the long prohibited-place list in § 28-1202.01.",
      "Ignoring banks, hospitals, places of worship, and athletic events.",
      "Ignoring schools and school activities.",
      "Ignoring alcohol-heavy establishments.",
      "Assuming permitless carry solves reciprocity or federal school-zone issues."
    ],
    [
      "Eligibility checked.",
      "Prohibited places checked under § 28-1202.01.",
      "Schools/courts/law enforcement facilities checked.",
      "Banks/hospitals/churches/events checked.",
      "Alcohol establishments checked.",
      "Federal/private property checked."
    ],
    [
      {
        myth: "Nebraska has permitless carry now, so there are no location restrictions.",
        reality: "No. Nebraska has an extensive prohibited-place list, including schools, courts, law-enforcement facilities, banks, hospitals, places of worship, athletic events, and certain alcohol establishments."
      }
    ]
  ),

  KS: makeProfile(
    "Kansas",
    "Law-Backed Ultra Expanded Travel State",
    "Kansas allows permitless concealed carry for eligible adults and recognizes out-of-state permits for nonresidents, but important restrictions remain for school zones, public buildings, buildings with adequate security, private property, state/local facilities, vehicles, and federal property. Kansas is permissive, but school-zone and building-security rules are major practical concerns.",
    {
      reciprocity: "Kansas recognizes valid carry licenses/permits issued by other jurisdictions for nonresidents under K.S.A. 75-7c03.",
      permitlessCarry: "Kansas allows permitless concealed carry for eligible adults, but school zones and buildings with restrictions still matter.",
      concealedCarry: "K.S.A. 75-7c03 governs Kansas concealed handgun licenses and recognition of licenses issued by other jurisdictions.",
      openCarry: "Open carry is generally lawful for eligible persons, but restrictions and private property still matter.",
      vehicleCarry: "Vehicle carry is generally permissive for eligible persons, but school zones and prohibited buildings must be checked.",
      dutyToInform: "Verify current Kansas police-contact rules. Keep hands visible and answer lawful questions truthfully.",
      privateSigns: "Private property and posted locations still matter. Leave if asked.",
      forceLaw: "Kansas self-defense law is fact-specific."
    },
    [
      "Kansas is generally permissive, but school zones are a major issue for unlicensed concealed carry.",
      "Kansas AG guidance states unlicensed concealed carry is not allowed in a school zone within 1,000 feet of a K-12 school.",
      "A valid Kansas CCHL or recognized license may matter for school-zone travel and reciprocity.",
      "Public buildings and buildings with adequate security measures may restrict firearms.",
      "Private property and federal property must be checked separately."
    ],
    [
      {
        title: "License Recognition / Concealed Handgun License",
        risk: "License / Reciprocity Rule",
        body: [
          "STATUTE: K.S.A. 75-7c03.",
          "SUMMARY: Kansas law provides for concealed handgun licenses and recognition of valid licenses/permits issued by other jurisdictions for nonresidents.",
          "GUIDANCE: A Michigan CPL may be recognized for nonresident travel, but Kansas law controls while in Kansas."
        ],
        source: "K.S.A. 75-7c03; Kansas Attorney General concealed carry guidance."
      },
      {
        title: "Permitless Carry",
        risk: "Core Eligibility Rule",
        body: [
          "STATUTE / SOURCE: Kansas concealed carry framework; Kansas Attorney General guidance.",
          "SUMMARY: Kansas generally allows eligible adults to carry concealed without a Kansas license, subject to restricted locations and federal/state school-zone issues.",
          "GUIDANCE: Do not assume unlicensed carry is equal to licensed carry in every situation. School zones are especially important."
        ],
        source: "Kansas Attorney General concealed carry FAQs; Kansas concealed carry framework."
      },
      {
        title: "School Zones",
        risk: "Extreme Risk Area",
        body: [
          "STATUTE / SOURCE: Kansas Attorney General concealed carry FAQs; federal Gun-Free School Zones Act.",
          "SUMMARY: Kansas AG guidance states unlicensed concealed carry is not allowed in a school zone within 1,000 feet of a K-12 school; recognized licenses may affect school-zone travel.",
          "GUIDANCE: School zones are the biggest Kansas trap for unlicensed carry. Verify school buildings, grounds, events, and travel through school zones."
        ],
        source: "Kansas Attorney General concealed carry FAQs; 18 U.S.C. § 922(q)."
      },
      {
        title: "Public Buildings / Adequate Security Measures",
        risk: "Building Restriction",
        body: [
          "STATUTE / SOURCE: Kansas Personal and Family Protection Act framework.",
          "SUMMARY: Kansas law includes rules for public buildings, signage, and adequate security measures that may restrict firearms in certain buildings.",
          "GUIDANCE: Do not assume a public building is carry-friendly. Look for signage, screening, metal detectors, and posted restrictions."
        ],
        source: "Kansas Personal and Family Protection Act framework; Kansas AG guidance."
      },
      {
        title: "Private Property / Posted Locations",
        risk: "Property Control",
        body: [
          "STATUTE / SOURCE: Kansas property/posting framework.",
          "SUMMARY: Private property owners may restrict firearms and require people to leave.",
          "GUIDANCE: If posted or asked to leave, leave immediately."
        ],
        source: "Kansas property/trespass framework."
      },
      {
        title: "College / University Buildings",
        risk: "Campus Building Rules",
        body: [
          "STATUTE / SOURCE: Kansas campus carry and adequate-security framework.",
          "SUMMARY: Kansas campus carry rules can depend on building security measures and posted restrictions.",
          "GUIDANCE: Universities and public buildings should be checked by building, not guessed from the general state carry rule."
        ],
        source: "Kansas campus carry/adequate security framework."
      },
      {
        title: "Vehicle Carry",
        risk: "Travel / School Zone Risk",
        body: [
          "STATUTE / SOURCE: Kansas carry and vehicle framework.",
          "SUMMARY: Vehicle carry is generally permissive for eligible persons, but school zones, public buildings, private property, and federal property can change the analysis.",
          "GUIDANCE: Keep hands visible during police contact and avoid reaching until instructed."
        ],
        source: "Kansas carry/vehicle framework."
      },
      {
        title: "Federal Property / Post Offices",
        risk: "Federal Law Overlay",
        body: [
          "STATUTE / SOURCE: Federal facility and postal property framework.",
          "SUMMARY: Kansas carry permission does not override federal restrictions.",
          "GUIDANCE: Federal buildings, post offices, federal courthouses, and secure federal property must be checked separately."
        ],
        source: "Federal facility and postal property framework."
      },
      {
        title: "Use of Force / Self-Defense",
        risk: "Fact-Specific Legal Risk",
        body: [
          "STATUTE / SOURCE: Kansas self-defense law framework.",
          "SUMMARY: Defensive force must be legally justified under the facts and applicable Kansas law.",
          "GUIDANCE: Avoid escalation, disengage when safe, call 911, identify evidence/witnesses, request counsel, and avoid detailed statements under stress."
        ],
        source: "Kansas self-defense law framework."
      }
    ],
    [
      {
        title: "Kansas Carry Checklist",
        steps: [
          "1. Verify recognition under K.S.A. 75-7c03 if relying on Michigan CPL.",
          "2. Check school-zone issues before unlicensed carry.",
          "3. Check public buildings and adequate security measures.",
          "4. Check private property and signs.",
          "5. Check campus/public building rules by building.",
          "6. Check federal property separately."
        ]
      }
    ],
    [
      {
        title: "Kansas Road Trip / School-Zone Travel",
        summary: "Kansas is permissive, but school-zone issues can be a major trap for unlicensed carry.",
        guidance: [
          "Verify whether a recognized license affects your school-zone status.",
          "Check buildings with security measures.",
          "Check private property and posted locations.",
          "Do not assume permitless carry solves every location."
        ]
      }
    ],
    [
      "Assuming Kansas permitless carry has no school-zone limits.",
      "Ignoring public-building security/signage rules.",
      "Ignoring campus building rules.",
      "Assuming recognition overrides private property.",
      "Ignoring federal property and post offices."
    ],
    [
      "Recognition checked.",
      "School-zone issues checked.",
      "Public buildings/security measures checked.",
      "Campus buildings checked.",
      "Private/federal property checked.",
      "Vehicle/police-contact plan ready."
    ],
    [
      {
        myth: "Kansas is permitless, so school zones do not matter.",
        reality: "No. Kansas AG guidance specifically flags school-zone limits for unlicensed concealed carry."
      }
    ]
  ),

  OK: makeProfile(
    "Oklahoma",
    "Law-Backed Ultra Expanded Travel State",
    "Oklahoma allows permitless carry for eligible persons and honors other states' permits, but Oklahoma law still has detailed restrictions involving prohibited places, schools, government buildings, bars, sports arenas, colleges, vehicle conduct, tribal land, private property, federal property, and defensive display/use-of-force conduct.",
    {
      reciprocity: "Oklahoma generally honors other states' carry permits and also has permitless carry for eligible persons under the Oklahoma Self-Defense Act framework.",
      permitlessCarry: "21 O.S. § 1272 and the Oklahoma Self-Defense Act framework allow eligible persons to carry openly or concealed, subject to prohibited locations.",
      concealedCarry: "Oklahoma carry authority does not override prohibited places under 21 O.S. § 1277 or other law.",
      openCarry: "Open carry may be lawful for eligible persons, but prohibited places, private property, and public conduct still matter.",
      vehicleCarry: "Vehicle carry is generally permissive for eligible persons, but schools, prohibited places, tribal land, and police-contact conduct still matter.",
      dutyToInform: "Verify current Oklahoma police-contact rules. Keep hands visible and answer lawful questions truthfully.",
      privateSigns: "Private property owners may restrict firearms. Leave if asked.",
      forceLaw: "Oklahoma self-defense law is fact-specific."
    },
    [
      "Oklahoma permitless carry does not override prohibited places.",
      "21 O.S. § 1277 is the key prohibited-location statute.",
      "Schools, government buildings, bars, sports arenas, colleges/universities, jails, and courthouses require careful review.",
      "Tribal land can have separate rules and is especially important in Oklahoma.",
      "Private property and federal property remain separate legal issues."
    ],
    [
      {
        title: "Permitless Carry / Unlawful Carry Framework",
        risk: "Core Eligibility Rule",
        body: [
          "STATUTE: 21 O.S. § 1272.",
          "SUMMARY: Oklahoma law allows eligible persons to carry firearms openly or concealed under the constitutional/permitless carry framework, subject to prohibited places and other restrictions.",
          "GUIDANCE: Do not treat Oklahoma as unrestricted. § 1272 itself points users back to prohibited places and other limits."
        ],
        source: "21 O.S. § 1272; Oklahoma Self-Defense Act."
      },
      {
        title: "Prohibited Places",
        risk: "Major Location Restriction",
        body: [
          "STATUTE: 21 O.S. § 1277.",
          "SUMMARY: Oklahoma law lists places where carrying firearms is prohibited, with exceptions specified in the statute.",
          "GUIDANCE: Treat government buildings, schools, courthouses, jails/prisons, sports arenas, bars, colleges/universities, and other listed locations as verify-first areas."
        ],
        source: "21 O.S. § 1277."
      },
      {
        title: "Schools",
        risk: "Extreme Risk Area",
        body: [
          "STATUTE: 21 O.S. § 1277 and Oklahoma school weapons framework.",
          "SUMMARY: Oklahoma restricts firearms in schools and school-related places, subject to limited statutory exceptions.",
          "GUIDANCE: School pickup, school events, school parking, and school activities should be treated as verify-first."
        ],
        source: "21 O.S. § 1277; Oklahoma school weapons framework."
      },
      {
        title: "Bars / Alcohol Locations",
        risk: "Alcohol Location Risk",
        body: [
          "STATUTE: 21 O.S. § 1277 and Oklahoma alcohol-location framework.",
          "SUMMARY: Oklahoma restricts firearms in certain places where alcoholic beverages are consumed or where the primary purpose involves alcohol, subject to statutory language and exceptions.",
          "GUIDANCE: Bars, clubs, event venues, restaurants with bars, casinos with alcohol service, and festivals should be checked carefully. If drinking is part of the plan, carrying should not be."
        ],
        source: "21 O.S. § 1277; Oklahoma Self-Defense Act."
      },
      {
        title: "Colleges / Universities",
        risk: "Campus Restriction",
        body: [
          "STATUTE: 21 O.S. § 1277 and Oklahoma higher-education firearms framework.",
          "SUMMARY: Oklahoma restricts carry on college, university, and technology center property except as authorized by law or policy.",
          "GUIDANCE: Campus property, events, dorms, classrooms, and parking should be checked before carrying."
        ],
        source: "21 O.S. § 1277; Oklahoma campus firearms framework."
      },
      {
        title: "Sports Arenas / Government Buildings / Courthouses",
        risk: "Public Venue Risk",
        body: [
          "STATUTE: 21 O.S. § 1277.",
          "SUMMARY: Oklahoma's prohibited-place framework includes public venue and government-related restrictions, with statutory exceptions.",
          "GUIDANCE: Do not enter sports arenas, courthouses, jail facilities, or government-controlled buildings armed unless a clear legal exception applies."
        ],
        source: "21 O.S. § 1277."
      },
      {
        title: "Tribal Land / Casinos",
        risk: "Jurisdiction Overlay",
        body: [
          "STATUTE / SOURCE: Tribal law framework; Oklahoma public/private property framework.",
          "SUMMARY: Oklahoma travel commonly involves tribal land and casinos, which may have separate rules, security policies, and jurisdictional issues.",
          "GUIDANCE: Verify tribal and casino policies before carrying. Leave immediately if instructed by security."
        ],
        source: "Tribal law framework; Oklahoma casino/property framework."
      },
      {
        title: "Vehicle Carry",
        risk: "Travel / Police Contact Risk",
        body: [
          "STATUTE / SOURCE: Oklahoma carry and vehicle framework.",
          "SUMMARY: Vehicle carry is generally permissive for eligible persons, but prohibited locations, school property, tribal land, and police-contact conduct still matter.",
          "GUIDANCE: Keep hands visible during traffic stops and avoid reaching until instructed."
        ],
        source: "Oklahoma Self-Defense Act; Oklahoma vehicle carry framework."
      },
      {
        title: "Private Property / Posted Locations",
        risk: "Property Control",
        body: [
          "STATUTE / SOURCE: Oklahoma property/trespass framework.",
          "SUMMARY: Private property owners may restrict firearms and require armed persons to leave.",
          "GUIDANCE: If posted or asked to leave, leave immediately."
        ],
        source: "Oklahoma property/trespass framework."
      },
      {
        title: "Use of Force / Self-Defense",
        risk: "Fact-Specific Legal Risk",
        body: [
          "STATUTE / SOURCE: Oklahoma self-defense law framework.",
          "SUMMARY: Defensive force must be legally justified under the facts and applicable Oklahoma law.",
          "GUIDANCE: Avoid escalation, disengage when safe, call 911, identify evidence/witnesses, request counsel, and avoid detailed statements under stress."
        ],
        source: "Oklahoma self-defense law framework."
      }
    ],
    [
      {
        title: "Oklahoma Carry Checklist",
        steps: [
          "1. Confirm eligibility under Oklahoma carry framework.",
          "2. Check prohibited places under 21 O.S. § 1277.",
          "3. Check schools, campuses, bars, sports arenas, government buildings, jails, and courthouses.",
          "4. Check tribal land and casino policies.",
          "5. Check private/federal property separately.",
          "6. Avoid carry while impaired."
        ]
      }
    ],
    [
      {
        title: "Casino / Tribal Land Travel",
        summary: "Oklahoma travel often involves tribal land, casinos, alcohol service, event venues, and private security.",
        guidance: [
          "Verify tribal jurisdiction.",
          "Check casino security policy.",
          "Check alcohol-location rules.",
          "Leave immediately if instructed by security."
        ]
      }
    ],
    [
      "Assuming Oklahoma permitless carry means carry anywhere.",
      "Ignoring prohibited places under § 1277.",
      "Ignoring tribal land and casino policies.",
      "Ignoring school and campus restrictions.",
      "Ignoring bars/alcohol locations.",
      "Assuming private property signs can be debated."
    ],
    [
      "Eligibility checked.",
      "Prohibited places under § 1277 checked.",
      "Schools/campuses checked.",
      "Bars/alcohol locations checked.",
      "Tribal/casino rules checked.",
      "Private/federal property checked."
    ],
    [
      {
        myth: "Oklahoma is constitutional carry, so I can carry anywhere.",
        reality: "No. Oklahoma has specific prohibited-place laws, especially 21 O.S. § 1277, and tribal/private/federal restrictions still matter."
      }
    ]
  ),


  LA: makeProfile(
    "Louisiana",
    "Law-Backed Ultra Expanded Travel State",
    "Louisiana is a high-priority southern travel state with permitless concealed carry for eligible adults 18 and older, effective July 4, 2024. Louisiana still has important statutory restrictions involving schools, firearm-free zones, concealed handgun permit restrictions, private residences, alcohol-related locations, parades/demonstrations, government buildings, federal property, and local travel issues such as New Orleans/French Quarter rules.",
    {
      reciprocity: "Louisiana generally recognizes valid out-of-state permits under its reciprocity framework, but Louisiana law controls while physically in Louisiana.",
      permitlessCarry: "Louisiana Act 1 / La. R.S. 14:95 framework: eligible adults 18+ may carry concealed without a permit effective July 4, 2024, subject to restrictions.",
      concealedCarry: "La. R.S. 40:1379.3 governs statewide concealed handgun permits and lists places where a permit does not authorize carry.",
      openCarry: "Open carry may be lawful for eligible persons, but prohibited places, local issues, and police-contact realities still matter.",
      vehicleCarry: "Vehicle carry must be analyzed with Louisiana prohibited-place rules, school/firearm-free zones, and safe storage concerns.",
      dutyToInform: "Verify current Louisiana police-contact rules. Keep hands visible and answer lawful questions truthfully.",
      privateSigns: "Private property and private residences matter. Louisiana law specifically addresses entering another person's private residence with a concealed handgun.",
      forceLaw: "Louisiana self-defense law is fact-specific and should be verified before relying on a summary."
    },
    [
      "Louisiana permitless carry does not mean carry anywhere.",
      "Permitless concealed carry became effective July 4, 2024 for eligible adults 18 and older, but prohibited locations remain in effect.",
      "Schools, school-sponsored functions, firearm-free zones, courthouses, law-enforcement facilities, private residences, alcohol-related locations, parades, demonstrations, and federal property require careful review.",
      "New Orleans and the French Quarter have generated special local attention around permitless carry and firearm-free zones; travelers should verify current local conditions before carrying.",
      "A recognized permit or permitless authority does not override Louisiana’s restricted-location rules."
    ],
    [
      {
        title: "Permitless Concealed Carry",
        risk: "Core Eligibility Rule",
        body: [
          "STATUTE / SOURCE: Louisiana Act 1 of 2024; La. R.S. 14:95 framework.",
          "SUMMARY: Louisiana law now provides an exemption to illegal carrying of weapons for eligible persons 18 or older who are not prohibited from possessing firearms under state or federal law.",
          "GUIDANCE: Permitless carry is not ruleless carry. The user must still be eligible and must avoid prohibited places and restricted conduct."
        ],
        source: "Louisiana Act 1 of 2024; La. R.S. 14:95 framework."
      },
      {
        title: "Statewide Concealed Handgun Permit / Prohibited Places",
        risk: "Major Location Restriction",
        body: [
          "STATUTE: La. R.S. 40:1379.3.",
          "SUMMARY: Louisiana’s concealed handgun permit statute identifies locations where no concealed handgun may be carried and where a permit does not authorize carry.",
          "GUIDANCE: Users should check the Louisiana prohibited-place list before entering any government building, school area, courthouse, law-enforcement facility, polling place, parade/demonstration, alcohol-related location, or other listed area."
        ],
        source: "La. R.S. 40:1379.3."
      },
      {
        title: "Schools / Firearm-Free Zones",
        risk: "Extreme Risk Area",
        body: [
          "STATUTE: La. R.S. 14:95.2.",
          "SUMMARY: Louisiana restricts carrying firearms or dangerous weapons on school property, at school-sponsored functions, and in firearm-free zones, subject to statutory exceptions.",
          "GUIDANCE: Schools, school buses, school-sponsored events, college/university property, and the surrounding firearm-free zone framework should be treated as verify-first areas."
        ],
        source: "La. R.S. 14:95.2."
      },
      {
        title: "Private Residence Consent",
        risk: "Private Residence Restriction",
        body: [
          "STATUTE: La. R.S. 40:1379.3.",
          "SUMMARY: Louisiana concealed handgun law addresses carrying a concealed handgun into another person’s private residence without first receiving that person’s consent.",
          "GUIDANCE: Do not assume a permit or permitless carry lets you enter someone else’s home armed without permission."
        ],
        source: "La. R.S. 40:1379.3."
      },
      {
        title: "Alcohol-Related Locations",
        risk: "Alcohol Location Risk",
        body: [
          "STATUTE / SOURCE: La. R.S. 40:1379.3 prohibited-place framework and Louisiana alcohol/firearm rules.",
          "SUMMARY: Louisiana law restricts concealed handgun carry in certain alcohol-related locations and under certain conditions.",
          "GUIDANCE: Bars, restaurants, festivals, entertainment districts, stadium events, and French Quarter nightlife should be checked carefully. If drinking is part of the plan, carrying should not be."
        ],
        source: "La. R.S. 40:1379.3; Louisiana alcohol/firearm framework."
      },
      {
        title: "Parades / Demonstrations / Public Events",
        risk: "Event Risk",
        body: [
          "STATUTE / SOURCE: La. R.S. 40:1379.3 prohibited-place framework.",
          "SUMMARY: Louisiana concealed handgun restrictions can apply to certain parades, demonstrations, and public gatherings.",
          "GUIDANCE: Mardi Gras events, festivals, parades, protests, and large public gatherings should be treated as high-risk verify-first locations."
        ],
        source: "La. R.S. 40:1379.3."
      },
      {
        title: "Courthouses / Government / Law Enforcement Facilities",
        risk: "Hard Stop Area",
        body: [
          "STATUTE / SOURCE: La. R.S. 40:1379.3 prohibited-place framework.",
          "SUMMARY: Louisiana restricts concealed carry in courthouses, law-enforcement facilities, and other listed government or secure locations.",
          "GUIDANCE: Do not approach courthouse security, police stations, jails, or secure government facilities armed unless a specific legal exception clearly applies."
        ],
        source: "La. R.S. 40:1379.3."
      },
      {
        title: "Vehicle Carry / New Orleans Travel",
        risk: "Travel and Storage Risk",
        body: [
          "STATUTE / SOURCE: Louisiana carry framework; local New Orleans travel considerations.",
          "SUMMARY: Vehicle carry may be lawful for eligible persons, but firearm-free zones, local event districts, vehicle storage, and theft risk must be considered.",
          "GUIDANCE: Do not leave firearms unsecured in vehicles. Verify local restrictions before entering entertainment districts or firearm-free zones."
        ],
        source: "Louisiana carry framework; New Orleans public safety guidance."
      },
      {
        title: "Federal Property / Post Offices",
        risk: "Federal Law Overlay",
        body: [
          "STATUTE / SOURCE: Federal facility and postal property framework.",
          "SUMMARY: Louisiana carry permission does not override federal restrictions.",
          "GUIDANCE: Federal buildings, federal courthouses, post offices, and secure federal property must be checked separately."
        ],
        source: "Federal facility and postal property framework."
      },
      {
        title: "Use of Force / Self-Defense",
        risk: "Fact-Specific Legal Risk",
        body: [
          "STATUTE / SOURCE: Louisiana self-defense and justifiable-force framework.",
          "SUMMARY: Defensive force must be justified under the facts and applicable Louisiana law.",
          "GUIDANCE: Avoid escalation, call 911 when safe, identify evidence/witnesses when necessary, request counsel, and avoid detailed statements under stress."
        ],
        source: "Louisiana self-defense law framework."
      }
    ],
    [
      {
        title: "Louisiana Carry Checklist",
        steps: [
          "1. Confirm eligibility under Louisiana permitless carry law.",
          "2. Check La. R.S. 40:1379.3 prohibited locations.",
          "3. Check school/firearm-free zones under La. R.S. 14:95.2.",
          "4. Check alcohol/event/parade restrictions.",
          "5. Get consent before entering another person's private residence armed.",
          "6. Check federal property separately.",
          "7. Verify local conditions in New Orleans/French Quarter."
        ]
      }
    ],
    [
      {
        title: "New Orleans / French Quarter Visit",
        summary: "Louisiana permitless carry does not make entertainment districts simple.",
        guidance: [
          "Check current local restrictions.",
          "Watch for firearm-free zones.",
          "Avoid carrying while drinking.",
          "Do not leave firearms unsecured in vehicles."
        ]
      },
      {
        title: "Mardi Gras / Parade Event",
        summary: "Parades and public gatherings require special caution.",
        guidance: [
          "Check event-specific restrictions.",
          "Check La. R.S. 40:1379.3.",
          "Avoid carrying in alcohol-heavy environments."
        ]
      }
    ],
    [
      "Assuming Louisiana permitless carry means carry anywhere.",
      "Ignoring school/firearm-free zones.",
      "Ignoring New Orleans local issues.",
      "Carrying into another person's private residence without consent.",
      "Carrying while drinking or in alcohol-heavy event areas.",
      "Leaving firearms unsecured in vehicles."
    ],
    [
      "Eligibility checked.",
      "La. R.S. 40:1379.3 prohibited places checked.",
      "La. R.S. 14:95.2 school/firearm-free zones checked.",
      "Private residence consent considered.",
      "Alcohol/event restrictions checked.",
      "Federal property checked."
    ],
    [
      {
        myth: "Louisiana has permitless carry, so I can carry everywhere in New Orleans.",
        reality: "No. Prohibited places, firearm-free zones, local event areas, alcohol locations, private property, and federal property still matter."
      }
    ]
  ),

  MS: makeProfile(
    "Mississippi",
    "Law-Backed Ultra Expanded Travel State",
    "Mississippi is a permitless carry state with a standard and enhanced permit structure. It is generally permissive, but users must still understand restricted locations, enhanced endorsement differences, schools, courthouses, police stations, detention facilities, polling places, government meetings, nuisance places, posted private property, vehicle carry, and federal property.",
    {
      reciprocity: "Michigan CPL recognition should be verified, but Mississippi also has permitless carry options for eligible persons.",
      permitlessCarry: "Mississippi allows permitless carry for eligible persons, but location restrictions still apply.",
      concealedCarry: "Miss. Code § 45-9-101 governs concealed carry licenses and enhanced endorsements.",
      openCarry: "Open carry may be lawful for eligible persons, but location restrictions and conduct still matter.",
      vehicleCarry: "Vehicle carry must be analyzed under Mississippi weapons and prohibited-location rules.",
      dutyToInform: "Verify current Mississippi police-contact rules. Keep hands visible and answer lawful questions truthfully.",
      privateSigns: "Private property and posted locations matter. Leave if asked.",
      forceLaw: "Mississippi self-defense law is fact-specific."
    },
    [
      "Mississippi is permissive, but not unrestricted.",
      "Enhanced endorsement rules can differ from standard permit or permitless carry rules.",
      "Schools, courthouses, police stations, jails, detention facilities, polling places, government meetings, and posted private property require caution.",
      "A permissive carry state still has legal traps for travelers.",
      "Federal property remains separate from Mississippi carry permission."
    ],
    [
      {
        title: "Permitless Carry / Carry Framework",
        risk: "Core Eligibility Rule",
        body: [
          "STATUTE / SOURCE: Mississippi weapons and concealed carry framework; Miss. Code § 45-9-101.",
          "SUMMARY: Mississippi allows permitless carry for eligible persons, while also maintaining a licensing and enhanced endorsement system.",
          "GUIDANCE: Do not assume permitless carry removes location restrictions. Eligibility, prohibited places, and private property still matter."
        ],
        source: "Miss. Code § 45-9-101; Mississippi weapons law framework."
      },
      {
        title: "Standard Permit and Enhanced Endorsement",
        risk: "Permit Type Difference",
        body: [
          "STATUTE: Miss. Code § 45-9-101.",
          "SUMMARY: Mississippi has a concealed carry license framework and an enhanced endorsement system tied to approved training.",
          "GUIDANCE: Enhanced carry may allow carry in some locations where standard carry is restricted, but the exact scope must be verified before relying on it."
        ],
        source: "Miss. Code § 45-9-101; Mississippi DPS enhanced endorsement guidance."
      },
      {
        title: "Prohibited / Restricted Locations",
        risk: "Major Location Restriction",
        body: [
          "STATUTE / SOURCE: Miss. Code § 45-9-101 restricted-location framework.",
          "SUMMARY: Mississippi law identifies locations where carry authority may not authorize carry, including places such as police/sheriff/highway patrol stations, detention facilities, courthouses/courtrooms, polling places, government meetings, and nuisance places.",
          "GUIDANCE: Check whether you are relying on permitless carry, a standard permit, or enhanced endorsement before entering any restricted area."
        ],
        source: "Miss. Code § 45-9-101."
      },
      {
        title: "Schools / Educational Property",
        risk: "Extreme Risk Area",
        body: [
          "STATUTE / SOURCE: Mississippi school weapons framework.",
          "SUMMARY: Mississippi restricts weapons on educational property subject to statutory exceptions and permit/endorsement distinctions.",
          "GUIDANCE: Schools, campuses, school events, parking lots, and student activities should be treated as verify-first locations."
        ],
        source: "Mississippi school weapons law framework."
      },
      {
        title: "Courthouses / Courtrooms",
        risk: "Hard Stop Area",
        body: [
          "STATUTE / SOURCE: Miss. Code § 45-9-101 restricted-location framework.",
          "SUMMARY: Mississippi restricts carry in courthouses and courtrooms under its carry-location rules, with narrow exceptions for authorized persons.",
          "GUIDANCE: Do not approach courthouse security armed unless a clear legal exception applies."
        ],
        source: "Miss. Code § 45-9-101."
      },
      {
        title: "Police Stations / Detention Facilities",
        risk: "Restricted Facility Risk",
        body: [
          "STATUTE / SOURCE: Miss. Code § 45-9-101 restricted-location framework.",
          "SUMMARY: Police, sheriff, highway patrol stations, detention facilities, prisons, and jails are restricted or high-risk locations.",
          "GUIDANCE: Do not enter these facilities armed unless a specific legal exception clearly applies."
        ],
        source: "Miss. Code § 45-9-101."
      },
      {
        title: "Polling Places / Government Meetings",
        risk: "Civic Location Risk",
        body: [
          "STATUTE / SOURCE: Miss. Code § 45-9-101 restricted-location framework.",
          "SUMMARY: Mississippi carry restrictions include polling places and meeting places of governing bodies, subject to the details of the statute and permit type.",
          "GUIDANCE: Election locations, city/county board meetings, and government meetings should be treated as verify-first locations."
        ],
        source: "Miss. Code § 45-9-101."
      },
      {
        title: "Private Property / Posted Locations",
        risk: "Property Control",
        body: [
          "STATUTE / SOURCE: Mississippi property and posted premises framework.",
          "SUMMARY: Private property owners may restrict firearms and require armed persons to leave.",
          "GUIDANCE: If posted or asked to leave, leave immediately. Do not turn a carry issue into a trespass or disorderly conduct issue."
        ],
        source: "Mississippi property/trespass framework."
      },
      {
        title: "Vehicle Carry",
        risk: "Travel / Storage Risk",
        body: [
          "STATUTE / SOURCE: Mississippi weapons and carry framework.",
          "SUMMARY: Vehicle carry may be lawful for eligible persons, but prohibited places, school property, and safe storage still matter.",
          "GUIDANCE: Keep hands visible during traffic stops, do not reach, and avoid leaving firearms unsecured in vehicles."
        ],
        source: "Mississippi weapons law framework."
      },
      {
        title: "Federal Property / Post Offices",
        risk: "Federal Law Overlay",
        body: [
          "STATUTE / SOURCE: Federal facility and postal property framework.",
          "SUMMARY: Mississippi carry permission does not override federal restrictions.",
          "GUIDANCE: Federal buildings, federal courthouses, post offices, and secure federal property must be checked separately."
        ],
        source: "Federal facility and postal property framework."
      }
    ],
    [
      {
        title: "Mississippi Carry Checklist",
        steps: [
          "1. Confirm eligibility to possess/carry.",
          "2. Identify whether relying on permitless carry, standard permit, or enhanced endorsement.",
          "3. Check Miss. Code § 45-9-101 restricted locations.",
          "4. Check schools and educational property.",
          "5. Check courthouses, police stations, jails, and polling places.",
          "6. Check private signs and federal property."
        ]
      }
    ],
    [
      {
        title: "Gulf Coast / Casino / Event Travel",
        summary: "Mississippi travel often involves casinos, restaurants, hotels, beaches, events, and vehicles.",
        guidance: [
          "Check private property policies.",
          "Check alcohol/event restrictions.",
          "Understand permitless vs enhanced carry distinctions.",
          "Secure firearms from unauthorized access."
        ]
      }
    ],
    [
      "Assuming Mississippi permitless carry means no restricted places.",
      "Confusing standard permit and enhanced endorsement authority.",
      "Ignoring courthouses and courtrooms.",
      "Ignoring police stations and detention facilities.",
      "Ignoring polling places and government meetings.",
      "Ignoring posted private property."
    ],
    [
      "Eligibility checked.",
      "Carry authority type identified.",
      "Restricted locations checked.",
      "School property checked.",
      "Court/police/jail locations checked.",
      "Private/federal property checked."
    ],
    [
      {
        myth: "Mississippi is permitless, so restrictions do not matter.",
        reality: "No. Mississippi still has restricted locations, enhanced endorsement distinctions, private property rules, and federal property restrictions."
      }
    ]
  ),

  AR: makeProfile(
    "Arkansas",
    "Law-Backed Ultra Expanded Travel State",
    "Arkansas is a generally permissive carry state with a concealed handgun licensing system and enhanced carry endorsement structure. Members must understand prohibited places, enhanced endorsement exceptions, schools, public buildings, places of worship, alcohol-related locations, private property, vehicles, and federal property before relying on Arkansas carry rights.",
    {
      reciprocity: "Michigan CPL recognition should be verified, and Arkansas has its own carry and license framework.",
      permitlessCarry: "Arkansas is generally permissive for carry by eligible persons, but prohibited locations still apply.",
      concealedCarry: "Ark. Code § 5-73-306 lists places where a concealed handgun license does not authorize carry; enhanced endorsement may change some rules.",
      openCarry: "Open carry may be lawful depending on circumstances, but conduct, intent, and prohibited places still matter.",
      vehicleCarry: "Vehicle carry must be analyzed under Arkansas carry law, prohibited places, and safe storage concerns.",
      dutyToInform: "Verify current Arkansas police-contact rules. Keep hands visible and answer lawful questions truthfully.",
      privateSigns: "Arkansas recognizes notice/signage restrictions in its concealed carry prohibited-place framework.",
      forceLaw: "Arkansas self-defense law is fact-specific."
    },
    [
      "Arkansas is permissive, but not unrestricted.",
      "Ark. Code § 5-73-306 is a key prohibited-places statute.",
      "Enhanced carry endorsement can change some location rules but does not make carry unlimited.",
      "Schools, public buildings, law enforcement facilities, detention facilities, places of worship, bars, private signs, and federal property require review.",
      "Do not rely on a one-sentence summary for Arkansas location rules."
    ],
    [
      {
        title: "Concealed Handgun License / Prohibited Places",
        risk: "Major Location Restriction",
        body: [
          "STATUTE: Ark. Code § 5-73-306.",
          "SUMMARY: Arkansas lists places where a concealed handgun license does not authorize carrying a concealed handgun, subject to exceptions and enhanced endorsement rules.",
          "GUIDANCE: Check the full prohibited-place list before entering police stations, jails, courthouses, schools, bars, airports, places of worship, posted property, or public buildings."
        ],
        source: "Ark. Code § 5-73-306."
      },
      {
        title: "Enhanced Carry Endorsement",
        risk: "Permit Type Difference",
        body: [
          "STATUTE: Ark. Code § 5-73-322.",
          "SUMMARY: Arkansas enhanced endorsement can allow carry in some places that are otherwise restricted, subject to statutory limits and signage/notice rules.",
          "GUIDANCE: Do not assume enhanced carry means carry anywhere. The endorsement must be checked against each specific restricted location."
        ],
        source: "Ark. Code § 5-73-322."
      },
      {
        title: "Schools / School Property",
        risk: "Extreme Risk Area",
        body: [
          "STATUTE / SOURCE: Ark. Code § 5-73-119 and § 5-73-306 framework.",
          "SUMMARY: Arkansas restricts firearms on school property, with specific exceptions and enhanced-endorsement nuances.",
          "GUIDANCE: Schools, school buses, school events, and K-12/private school policies should be treated as verify-first areas."
        ],
        source: "Ark. Code § 5-73-119; Ark. Code § 5-73-306."
      },
      {
        title: "Public Buildings / Government Locations",
        risk: "Public Facility Risk",
        body: [
          "STATUTE: Ark. Code § 5-73-122; Ark. Code § 5-73-306.",
          "SUMMARY: Arkansas restricts carry in certain publicly owned buildings and government-controlled facilities, with enhanced-endorsement exceptions in some contexts.",
          "GUIDANCE: Do not assume a public building is lawful. Check whether enhanced endorsement changes the answer and whether signs prohibit carry."
        ],
        source: "Ark. Code § 5-73-122; Ark. Code § 5-73-306."
      },
      {
        title: "Police Stations / Jails / Detention Facilities",
        risk: "Restricted Facility Risk",
        body: [
          "STATUTE: Ark. Code § 5-73-306.",
          "SUMMARY: Arkansas prohibited-place law includes law enforcement and detention-related facilities.",
          "GUIDANCE: Police stations, sheriff stations, jails, prisons, detention centers, and correctional facilities should be treated as hard-stop verify-first locations."
        ],
        source: "Ark. Code § 5-73-306."
      },
      {
        title: "Places of Worship",
        risk: "Property / Permission Risk",
        body: [
          "STATUTE: Ark. Code § 5-73-306.",
          "SUMMARY: Arkansas law recognizes that churches and places of worship may determine who may carry on their property, with notice/signage rules relevant to enhanced carry.",
          "GUIDANCE: Verify policy with the proper authority before carrying into a church or place of worship."
        ],
        source: "Ark. Code § 5-73-306."
      },
      {
        title: "Alcohol Locations / Bars",
        risk: "Alcohol Location Risk",
        body: [
          "STATUTE: Ark. Code § 5-73-306.",
          "SUMMARY: Arkansas prohibited-place law includes certain alcohol-related locations and bars, subject to statutory language and exceptions.",
          "GUIDANCE: If drinking is part of the plan, carrying should not be. Restaurants, bars, clubs, festivals, and event venues should be checked carefully."
        ],
        source: "Ark. Code § 5-73-306."
      },
      {
        title: "Private Property / Posted Locations",
        risk: "Signage and Notice Risk",
        body: [
          "STATUTE: Ark. Code § 5-73-306.",
          "SUMMARY: Arkansas recognizes written notice and other notice prohibiting concealed carry at physical locations.",
          "GUIDANCE: Posted signs and verbal instructions matter. Leave immediately if asked."
        ],
        source: "Ark. Code § 5-73-306."
      },
      {
        title: "Vehicle Carry",
        risk: "Travel / Storage Risk",
        body: [
          "STATUTE / SOURCE: Arkansas carry and weapons law framework.",
          "SUMMARY: Vehicle carry may be lawful for eligible persons, but prohibited places, school property, and safe storage concerns still matter.",
          "GUIDANCE: Keep hands visible during police contact and do not leave firearms unsecured in vehicles."
        ],
        source: "Arkansas weapons law framework."
      },
      {
        title: "Federal Property / Post Offices",
        risk: "Federal Law Overlay",
        body: [
          "STATUTE / SOURCE: Federal facility and postal property framework.",
          "SUMMARY: Arkansas carry permission does not override federal restrictions.",
          "GUIDANCE: Federal buildings, federal courthouses, post offices, and secure federal property must be checked separately."
        ],
        source: "Federal facility and postal property framework."
      }
    ],
    [
      {
        title: "Arkansas Carry Checklist",
        steps: [
          "1. Confirm eligibility and carry authority.",
          "2. Check Ark. Code § 5-73-306 prohibited places.",
          "3. Identify whether enhanced endorsement applies.",
          "4. Check school property under § 5-73-119.",
          "5. Check public buildings under § 5-73-122.",
          "6. Check private signs and federal property."
        ]
      }
    ],
    [
      {
        title: "Enhanced Carry Assumption",
        summary: "Enhanced carry gives added authority in some places but not everywhere.",
        guidance: [
          "Check the specific statute.",
          "Check signs/notice.",
          "Do not assume enhanced equals unlimited."
        ]
      }
    ],
    [
      "Assuming Arkansas is unrestricted carry.",
      "Ignoring Ark. Code § 5-73-306 prohibited places.",
      "Assuming enhanced endorsement overrides all signs.",
      "Ignoring school property restrictions.",
      "Ignoring places of worship policy.",
      "Ignoring alcohol-related locations."
    ],
    [
      "Eligibility checked.",
      "Prohibited places checked.",
      "Enhanced endorsement status checked.",
      "School/public building rules checked.",
      "Private signs checked.",
      "Federal property checked."
    ],
    [
      {
        myth: "Arkansas enhanced carry means I can carry anywhere.",
        reality: "No. Enhanced endorsement can change some location rules, but signs, prohibited places, schools, private property, and federal law still matter."
      }
    ]
  ),

  ME: makeProfile(
    "Maine",
    "Law-Backed Ultra Expanded Travel State",
    "Maine allows permitless concealed carry for eligible persons, but the state has an important duty-to-inform rule for permitless carriers and still restricts schools, courthouses, certain state/federal properties, posted private property, vehicles, parks, and other sensitive locations. Michigan travelers should treat Maine as permissive but not unrestricted.",
    {
      reciprocity: "Maine has permitless carry for eligible persons, but permit recognition and documentation should still be verified for travel and reciprocity purposes.",
      permitlessCarry: "Maine allows eligible persons to carry concealed without a permit, subject to restrictions.",
      concealedCarry: "Maine concealed handgun permits remain available and may affect reciprocity and duty-to-inform context.",
      openCarry: "Open carry may be lawful for eligible persons, but location restrictions and public-contact realities still matter.",
      vehicleCarry: "Vehicle carry must be analyzed with Maine carry rules, prohibited places, and police-contact duties.",
      dutyToInform: "Maine State Police guidance says a person carrying concealed without a permit has a duty to immediately inform law enforcement during a routine stop, detention, or arrest.",
      privateSigns: "Posted private property and instructions to leave matter.",
      forceLaw: "Maine self-defense law is fact-specific."
    },
    [
      "Maine permitless carry has a specific police-contact duty for permitless concealed carriers.",
      "A Maine permit may still matter for reciprocity and documentation.",
      "Schools, courthouses, federal property, state/federal parks, posted private property, and vehicles require review.",
      "Travelers should not assume rural/permissive means no restrictions.",
      "If carrying without a permit and stopped/detained/arrested, duty-to-inform is a critical Maine issue."
    ],
    [
      {
        title: "Permitless Concealed Carry",
        risk: "Core Carry Rule",
        body: [
          "STATUTE / SOURCE: Maine concealed carry framework; Maine State Police concealed carry guidance.",
          "SUMMARY: Maine allows eligible persons to carry concealed handguns without a permit, subject to restrictions.",
          "GUIDANCE: Permitless carry does not override prohibited places, private property, federal property, or police-contact duties."
        ],
        source: "Maine State Police concealed carry guidance."
      },
      {
        title: "Duty to Inform for Permitless Carry",
        risk: "Police Contact Requirement",
        body: [
          "STATUTE / SOURCE: Maine State Police concealed carry guidance.",
          "SUMMARY: Maine State Police guidance states that an individual carrying a concealed handgun without a permit has a duty, during a routine stop, detention, or arrest, to immediately inform the law enforcement officer that the individual is carrying concealed.",
          "GUIDANCE: Recommended script: Officer, I am carrying concealed without a permit under Maine law. How would you like me to proceed? Keep hands visible and do not reach."
        ],
        source: "Maine State Police concealed carry guidance."
      },
      {
        title: "Concealed Handgun Permit",
        risk: "Permit / Reciprocity Context",
        body: [
          "STATUTE / SOURCE: Maine concealed handgun permit framework.",
          "SUMMARY: Maine still issues concealed handgun permits even though permitless carry exists.",
          "GUIDANCE: A permit may matter for reciprocity, documentation, and police-contact context when traveling."
        ],
        source: "Maine concealed handgun permit framework."
      },
      {
        title: "Schools",
        risk: "Extreme Risk Area",
        body: [
          "STATUTE / SOURCE: Maine school weapons framework.",
          "SUMMARY: Maine restricts firearms and dangerous weapons in schools and school-related areas subject to exceptions.",
          "GUIDANCE: School buildings, school grounds, buses, events, and parking areas should be treated as verify-first locations."
        ],
        source: "Maine school weapons law framework."
      },
      {
        title: "Courthouses / Court Facilities",
        risk: "Hard Stop Area",
        body: [
          "STATUTE / SOURCE: Maine court facility weapons framework.",
          "SUMMARY: Maine restricts weapons in courthouses and court facilities under court/security rules and applicable law.",
          "GUIDANCE: Do not approach courthouse security armed unless a clear legal exception applies."
        ],
        source: "Maine court facility weapons framework."
      },
      {
        title: "State Parks / Public Lands / Outdoors",
        risk: "Parks and Land Management Risk",
        body: [
          "STATUTE / SOURCE: Maine public land, park, and firearms framework.",
          "SUMMARY: Outdoor carry may involve state park rules, federal land rules, hunting regulations, camping rules, and private land access issues.",
          "GUIDANCE: Verify whether the land is state, federal, municipal, private, or tribal before relying on general carry rules."
        ],
        source: "Maine parks/public lands firearms framework."
      },
      {
        title: "Private Property / Posted Locations",
        risk: "Property Control",
        body: [
          "STATUTE / SOURCE: Maine property/trespass framework.",
          "SUMMARY: Private property owners may control access and require armed persons to leave.",
          "GUIDANCE: If posted or asked to leave, leave immediately. Do not debate policy at the doorway."
        ],
        source: "Maine property/trespass framework."
      },
      {
        title: "Vehicle Carry",
        risk: "Travel / Police Contact Risk",
        body: [
          "STATUTE / SOURCE: Maine carry and motor vehicle framework.",
          "SUMMARY: Vehicle carry may be lawful for eligible persons, but police contact, restricted locations, and safe storage remain important.",
          "GUIDANCE: If carrying concealed without a permit, remember Maine’s duty-to-inform guidance during a stop, detention, or arrest."
        ],
        source: "Maine carry and vehicle framework."
      },
      {
        title: "Federal Property / Post Offices",
        risk: "Federal Law Overlay",
        body: [
          "STATUTE / SOURCE: Federal facility and postal property framework.",
          "SUMMARY: Maine carry permission does not override federal restrictions.",
          "GUIDANCE: Federal buildings, federal courthouses, post offices, and secure federal property must be checked separately."
        ],
        source: "Federal facility and postal property framework."
      },
      {
        title: "Use of Force / Self-Defense",
        risk: "Fact-Specific Legal Risk",
        body: [
          "STATUTE / SOURCE: Maine self-defense framework.",
          "SUMMARY: Defensive force must be justified under the facts and applicable Maine law.",
          "GUIDANCE: Avoid confrontation, disengage if safe, call 911, request counsel, and avoid long statements under adrenaline."
        ],
        source: "Maine self-defense law framework."
      }
    ],
    [
      {
        title: "Maine Carry Checklist",
        steps: [
          "1. Confirm eligibility to carry.",
          "2. Determine whether carrying with or without a permit.",
          "3. If permitless, remember duty to inform during stop/detention/arrest.",
          "4. Check schools and courthouses.",
          "5. Check public lands, parks, federal land, and private property.",
          "6. Check federal property separately."
        ]
      }
    ],
    [
      {
        title: "Routine Traffic Stop While Permitless Carrying",
        summary: "Maine’s duty-to-inform rule is a major difference from many states.",
        guidance: [
          "Keep hands visible.",
          "Immediately inform if carrying concealed without a permit.",
          "Do not reach until instructed.",
          "Answer calmly."
        ]
      }
    ],
    [
      "Forgetting Maine's duty to inform when permitless carrying.",
      "Assuming permitless carry means no prohibited places.",
      "Ignoring schools and court facilities.",
      "Assuming state park rules equal federal land rules.",
      "Ignoring posted private property."
    ],
    [
      "Eligibility checked.",
      "Permit vs permitless status identified.",
      "Duty-to-inform plan ready.",
      "Schools/courts checked.",
      "Public/private/federal land status checked.",
      "Private signs checked."
    ],
    [
      {
        myth: "Maine permitless carry means I do not have to say anything during a stop.",
        reality: "Maine State Police guidance states permitless concealed carriers have a duty to immediately inform during a routine stop, detention, or arrest."
      }
    ]
  ),

  NH: makeProfile(
    "New Hampshire",
    "Law-Backed Ultra Expanded Travel State",
    "New Hampshire is a permitless carry state and one of the more permissive states in the Northeast, but members still need to understand eligibility, courthouses/courtrooms, schools/federal school-zone overlay, private property, vehicles, federal property, universities/colleges, and use-of-force conduct.",
    {
      reciprocity: "New Hampshire has permitless carry for eligible persons and also issues pistol/revolver licenses for reciprocity purposes.",
      permitlessCarry: "New Hampshire generally allows eligible persons to carry openly or concealed without a license.",
      concealedCarry: "New Hampshire pistol/revolver licenses remain available, mostly for reciprocity and documentation purposes.",
      openCarry: "Open carry may be lawful for eligible persons, but restricted locations and public-contact issues still matter.",
      vehicleCarry: "Vehicle carry is generally permissive for eligible persons, but police-contact behavior and restricted locations still matter.",
      dutyToInform: "Verify current New Hampshire police-contact rules. Keep hands visible and answer lawful questions truthfully.",
      privateSigns: "Private property and instructions to leave matter.",
      forceLaw: "New Hampshire self-defense law is fact-specific."
    },
    [
      "New Hampshire is permissive, but not restriction-free.",
      "Courthouses/courtrooms are a major New Hampshire restriction.",
      "Federal school-zone law, federal property, private property, and university policies still matter.",
      "A New Hampshire license may matter for reciprocity even if not required for in-state carry.",
      "Travelers should not treat New Hampshire as a no-rules state."
    ],
    [
      {
        title: "Permitless Carry / License Optional",
        risk: "Core Carry Rule",
        body: [
          "STATUTE / SOURCE: New Hampshire RSA Chapter 159 framework.",
          "SUMMARY: New Hampshire generally allows eligible persons to carry openly or concealed without a pistol/revolver license.",
          "GUIDANCE: Eligibility and restricted locations still matter. A license may still be useful for reciprocity outside New Hampshire."
        ],
        source: "New Hampshire RSA Chapter 159 framework."
      },
      {
        title: "Pistol / Revolver License",
        risk: "Reciprocity Context",
        body: [
          "STATUTE: RSA 159:6.",
          "SUMMARY: New Hampshire issues pistol/revolver licenses even though a license is generally not required for in-state carry by eligible persons.",
          "GUIDANCE: The license can matter for reciprocity and documentation when traveling outside New Hampshire."
        ],
        source: "RSA 159:6."
      },
      {
        title: "Courthouses / Courtrooms",
        risk: "Hard Stop Area",
        body: [
          "STATUTE: RSA 159:19.",
          "SUMMARY: New Hampshire restricts firearms and other dangerous weapons in courtrooms and areas used by a court.",
          "GUIDANCE: Do not enter courthouse/courtroom areas armed unless a clear legal exception applies."
        ],
        source: "RSA 159:19."
      },
      {
        title: "Schools / Federal School-Zone Overlay",
        risk: "School Zone Risk",
        body: [
          "STATUTE / SOURCE: Federal Gun-Free School Zones Act; New Hampshire school property policies/framework.",
          "SUMMARY: New Hampshire state law is generally permissive, but federal school-zone law and school policies may still apply.",
          "GUIDANCE: Schools, campuses, events, and parking areas should be checked carefully before carrying."
        ],
        source: "Federal school-zone framework; New Hampshire education/property rules."
      },
      {
        title: "Private Property / Posted Locations",
        risk: "Property Control",
        body: [
          "STATUTE / SOURCE: New Hampshire property/trespass framework.",
          "SUMMARY: Private property owners may control access and require armed persons to leave.",
          "GUIDANCE: Leave immediately if asked. Do not turn a carry issue into a trespass or disorderly conduct issue."
        ],
        source: "New Hampshire property/trespass framework."
      },
      {
        title: "Vehicle Carry",
        risk: "Travel / Police Contact Risk",
        body: [
          "STATUTE / SOURCE: New Hampshire RSA Chapter 159 framework.",
          "SUMMARY: New Hampshire vehicle carry is generally permissive for eligible persons, but restricted places and police-contact behavior still matter.",
          "GUIDANCE: During police contact, keep hands visible, do not reach, and answer lawful questions truthfully."
        ],
        source: "New Hampshire RSA Chapter 159 framework."
      },
      {
        title: "Federal Property / Post Offices",
        risk: "Federal Law Overlay",
        body: [
          "STATUTE / SOURCE: Federal facility and postal property framework.",
          "SUMMARY: New Hampshire carry permission does not override federal restrictions.",
          "GUIDANCE: Federal buildings, federal courthouses, post offices, and secure federal property must be checked separately."
        ],
        source: "Federal facility and postal property framework."
      },
      {
        title: "Colleges / Universities / Employer Rules",
        risk: "Policy Risk",
        body: [
          "STATUTE / SOURCE: New Hampshire property, campus, and employer policy framework.",
          "SUMMARY: Even where criminal law is permissive, campus, employer, and property policies can create removal, discipline, or access consequences.",
          "GUIDANCE: Verify campus or employer policy separately from criminal carry law."
        ],
        source: "New Hampshire property/campus/employer framework."
      },
      {
        title: "Use of Force / Self-Defense",
        risk: "Fact-Specific Legal Risk",
        body: [
          "STATUTE / SOURCE: New Hampshire self-defense framework.",
          "SUMMARY: Defensive force must be justified under the facts and applicable New Hampshire law.",
          "GUIDANCE: Avoid escalation, call 911 when safe, identify evidence/witnesses if necessary, request counsel, and avoid detailed statements under stress."
        ],
        source: "New Hampshire self-defense law framework."
      }
    ],
    [
      {
        title: "New Hampshire Carry Checklist",
        steps: [
          "1. Confirm eligibility to possess/carry.",
          "2. Check courthouse/courtroom areas under RSA 159:19.",
          "3. Check federal school-zone issues.",
          "4. Check private property and workplace/campus policies.",
          "5. Check federal property separately.",
          "6. Consider whether a pistol/revolver license is needed for reciprocity outside New Hampshire."
        ]
      }
    ],
    [
      {
        title: "Courthouse Errand",
        summary: "New Hampshire is permissive, but court areas are a hard-stop issue.",
        guidance: [
          "Check RSA 159:19.",
          "Do not approach court security armed.",
          "Secure lawfully before arrival."
        ]
      }
    ],
    [
      "Assuming permitless carry means no restricted places.",
      "Ignoring courthouse/courtroom restrictions.",
      "Ignoring federal school-zone issues.",
      "Ignoring private property instructions.",
      "Ignoring campus or employer policies."
    ],
    [
      "Eligibility checked.",
      "Court restrictions checked.",
      "School/federal overlay checked.",
      "Private property checked.",
      "Federal property checked.",
      "Reciprocity/license needs checked."
    ],
    [
      {
        myth: "New Hampshire has permitless carry, so there are no restrictions.",
        reality: "No. Courthouses, federal property, school-zone overlays, private property, and policy restrictions still matter."
      }
    ]
  ),

  VT: makeProfile(
    "Vermont",
    "Law-Backed Ultra Expanded Travel State",
    "Vermont is a constitutional carry state and does not issue carry permits for ordinary defensive carry, but members still need to understand school building/school bus restrictions, court/security rules, intent-based weapon offenses, private property, vehicles, federal property, parks/public lands, and the limits of permitless carry when traveling into other states.",
    {
      reciprocity: "Vermont does not issue ordinary carry permits. Reciprocity generally matters when traveling out of Vermont, not for carrying in Vermont.",
      permitlessCarry: "Vermont allows eligible persons to carry without a permit, subject to restrictions.",
      concealedCarry: "No Vermont carry permit is generally required or issued for ordinary carry by law-abiding eligible persons.",
      openCarry: "Open carry may be lawful for eligible persons, but restricted locations and conduct still matter.",
      vehicleCarry: "Vehicle carry should be analyzed with Vermont weapons law, school restrictions, and safe storage concerns.",
      dutyToInform: "Verify current Vermont police-contact rules. Keep hands visible and answer lawful questions truthfully.",
      privateSigns: "Private property and instructions to leave matter.",
      forceLaw: "Vermont self-defense law is fact-specific."
    },
    [
      "Vermont is permissive, but not no-rules.",
      "Vermont does not issue ordinary carry permits, so reciprocity has special meaning for travelers.",
      "School buildings and school buses have specific statutory restrictions.",
      "Court facilities, federal property, private property, and employer/campus policies still matter.",
      "Intent-based weapon offenses can matter if conduct appears threatening or unlawful."
    ],
    [
      {
        title: "Permitless Carry / No Ordinary Permit System",
        risk: "Core Carry Rule",
        body: [
          "STATUTE / SOURCE: Vermont firearms law framework.",
          "SUMMARY: Vermont generally allows eligible persons to carry without a permit and does not issue ordinary concealed carry permits for reciprocity-style carry.",
          "GUIDANCE: Permitless carry still requires eligibility and compliance with restricted-location and conduct laws."
        ],
        source: "Vermont firearms law framework."
      },
      {
        title: "School Buildings and School Buses",
        risk: "Extreme Risk Area",
        body: [
          "STATUTE: 13 V.S.A. § 4004.",
          "SUMMARY: Vermont law restricts possessing a firearm or dangerous/deadly weapon within a school building or on a school bus.",
          "GUIDANCE: Schools, school buses, school events, and school-controlled areas should be treated as verify-first locations."
        ],
        source: "13 V.S.A. § 4004."
      },
      {
        title: "Intent-Based Weapon Offenses",
        risk: "Conduct / Threat Risk",
        body: [
          "STATUTE: 13 V.S.A. § 4003.",
          "SUMMARY: Vermont law addresses carrying a dangerous or deadly weapon with intent to injure another.",
          "GUIDANCE: Lawful carry can become criminal exposure if the facts show threats, intimidation, unlawful intent, or escalation."
        ],
        source: "13 V.S.A. § 4003."
      },
      {
        title: "Courthouses / Court Facilities",
        risk: "Hard Stop Area",
        body: [
          "STATUTE / SOURCE: Vermont court/security weapons framework.",
          "SUMMARY: Vermont court facilities and security-controlled judicial locations may restrict weapons by statute, court rule, or security order.",
          "GUIDANCE: Do not approach court security armed unless a clear legal exception applies."
        ],
        source: "Vermont court/security weapons framework."
      },
      {
        title: "Private Property / Posted Locations",
        risk: "Property Control",
        body: [
          "STATUTE / SOURCE: Vermont property/trespass framework.",
          "SUMMARY: Private property owners may control access and require armed persons to leave.",
          "GUIDANCE: If posted or asked to leave, leave immediately. Do not debate firearm policy at the doorway."
        ],
        source: "Vermont property/trespass framework."
      },
      {
        title: "Vehicle Carry / Storage",
        risk: "Vehicle / Storage Risk",
        body: [
          "STATUTE / SOURCE: Vermont firearms and vehicle framework.",
          "SUMMARY: Vehicle carry may be lawful for eligible persons, but schools, private property, safe storage, and police-contact behavior still matter.",
          "GUIDANCE: Avoid leaving firearms unsecured in vehicles and keep hands visible during police contact."
        ],
        source: "Vermont firearms and vehicle framework."
      },
      {
        title: "Public Lands / Outdoor Activity",
        risk: "Hunting / Land Management Risk",
        body: [
          "STATUTE / SOURCE: Vermont hunting, public land, and firearms framework.",
          "SUMMARY: Outdoor carry can involve hunting rules, park rules, private land permission, state land, federal land, and seasonal restrictions.",
          "GUIDANCE: Verify whether the location is state, federal, municipal, private, or tribal land before relying on general carry assumptions."
        ],
        source: "Vermont public lands and hunting/firearms framework."
      },
      {
        title: "Federal Property / Post Offices",
        risk: "Federal Law Overlay",
        body: [
          "STATUTE / SOURCE: Federal facility and postal property framework.",
          "SUMMARY: Vermont carry permission does not override federal restrictions.",
          "GUIDANCE: Federal buildings, federal courthouses, post offices, and secure federal property must be checked separately."
        ],
        source: "Federal facility and postal property framework."
      },
      {
        title: "Use of Force / Self-Defense",
        risk: "Fact-Specific Legal Risk",
        body: [
          "STATUTE / SOURCE: Vermont self-defense framework.",
          "SUMMARY: Defensive force must be justified under the facts and applicable Vermont law.",
          "GUIDANCE: Avoid escalation, call 911 when safe, identify evidence/witnesses if necessary, request counsel, and avoid detailed statements under stress."
        ],
        source: "Vermont self-defense law framework."
      }
    ],
    [
      {
        title: "Vermont Carry Checklist",
        steps: [
          "1. Confirm eligibility to possess/carry.",
          "2. Check 13 V.S.A. § 4004 school building/school bus restrictions.",
          "3. Avoid threatening or intent-based conduct under § 4003.",
          "4. Check court/security-controlled facilities.",
          "5. Check private property and federal property.",
          "6. Check land status for outdoor activity."
        ]
      }
    ],
    [
      {
        title: "Ski Trip / Rural Travel",
        summary: "Vermont is permissive, but hotels, private property, federal land, and school areas can still create restrictions.",
        guidance: [
          "Check private property policy.",
          "Check school/campus areas.",
          "Check federal land separately.",
          "Avoid threatening display."
        ]
      }
    ],
    [
      "Assuming constitutional carry means no prohibited places.",
      "Ignoring school building/school bus restrictions.",
      "Ignoring intent-based weapon offenses.",
      "Ignoring private property instructions.",
      "Assuming Vermont issues permits for reciprocity.",
      "Ignoring federal property."
    ],
    [
      "Eligibility checked.",
      "School restrictions checked.",
      "Intent/threat risk understood.",
      "Court/private/federal property checked.",
      "Outdoor land status checked."
    ],
    [
      {
        myth: "Vermont constitutional carry means there are no firearm laws.",
        reality: "No. Vermont still restricts schools, threatening/intent-based conduct, courts/security locations, private property, federal property, and other specific situations."
      }
    ]
  ),

  AK: makeProfile(
    "Alaska",
    "Law-Backed Ultra Expanded Travel State",
    "Alaska is a high-value travel and outdoor state for Michigan CPL holders because it has broad permitless carry for eligible adults, but it also has important restrictions involving age, prohibited persons, police-contact duties, schools, courts, domestic violence shelters, child care facilities, federal lands, tribal/local property, aircraft/ferry travel, vehicle storage, and wildlife/public-land contexts.",
    {
      reciprocity: "Alaska is treated as recognized / lawful for Michigan CPL travel in this app because Alaska has broad permitless carry and recognizes permits from other states, but Alaska law controls while physically in Alaska.",
      permitlessCarry: "Alaska generally allows eligible adults 21+ who may lawfully possess firearms to carry without a permit, subject to Alaska restrictions.",
      concealedCarry: "Alaska has permitless concealed carry for eligible adults, with an optional concealed handgun permit system under AS 18.65.700.",
      openCarry: "Open carry is generally lawful for eligible adults, but restricted places, police contact, threatening conduct, and property rules still matter.",
      vehicleCarry: "Vehicle carry is generally permissive for eligible adults, but schools, federal property, ferry/airline rules, private property, and wildlife/public-land rules require separate review.",
      dutyToInform: "Alaska has police-contact duties for concealed carry. Treat official law-enforcement contact as an immediate disclosure/visible-hands situation.",
      privateSigns: "Private property owners may control access. Leave immediately if asked.",
      forceLaw: "Alaska self-defense law is fact-specific. Force must still be justified under the facts."
    },
    [
      "Alaska permitless carry does not mean carry everywhere.",
      "Outdoor travel, ferries, aircraft, national parks, wildlife areas, tribal/local property, and remote lodging create special legal and practical issues.",
      "Police-contact duties should be treated seriously because Alaska has concealment-related notification language.",
      "Federal property and federal land buildings are separate from Alaska state carry permission.",
      "Travelers should verify current Alaska law and official state guidance before relying on any summary."
    ],
    [
      {
        title: "Permitless Carry / Concealed Carry Authority",
        risk: "Core Carry Rule",
        body: [
          "STATUTE / SOURCE: Alaska weapons law framework; optional permit system under AS 18.65.700.",
          "SUMMARY: Alaska generally allows eligible adults to carry concealed without a permit, and Alaska maintains an optional concealed handgun permit system for people who want a credential for reciprocity or other purposes.",
          "GUIDANCE: Do not teach Alaska as ruleless. The user must still be old enough, legally eligible, not prohibited, not in a restricted place, and not using the firearm unlawfully."
        ],
        source: "AS 18.65.700; Alaska weapons law framework."
      },
      {
        title: "Optional Alaska Concealed Handgun Permit",
        risk: "License / Reciprocity Context",
        body: [
          "STATUTE: AS 18.65.700.",
          "SUMMARY: Alaska law provides a process for the Department of Public Safety to issue concealed handgun permits to qualified applicants.",
          "GUIDANCE: Even where Alaska permitless carry is available, an optional permit may matter for travel to other states, documentation, and reciprocity."
        ],
        source: "AS 18.65.700."
      },
      {
        title: "Age / Eligibility / Prohibited Persons",
        risk: "Disqualification Risk",
        body: [
          "STATUTE / SOURCE: Alaska weapons eligibility and prohibited-person framework.",
          "SUMMARY: Permitless carry does not apply to people who are legally prohibited from possessing firearms under state or federal law.",
          "GUIDANCE: Domestic violence restrictions, court orders, felony history, mental health restrictions, intoxication, and federal prohibitions should be checked before carrying."
        ],
        source: "Alaska weapons law and federal prohibited-person framework."
      },
      {
        title: "Police Contact / Duty to Inform",
        risk: "Officer Safety / Compliance Risk",
        body: [
          "STATUTE / SOURCE: Alaska concealed carry and law-enforcement contact framework.",
          "SUMMARY: Alaska has notification-style obligations connected to carrying concealed during official law-enforcement contact.",
          "GUIDANCE: Treat Alaska police contact as an immediate visible-hands and disclosure situation. Suggested language: Officer, I am lawfully carrying. How would you like me to proceed?"
        ],
        source: "Alaska concealed carry law-enforcement contact framework."
      },
      {
        title: "Schools / School Property",
        risk: "Extreme Risk Area",
        body: [
          "STATUTE / SOURCE: Alaska misconduct involving weapons and school-location framework.",
          "SUMMARY: Alaska restricts firearms in certain school-related locations and educational settings, subject to exceptions.",
          "GUIDANCE: School buildings, school grounds, school events, school buses, and parking situations should be treated as verify-first areas."
        ],
        source: "Alaska misconduct involving weapons / school property framework."
      },
      {
        title: "Courts / Courthouses / Justice Facilities",
        risk: "Hard Stop Area",
        body: [
          "STATUTE / SOURCE: Alaska court/security facility framework.",
          "SUMMARY: Court facilities, law-enforcement-controlled buildings, and security-screened government facilities may prohibit weapons regardless of general carry permission.",
          "GUIDANCE: Do not approach a courthouse or security checkpoint armed unless a clear legal exception applies."
        ],
        source: "Alaska court and security facility framework."
      },
      {
        title: "Child Care Facilities / Domestic Violence Shelters",
        risk: "Sensitive Location Risk",
        body: [
          "STATUTE / SOURCE: Alaska sensitive-location framework.",
          "SUMMARY: Alaska law and facility rules may restrict weapons in sensitive facilities such as child care facilities or domestic violence/shelter settings.",
          "GUIDANCE: Treat shelters, child care facilities, and social-service facilities as verify-first locations and follow posted/property rules."
        ],
        source: "Alaska sensitive-location and property framework."
      },
      {
        title: "Federal Lands, National Parks, Post Offices, and Federal Buildings",
        risk: "Federal Law Overlay",
        body: [
          "STATUTE / SOURCE: Federal facility and federal public-land framework.",
          "SUMMARY: Alaska has significant federal land, but state carry permission does not override federal building, post office, courthouse, airport, or secure-facility restrictions.",
          "GUIDANCE: In national parks, federal buildings and visitor centers must be checked separately. Post offices and secure federal facilities are not controlled by Alaska permitless carry."
        ],
        source: "Federal facility, postal property, and National Park Service firearms framework."
      },
      {
        title: "Air Travel, Ferries, Cruise Ships, and Remote Transport",
        risk: "Transportation-Specific Risk",
        body: [
          "STATUTE / SOURCE: Federal aviation/TSA rules, maritime/ferry operator rules, and Alaska transport framework.",
          "SUMMARY: Airline, ferry, cruise, and remote transport rules may restrict carry or require separate locked/unloaded transport procedures.",
          "GUIDANCE: Do not assume Alaska permitless carry applies on aircraft, cruise ships, ferries, port facilities, or private carriers. Verify before travel."
        ],
        source: "TSA/firearm transport framework; carrier and maritime transport rules."
      },
      {
        title: "Hunting, Fishing, Wildlife, and Public Lands",
        risk: "DNR / Wildlife Law Overlay",
        body: [
          "STATUTE / SOURCE: Alaska fish and game/public-land framework.",
          "SUMMARY: Carry for personal protection does not replace hunting, fishing, wildlife, seasons, species, guide, transport, or land-management rules.",
          "GUIDANCE: If the trip involves hunting, fishing, bear country, boats, ATVs, guides, aircraft, or public land, check fish/game and land-management rules separately."
        ],
        source: "Alaska fish and game/public-land framework."
      },
      {
        title: "Use of Force / Self-Defense",
        risk: "Fact-Specific Legal Risk",
        body: [
          "STATUTE / SOURCE: Alaska self-defense law framework.",
          "SUMMARY: Alaska self-defense law is fact-specific and depends on threat, necessity, proportionality, and reasonableness.",
          "GUIDANCE: Avoid confrontation when safe, call 911 when possible, preserve evidence/witness information, request counsel, and do not give long emotional statements under stress."
        ],
        source: "Alaska self-defense law framework."
      }
    ],
    [
      {
        title: "Alaska Travel Checklist",
        steps: [
          "1. Confirm age and legal eligibility.",
          "2. Confirm school/sensitive-location status.",
          "3. Check federal land/building rules.",
          "4. Check ferry, cruise, airport, and carrier rules.",
          "5. Check hunting/fishing/public-land rules.",
          "6. Know the law-enforcement disclosure script."
        ]
      }
    ],
    [
      {
        title: "Remote Outdoor Trip",
        summary: "Alaska travel often involves federal land, guides, boats, aircraft, wildlife areas, and remote lodging.",
        guidance: [
          "Check who controls the land or facility.",
          "Verify airline/ferry/cruise rules.",
          "Check fish and game rules separately.",
          "Do not assume permitless carry applies everywhere."
        ]
      }
    ],
    [
      "Assuming Alaska permitless carry means no prohibited places.",
      "Ignoring police-contact disclosure duties.",
      "Ignoring federal buildings on federal land.",
      "Ignoring ferries, aircraft, and cruise restrictions.",
      "Ignoring wildlife, hunting, or public-land rules."
    ],
    [
      "Age and eligibility checked.",
      "Police-contact script ready.",
      "School/sensitive locations checked.",
      "Federal property checked.",
      "Transport carrier rules checked.",
      "Outdoor land/fish/game rules checked."
    ],
    [
      {
        myth: "Alaska is permitless, so there are no rules.",
        reality: "No. Alaska is permissive, but age, eligibility, schools, sensitive locations, police-contact duties, federal property, transportation rules, and outdoor regulations still matter."
      }
    ]
  ),

  HI: makeProfile(
    "Hawaii",
    "Law-Backed Ultra Expanded High-Risk Travel State",
    "Hawaii is a high-risk non-recognition travel state for Michigan CPL holders. Hawaii does not provide broad out-of-state carry reciprocity, requires a Hawaii license to carry, has strict firearm registration and transport rules, and has detailed sensitive-place, disclosure, private-property, vehicle-storage, and carry-conduct requirements under Chapter 134.",
    {
      reciprocity: "Michigan CPL is treated as not recognized for ordinary carry in Hawaii in this app travel engine. A Hawaii-issued license is required for carry.",
      permitlessCarry: "No permitless carry. Hawaii requires a license under HRS § 134-9 for public carry.",
      concealedCarry: "HRS § 134-9 governs Hawaii licenses to carry pistols or revolvers concealed on the person.",
      openCarry: "HRS § 134-9 separately addresses unconcealed carry licensing and imposes additional criteria.",
      vehicleCarry: "Hawaii transport and vehicle rules are strict. Carrying loaded or accessible firearms without proper authority can create serious felony risk.",
      dutyToInform: "HRS § 134-9.2 imposes license-possession and disclosure duties for licensees.",
      privateSigns: "HRS § 134-9.5 restricts carrying or possessing firearms on private property of another without authorization.",
      forceLaw: "Hawaii self-defense law is fact-specific and should be verified from current statutes/case law."
    },
    [
      "Hawaii should be treated as a non-recognition/high-risk travel state for Michigan CPL holders.",
      "A Michigan CPL does not authorize public carry in Hawaii.",
      "Hawaii requires registration and tightly controls transport, carry licensing, sensitive places, private property, and vehicle storage.",
      "Hawaii law has recently changed and continues to be litigated in federal courts, especially private-property carry restrictions.",
      "Travelers should verify current Hawaii law and county police/firearms instructions before bringing any firearm into the state."
    ],
    [
      {
        title: "No Michigan CPL Reciprocity / Hawaii License Required",
        risk: "Do Not Carry on Michigan CPL",
        body: [
          "STATUTE: HRS § 134-9.",
          "SUMMARY: Hawaii licenses to carry are issued by the chief of police of a county to qualified applicants under Hawaii law. Hawaii does not treat a Michigan CPL as public carry authority.",
          "GUIDANCE: Do not carry in Hawaii on a Michigan CPL alone. Verify county police requirements before bringing or possessing a firearm."
        ],
        source: "HRS § 134-9."
      },
      {
        title: "Hawaii License to Carry Eligibility",
        risk: "License / Eligibility Rule",
        body: [
          "STATUTE: HRS § 134-9.",
          "SUMMARY: Hawaii concealed carry licensing requires statutory eligibility, background checks, training, registration, age 21+, and other criteria. Unconcealed carry has separate statutory requirements.",
          "GUIDANCE: Hawaii carry licensing is not a tourist-friendly reciprocity system. Michigan members should assume no carry unless they have Hawaii-issued authority."
        ],
        source: "HRS § 134-9."
      },
      {
        title: "Registration / Possession Basics",
        risk: "Registration and Transport Risk",
        body: [
          "STATUTE / SOURCE: HRS Chapter 134 registration and possession framework.",
          "SUMMARY: Hawaii regulates firearm registration, possession, and transport more strictly than most states.",
          "GUIDANCE: Anyone bringing a firearm to Hawaii should review county police registration procedures before arrival. Do not assume airline check-in compliance equals Hawaii legal possession."
        ],
        source: "HRS Chapter 134; county police firearms registration guidance."
      },
      {
        title: "Sensitive Places / Prohibited Locations",
        risk: "Major Carry Restriction",
        body: [
          "STATUTE: HRS § 134-9.1.",
          "SUMMARY: Hawaii law prohibits carrying or possessing firearms in certain locations and premises, subject to statutory language and ongoing litigation considerations.",
          "GUIDANCE: Treat schools, government buildings, courts, bars/restaurants serving alcohol, parks/beaches, public transportation, and other sensitive places as verify-first/no-carry areas unless current law clearly permits otherwise."
        ],
        source: "HRS § 134-9.1; Hawaii Act 52 framework."
      },
      {
        title: "License Possession and Duty to Disclose",
        risk: "Police Contact Requirement",
        body: [
          "STATUTE: HRS § 134-9.2.",
          "SUMMARY: Hawaii imposes duties to maintain possession of the carry license while carrying and to disclose information when stopped by law enforcement.",
          "GUIDANCE: Hawaii licensees should keep license/ID on person and disclose calmly during police contact. Michigan CPL alone is not enough."
        ],
        source: "HRS § 134-9.2."
      },
      {
        title: "Unsecured Firearm in Vehicle",
        risk: "Vehicle Storage Risk",
        body: [
          "STATUTE: HRS § 134-9.3.",
          "SUMMARY: Hawaii law addresses leaving unsecured firearms in unattended vehicles.",
          "GUIDANCE: Do not leave firearms loose in rental cars, hotel valet situations, beach parking lots, or tourist areas. Vehicle storage is a major theft and criminal exposure point."
        ],
        source: "HRS § 134-9.3."
      },
      {
        title: "Unlawful Conduct While Carrying",
        risk: "Conduct-Based Risk",
        body: [
          "STATUTE: HRS § 134-9.4.",
          "SUMMARY: Hawaii imposes penalties for unlawful conduct while carrying a firearm.",
          "GUIDANCE: Carry, if lawfully licensed, must be paired with sober, restrained, non-threatening conduct. Avoid arguments, alcohol, road rage, and any display not tied to a lawful imminent threat."
        ],
        source: "HRS § 134-9.4."
      },
      {
        title: "Private Property Requires Authorization",
        risk: "Private Property Trap",
        body: [
          "STATUTE: HRS § 134-9.5.",
          "SUMMARY: Hawaii restricts carrying or possessing a firearm on private property of another person without authorization. The private-property rule has also been the subject of federal litigation.",
          "GUIDANCE: Do not carry into hotels, stores, restaurants, rental properties, businesses, or other private property unless current law and property authorization clearly allow it."
        ],
        source: "HRS § 134-9.5; ongoing federal litigation regarding Hawaii private-property carry restrictions."
      },
      {
        title: "Failure to Conceal",
        risk: "Concealment Compliance Risk",
        body: [
          "STATUTE: HRS § 134-9.7.",
          "SUMMARY: Hawaii imposes penalties for failure to conceal by a concealed carry licensee.",
          "GUIDANCE: If a person has a Hawaii concealed carry license, accidental exposure can create legal risk. Carry method and cover garment discipline matter."
        ],
        source: "HRS § 134-9.7."
      },
      {
        title: "Air Travel / Inter-Island Travel / Hotels",
        risk: "Travel Logistics Risk",
        body: [
          "STATUTE / SOURCE: TSA/firearm transport rules and Hawaii county police registration/transport framework.",
          "SUMMARY: Airline transport, inter-island travel, hotels, rental cars, and police registration procedures create separate compliance issues.",
          "GUIDANCE: Plan firearm travel before arrival. Do not bring a firearm unless you understand airline, Hawaii registration, transport, hotel, rental vehicle, and storage requirements."
        ],
        source: "TSA firearm transport framework; Hawaii county police firearms procedures."
      },
      {
        title: "Federal Property / Military Installations / National Parks",
        risk: "Federal Law Overlay",
        body: [
          "STATUTE / SOURCE: Federal facility, military installation, postal property, and National Park Service framework.",
          "SUMMARY: Hawaii has military bases, federal buildings, national parks, ports, airports, and federal property where state carry permission does not control.",
          "GUIDANCE: Treat federal property as separate. Do not rely on any state carry permission for military bases, post offices, secure federal buildings, or airport sterile areas."
        ],
        source: "Federal facility, postal, military installation, TSA, and NPS firearms framework."
      },
      {
        title: "Use of Force / Civil Exposure",
        risk: "Fact-Specific Legal Risk",
        body: [
          "STATUTE / SOURCE: Hawaii self-defense and civil-liability framework, including HRS § 663-9.5 noted in carry-license affidavit language.",
          "SUMMARY: Hawaii carry-license law requires applicants to acknowledge firearm-use laws and liability concepts. Unjustified discharge can create severe criminal and civil consequences.",
          "GUIDANCE: Avoid conflict, call 911, identify evidence/witnesses, request counsel, and avoid detailed statements under stress."
        ],
        source: "HRS § 134-9; HRS § 663-9.5 reference in carry-license affidavit framework."
      }
    ],
    [
      {
        title: "Hawaii Travel Checklist",
        steps: [
          "1. Do not rely on Michigan CPL.",
          "2. Verify Hawaii licensing and county police procedures.",
          "3. Verify registration requirements before bringing a firearm.",
          "4. Check HRS §§ 134-9.1 through 134-9.7.",
          "5. Check hotel/rental/private-property authorization.",
          "6. Check federal/military/airport/park rules separately."
        ]
      }
    ],
    [
      {
        title: "Vacation / Hotel / Rental Car Scenario",
        summary: "Hawaii firearm travel is not like a mainland road trip. Licensing, registration, transport, hotel/private property, vehicle storage, and federal/military property can all create risk.",
        guidance: [
          "Do not rely on Michigan CPL.",
          "Check county police registration before arrival.",
          "Do not leave firearms unsecured in rental vehicles.",
          "Check hotel/private-property authorization."
        ]
      }
    ],
    [
      "Assuming Michigan CPL works in Hawaii.",
      "Ignoring firearm registration requirements.",
      "Ignoring HRS § 134-9.5 private-property authorization rules.",
      "Leaving a firearm unsecured in a rental car.",
      "Ignoring sensitive-place restrictions and federal/military property."
    ],
    [
      "No-reciprocity warning understood.",
      "Hawaii license/registration requirements checked.",
      "Sensitive places checked.",
      "Private property authorization checked.",
      "Vehicle storage rules checked.",
      "Federal/military/airport rules checked."
    ],
    [
      {
        myth: "I can carry in Hawaii because I have a Michigan CPL.",
        reality: "No. Hawaii is treated as a non-recognition state in this app. Hawaii public carry requires Hawaii authority and compliance with Chapter 134."
      }
    ]
  ),

  WA: makeProfile(
    "Washington",
    "Law-Backed Ultra Expanded Travel State",
    "Washington is a priority correction state because the Washington Attorney General lists Michigan as meeting Washington reciprocity requirements, while many other states are not recognized. Washington still has important restrictions involving concealed pistol licensing, vehicle carry, loaded pistols, schools, courthouses, child care premises, voting facilities, government/legislative locations, demonstrations, private property, federal property, and use-of-force conduct.",
    {
      reciprocity: "Washington Attorney General lists Michigan as recognized / meeting Washington requirements, but Michigan CPL holders must follow Washington law while physically in Washington.",
      permitlessCarry: "No general permitless concealed pistol carry. Concealed pistol carry generally requires a Washington CPL or a recognized out-of-state license.",
      concealedCarry: "RCW 9.41.050 governs carrying pistols and concealed pistol carry, including loaded pistols in vehicles.",
      openCarry: "Open carry may be lawful in some contexts, but Washington restricts open carry in specific places and circumstances.",
      vehicleCarry: "RCW 9.41.050(2)(a): loaded pistol in a vehicle generally requires a license and specific conditions.",
      dutyToInform: "Washington does not use Michigan’s exact immediate-disclosure rule, but police-contact behavior still matters. Keep hands visible and answer lawful questions truthfully.",
      privateSigns: "Private property owners may control access. Leave immediately if asked.",
      forceLaw: "Washington self-defense law is fact-specific. Force must be justified under the circumstances."
    },
    [
      "Washington officially lists Michigan as recognized for Washington CPL reciprocity purposes.",
      "Recognition does not override Washington restricted places, vehicle rules, school rules, federal property, or private property.",
      "Loaded pistol vehicle rules are a major Washington travel issue.",
      "Schools, child care premises, voting facilities, courts, capitol/municipal buildings, and demonstrations require special caution.",
      "Michigan members should be warned that Washington does not recognize many other states, so reciprocity must be checked permit-by-permit."
    ],
    [
      {
        title: "Michigan CPL Recognition in Washington",
        risk: "Reciprocity Rule",
        body: [
          "STATUTE / SOURCE: Washington Attorney General reciprocity list; RCW 9.41.073 framework.",
          "SUMMARY: Washington Attorney General’s reciprocity page lists Michigan as meeting Washington requirements for recognition.",
          "GUIDANCE: Treat Michigan CPL as recognized in Washington, but Washington law controls all conduct while physically in the state."
        ],
        source: "Washington Attorney General Concealed Pistol License Reciprocity; RCW 9.41.073 framework."
      },
      {
        title: "Concealed Pistol Carry / License Requirement",
        risk: "Core Carry Rule",
        body: [
          "STATUTE: RCW 9.41.050.",
          "SUMMARY: Washington law regulates carrying pistols and concealed pistol carry. Concealed carry generally requires a Washington CPL or recognized out-of-state license.",
          "GUIDANCE: Do not treat Washington as permitless concealed carry. Carry permit/ID documentation and verify current recognition before travel."
        ],
        source: "RCW 9.41.050."
      },
      {
        title: "Loaded Pistol in Vehicle",
        risk: "High-Risk Vehicle Rule",
        body: [
          "STATUTE: RCW 9.41.050(2)(a).",
          "SUMMARY: A person generally may not carry or place a loaded pistol in a vehicle unless licensed and one of the statutory conditions is met, such as the pistol being on the licensee's person, the licensee being in the vehicle, or the pistol being locked in the vehicle and concealed from view when the licensee is away.",
          "GUIDANCE: Washington vehicle carry is not casual. Keep the permit/ID available, avoid reaching during stops, and secure the firearm properly if leaving the vehicle."
        ],
        source: "RCW 9.41.050(2)(a)."
      },
      {
        title: "School Facilities",
        risk: "Extreme Risk Area",
        body: [
          "STATUTE: RCW 9.41.280.",
          "SUMMARY: Washington prohibits possessing firearms and other dangerous weapons on public or private elementary or secondary school premises, school-provided transportation, and areas used exclusively by schools, subject to statutory exceptions.",
          "GUIDANCE: School pickup, school events, parking lots, and school meetings should be treated as verify-first areas."
        ],
        source: "RCW 9.41.280."
      },
      {
        title: "Child Care Premises",
        risk: "Sensitive Location Risk",
        body: [
          "STATUTE: RCW 9.41.282.",
          "SUMMARY: Washington restricts dangerous weapons on child care premises, subject to statutory exceptions.",
          "GUIDANCE: Treat child care centers, daycare-related facilities, and child care premises as verify-first/no-carry areas unless a clear exception applies."
        ],
        source: "RCW 9.41.282."
      },
      {
        title: "Voting Facilities",
        risk: "Election Location Risk",
        body: [
          "STATUTE: RCW 9.41.284.",
          "SUMMARY: Washington restricts dangerous weapons at voting facilities, subject to statutory language and exceptions.",
          "GUIDANCE: Ballot drop sites, vote centers, election offices, and voting facilities should be checked before carrying."
        ],
        source: "RCW 9.41.284."
      },
      {
        title: "Weapons Prohibited in Certain Places",
        risk: "Major Location Restriction",
        body: [
          "STATUTE: RCW 9.41.300.",
          "SUMMARY: Washington prohibits weapons in certain places and addresses local laws/ordinances and exceptions under the statutory framework.",
          "GUIDANCE: Check jails, law-enforcement facilities, court-related spaces, mental health facilities, restricted government areas, and other listed locations before entering."
        ],
        source: "RCW 9.41.300."
      },
      {
        title: "Open Carry at Capitol Grounds / Municipal Buildings / Demonstrations",
        risk: "Public Event / Government Location Risk",
        body: [
          "STATUTE: RCW 9.41.305.",
          "SUMMARY: Washington restricts open carry of weapons on state capitol grounds and municipal buildings under specified circumstances.",
          "GUIDANCE: Protests, public hearings, municipal buildings, capitol grounds, and permitted demonstrations should be treated as high-risk areas."
        ],
        source: "RCW 9.41.305."
      },
      {
        title: "Private Property / Posted Locations",
        risk: "Property Control",
        body: [
          "STATUTE / SOURCE: Washington property and trespass framework.",
          "SUMMARY: Private property owners may control access and require armed persons to leave.",
          "GUIDANCE: If posted or asked to leave, leave immediately. Do not argue with staff or security."
        ],
        source: "Washington property/trespass framework."
      },
      {
        title: "Federal Property / Post Offices / Military Installations",
        risk: "Federal Law Overlay",
        body: [
          "STATUTE / SOURCE: Federal facility, postal property, and military installation framework.",
          "SUMMARY: Washington recognition of a Michigan CPL does not override federal property restrictions.",
          "GUIDANCE: Federal buildings, post offices, federal courthouses, military bases, secure port/airport areas, and federal facilities must be checked separately."
        ],
        source: "Federal facility, postal property, military installation, and TSA framework."
      },
      {
        title: "Use of Force / Self-Defense",
        risk: "Fact-Specific Legal Risk",
        body: [
          "STATUTE / SOURCE: Washington self-defense law framework.",
          "SUMMARY: Washington self-defense law is fact-specific and depends on necessity, reasonableness, and the circumstances.",
          "GUIDANCE: Avoid confrontation, disengage when safe, call 911, identify evidence/witnesses if necessary, request counsel, and avoid long statements under stress."
        ],
        source: "Washington self-defense law framework."
      }
    ],
    [
      {
        title: "Washington Carry Checklist",
        steps: [
          "1. Verify Michigan CPL recognition using Washington AG list.",
          "2. Check RCW 9.41.050 for concealed/vehicle carry.",
          "3. Check RCW 9.41.280 school facilities.",
          "4. Check RCW 9.41.282 child care premises.",
          "5. Check RCW 9.41.284 voting facilities.",
          "6. Check RCW 9.41.300 prohibited places.",
          "7. Check RCW 9.41.305 open carry/government/demonstration restrictions."
        ]
      }
    ],
    [
      {
        title: "Driving Around Seattle / Tacoma / Olympia",
        summary: "Washington recognition helps, but vehicle carry, government buildings, protests, schools, child care premises, and private property still create risk.",
        guidance: [
          "Carry permit and photo ID.",
          "Follow loaded pistol vehicle rules.",
          "Avoid government/protest carry issues.",
          "Check schools and child care premises."
        ]
      }
    ],
    [
      "Assuming Washington is permitless concealed carry.",
      "Ignoring loaded pistol vehicle rules under RCW 9.41.050.",
      "Ignoring schools under RCW 9.41.280.",
      "Ignoring child care premises under RCW 9.41.282.",
      "Ignoring voting facilities under RCW 9.41.284.",
      "Ignoring public demonstration/government building restrictions."
    ],
    [
      "Michigan recognition verified.",
      "Permit/ID carried.",
      "Vehicle carry checked.",
      "Schools/child care/voting facilities checked.",
      "Government/demonstration restrictions checked.",
      "Federal property checked."
    ],
    [
      {
        myth: "Washington is green on the map, so I can carry anywhere.",
        reality: "No. Washington recognizes Michigan CPL according to the AG list, but Washington vehicle rules, school rules, prohibited places, private property, and federal property still apply."
      }
    ]
  ),

};

var additionalHighRiskStates = {
  DE: "Delaware",
  OR: "Oregon",
  CT: "Connecticut",
  MA: "Massachusetts",
  NJ: "New Jersey",
  MD: "Maryland",
  RI: "Rhode Island",
  NV: "Nevada"
};

Object.keys(additionalHighRiskStates).forEach(function(abbr){
  if(!stateLawData[abbr]){
    var name = additionalHighRiskStates[abbr];
    stateLawData[abbr] = makeProfile(
      name,
      "High-Risk Travel State",
      name + " is treated as not recognizing Michigan CPL in this app travel engine. Verify official " + name + " law before travel. This is a high-risk travel state profile and should be expanded in detail before members rely on it.",
      {
        reciprocity: "Michigan CPL treated as not recognized in this app travel engine.",
        permitlessCarry: "Do not rely on permitless carry. Verify current law.",
        concealedCarry: "Michigan CPL does not authorize concealed carry in this app travel engine.",
        openCarry: "Verify current law.",
        vehicleCarry: "Verify transport and vehicle rules.",
        dutyToInform: "Verify police-contact rules.",
        privateSigns: "Private property, local, and sensitive-place rules may matter.",
        forceLaw: "Verify current self-defense law."
      },
      [
        "Do not rely on Michigan CPL alone.",
        "Verify lawful transport before travel.",
        "Verify prohibited places and sensitive locations.",
        "Verify local restrictions, magazine restrictions, ammunition restrictions, and private property rules where applicable."
      ],
      [
        {
          title: "Michigan CPL Not Recognized",
          risk: "Do Not Carry on Michigan CPL",
          body: [
            name + " is treated as not recognizing Michigan CPL in this app travel engine.",
            "Do not assume a Michigan CPL creates carry authority.",
            "Verify transport, possession, prohibited places, and local restrictions before travel."
          ],
          source: "High-risk travel profile. Official state source verification required."
        }
      ],
      [
        {
          title: "Before Traveling to " + name,
          steps: [
            "1. Do not rely on Michigan CPL alone.",
            "2. Verify lawful transport.",
            "3. Verify prohibited places.",
            "4. Verify local restrictions.",
            "5. Verify magazine/ammunition rules where applicable.",
            "6. Verify police-contact expectations."
          ]
        }
      ],
      [
        {
          title: "Entering a Non-Recognition State",
          summary: "Non-recognition states require much stricter travel planning.",
          guidance: [
            "Do not treat the state like a recognized carry state.",
            "Plan transport carefully.",
            "Avoid unnecessary handling.",
            "Verify official law before travel."
          ]
        }
      ],
      [
        "Assuming Michigan CPL has carry value.",
        "Ignoring transport restrictions.",
        "Ignoring local rules.",
        "Ignoring sensitive-place restrictions."
      ],
      [
        "Recognition checked.",
        "Transport checked.",
        "Prohibited places checked.",
        "Local restrictions checked.",
        "Magazine/ammo restrictions checked."
      ],
      [
        {
          myth: "I have a Michigan CPL, so I should be covered.",
          reality: name + " is treated as not recognizing Michigan CPL in this app travel engine. Do not carry on Michigan CPL alone."
        }
      ]
    );
  }
});

states.forEach(function(s){
  if(!stateLawData[s[0]]){
    var status = "Verify recognition.";
    if(reciprocityData.MI.recognized.indexOf(s[0]) !== -1) status = "Michigan CPL treated as recognized in this app travel engine.";
    if(reciprocityData.MI.notRecognized.indexOf(s[0]) !== -1) status = "Michigan CPL treated as not recognized in this app travel engine.";
    stateLawData[s[0]] = starterProfile(s[0], s[1], status);
  }
});

function hasSection(profile, title){
  return (profile.legalSections || []).some(function(section){
    return String(section.title || "").toLowerCase() === String(title || "").toLowerCase();
  });
}

function pushSectionIfMissing(profile, title, risk, body, source){
  profile.legalSections = profile.legalSections || [];
  if(!hasSection(profile, title)){
    profile.legalSections.push({ title: title, risk: risk, body: body, source: source });
  }
}

function pushUnique(list, value){
  if(!list) return;
  if(list.indexOf(value) === -1) list.push(value);
}

function applyEliteLiteAllStates(){
  Object.keys(stateLawData).forEach(function(abbr){
    var profile = stateLawData[abbr];
    if(!profile) return;

    var qk = profile.quick || {};
    profile.profileStatus = profile.profileStatus && profile.profileStatus.indexOf("Elite") !== -1 ? profile.profileStatus : "Elite Lite Expanded State";
    profile.scenarios = [];

    pushSectionIfMissing(profile,
      "Reciprocity / Permit Recognition",
      "Travel Authority Check",
      [
        "STATUTE / SOURCE: State reciprocity and permit-recognition framework.",
        "SUMMARY: Permit recognition only answers whether the selected permit may provide carry authority in this state. It does not override state law, prohibited places, transport rules, federal restrictions, private property, or police-contact obligations.",
        "GUIDANCE: Treat the map color as the first step, not the final answer. Before carrying, verify recognition, age, residency, permit type, location, vehicle status, and whether any exception or restriction applies."
      ],
      "State permit-recognition framework; official state reciprocity resources."
    );

    pushSectionIfMissing(profile,
      "Restricted & Sensitive Locations",
      "Location Restriction Review",
      [
        "STATUTE / SOURCE: State prohibited-place, restricted-location, and property-control framework.",
        "SUMMARY: Carry authority does not authorize carry in every location. Schools, courts, government buildings, police or correctional facilities, alcohol-related locations, places of worship, private posted property, secure areas, and federal property may be restricted depending on state law.",
        "GUIDANCE: This is the most important practical check before entering a building or event. If the location is school-related, court-related, government-controlled, alcohol-centered, posted, security-screened, or federal, verify before entering armed."
      ],
      "State restricted-location framework; federal facility and property law overlay."
    );

    pushSectionIfMissing(profile,
      "Vehicle Carry / Transport Rules",
      "Vehicle and Travel Risk",
      [
        "STATUTE / SOURCE: State vehicle-carry and firearm-transport framework.",
        "SUMMARY: Vehicle carry is often treated differently from carry on foot. Some states allow loaded accessible vehicle carry with a permit or qualifying status, while others require unloaded, secured, inaccessible, or case/locked-container transport unless a permit or exception applies.",
        "GUIDANCE: Do not assume the same rules apply once you enter a vehicle. Check loaded vs. unloaded status, accessibility, trunk vs. passenger compartment, glovebox/console issues, ammunition rules where applicable, and whether the person is carrying or merely transporting."
      ],
      "State vehicle-carry and firearm-transport framework."
    );

    pushSectionIfMissing(profile,
      "Police Contact / Officer Interaction",
      "Stop and Disclosure Risk",
      [
        "STATUTE / SOURCE: State duty-to-inform, permit-display, and police-contact framework.",
        "SUMMARY: Police-contact duties vary by state. Some states require immediate disclosure, some require disclosure when asked, and some require permit/ID display upon lawful demand.",
        "GUIDANCE: Use the conservative field rule: hands visible, no reaching, calm voice, truthful answers, and ask for instructions before moving. If the state requires disclosure, disclose immediately using a clear script."
      ],
      "State police-contact and permit-display framework."
    );

    pushSectionIfMissing(profile,
      "Storage, Hotels, and Temporary Lodging",
      "Unauthorized Access Risk",
      [
        "STATUTE / SOURCE: State storage, child-access, property, and general possession framework.",
        "SUMMARY: Hotels, rentals, vehicles, campsites, and temporary lodging can create possession, storage, theft, child-access, and private-property issues. A hotel room or rental is not always legally identical to a permanent residence for every purpose.",
        "GUIDANCE: Secure unattended firearms against unauthorized access. Check hotel/rental policies, vehicle-storage risk, minors/unauthorized persons, and whether the location is private, state, federal, tribal, school-related, or otherwise restricted."
      ],
      "State storage/property framework; federal and private-property overlay."
    );

    pushSectionIfMissing(profile,
      "Civil Liability / Aftermath Discipline",
      "Post-Incident Exposure",
      [
        "STATUTE / SOURCE: State self-defense, civil-liability, criminal procedure, and evidence framework.",
        "SUMMARY: Even when force may be legally justified, the defender may still face investigation, arrest, prosecution risk, civil claims, employment consequences, and public-record or media exposure depending on the facts.",
        "GUIDANCE: After a defensive incident, get safe, call 911, request police/medical, identify attacker/evidence/witnesses if necessary, request counsel, and avoid detailed statements under stress. Do not post online or discuss the incident publicly."
      ],
      "State self-defense and civil-liability framework; Prime Defense aftermath protocol."
    );

    profile.commonMistakes = profile.commonMistakes || [];
    pushUnique(profile.commonMistakes, "Assuming reciprocity means carry anywhere in the state.");
    pushUnique(profile.commonMistakes, "Ignoring vehicle-carry and transport rules.");
    pushUnique(profile.commonMistakes, "Ignoring restricted or sensitive locations.");
    pushUnique(profile.commonMistakes, "Assuming private property signs or staff instructions do not matter.");
    pushUnique(profile.commonMistakes, "Talking too much after a defensive incident.");

    profile.beforeCarryChecklist = profile.beforeCarryChecklist || [];
    pushUnique(profile.beforeCarryChecklist, "Permit recognition / carry authority checked.");
    pushUnique(profile.beforeCarryChecklist, "Vehicle carry and transport rules checked.");
    pushUnique(profile.beforeCarryChecklist, "Restricted & sensitive locations checked.");
    pushUnique(profile.beforeCarryChecklist, "Police-contact / duty-to-inform rules checked.");
    pushUnique(profile.beforeCarryChecklist, "Federal property, private property, and posted-location issues checked.");
    pushUnique(profile.beforeCarryChecklist, "Aftermath plan and legal-defense contact ready.");
  });
}

applyEliteLiteAllStates();

function q(id){ return document.getElementById(id); }

function setMsg(text){
  var msg = q("msg");
  if(msg) msg.innerText = text || "";
}

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

function statusFill(status){
  if(status === "recognized") return "#b9f3cc";
  if(status === "restricted") return "#fde2b8";
  if(status === "not_recognized") return "#ffc2c7";
  return "#dbe2ea";
}

function renderMapLegend(){
  return '<div class="mapLegend">' +
    '<span class="legendItem green">Recognized</span>' +
    '<span class="legendItem yellow">Restrictions</span>' +
    '<span class="legendItem red">Not Recognized</span>' +
    '<span class="legendItem gray">Verify</span>' +
  '</div>';
}

function permitDataFor(permitState){
  return reciprocityData[permitState] || null;
}

function permitEngineCounts(permitState){
  var recognized = 0;
  var restricted = 0;
  var notRecognized = 0;
  var unverified = 0;

  states.forEach(function(row){
    var status = stateStatus(permitState, row[0]);
    if(status === "recognized") recognized++;
    else if(status === "restricted") restricted++;
    else if(status === "not_recognized") notRecognized++;
    else unverified++;
  });

  return { recognized:recognized, restricted:restricted, notRecognized:notRecognized, unverified:unverified };
}

function renderPermitEngineCard(permitState){
  var data = permitDataFor(permitState);
  var counts = permitEngineCounts(permitState);
  var title = data ? (data.title || (stateName(permitState) + " Permit Reciprocity Engine")) : (stateName(permitState) + " Permit Reciprocity Engine");
  var reviewed = data ? (data.verifiedDate || "Verify before travel") : "Not built yet";
  var note = data ? (data.sourceNote || "Map colors are based on the selected permit state.") : "This permit state is not fully built in the reciprocity engine yet. The map will show VERIFY until this permit dataset is added.";

  return '<div class="permitEngineCard">' +
    '<h3>' + escapeHtml(title) + '</h3>' +
    '<p class="small"><b>Selected permit:</b> ' + escapeHtml(stateName(permitState)) + ' | <b>Reciprocity reviewed:</b> ' + escapeHtml(reviewed) + '</p>' +
    '<p class="small">' + escapeHtml(note) + '</p>' +
    '<div class="permitEngineStats">' +
      '<div class="permitEngineStat green"><b>' + counts.recognized + '</b><span>Recognized</span></div>' +
      '<div class="permitEngineStat yellow"><b>' + counts.restricted + '</b><span>Verify</span></div>' +
      '<div class="permitEngineStat red"><b>' + counts.notRecognized + '</b><span>Not Honored</span></div>' +
      '<div class="permitEngineStat gray"><b>' + counts.unverified + '</b><span>Unverified</span></div>' +
    '</div>' +
  '</div>';
}

function renderSvgMap(permitState){
  var html = '<svg class="mapSvg" viewBox="0 0 960 690" role="img" aria-label="Clickable United States reciprocity map">';
  html += '<defs>';
  html += '<filter id="stateShadow" x="-10%" y="-10%" width="120%" height="120%"><feDropShadow dx="0" dy="2" stdDeviation="2" flood-color="#101318" flood-opacity="0.18"/></filter>';
  html += '</defs>';
  html += '<rect x="0" y="0" width="960" height="690" rx="22" fill="#f8fafc"></rect>';
  html += '<text x="24" y="32" style="font-size:20px;font-weight:950;fill:#11151b">Interactive U.S. Reciprocity Map</text>';
  html += '<text x="24" y="54" style="font-size:12px;font-weight:800;fill:#626975">Click any state shape to view reciprocity status and state legal intelligence.</text>';
  html += '<text x="24" y="76" style="font-size:11px;font-weight:800;fill:#8a93a3">Map colors are based on the selected permit state.</text>';
  html += '<g transform="translate(0,54)">';
  html += '<rect x="33" y="462" width="275" height="142" rx="16" fill="#ffffff" stroke="rgba(16,19,24,.12)"></rect>';
  html += '<text x="48" y="484" style="font-size:12px;font-weight:950;fill:#626975">ALASKA</text>';
  html += '<rect x="323" y="492" width="235" height="112" rx="16" fill="#ffffff" stroke="rgba(16,19,24,.12)"></rect>';
  html += '<text x="338" y="514" style="font-size:12px;font-weight:950;fill:#626975">HAWAII</text>';

  states.forEach(function(stateRow){
    var abbr = stateRow[0];
    var name = stateRow[1];
    var path = realStatePaths[abbr];
    if(!path) return;

    var status = stateStatus(permitState, abbr);
    var selected = selectedMapState === abbr;
    html += '<path class="mapCell ' + (selected ? 'selected' : '') + '" d="' + path + '" fill="' + statusFill(status) + '" onclick="selectMapState(\\\'' + abbr + '\\\')"><title>' + escapeHtml(name) + ' — ' + statusLabelByStatus(status) + '</title></path>';
  });

  html += '<g class="mapLabels">';
  states.forEach(function(stateRow){
    var abbr = stateRow[0];
    var label = realStateLabels[abbr];
    if(!label) return;
    var x = label[0];
    var y = label[1];
    var tiny = ['CT','RI','DE','MD','NJ','MA','VT','NH'].indexOf(abbr) !== -1;
    var fs = tiny ? 9 : 11;
    html += '<text class="mapText" x="' + x + '" y="' + y + '" style="font-size:' + fs + 'px">' + abbr + '</text>';
  });
  html += '</g>';
  html += '</g>';
  html += '</svg>';
  return html;
}

function renderList(title, items, bullet){
  if(!items || !items.length) return "";
  var html = '<h3>' + escapeHtml(title) + '</h3><div class="legalItem">';
  items.forEach(function(item){
    html += '<p>' + (bullet || "• ") + escapeHtml(item) + '</p>';
  });
  html += '</div>';
  return html;
}

function containsAny(value, terms){
  value = String(value || "").toLowerCase();
  return terms.some(function(t){ return value.indexOf(t) !== -1; });
}

function sectionCategory(section){
  var text = (section.title + " " + (section.risk || "") + " " + (section.source || "") + " " + (section.body || []).join(" ")).toLowerCase();
  if(containsAny(text,["school","court","courthouse","liquor","alcohol","airport","federal","post office","police","correctional","jail","prohibited","restricted","unauthorized","sensitive","casino","government"])) return "critical";
  if(containsAny(text,["vehicle","motor vehicle","transport","traffic stop","glove","console","car"])) return "vehicle";
  if(containsAny(text,["police","officer","inform","disclose","notification","traffic stop"])) return "police";
  if(containsAny(text,["private","posted","property","employer","workplace","sign"])) return "property";
  if(containsAny(text,["force","self-defense","display","brandish","aftermath","911","civil","liability"])) return "force";
  return "general";
}

function sectionPriority(section){
  var text = (section.title + " " + (section.risk || "") + " " + (section.body || []).join(" ")).toLowerCase();
  var score = 0;
  if(containsAny(text,["school","court","courthouse","federal","airport","liquor","alcohol","jail","correctional","police","casino","prohibited","restricted","unauthorized","sensitive"])) score += 8;
  if(containsAny(text,["vehicle","traffic stop","transport","motor vehicle"])) score += 6;
  if(containsAny(text,["private","posted","employer","property"])) score += 4;
  if(containsAny(text,["force","self-defense","display","brandish","aftermath","911"])) score += 3;
  return score;
}

function firstLineByPrefix(section, prefix){
  var rows = section.body || [];
  prefix = prefix.toLowerCase();
  for(var i=0;i<rows.length;i++){
    var row = String(rows[i] || "");
    if(row.toLowerCase().indexOf(prefix) === 0){
      row = row.replace("STATUTE / SOURCE:", "");
      row = row.replace("STATUTE:", "");
      row = row.replace("SOURCE:", "");
      row = row.replace("SUMMARY:", "");
      row = row.replace("GUIDANCE:", "");
      return row.trim();
    }
  }
  return "";
}

function buildIntelSummary(permitState, travelState){
  var law = stateLawData[travelState] || {};
  var qk = law.quick || {};
  var status = stateStatus(permitState, travelState);
  var legalSections = law.legalSections || [];
  var highRisk = legalSections
    .slice()
    .sort(function(a,b){ return sectionPriority(b) - sectionPriority(a); })
    .filter(function(section){ return sectionPriority(section) > 0; })
    .slice(0,6);

  var warnings = [];
  if(status === "not_recognized") warnings.push("Michigan CPL not recognized / do not carry on Michigan CPL alone.");
  if(status === "restricted") warnings.push("Reciprocity marked VERIFY / conditional — confirm before travel.");
  if(qk.vehicleCarry) warnings.push("Vehicle: " + qk.vehicleCarry);
  if(qk.dutyToInform) warnings.push("Police contact: " + qk.dutyToInform);
  if(qk.privateSigns) warnings.push("Private property: " + qk.privateSigns);

  return { highRisk: highRisk, warnings: warnings.slice(0,5) };
}

function renderIntelPanel(permitState, travelState){
  var law = stateLawData[travelState] || {};
  var qk = law.quick || {};
  var status = stateStatus(permitState, travelState);
  var cls = statusClass(status);
  var intel = buildIntelSummary(permitState, travelState);

  var html = '<div class="intelBanner">' +
    '<h3>' + travelState + ' — ' + escapeHtml(stateName(travelState)) + ' State Intelligence</h3>' +
    '<span class="detailStatus ' + cls + '">' + statusLabelByStatus(status) + '</span>' +
    '<p><b>Permit selected:</b> ' + escapeHtml(stateName(permitState)) + ' | <b>Clicked state:</b> ' + escapeHtml(stateName(travelState)) + '</p>' +
    '<p>This panel shows the fast-read carry intelligence first, then the detailed legal profile below.</p>' +
    '<div class="intelGrid">' +
      '<div class="intelTile"><b>Reciprocity</b><span>' + escapeHtml(qk.reciprocity || 'Verify recognition before travel.') + '</span></div>' +
      '<div class="intelTile"><b>Permitless / Concealed</b><span>' + escapeHtml(qk.permitlessCarry || 'Verify permitless carry status.') + '</span></div>' +
      '<div class="intelTile"><b>Vehicle / Transport</b><span>' + escapeHtml(qk.vehicleCarry || 'Verify vehicle carry and transport rules.') + '</span></div>' +
      '<div class="intelTile"><b>Police Contact</b><span>' + escapeHtml(qk.dutyToInform || 'Verify duty-to-inform rules.') + '</span></div>' +
      '<div class="intelTile"><b>Private Property</b><span>' + escapeHtml(qk.privateSigns || 'Verify signage/property rules.') + '</span></div>' +
      '<div class="intelTile"><b>Use of Force</b><span>' + escapeHtml(qk.forceLaw || 'Verify self-defense law.') + '</span></div>' +
    '</div>' +
  '</div>';

  if(intel.warnings.length){
    html += '<div class="detailBox"><h3>Fast Travel Warnings</h3><div class="riskStack">';
    intel.warnings.forEach(function(w){ html += '<div class="riskCard"><strong>Warning</strong><p>' + escapeHtml(w) + '</p></div>'; });
    html += '</div></div>';
  }

  if(intel.highRisk.length){
    html += '<div class="detailBox"><h3>Restricted & Sensitive Locations</h3><div class="riskStack">';
    intel.highRisk.forEach(function(section){
      var summary = firstLineByPrefix(section,"SUMMARY:") || (section.body && section.body[0]) || "Review this section before travel.";
      html += '<div class="riskCard"><strong>' + escapeHtml(section.title) + '</strong><p>' + escapeHtml(summary) + '</p></div>';
    });
    html += '</div></div>';
  }

  html += '<div class="jumpNav">' +
    '<button type="button" onclick="document.getElementById(\\'pd-legal-details\\').scrollIntoView({behavior:\\'smooth\\'})">Detailed Law</button>' +
    '<button type="button" onclick="document.getElementById(\\'pd-decision-blocks\\').scrollIntoView({behavior:\\'smooth\\'})">Checklists</button>' +
    '<button type="button" onclick="document.getElementById(\\'pd-common-mistakes\\').scrollIntoView({behavior:\\'smooth\\'})">Common Mistakes</button>' +
  '</div>';

  return html;
}

function renderLegalSection(section){
  var cat = sectionCategory(section);
  var html = '<div class="legalItem ' + cat + '">' +
    '<h3>' + escapeHtml(section.title) + '</h3>' +
    '<span class="lawPill yellow">' + escapeHtml(section.risk || "Legal Topic") + '</span>';

  (section.body || []).forEach(function(p){
    var safe = escapeHtml(p);
    if(String(p).indexOf("STATUTE:") === 0 || String(p).indexOf("STATUTE / SOURCE:") === 0 || String(p).indexOf("SOURCE:") === 0){
      html += '<p><b>' + safe + '</b></p>';
    } else if(String(p).indexOf("SUMMARY:") === 0){
      html += '<p><b>' + safe + '</b></p>';
    } else if(String(p).indexOf("GUIDANCE:") === 0){
      html += '<p><b>' + safe + '</b></p>';
    } else {
      html += '<p>' + safe + '</p>';
    }
  });

  if(section.source){
    html += '<div class="legalSource">' + escapeHtml(section.source) + '</div>';
  }
  html += '</div>';
  return html;
}

function renderLawProfile(abbr){
  var law = stateLawData[abbr];

  if(!law){
    return '<div class="detailBox">' +
      '<h3>' + abbr + ' — ' + stateName(abbr) + '</h3>' +
      '<p><b>State law profile:</b> Not built yet.</p>' +
      '<p class="small">This state is still using the reciprocity-only travel warning.</p>' +
      '</div>';
  }

  var html = '<div class="detailBox">' +
    '<h3>' + abbr + ' — ' + escapeHtml(law.name || stateName(abbr)) + '</h3>' +
    '<span class="lawPill green">' + escapeHtml(law.profileStatus || "Profile") + '</span>' +
    '<span class="lawPill gray">Reviewed: ' + escapeHtml(law.lastReviewed || "Verify") + '</span>' +
    '<p>' + escapeHtml(law.summary || "") + '</p>';

  html += renderList("Important Carry Warnings", law.travelAlerts);

  html += '<div id="pd-legal-details" class="sectionHeader"><h3>Detailed Legal Intelligence</h3><p>Statute-backed sections, summaries, and Prime Defense practical guidance.</p></div>';
  if(law.legalSections && law.legalSections.length){
    law.legalSections.forEach(function(section){ html += renderLegalSection(section); });
  } else {
    html += '<div class="legalItem"><p>No expanded legal sections are built for this state yet.</p></div>';
  }

  html += '<div id="pd-decision-blocks" class="sectionHeader"><h3>Decision Blocks / Checklists</h3><p>Fast field checks before carrying or traveling.</p></div>';
  if(law.decisionBlocks && law.decisionBlocks.length){
    law.decisionBlocks.forEach(function(block){
      html += '<div class="legalItem"><h3>' + escapeHtml(block.title) + '</h3>';
      (block.steps || []).forEach(function(step){ html += '<p>' + escapeHtml(step) + '</p>'; });
      html += '</div>';
    });
  } else {
    html += '<div class="legalItem"><p>No state-specific decision blocks built yet.</p></div>';
  }

  html += '<div id="pd-common-mistakes" class="sectionHeader"><h3>Common Mistakes & Final Checklist</h3><p>Things members should avoid before they create legal exposure.</p></div>';
  html += renderList("Common Mistakes", law.commonMistakes);
  html += renderList("Before You Carry Checklist", law.beforeCarryChecklist, "☐ ");

  if(law.plainEnglishReality && law.plainEnglishReality.length){
    html += '<h3>Plain English vs. Legal Reality</h3>';
    law.plainEnglishReality.forEach(function(item){
      html += '<div class="legalItem">' +
        '<p><b>What people think:</b> ' + escapeHtml(item.myth) + '</p>' +
        '<p><b>Reality:</b> ' + escapeHtml(item.reality) + '</p>' +
        '</div>';
    });
  }

  html += '<p class="small"><b>Disclaimer:</b> Educational field reference only. Not legal advice. Verify current law before relying on any summary.</p>';
  html += '</div>';

  return html;
}

function getStateDetailHtml(permitState, travelState){
  return renderIntelPanel(permitState, travelState) + renderLawProfile(travelState);
}

function getReciprocityHtml(state){
  var data = reciprocityData[state];
  var selectedName = stateName(state);

  if(!selectedMapState) selectedMapState = state;

  if(!data){
    return '<div class="reciprocityTitle">' + selectedName + ' Permit Profile</div>' +
      '<p><b>Status:</b> State-specific outbound reciprocity data has not been fully verified in this app yet.</p>' +
      renderPermitEngineCard(state) +
      '<div class="mapShell">' +
        '<div class="mapPanel">' + renderMapLegend() + renderSvgMap(state) + '</div>' +
        '<div>' + getStateDetailHtml(state, selectedMapState) + '</div>' +
      '</div>' +
      '<div class="warn">Before carrying outside your home state, verify destination-state recognition, prohibited locations, duty-to-inform rules, vehicle carry rules, age restrictions, permit residency requirements, local restrictions, federal restrictions, and private property rules.</div>';
  }

  return '<div class="reciprocityTitle">' + data.title + '</div>' +
    '<p><b>Selected permit:</b> ' + selectedName + '</p>' +
    '<p><b>Last reviewed:</b> ' + data.verifiedDate + '</p>' +
    '<p class="reciprocitySub">' + data.sourceNote + '</p>' +
    renderPermitEngineCard(state) +
    '<div class="mapShell">' +
      '<div class="mapPanel">' + renderMapLegend() + renderSvgMap(state) + '</div>' +
      '<div>' + getStateDetailHtml(state, selectedMapState) + '</div>' +
    '</div>' +
    '<h3>Critical Travel Warnings</h3>' +
    data.warnings.map(function(w){ return '<p class="small">• ' + escapeHtml(w) + '</p>'; }).join('');
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
      '<p class="subtitle">Premium member-only protection dashboard for permit tracking, emergency tools, legal education, reciprocity, and defensive incident guidance.</p>' +
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

  q("loginTab").onclick = function(){ authMode = "login"; showAuth(); };
  q("registerTab").onclick = function(){ authMode = "register"; showAuth(); };
  q("submitBtn").onclick = function(){ if(authMode === "register") registerUser(); else loginUser(); };
}

async function registerUser(){
  setMsg("Creating account and checking membership...");

  try{
    var res = await fetch("/api/register", {
      method:"POST",
      headers:{ "Content-Type":"application/json" },
      body:JSON.stringify({
        name:q("name").value,
        email:q("email").value,
        password:q("password").value
      })
    });

    var data = await res.json();

    if(data.token){
      token = data.token;
      localStorage.setItem("pd_token", token);
      if(data.user && data.user.accessAllowed) showDashboard();
      else showLocked(data.user);
    } else {
      setMsg(data.error || "Registration failed.");
    }
  }catch(e){
    setMsg("Registration failed.");
  }
}

async function loginUser(){
  setMsg("Logging in and checking membership...");

  try{
    var res = await fetch("/api/login", {
      method:"POST",
      headers:{ "Content-Type":"application/json" },
      body:JSON.stringify({
        email:q("email").value,
        password:q("password").value
      })
    });

    var data = await res.json();

    if(data.token){
      token = data.token;
      localStorage.setItem("pd_token", token);
      if(data.user && data.user.accessAllowed) showDashboard();
      else showLocked(data.user);
    } else {
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

async function refreshMembership(){
  setMsg("Refreshing membership status...");

  try{
    var res = await fetch("/api/refresh-membership", {
      method:"POST",
      headers:{ "Content-Type":"application/json" },
      body:JSON.stringify({ token:token })
    });

    var user = await res.json();

    if(user.accessAllowed) showDashboard();
    else showLocked(user);
  }catch(e){
    setMsg("Unable to refresh membership.");
  }
}

async function openBilling(){
  setMsg("Opening billing portal...");

  try{
    var res = await fetch("/api/billing-portal", {
      method:"POST",
      headers:{ "Content-Type":"application/json" },
      body:JSON.stringify({ token:token })
    });

    var data = await res.json();

    if(data.url) window.location.href = data.url;
    else setMsg(data.error || "Unable to open billing.");
  }catch(e){
    setMsg("Unable to open billing.");
  }
}

function showLocked(user){
  user = user || {};

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

  q("refreshBtn").onclick = refreshMembership;
  q("billingBtn").onclick = openBilling;
  q("logoutBtn").onclick = logout;
}

function buildStateOptions(selected){
  var html = "";

  states.forEach(function(s){
    html += '<option value="' + s[0] + '"' + (s[0] === selected ? ' selected' : '') + '>' + s[1] + '</option>';
  });

  return html;
}

async function showDashboard(){
  try{
    var res = await fetch("/api/get-profile", {
      method:"POST",
      headers:{ "Content-Type":"application/json" },
      body:JSON.stringify({ token:token })
    });

    var user = await res.json();

    if(user.error){
      localStorage.removeItem("pd_token");
      token = null;
      showAuth();
      return;
    }

    if(!user.accessAllowed){
      showLocked(user);
      return;
    }

    currentUser = user;
    var selectedState = user.permitState || "MI";
    selectedMapState = selectedMapState || selectedState;

    q("app").innerHTML =
      '<div class="dashboard">' +
        '<div class="hero">' +
          '<div class="brand">Prime Defense Protection</div>' +
          '<h1>Member Dashboard</h1>' +
          '<span class="status">' + escapeHtml(user.membershipLabel) + '</span>' +
          '<p class="subtitle">Welcome' + (user.name ? ', ' + escapeHtml(user.name) : '') + '. Your premium member dashboard for permit tracking, incident tools, reciprocity, and legal intelligence.</p>' +
          '<div class="badgeRow">' +
            '<span class="badge">Permit Profile</span>' +
            '<span class="badge">Interactive Map</span>' +
            '<span class="badge">State Detail Panel</span>' +
            '<span class="badge">Michigan Ultra Guide</span>' +
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
          '<h2>Interactive Reciprocity Map & State Detail Panel</h2>' +
          '<p class="small">Select the permit you hold. The map colors update from that permit’s reciprocity data. Click any state to view reciprocity status and legal intelligence.</p>' +
          '<div class="grid">' +
            '<select id="state">' + buildStateOptions(selectedState) + '</select>' +
            '<input id="issue" type="date" value="' + escapeHtml(user.issueDate || '') + '">' +
            '<input id="exp" type="date" value="' + escapeHtml(user.expirationDate || '') + '">' +
          '</div>' +
          '<div id="reciprocityBox" class="reciprocityBox"></div>' +
        '</div>' +

        '<div class="card">' +
          '<div class="brand">Michigan Ultra Guide</div>' +
          '<h2>Michigan CPL & Firearms Law Intelligence</h2>' +
          '<p class="small">Open the expanded Michigan guide with detailed sections, decision blocks, common mistakes, restricted-location guidance, plain-English reality checks, and before-carry checklists.</p>' +
          '<button id="miGuideBtn" class="primary" type="button">Open Michigan Ultra Guide</button>' +
        '</div>' +

        '<div class="card">' +
          '<div class="brand">Incident Modes</div>' +
          '<h2>Emergency Tools</h2>' +
          '<p class="small">Use the mode that best matches the situation. These tools help you slow down, call for help, and avoid damaging statements.</p>' +
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

    q("state").onchange = function(){
      selectedMapState = q("state").value;
      updateReciprocity();
    };

    q("saveBtn").onclick = saveProfile;
    q("logoutBtn").onclick = logout;
    q("refreshBtn").onclick = refreshMembership;
    q("emergencyBtn").onclick = openEmergency;
    q("shootingModeBtn").onclick = openEmergency;
    q("displayModeBtn").onclick = openDefensiveDisplay;
    q("aftermathBtn").onclick = openAftermath;
    q("miGuideBtn").onclick = function(){
      selectedMapState = "MI";
      showStateLawFull("MI");
    };

  }catch(e){
    localStorage.removeItem("pd_token");
    token = null;
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
    var res = await fetch("/api/save-profile", {
      method:"POST",
      headers:{ "Content-Type":"application/json" },
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

function showStateLawFull(abbr){
  q("app").innerHTML =
    '<div class="dashboard">' +
      '<div class="hero">' +
        '<div class="brand">Prime Defense Legal Intelligence</div>' +
        '<h1>' + stateName(abbr) + ' State Law Engine</h1>' +
        '<p class="subtitle">Structured legal reference, decision blocks, scenario guidance, and practical carry warnings. Educational only. Not legal advice.</p>' +
        '<div class="actions">' +
          '<button class="secondary" type="button" onclick="showDashboard()">Back to Dashboard</button>' +
          '<button class="primary" type="button" onclick="openEmergency()">Emergency Mode</button>' +
        '</div>' +
      '</div>' +
      '<div class="callout">' +
        '<div class="brand">Premium Field Reference</div>' +
        '<h2>Law + Real-World Decision Support</h2>' +
        '<p class="small">This section is built to go beyond generic summaries. The goal is to help members identify risk before they make a bad carry, storage, transport, or post-incident decision.</p>' +
      '</div>' +
      renderLawProfile(abbr) +
    '</div>';
}

function openEmergency(){
  var phone = q("phone") ? q("phone").value : "";
  var name = q("ename") ? q("ename").value : "";
  var cleanPhone = phone.replace(/[^0-9+]/g,"");

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
          (phone ? '<button class="primary bigAction" type="button" onclick="window.location.href=\\'tel:' + cleanPhone + '\\'">CALL CONTACT</button>' : '<div class="warn">No emergency contact saved.</div>') +
          '<div class="script">“I’ve been involved in a defensive incident. I’m safe. Do not discuss anything with anyone until I have legal guidance.”</div>' +
        '</div>' +

        '<div class="card">' +
          '<div class="brand">Step 4 — When Police Arrive</div>' +
          '<div class="script">Hands visible. Do not move unless instructed. Follow commands. Do not argue. Do not explain in detail.</div>' +
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

if(token) showDashboard();
else showAuth();
</script>
</body>
</html>
`;

app.get("/", (req, res) => res.send(html));

app.use((req, res) => res.send(html));


app.listen(PORT, "0.0.0.0", () => {
  console.log("Running on port " + PORT);
});
