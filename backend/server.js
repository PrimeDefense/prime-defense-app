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
  padding:8px;
}
.actualMap{
  width:100%;
  min-height:430px;
  background:linear-gradient(135deg,#f9fafb,#eef1f5);
  border:1px solid rgba(16,19,24,.08);
  border-radius:20px;
  overflow:hidden;
  position:relative;
}
.actualMap svg{
  width:100%;
  height:430px;
  display:block;
}
.mapLoading{
  background:#fff;
  border:1px solid rgba(16,19,24,.08);
  border-radius:16px;
  padding:14px;
  margin-top:10px;
  color:#626975;
  font-size:13px;
  line-height:1.45;
}

.mapCell{
  cursor:pointer;
  stroke:#fff;
  stroke-width:2;
  rx:8;
  transition:.12s ease;
}
.mapCell:hover{filter:brightness(.94)}
.mapCell.selected{stroke:#11151b;stroke-width:4}
.mapText{
  pointer-events:none;
  font-size:13px;
  font-weight:950;
  fill:#11151b;
  text-anchor:middle;
  dominant-baseline:middle;
}
.mapLegend{
  display:flex;
  flex-wrap:wrap;
  gap:8px;
  margin:8px 0 14px;
}
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

<script src="https://d3js.org/d3.v3.min.js"></script>
<script src="https://d3js.org/topojson.v1.min.js"></script>
<script src="https://datamaps.github.io/scripts/datamaps.usa.min.js"></script>

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

var reciprocityData = {
  MI: {
    title: "Michigan CPL Reciprocity & Travel Guide",
    verifiedDate: "May 2, 2026",
    sourceNote: "Recognition does not mean identical laws. Follow the law of the state you are physically in. Michigan MSP advises CPL holders to check the destination state directly before travel.",
    recognized: [
      "AL","AK","AZ","AR","CO","FL","GA","HI","ID","IN","IA","KS","KY","LA","ME","MN","MS",
      "MO","MT","NE","NH","NM","NC","ND","OH","OK","PA","SC","SD","TN","TX","UT","VA","VT",
      "WA","WV","WI","WY"
    ],
    restricted: [],
    notRecognized: ["CA","CT","DE","IL","MD","MA","NJ","NV","NY","OR","RI"],
    warnings: [
      "This is an outbound Michigan CPL travel reference, not a substitute for destination-state law.",
      "Recognition can depend on residency, age, permit type, current state law, and state-specific restrictions.",
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
    "Ultra Expanded",
    "Michigan is not permitless for concealed pistol carry. A CPL is generally required for concealed carry and ready-access pistol carry in a vehicle. Michigan carry decisions require careful attention to disclosure, prohibited premises, weapon-free school zones, safe storage, transport rules, prohibited-person status, ERPOs, civil liability, and post-incident conduct.",
    {
      reciprocity: "Home state profile.",
      permitlessCarry: "No permitless concealed pistol carry.",
      concealedCarry: "Michigan generally requires a valid CPL to carry a concealed pistol.",
      openCarry: "Generally lawful for eligible people, but location, vehicle, intent, and prohibited-person status matter.",
      vehicleCarry: "A CPL is generally required for ready-access pistol carry in a vehicle. Without a CPL, treat it as lawful transport only.",
      dutyToInform: "Yes. A CPL holder carrying concealed and stopped by a peace officer must immediately disclose.",
      privateSigns: "Private property rules matter. Refusal to leave after notice can create trespass exposure.",
      forceLaw: "Deadly force requires an honest and reasonable belief of imminent death, great bodily harm, or sexual assault, plus other statutory conditions."
    },
    [
      "Michigan has multiple overlapping location rules. CPL pistol-free zones, general firearm-prohibited premises, federal property, casinos, schools, and private property must be analyzed separately.",
      "Vehicle carry is a major dividing line. Without a CPL, treat pistol movement in a vehicle as lawful transport only.",
      "Police disclosure is mandatory for CPL holders carrying concealed during a stop.",
      "School property and school zones are high-risk areas that should not be handled from memory or word-of-mouth.",
      "Safe storage and child access rules create both legal and moral responsibility."
    ],
    [
      {
        title: "Michigan CPL Basics",
        risk: "Core Rule",
        body: [
          "A Michigan CPL allows a qualified license holder to carry a concealed pistol, but only within the limits of Michigan law.",
          "A CPL does not override federal law, court rules, school rules, private property restrictions, employer rules, tribal rules, secure facility rules, or the laws of another state.",
          "The correct mindset is not: I have a CPL, so I can carry. The correct mindset is: I have a CPL, and now I must verify whether this location, method of carry, and circumstance are lawful.",
          "Prime Defense field rule: before carrying, ask: Am I eligible today? Is this location lawful? Is my method of carry lawful? Am I emotionally and mentally prepared to avoid conflict?"
        ],
        source: "Michigan Firearms Laws publication; MCL 28.425f; MCL 28.425o."
      },
      {
        title: "Duty to Disclose During Police Contact",
        risk: "High-Risk Stop",
        body: [
          "If you are carrying concealed under a CPL and are stopped by a peace officer, Michigan law requires immediate disclosure that you are carrying.",
          "Recommended wording: Officer, I have a CPL and I am currently carrying. How would you like me to proceed?",
          "Keep your hands visible. Do not reach for your firearm, wallet, purse, registration, glove box, center console, or pocket until instructed.",
          "Do not assume the officer already knows. Do not wait until later in the stop. Do not say it casually while reaching.",
          "If passengers are present, stay calm and do not allow the vehicle to become chaotic.",
          "Prime Defense field rule: disclosure should be early, calm, clear, and paired with visible hands."
        ],
        source: "MCL 28.425f."
      },
      {
        title: "CPL Pistol-Free Zones / Concealed Carry Restricted Premises",
        risk: "Major Carry Restriction",
        body: [
          "MCL 28.425o lists places where a CPL holder generally may not carry a concealed pistol, subject to statutory language and exceptions.",
          "Common listed categories include schools and school property, public or private child care centers, sports arenas or stadiums, certain bars and taverns, places of worship unless allowed by the presiding official, certain entertainment facilities, hospitals, and college or university dormitories and classrooms.",
          "Exact statutory wording matters. A summary is useful for education, but not enough for a close-call carry decision.",
          "Do not treat every restriction the same. A statutory pistol-free zone, private no-firearm sign, employer policy, court rule, school policy, casino rule, and federal restriction can all operate differently.",
          "Prime Defense field rule: if the location is school-related, court-related, government-related, medical, alcohol-centered, worship-related, entertainment-related, casino-related, security-controlled, or posted, stop and verify before entering armed."
        ],
        source: "MCL 28.425o; Michigan State Police prohibited premises guidance."
      },
      {
        title: "General Firearm-Prohibited Premises",
        risk: "Separate Legal Framework",
        body: [
          "Michigan also has general firearm-prohibited premises under MCL 750.234d. This is separate from the CPL-specific pistol-free zone statute.",
          "General prohibited premises can include places such as depository financial institutions, churches or houses of worship, courts, theatres, sports arenas, day care centers, hospitals, and establishments licensed under the Liquor Control Code, subject to statutory exceptions.",
          "A CPL may change the analysis in certain situations, but it should not be treated as a universal pass.",
          "This is one reason Michigan carry law can be confusing: one statute may address CPL concealed carry, while another statute may address possession on certain premises more broadly.",
          "Prime Defense field rule: identify the location first, then identify which legal framework applies."
        ],
        source: "MCL 750.234d."
      },
      {
        title: "Schools & Weapon-Free School Zones",
        risk: "Extreme Risk Area",
        body: [
          "Schools and school property are among the most legally dangerous places for carry mistakes.",
          "Michigan law includes both CPL prohibited-premises rules and weapon-free school zone rules. Those are related but not identical.",
          "School property can involve buildings, parking lots, school vehicles, school events, school property used for school purposes, and other fact-specific questions.",
          "Parent pickup and drop-off can be misunderstood. Do not rely on what another parent, internet comment, or old article says.",
          "Open carry, concealed carry, vehicle presence, student events, extracurricular activities, and school-owned property can all change the analysis.",
          "Prime Defense field rule: if school property is involved, verify the exact statute and exception before carrying. When uncertain, do not enter armed."
        ],
        source: "MCL 28.425o; MCL 750.237a."
      },
      {
        title: "Secure Storage / Child Access",
        risk: "Criminal & Civil Exposure",
        body: [
          "Michigan secure storage law requires special care when minors are likely to be present.",
          "A firearm that is unattended should be unloaded and locked with a locking device or stored in a locked box or container if it is reasonably known that a minor is likely to be present.",
          "High-risk locations include vehicles, nightstands, purses, backpacks, range bags, unlocked closets, garages, and bedside tables.",
          "Responsible carry does not end when the firearm leaves your holster. Storage decisions can create criminal liability, civil liability, family consequences, and community harm.",
          "Vehicle storage deserves special attention. A locked vehicle is not a gun safe. Vehicle theft is predictable and common.",
          "Prime Defense field rule: when a firearm is unattended, ask: could a child, guest, roommate, prohibited person, contractor, visitor, or thief access it?"
        ],
        source: "MCL 28.429; Michigan secure storage framework."
      },
      {
        title: "EMD / Stun Gun Disclosure & Carry",
        risk: "Less Lethal Does Not Mean Legally Simple",
        body: [
          "Michigan law includes electro-muscular disruption devices in portions of the defensive tool and prohibited premises framework.",
          "A device being less lethal does not mean it is legally casual. Possession, carry method, disclosure, prohibited places, and use-of-force principles still matter.",
          "Disclosure obligations may apply depending on the device, carry authority, and police contact circumstances.",
          "Recommended wording during police contact: Officer, I have a CPL and I am carrying an electronic defensive device. How would you like me to proceed?",
          "Prime Defense field rule: treat EMD and stun gun carry with the same seriousness as any defensive tool. Less lethal does not mean consequence-free."
        ],
        source: "Michigan EMD/stun gun and CPL statutory framework."
      },
      {
        title: "Casinos",
        risk: "Special Prohibited Location Concern",
        body: [
          "Michigan State Police prohibited-premises guidance specifically flags casinos and notes that a pistol is subject to seizure in a casino whether carried concealed or exposed.",
          "Casinos may also involve private property rules, gaming regulations, tribal considerations, alcohol, event security, and surveillance.",
          "The legal risk is not just whether you are allowed to possess. It is also whether you are violating property rules, gaming rules, or a specific restricted-area rule.",
          "Prime Defense field rule: do not assume your CPL authorizes casino carry. Verify the specific property. If instructed to leave, leave calmly and immediately."
        ],
        source: "Michigan State Police prohibited premises guidance."
      },
      {
        title: "Federal Buildings / Post Offices",
        risk: "Federal Law Overlay",
        body: [
          "Federal property can be governed by federal law, not Michigan CPL law.",
          "Post offices, federal agency buildings, federal courthouses, secure federal facilities, and posted federal property are high-risk locations.",
          "A Michigan CPL does not override federal property restrictions.",
          "Postal property is a classic trap area because people may think they are simply running a quick errand.",
          "Prime Defense field rule: if the property is federal, stop using a Michigan-only carry analysis. Verify federal law and posted instructions."
        ],
        source: "Federal facility and postal property legal framework."
      },
      {
        title: "Transport Without CPL",
        risk: "Vehicle Mistake Zone",
        body: [
          "Without a CPL, do not treat a pistol in a vehicle as carry. Treat it as lawful transport only.",
          "Practical transport method: unloaded, secured, inaccessible, and connected to a lawful purpose or destination.",
          "Common lawful transport contexts may include going to or from a range, repair, lawful sale, purchase, hunting-related lawful activity, or another lawful destination.",
          "A common mistake is open carrying on foot, then entering a vehicle with the pistol accessible.",
          "Another common mistake is keeping a pistol loaded in a center console or glove box without a CPL.",
          "Prime Defense field rule: the moment you enter a vehicle, your legal analysis changes."
        ],
        source: "Michigan Firearms Laws publication."
      },
      {
        title: "Prohibited Persons / Domestic Violence / PPOs",
        risk: "Possession Eligibility Warning",
        body: [
          "Not everyone who owns or wants a firearm is legally allowed to possess one.",
          "Possible disqualifiers can include felony convictions, certain misdemeanor convictions, domestic violence restrictions, mental health adjudications, court orders, personal protection orders, bond conditions, probation or parole restrictions, and federal prohibitions.",
          "Domestic violence-related cases can trigger both state and federal firearm restrictions.",
          "A PPO or bond condition can create restrictions even when the person thinks they have not been convicted of anything.",
          "Do not assume you are still eligible because you physically still possess your CPL card.",
          "Prime Defense field rule: if there is a pending case, domestic dispute, PPO, bond condition, court order, prior conviction, or mental health adjudication, get legal guidance before possessing or carrying."
        ],
        source: "Michigan and federal prohibited-person framework."
      },
      {
        title: "ERPO / Red Flag Orders",
        risk: "Court Order Emergency",
        body: [
          "Michigan has an Extreme Risk Protection Order framework commonly referred to as ERPO or red flag law.",
          "An ERPO can temporarily prevent a person from possessing or purchasing firearms and can require surrender or removal under court order.",
          "Violating an ERPO can create serious criminal exposure and long-term firearms consequences.",
          "Do not hide firearms, transfer property casually, argue during service, or post about the situation online.",
          "Prime Defense field rule: if served with a firearm-related court order, comply safely at the scene and contact qualified legal counsel immediately."
        ],
        source: "Michigan Extreme Risk Protection Order Act; MCL 691.1801 to MCL 691.1821 framework."
      },
      {
        title: "Purchase / Registration Basics",
        risk: "Paperwork & Transfer Risk",
        body: [
          "Michigan pistol acquisition and transfer rules involve paperwork and record requirements that can vary based on CPL status, transaction type, and where the pistol is obtained.",
          "A private sale is not complete just because money changed hands.",
          "Keep copies of purchase records, sales records, registration paperwork, transfer documents, and receipts organized.",
          "Mistakes can happen during private transfers, inherited firearms, gifts, family transfers, and out-of-state purchases.",
          "Prime Defense field rule: if buying, selling, inheriting, gifting, or transferring a pistol, verify the required Michigan process before the transfer."
        ],
        source: "Michigan Firearms Laws publication."
      },
      {
        title: "Civil Liability / Wrongful Death Exposure",
        risk: "Financial & Legal Exposure",
        body: [
          "Even if no criminal charge is filed, a defensive incident can still trigger civil litigation.",
          "Potential civil claims may involve wrongful death, personal injury, negligence, emotional distress, property damage, or claims from the attacker or attacker’s family.",
          "Michigan law includes civil-liability protection language for qualifying lawful self-defense situations, but whether it applies depends on the facts.",
          "Your behavior before, during, and after the incident may all be examined.",
          "Social media posts, angry texts, prior threats, bad training statements, reckless behavior, and inconsistent statements can hurt you.",
          "Prime Defense field rule: self-defense is not only a trigger-pull decision. It is a total-facts investigation."
        ],
        source: "MCL 780.972; MCL 600.2922 framework."
      },
      {
        title: "Hunting / DNR Context",
        risk: "CPL Does Not Replace DNR Rules",
        body: [
          "Hunting, public land, state land, DNR rules, species seasons, transport rules, ORVs, boats, and firearm-type rules can affect what is lawful.",
          "A CPL does not replace hunting laws, game laws, trespass rules, DNR restrictions, or public-land rules.",
          "Long guns, pistols, loaded firearms, vehicles, blinds, boats, ORVs, and public land may each involve different rules.",
          "Prime Defense field rule: if carrying or transporting during hunting, scouting, camping, boating, ORV use, or public-land activity, check DNR rules in addition to CPL law."
        ],
        source: "Michigan DNR and firearms transport/hunting framework."
      },
      {
        title: "Use of Force / Deadly Force",
        risk: "Life-Altering Standard",
        body: [
          "Deadly force may be justified only if the person honestly and reasonably believes it is necessary to prevent imminent death, great bodily harm, or sexual assault, and other statutory conditions are met.",
          "Honest belief means you actually believed the threat was real.",
          "Reasonable belief means a reasonable person in the same circumstances would likely understand the danger similarly.",
          "Imminent means happening now or immediately about to happen. A past threat, vague future threat, insult, fear, property dispute, or anger is not enough by itself.",
          "Necessity means deadly force was needed to stop the qualifying threat. It is not punishment, revenge, warning, control, or intimidation.",
          "Prime Defense field rule: the legal question is not whether you were scared. The legal question is whether the facts support an honest and reasonable belief that deadly force was immediately necessary."
        ],
        source: "MCL 780.972."
      },
      {
        title: "Defense of Others",
        risk: "Third-Party Uncertainty",
        body: [
          "Defense of another person can be lawful under the same type of honest, reasonable, imminent-threat analysis.",
          "The threshold is not lower because someone else is involved.",
          "The danger is that you may not know who started the fight, who escalated it, who is the aggressor, or whether the person you are defending is legally innocent.",
          "High-risk mistake: jumping into a third-party fight based on emotion or incomplete information.",
          "Prime Defense field rule: defense of others is legally and tactically dangerous because you may not know the whole story."
        ],
        source: "MCL 780.972."
      },
      {
        title: "Stand Your Ground / No Duty to Retreat",
        risk: "Often Misunderstood",
        body: [
          "Michigan law may remove a duty to retreat in qualifying lawful self-defense situations where the person has a legal right to be.",
          "No duty to retreat does not mean permission to escalate, chase, provoke, re-engage, threaten, or use force over pride or property.",
          "No duty to retreat does not eliminate the requirement that force be honest, reasonable, imminent, and necessary.",
          "Leaving safely, creating distance, and avoiding conflict can still help show reasonableness.",
          "Prime Defense field rule: avoidance is not weakness. Avoidance is often excellent evidence."
        ],
        source: "Michigan Self-Defense Act framework."
      },
      {
        title: "Attorney / Contact-After-Incident Reminders",
        risk: "Words Become Evidence",
        body: [
          "After a defensive incident: get safe, call 911, request police and medical, then contact legal-defense support or attorney guidance as soon as practical.",
          "Contact one trusted family member only if safe and appropriate.",
          "Do not text a group, post online, call multiple friends, argue with bystanders, talk to media, or repeatedly explain what happened.",
          "Family script: I was involved in a defensive incident. I am safe. Please do not discuss this with anyone. I am waiting for legal guidance.",
          "Prime Defense field rule: short, factual, rights-protecting communications are safer than emotional explanations."
        ],
        source: "Prime Defense aftermath protocol."
      }
    ],
    [
      {
        title: "Can I Carry Here?",
        steps: [
          "1. Am I legally allowed to possess today?",
          "2. Is my CPL valid, current, and not restricted?",
          "3. Am I carrying concealed, openly, in a vehicle, or transporting?",
          "4. Is this a CPL pistol-free zone under MCL 28.425o?",
          "5. Is this a general firearm-prohibited premise under MCL 750.234d?",
          "6. Is this school-related, court-related, federal, casino-related, hospital-related, worship-related, alcohol-related, private property, tribal, employer-controlled, or security-controlled?",
          "7. Are there signs, verbal instructions, event rules, bag checks, or security screening?",
          "8. If any answer is uncertain, do not enter armed until verified."
        ]
      },
      {
        title: "Should I Display My Defensive Tool?",
        steps: [
          "1. Is there an immediate threat of death, great bodily harm, sexual assault, or serious unlawful force?",
          "2. Is display necessary to stop the threat right now?",
          "3. Am I displaying from fear and necessity, or from anger and intimidation?",
          "4. Can I safely leave, create distance, lock a door, drive away, or call 911?",
          "5. If displayed, call 911 first and report the attack or attempted attack.",
          "6. Do not say: I showed it to scare him. Say only necessary facts and wait for legal guidance."
        ]
      },
      {
        title: "After a Defensive Incident",
        steps: [
          "1. Get safe and make sure the threat has stopped.",
          "2. Call 911 and request police and medical.",
          "3. Keep hands visible when police arrive.",
          "4. Identify the attacker, evidence, and witnesses only as necessary.",
          "5. State that you will cooperate after speaking with counsel.",
          "6. Do not argue, speculate, exaggerate, apologize, explain repeatedly, or post online."
        ]
      },
      {
        title: "Transport Without CPL",
        steps: [
          "1. Confirm you are legally eligible to possess.",
          "2. Confirm the destination is lawful.",
          "3. Unload the pistol.",
          "4. Secure it in a lawful transport configuration.",
          "5. Keep it inaccessible and separate from ammunition where appropriate.",
          "6. Do not treat the vehicle as carry. Treat it as transport only."
        ]
      }
    ],
    [
      {
        title: "Parking Lot Confrontation",
        summary: "Parking lots create distance, vehicle, witness, lighting, and escape-route issues. Most bad cases start as avoidable arguments.",
        guidance: [
          "Stay mobile.",
          "Create distance.",
          "Do not argue over parking, gestures, insults, or disrespect.",
          "Use your vehicle as an escape tool when safe.",
          "If you display, be ready to explain the immediate threat that made it necessary.",
          "Call 911 first if you were attacked or threatened."
        ]
      },
      {
        title: "Road Rage",
        summary: "Road rage is one of the worst legal contexts for armed citizens because both sides may look like aggressors.",
        guidance: [
          "Do not follow.",
          "Do not brake-check.",
          "Do not gesture.",
          "Do not get out unless absolutely necessary for safety.",
          "Drive to a safe public place or police station if needed.",
          "Call 911 if there is an active threat."
        ]
      },
      {
        title: "Home Defense",
        summary: "Castle Doctrine concepts do not eliminate the need for reasonableness, target identification, and post-incident discipline.",
        guidance: [
          "Identify before acting.",
          "Do not shoot at sounds or shadows.",
          "Use lights, verbal commands, barriers, and 911 when safe.",
          "Avoid chasing outside after the threat leaves.",
          "Preserve evidence and wait for counsel before detailed statements."
        ]
      },
      {
        title: "School Pickup / Drop-Off",
        summary: "School property is a high-risk legal environment with multiple overlapping rules.",
        guidance: [
          "Verify statute and exceptions before carrying.",
          "Do not rely on what another parent says.",
          "Understand the difference between parking lot, building, vehicle, school event, and school property contexts.",
          "When uncertain, choose the safest lawful option."
        ]
      },
      {
        title: "No Shots Fired / Defensive Display",
        summary: "The person who calls 911 first often frames the incident first. If you lawfully displayed due to a threat, report the attack or attempted attack immediately.",
        guidance: [
          "Call 911.",
          "Report the threat.",
          "Give suspect description and direction.",
          "Do not over-explain before legal guidance.",
          "Do not say you displayed to scare someone."
        ]
      },
      {
        title: "Third-Party Fight",
        summary: "Defense of others may be lawful, but third-party fights are dangerous because you may not know who the aggressor is.",
        guidance: [
          "Create distance and call 911 when possible.",
          "Look for weapons, disparity of force, and imminent serious harm.",
          "Do not assume the loudest person is the bad guy.",
          "Do not intervene with deadly force unless the legal threshold is clearly met."
        ]
      }
    ],
    [
      "Assuming open carry answers every location question.",
      "Forgetting that vehicle carry changes the legal analysis.",
      "Failing to immediately disclose during police contact.",
      "Carrying in a prohibited location because a summary seemed unclear.",
      "Displaying a firearm during an argument rather than an immediate threat.",
      "Saying: I showed it to scare him.",
      "Intervening in a third-party fight without knowing the aggressor.",
      "Using or threatening deadly force over property.",
      "Talking too much after an incident.",
      "Posting online after an incident.",
      "Ignoring PPO, bond condition, domestic violence, or prohibited-person issues.",
      "Assuming a CPL overrides school rules, federal rules, casino rules, or employer rules.",
      "Leaving a firearm unsecured in a vehicle.",
      "Relying on old reciprocity information before travel."
    ],
    [
      "Am I legally eligible to possess today?",
      "Is my CPL valid and not expired?",
      "Am I under any PPO, bond condition, court order, ERPO, probation, parole, or domestic violence restriction?",
      "Am I entering a school, hospital, casino, court, federal property, alcohol-heavy location, place of worship, posted private property, or employer-controlled location?",
      "Am I carrying in a vehicle or merely transporting?",
      "Do I know my disclosure script if stopped?",
      "Is my defensive tool secured from children and unauthorized access?",
      "Am I emotionally calm enough to avoid unnecessary confrontation?",
      "Do I have my emergency contact and legal-defense contact ready?",
      "Do I know what I will say and what I will not say after an incident?"
    ],
    [
      {
        myth: "Stand your ground means I can shoot if I feel threatened.",
        reality: "No. You still need an honest and reasonable belief that deadly force is immediately necessary to stop a qualifying threat."
      },
      {
        myth: "Open carry is legal, so I can open carry anywhere.",
        reality: "No. Location restrictions, vehicle rules, prohibited-person rules, private property, schools, casinos, courts, and federal property still matter."
      },
      {
        myth: "A CPL lets me carry everywhere.",
        reality: "No. A CPL is permission under limits, not unlimited authority."
      },
      {
        myth: "If I do not fire, it is not a big deal.",
        reality: "A defensive display can still create brandishing, assault, disorderly conduct, or intimidation allegations if not justified."
      },
      {
        myth: "If the shooting is justified, I do not need to worry about civil court.",
        reality: "Civil claims can still be filed, and whether immunity applies depends on the facts."
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

  CA: makeProfile(
    "California",
    "High-Risk Travel State",
    "California does not honor a Michigan CPL in this app travel engine. Treat as not recognized and verify California law before travel. California is a high-risk state for transport, local restrictions, magazine rules, ammunition rules, and sensitive-place restrictions.",
    {
      reciprocity: "Michigan CPL not recognized.",
      permitlessCarry: "No. Do not rely on permitless carry.",
      concealedCarry: "Michigan CPL does not authorize concealed carry in California.",
      openCarry: "Highly restricted. Verify current California law.",
      vehicleCarry: "Verify California transport rules before entering the state.",
      dutyToInform: "Verify current California police-contact rules.",
      privateSigns: "Private, local, and sensitive-place rules may matter.",
      forceLaw: "Verify current California self-defense law."
    },
    [
      "Do not carry on a Michigan CPL in California.",
      "Verify transport rules before entering the state.",
      "Magazine, ammunition, and local restrictions may apply.",
      "Avoid casual stops when transporting under any federal travel framework."
    ],
    [
      {
        title: "Michigan CPL Not Recognized",
        risk: "Do Not Carry on Michigan CPL",
        body: [
          "California does not honor a Michigan CPL in this app travel engine.",
          "Do not assume a permit, training certificate, or Michigan CPL creates carry authority in California.",
          "Possession, transport, ammunition, magazine, and local rules require careful review."
        ],
        source: "High-risk travel profile. Official California source verification required."
      }
    ],
    [
      {
        title: "Before Traveling to California",
        steps: [
          "1. Do not rely on Michigan CPL.",
          "2. Verify lawful transport rules.",
          "3. Verify magazine and ammunition restrictions.",
          "4. Verify local restrictions.",
          "5. Avoid unnecessary stops if transporting under federal framework."
        ]
      }
    ],
    [
      {
        title: "Driving Through California",
        summary: "Transport rules and local restrictions are major risk points.",
        guidance: [
          "Plan the route.",
          "Verify transport method.",
          "Avoid unnecessary handling.",
          "Do not assume other states' rules apply."
        ]
      }
    ],
    [
      "Assuming a Michigan CPL travels into California.",
      "Ignoring transport rules.",
      "Ignoring magazine, ammunition, local, and sensitive-place restrictions.",
      "Stopping unnecessarily while transporting."
    ],
    [
      "Do not carry on Michigan CPL alone.",
      "Verify lawful transport.",
      "Verify magazine and ammunition restrictions.",
      "Verify local rules."
    ],
    [
      {
        myth: "I am only visiting, so my Michigan CPL should be enough.",
        reality: "California does not treat a Michigan CPL as carry authority in this app travel engine."
      }
    ]
  ),

  IL: makeProfile(
    "Illinois",
    "High-Risk Travel State",
    "Illinois does not honor a Michigan CPL for ordinary carry in this app travel engine. Verify Illinois law before travel, especially vehicle transport, Chicago/local issues, prohibited places, and private property.",
    {
      reciprocity: "Michigan CPL not recognized for ordinary carry in this app travel engine.",
      permitlessCarry: "No. Do not rely on permitless carry.",
      concealedCarry: "Michigan CPL does not authorize ordinary concealed carry in Illinois.",
      openCarry: "Verify current Illinois law.",
      vehicleCarry: "Verify Illinois transport and vehicle rules.",
      dutyToInform: "Verify current Illinois law.",
      privateSigns: "Private property and signage may matter.",
      forceLaw: "Verify current Illinois self-defense law."
    },
    [
      "Do not assume Michigan CPL permits carry in Illinois.",
      "Vehicle transport rules matter heavily.",
      "Chicago/local rules may add risk.",
      "Prohibited places and signage need verification."
    ],
    [
      {
        title: "Michigan CPL Not Recognized for Ordinary Carry",
        risk: "Do Not Rely on Michigan CPL",
        body: [
          "Illinois does not honor a Michigan CPL for ordinary carry in this app travel engine.",
          "Transport and vehicle rules should be verified before travel.",
          "Local rules and sensitive locations can add risk."
        ],
        source: "High-risk travel profile. Official Illinois source verification required."
      }
    ],
    [
      {
        title: "Before Traveling to Illinois",
        steps: [
          "1. Do not rely on Michigan CPL for ordinary carry.",
          "2. Verify vehicle transport rules.",
          "3. Verify local restrictions.",
          "4. Verify prohibited places.",
          "5. Verify ammunition/magazine restrictions where applicable."
        ]
      }
    ],
    [
      {
        title: "Chicago Area Travel",
        summary: "Dense urban areas and local rules can increase risk.",
        guidance: [
          "Verify local restrictions.",
          "Plan transport carefully.",
          "Avoid unnecessary handling.",
          "Do not assume Michigan rules apply."
        ]
      }
    ],
    [
      "Assuming Michigan CPL permits carry in Illinois.",
      "Ignoring Chicago/local issues.",
      "Ignoring vehicle transport rules.",
      "Ignoring posted locations."
    ],
    [
      "Verify transport rules.",
      "Verify prohibited places.",
      "Do not rely on Michigan CPL alone.",
      "Verify local restrictions."
    ],
    [
      {
        myth: "Illinois is next to Michigan, so reciprocity should be easy.",
        reality: "Illinois does not honor Michigan CPL for ordinary carry in this app travel engine."
      }
    ]
  ),

  NY: makeProfile(
    "New York",
    "High-Risk Travel State",
    "New York does not honor a Michigan CPL in this app travel engine. Treat as not recognized and verify New York law before travel. New York is a high-risk state for transport, sensitive locations, magazine/ammunition issues, and New York City restrictions.",
    {
      reciprocity: "Michigan CPL not recognized.",
      permitlessCarry: "No. Do not rely on permitless carry.",
      concealedCarry: "Michigan CPL does not authorize concealed carry in New York.",
      openCarry: "Verify current New York law.",
      vehicleCarry: "Verify strict transport rules.",
      dutyToInform: "Verify current New York law.",
      privateSigns: "Sensitive and restricted location rules may be extensive.",
      forceLaw: "Verify current New York self-defense law."
    },
    [
      "Do not carry on Michigan CPL in New York.",
      "New York City requires separate caution and verification.",
      "Sensitive-place rules can be extensive.",
      "Transport, magazine, and ammunition rules require careful verification."
    ],
    [
      {
        title: "Michigan CPL Not Recognized",
        risk: "Do Not Carry on Michigan CPL",
        body: [
          "New York does not honor a Michigan CPL in this app travel engine.",
          "Do not assume federal travel rules allow casual possession during stops.",
          "New York City and sensitive-place rules require separate review."
        ],
        source: "High-risk travel profile. Official New York source verification required."
      }
    ],
    [
      {
        title: "Before Traveling to New York",
        steps: [
          "1. Do not rely on Michigan CPL.",
          "2. Verify transport rules.",
          "3. Verify New York City rules separately.",
          "4. Verify sensitive-place restrictions.",
          "5. Verify magazine and ammunition restrictions."
        ]
      }
    ],
    [
      {
        title: "Passing Through New York",
        summary: "Federal travel concepts can be misunderstood and may not protect casual stops or deviations.",
        guidance: [
          "Plan carefully.",
          "Avoid unnecessary stops.",
          "Keep transport method compliant.",
          "Verify law before the trip."
        ]
      }
    ],
    [
      "Assuming federal travel rules allow casual possession during stops.",
      "Ignoring New York City rules.",
      "Ignoring sensitive-place restrictions.",
      "Assuming Michigan CPL has any carry value in New York."
    ],
    [
      "Do not carry on Michigan CPL alone.",
      "Verify transport and ammunition/magazine rules.",
      "Avoid unnecessary stops if transporting under federal framework.",
      "Verify New York City restrictions separately."
    ],
    [
      {
        myth: "I am just passing through New York, so I am fine.",
        reality: "Transport through New York requires careful planning and strict compliance. Casual stops can create risk."
      }
    ]
  )
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

function renderTileMapFallback(permitState){
  var cellW = 62;
  var cellH = 46;
  var gap = 5;

  var html = '<svg class="mapSvg" viewBox="0 0 720 390" role="img" aria-label="Fallback clickable United States reciprocity map">';
  html += '<text x="18" y="26" style="font-size:17px;font-weight:950;fill:#11151b">Fallback State Map</text>';
  html += '<text x="18" y="47" style="font-size:12px;font-weight:700;fill:#626975">Tap a state to populate the legal intelligence panel.</text>';

  mapCells.forEach(function(cell){
    var abbr = cell[0];
    var col = cell[1];
    var row = cell[2];
    var x = 18 + col * (cellW + gap);
    var y = 68 + row * (cellH + gap);
    var status = stateStatus(permitState, abbr);
    var selected = selectedMapState === abbr;

    html += '<rect class="mapCell ' + (selected ? 'selected' : '') + '" x="' + x + '" y="' + y + '" width="' + cellW + '" height="' + cellH + '" rx="9" fill="' + statusFill(status) + '" onclick="selectMapState(\'' + abbr + '\')"></rect>';
    html += '<text class="mapText" x="' + (x + cellW / 2) + '" y="' + (y + cellH / 2) + '">' + abbr + '</text>';
  });

  html += '</svg>';
  return html;
}

function renderSvgMap(permitState){
  return '<div id="actualUsMap" class="actualMap" aria-label="Clickable United States map"></div>' +
    '<div id="mapLoading" class="mapLoading">Loading interactive state-shape map. If it does not load, the app will show the fallback clickable state map.</div>';
}

function statusFillKey(status){
  if(status === "recognized") return "recognized";
  if(status === "restricted") return "restricted";
  if(status === "not_recognized") return "notRecognized";
  return "verify";
}

function initActualMap(permitState){
  var el = q("actualUsMap");
  if(!el) return;

  var loading = q("mapLoading");

  if(typeof Datamap === "undefined" || typeof d3 === "undefined"){
    if(loading){
      loading.innerHTML = "The live state-shape map could not load from the map library. Showing fallback clickable map instead.";
    }
    el.innerHTML = renderTileMapFallback(permitState);
    return;
  }

  var mapData = {};
  states.forEach(function(s){
    var abbr = s[0];
    mapData[abbr] = {
      fillKey: statusFillKey(stateStatus(permitState, abbr)),
      statusLabel: statusLabelByStatus(stateStatus(permitState, abbr)),
      stateName: s[1]
    };
  });

  try{
    el.innerHTML = "";
    var map = new Datamap({
      element: el,
      scope: "usa",
      responsive: true,
      fills: {
        recognized: "#b9f3cc",
        restricted: "#fde2b8",
        notRecognized: "#ffc2c7",
        verify: "#dbe2ea",
        defaultFill: "#dbe2ea"
      },
      data: mapData,
      geographyConfig: {
        borderColor: "#ffffff",
        borderWidth: 1.4,
        highlightBorderColor: "#11151b",
        highlightBorderWidth: 2,
        highlightFillColor: function(geo){
          var item = mapData[geo.id];
          return item ? statusFill(stateStatus(permitState, geo.id)) : "#dbe2ea";
        },
        popupTemplate: function(geo, data){
          var status = data && data.statusLabel ? data.statusLabel : statusLabelByStatus(stateStatus(permitState, geo.id));
          return '<div class="hoverinfo"><strong>' + geo.properties.name + '</strong><br>' + status + '<br>Click for laws and reciprocity</div>';
        }
      },
      done: function(datamap){
        datamap.svg.selectAll('.datamaps-subunit')
          .style('cursor', 'pointer')
          .style('stroke', function(geo){ return geo.id === selectedMapState ? '#11151b' : '#ffffff'; })
          .style('stroke-width', function(geo){ return geo.id === selectedMapState ? 3.5 : 1.4; })
          .on('click', function(geo){ selectMapState(geo.id); });
      }
    });

    if(loading){
      loading.innerHTML = "Click any state shape to view reciprocity and that state’s law profile.";
    }

    window.setTimeout(function(){
      if(map && map.resize){ map.resize(); }
    }, 150);
  } catch(err){
    console.log("Map render error:", err);
    if(loading){
      loading.innerHTML = "The state-shape map could not render. Showing fallback clickable map instead.";
    }
    el.innerHTML = renderTileMapFallback(permitState);
  }
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

function renderLawProfile(abbr){
  var law = stateLawData[abbr];

  if(!law){
    return '<div class="detailBox">' +
      '<h3>' + abbr + ' — ' + stateName(abbr) + '</h3>' +
      '<p><b>State law profile:</b> Not built yet.</p>' +
      '<p class="small">This state is still using the reciprocity-only travel warning.</p>' +
      '</div>';
  }

  var qk = law.quick || {};

  var html = '<div class="detailBox">' +
    '<h3>' + abbr + ' — ' + escapeHtml(law.name || stateName(abbr)) + '</h3>' +
    '<span class="lawPill green">' + escapeHtml(law.profileStatus || "Profile") + '</span>' +
    '<span class="lawPill gray">Reviewed: ' + escapeHtml(law.lastReviewed || "Verify") + '</span>' +
    '<p>' + escapeHtml(law.summary || "") + '</p>';

  html += '<div class="profileGrid">' +
    '<div class="miniPanel"><b>Michigan CPL / Recognition</b><p class="small">' + escapeHtml(qk.reciprocity || "Verify recognition.") + '</p></div>' +
    '<div class="miniPanel"><b>Permitless Carry</b><p class="small">' + escapeHtml(qk.permitlessCarry || "Verify current law.") + '</p></div>' +
    '<div class="miniPanel"><b>Concealed Carry</b><p class="small">' + escapeHtml(qk.concealedCarry || "Verify current law.") + '</p></div>' +
    '<div class="miniPanel"><b>Open Carry</b><p class="small">' + escapeHtml(qk.openCarry || "Verify current law.") + '</p></div>' +
    '<div class="miniPanel"><b>Vehicle Carry</b><p class="small">' + escapeHtml(qk.vehicleCarry || "Verify current law.") + '</p></div>' +
    '<div class="miniPanel"><b>Duty to Inform</b><p class="small">' + escapeHtml(qk.dutyToInform || "Verify current law.") + '</p></div>' +
    '<div class="miniPanel"><b>Private Property / Signs</b><p class="small">' + escapeHtml(qk.privateSigns || "Verify current law.") + '</p></div>' +
    '<div class="miniPanel"><b>Use of Force</b><p class="small">' + escapeHtml(qk.forceLaw || "Verify current law.") + '</p></div>' +
  '</div>';

  html += renderList("Red Flag Travel Alerts", law.travelAlerts);

  if(law.legalSections && law.legalSections.length){
    html += '<h3>Detailed Legal Intelligence</h3>';
    law.legalSections.forEach(function(section){
      html += '<div class="legalItem">' +
        '<h3>' + escapeHtml(section.title) + '</h3>' +
        '<span class="lawPill yellow">' + escapeHtml(section.risk || "Legal Topic") + '</span>';

      (section.body || []).forEach(function(p){
        html += '<p>' + escapeHtml(p) + '</p>';
      });

      if(section.source){
        html += '<div class="legalSource">' + escapeHtml(section.source) + '</div>';
      }

      html += '</div>';
    });
  }

  if(law.decisionBlocks && law.decisionBlocks.length){
    html += '<h3>Decision Blocks</h3>';
    law.decisionBlocks.forEach(function(block){
      html += '<div class="legalItem"><h3>' + escapeHtml(block.title) + '</h3>';
      (block.steps || []).forEach(function(step){
        html += '<p>' + escapeHtml(step) + '</p>';
      });
      html += '</div>';
    });
  }

  if(law.scenarios && law.scenarios.length){
    html += '<h3>High-Risk Scenarios</h3>';
    law.scenarios.forEach(function(s){
      html += '<div class="scenario">' +
        '<h3>' + escapeHtml(s.title) + '</h3>' +
        '<p>' + escapeHtml(s.summary || "") + '</p>';

      (s.guidance || []).forEach(function(g){
        html += '<p class="small">• ' + escapeHtml(g) + '</p>';
      });

      html += '</div>';
    });
  }

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
  var status = stateStatus(permitState, travelState);
  var cls = statusClass(status);

  return '<div class="detailBox">' +
    '<h3>' + travelState + ' — ' + stateName(travelState) + '</h3>' +
    '<span class="detailStatus ' + cls + '">' + statusLabelByStatus(status) + '</span>' +
    '<p><b>Travel meaning:</b> This color is a starting point only. It does not guarantee lawful carry in every place or situation.</p>' +
    '<p><b>Check before travel:</b> permit recognition, prohibited places, vehicle carry, duty to inform, signage/private property rules, alcohol restrictions, age restrictions, magazine/ammunition rules, local restrictions, tribal restrictions, federal property, and whether your permit must be resident or nonresident.</p>' +
  '</div>' +
  renderLawProfile(travelState);
}

function getReciprocityHtml(state){
  var data = reciprocityData[state];
  var selectedName = stateName(state);

  if(!selectedMapState) selectedMapState = state;

  if(!data){
    return '<div class="reciprocityTitle">' + selectedName + ' Permit Profile</div>' +
      '<p><b>Status:</b> State-specific outbound reciprocity data has not been fully verified in this app yet.</p>' +
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
          '<p class="small">Select your permit state. Click any state on the map to view reciprocity status and available legal profile data.</p>' +
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
          '<p class="small">Open the expanded Michigan guide with detailed sections, decision blocks, common mistakes, scenarios, plain-English reality checks, and before-carry checklists.</p>' +
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
  window.setTimeout(function(){ initActualMap(stateEl.value); }, 50);
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

window.addEventListener("resize", function(){
  var stateEl = q("state");
  if(stateEl && q("actualUsMap")){
    window.setTimeout(function(){ initActualMap(stateEl.value); }, 150);
  }
});

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
