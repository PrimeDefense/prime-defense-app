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
.subtitle{color:var(--muted);line-height:1.55;margin-bottom:24px}
.tabs{
  display:grid;
  grid-template-columns:1fr 1fr;
  gap:10px;
  margin-bottom:20px;
  background:#e9ecf1;
  padding:6px;
  border-radius:18px;
}
.tab{background:transparent;color:var(--ink);border:0}
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
.msg{margin-top:16px;color:#9a3412;font-weight:800;min-height:22px}
.dashboard{max-width:1220px;margin:28px auto;padding:22px}
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
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(240px,1fr));gap:14px}
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
.status.locked{background:rgba(215,25,32,.10);color:#b91c1c;border:1px solid rgba(215,25,32,.30)}
.small{color:var(--muted);font-size:13px;line-height:1.55}
.actions{display:flex;flex-wrap:wrap;gap:10px;margin-top:14px}
.actions button{min-width:150px}
.lockbox{max-width:750px;margin:60px auto;text-align:center;border-color:rgba(215,25,32,.25)}
.modeButtonGrid{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:12px;margin-top:14px}
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
.bigAction{width:100%;padding:20px;font-size:20px;margin:10px 0}
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
.reciprocityTitle{font-size:22px;font-weight:950;color:var(--ink);margin-bottom:10px}
.reciprocitySub{color:var(--muted);font-size:13px;line-height:1.45;margin:8px 0 14px}
.green{background:rgba(22,163,74,.10);color:#13733a;border-color:rgba(22,163,74,.30)}
.yellow{background:rgba(217,119,6,.12);color:#9a3412;border-color:rgba(217,119,6,.32)}
.red{background:rgba(215,25,32,.10);color:#b91c1c;border-color:rgba(215,25,32,.30)}
.gray{background:rgba(100,116,139,.10);color:#475569;border-color:rgba(100,116,139,.22)}
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
.mapState.selected{outline:3px solid var(--dark);transform:scale(1.04)}
.mapLegend{display:flex;flex-wrap:wrap;gap:8px;margin:8px 0 14px}
.legendItem{font-size:12px;font-weight:900;padding:7px 10px;border-radius:999px;border:1px solid rgba(16,19,24,.12)}
.detailBox,.legalItem{
  background:#fff;
  border:1px solid rgba(16,19,24,.10);
  border-radius:20px;
  padding:18px;
  margin-top:14px;
}
.legalItem{padding:20px;margin:14px 0;line-height:1.6}
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
.profileGrid{display:grid;grid-template-columns:repeat(auto-fit,minmax(250px,1fr));gap:12px}
.miniPanel{background:#fff;border:1px solid rgba(16,19,24,.08);border-radius:18px;padding:16px}
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
.twoColumn{display:grid;grid-template-columns:1fr 1.1fr;gap:16px;align-items:start}
.stickyMap{position:sticky;top:18px}
@media(max-width:850px){.twoColumn{grid-template-columns:1fr}.stickyMap{position:static}}
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
  ["SD","South Dakota"],["TN","Tennessee"],["TX","Texas"],["UT","Utah"],["VT","Vermont"],["VA","Virginia"],["WA","Washington"],["WV","West Virginia"],["WI","Wisconsin"],["WY","Wyoming"]
];

var mapOrder = ["WA","MT","ND","MN","WI","MI","NY","VT","NH","ME","OR","ID","SD","IA","IL","IN","OH","PA","NJ","MA","CA","NV","WY","NE","MO","KY","WV","VA","MD","CT","AK","UT","CO","KS","AR","TN","NC","SC","DE","RI","HI","AZ","NM","OK","LA","MS","AL","GA","FL","TX"];

var reciprocityData = {
  MI: {
    title: "Michigan CPL Reciprocity & Travel Guide",
    verifiedDate: "May 2, 2026",
    sourceNote: "Recognition does not mean identical laws. Follow the law of the state you are physically in. Michigan MSP advises CPL holders to check destination-state law before travel.",
    recognized: ["AL","AK","AZ","AR","CO","FL","GA","HI","ID","IN","IA","KS","KY","LA","ME","MN","MS","MO","MT","NE","NH","NM","NC","ND","OH","OK","PA","SC","SD","TN","TX","UT","VA","VT","WA","WV","WI","WY"],
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

function starterProfile(abbr, name, recognizedText) {
  return {
    name: name,
    lastReviewed: "Starter profile — verify before reliance",
    profileStatus: "Starter",
    summary: name + " is included in the state-law engine as a starter profile. This panel is designed to be expanded to Michigan-level detail. Verify official " + name + " law before carrying or transporting.",
    quick: {
      reciprocity: recognizedText || "Verify permit recognition before travel.",
      permitlessCarry: "Verify current permitless carry status.",
      concealedCarry: "Verify current concealed carry rules.",
      openCarry: "Verify current open carry rules.",
      vehicleCarry: "Verify vehicle carry and transport rules.",
      dutyToInform: "Verify police-contact and duty-to-inform rules.",
      privateSigns: "Verify private property and signage rules.",
      forceLaw: "Verify current self-defense law."
    },
    travelAlerts: [
      "Do not assume Michigan rules apply in " + name + ".",
      "Verify recognition, vehicle carry, prohibited places, schools, private property, and duty-to-inform rules before travel.",
      "Check current official state sources before relying on this summary."
    ],
    legalSections: [
      {
        title: "Permit Recognition",
        risk: "Verify Before Travel",
        body: [
          "This state profile is present so the map can populate a state intelligence panel.",
          "The detailed legal buildout for this state should include permit recognition, permitless carry, prohibited places, vehicle carry, school rules, private property rules, and force law.",
          "Until this state is fully expanded, use the map status as a starting warning only."
        ],
        source: "Starter profile. Official source verification required."
      }
    ],
    commonMistakes: [
      "Assuming Michigan CPL rules apply outside Michigan.",
      "Ignoring vehicle carry and transport differences.",
      "Ignoring prohibited places.",
      "Failing to check duty-to-inform requirements.",
      "Relying on old reciprocity data."
    ],
    beforeCarryChecklist: [
      "Permit recognition checked.",
      "Vehicle carry checked.",
      "Prohibited places checked.",
      "School rules checked.",
      "Private property/signage checked.",
      "Duty-to-inform checked.",
      "Magazine/ammo restrictions checked."
    ]
  };
}

var stateLawData = {
  MI: {
    name: "Michigan",
    lastReviewed: "May 2, 2026",
    profileStatus: "Ultra Expanded",
    summary: "Michigan is not permitless for concealed pistol carry. A CPL is generally required for concealed carry and ready-access pistol carry in a vehicle. Michigan carry decisions require careful attention to disclosure, prohibited premises, weapon-free school zones, safe storage, transport rules, prohibited-person status, ERPOs, civil liability, and post-incident conduct.",
    quick: {
      reciprocity: "Home state profile.",
      permitlessCarry: "No permitless concealed pistol carry.",
      concealedCarry: "Michigan generally requires a valid CPL to carry a concealed pistol.",
      openCarry: "Generally lawful for eligible people, but location, vehicle, intent, and prohibited-person status matter.",
      vehicleCarry: "A CPL is generally required for ready-access pistol carry in a vehicle. Without a CPL, treat it as lawful transport only.",
      dutyToInform: "Yes. A CPL holder carrying concealed and stopped by a peace officer must immediately disclose.",
      privateSigns: "Private property rules matter. Refusal to leave after notice can create trespass exposure.",
      forceLaw: "Deadly force requires an honest and reasonable belief of imminent death, great bodily harm, or sexual assault, plus other statutory conditions."
    },
    travelAlerts: [
      "Michigan has multiple overlapping location rules. CPL pistol-free zones, general firearm-prohibited premises, federal property, casinos, schools, and private property must be analyzed separately.",
      "Vehicle carry is a major dividing line. Without a CPL, treat pistol movement in a vehicle as lawful transport only.",
      "Police disclosure is mandatory for CPL holders carrying concealed during a stop.",
      "School property and school zones are high-risk areas that should not be handled from memory or word-of-mouth.",
      "Safe storage and child access rules create both legal and moral responsibility."
    ],
    legalSections: [
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
          "This is one reason Michigan carry law can be confusing: one statute may address CPL concealed carry, while another statute may address possession on certain premises more broadly."
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
          "A PPO or bond condition can create restrictions even when the person thinks they have not been convicted of anything.",
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
    decisionBlocks: [
      { title: "Can I Carry Here?", steps: ["1. Am I legally allowed to possess today?", "2. Is my CPL valid, current, and not restricted?", "3. Am I carrying concealed, openly, in a vehicle, or transporting?", "4. Is this a CPL pistol-free zone under MCL 28.425o?", "5. Is this a general firearm-prohibited premise under MCL 750.234d?", "6. Is this school-related, court-related, federal, casino-related, hospital-related, worship-related, alcohol-related, private property, tribal, employer-controlled, or security-controlled?", "7. If any answer is uncertain, do not enter armed until verified."] },
      { title: "Should I Display My Defensive Tool?", steps: ["1. Is there an immediate threat of death, great bodily harm, sexual assault, or serious unlawful force?", "2. Is display necessary to stop the threat right now?", "3. Am I displaying from fear and necessity, or from anger and intimidation?", "4. Can I safely leave, create distance, lock a door, drive away, or call 911?", "5. If displayed, call 911 first and report the attack or attempted attack.", "6. Do not say: I showed it to scare him. Say only necessary facts and wait for legal guidance."] },
      { title: "After a Defensive Incident", steps: ["1. Get safe and make sure the threat has stopped.", "2. Call 911 and request police and medical.", "3. Keep hands visible when police arrive.", "4. Identify the attacker, evidence, and witnesses only as necessary.", "5. State that you will cooperate after speaking with counsel.", "6. Do not argue, speculate, exaggerate, apologize, explain repeatedly, or post online."] },
      { title: "Transport Without CPL", steps: ["1. Confirm you are legally eligible to possess.", "2. Confirm the destination is lawful.", "3. Unload the pistol.", "4. Secure it in a lawful transport configuration.", "5. Keep it inaccessible and separate from ammunition where appropriate.", "6. Do not treat the vehicle as carry. Treat it as transport only."] }
    ],
    scenarios: [
      { title: "Parking Lot Confrontation", summary: "Parking lots create distance, vehicle, witness, lighting, and escape-route issues. Most bad cases start as avoidable arguments.", guidance: ["Stay mobile.", "Create distance.", "Do not argue over parking, gestures, insults, or disrespect.", "Use your vehicle as an escape tool when safe.", "If you display, be ready to explain the immediate threat that made it necessary."] },
      { title: "Road Rage", summary: "Road rage is one of the worst legal contexts for armed citizens because both sides may look like aggressors.", guidance: ["Do not follow.", "Do not brake-check.", "Do not gesture.", "Do not get out unless absolutely necessary for safety.", "Drive to a safe public place or police station if needed."] },
      { title: "Home Defense", summary: "Castle Doctrine concepts do not eliminate the need for reasonableness, target identification, and post-incident discipline.", guidance: ["Identify before acting.", "Do not shoot at sounds or shadows.", "Use lights, verbal commands, barriers, and 911 when safe.", "Avoid chasing outside after the threat leaves."] },
      { title: "School Pickup / Drop-Off", summary: "School property is a high-risk legal environment with multiple overlapping rules.", guidance: ["Verify statute and exceptions before carrying.", "Do not rely on what another parent says.", "Understand the difference between parking lot, building, vehicle, school event, and school property contexts."] },
      { title: "No Shots Fired / Defensive Display", summary: "The person who calls 911 first often frames the incident first. If you lawfully displayed due to a threat, report the attack or attempted attack immediately.", guidance: ["Call 911.", "Report the threat.", "Give suspect description and direction.", "Do not over-explain before legal guidance.", "Do not say you displayed to scare someone."] }
    ],
    commonMistakes: [
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
    beforeCarryChecklist: [
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
    plainEnglishReality: [
      { myth: "Stand your ground means I can shoot if I feel threatened.", reality: "No. You still need an honest and reasonable belief that deadly force is immediately necessary to stop a qualifying threat." },
      { myth: "Open carry is legal, so I can open carry anywhere.", reality: "No. Location restrictions, vehicle rules, prohibited-person rules, private property, schools, casinos, courts, and federal property still matter." },
      { myth: "A CPL lets me carry everywhere.", reality: "No. A CPL is permission under limits, not unlimited authority." },
      { myth: "If I do not fire, it is not a big deal.", reality: "A defensive display can still create brandishing, assault, disorderly conduct, or intimidation allegations if not justified." }
    ]
  },

  OH: {
    name: "Ohio",
    lastReviewed: "May 2, 2026",
    profileStatus: "Expanded Travel State",
    summary: "Ohio is a high-priority Michigan travel state. Ohio has permitless carry for qualifying adults, but members still need to verify eligibility, prohibited places, vehicle carry, officer-notification expectations, signage, and self-defense law.",
    quick: {
      reciprocity: "Michigan CPL treated as recognized; Ohio also has permitless carry for qualifying adults.",
      permitlessCarry: "Ohio has permitless carry for qualifying adults, but restrictions still apply.",
      concealedCarry: "Qualifying adults may have permitless carry authority; licensing still matters for reciprocity and proof.",
      openCarry: "Open carry is generally recognized, but location and conduct matter.",
      vehicleCarry: "Vehicle carry is more flexible than many states but still subject to restrictions and officer safety rules.",
      dutyToInform: "Do not assume Michigan-style immediate disclosure. Ohio rules changed; know current officer-notification requirements.",
      privateSigns: "Posted private property and statutory no-carry zones matter.",
      forceLaw: "Ohio has strong self-defense protections, but force must still be legally justified."
    },
    travelAlerts: [
      "Do not assume Michigan disclosure rules are identical in Ohio.",
      "Verify prohibited places such as schools, courthouses, government buildings, police stations, correctional facilities, and posted private property.",
      "Permitless carry does not erase prohibited-location rules.",
      "Vehicle carry rules still require calm, safe conduct during traffic stops."
    ],
    legalSections: [
      { title: "Permitless Carry / Recognition", risk: "Eligibility Required", body: ["Ohio allows qualifying adults to carry without a permit, but that does not mean everyone may carry.", "A Michigan CPL can still be useful for reciprocity, documentation, and travel context.", "If you are prohibited from possessing or carrying, permitless carry does not help you."], source: "Ohio Attorney General concealed carry guidance; Ohio Revised Code framework." },
      { title: "Duty to Inform / Police Contact", risk: "Different From Michigan", body: ["Ohio's police-contact rules are not the same as Michigan's immediate disclosure rule.", "Even when not required to immediately volunteer information, safest conduct includes visible hands, calm communication, and no reaching until instructed.", "If asked whether you are armed, answer truthfully and calmly."], source: "Ohio Attorney General concealed carry manual framework." },
      { title: "Vehicle Carry", risk: "Traffic Stop Risk", body: ["Vehicle carry can be lawful, but a traffic stop can become dangerous if the driver reaches, argues, or fails to follow commands.", "Keep your hands visible and avoid sudden movements.", "Know whether your handgun can be loaded, where it may be located, and how it must be handled."], source: "Ohio Revised Code framework." },
      { title: "Prohibited Places", risk: "Location Restrictions", body: ["Verify schools, school safety zones, courthouses, government buildings, police stations, correctional facilities, airports, places of worship, universities, and posted private property.", "Permitless carry does not mean carry everywhere.", "A posted business or instructed departure should be handled calmly."], source: "Ohio Revised Code 2923.126 framework." }
    ],
    decisionBlocks: [
      { title: "Before Carrying in Ohio", steps: ["1. Confirm you qualify under Ohio law.", "2. Confirm your destination is not prohibited.", "3. Confirm vehicle carry and police-contact rules.", "4. Check signage before entering private property.", "5. If stopped, keep hands visible and do not reach."] }
    ],
    scenarios: [
      { title: "Traffic Stop in Ohio", summary: "Ohio rules differ from Michigan, so do not operate on Michigan autopilot.", guidance: ["Keep hands visible.", "Do not reach.", "Answer honestly if asked.", "Follow instructions."] },
      { title: "Posted Store or Restaurant", summary: "Posted locations can create legal and trespass risk.", guidance: ["Look before entering.", "Leave if asked.", "Do not debate staff."] }
    ],
    commonMistakes: ["Assuming Michigan duty-to-disclose rules apply exactly.", "Assuming permitless carry means no prohibited places.", "Ignoring posted private property.", "Handling a traffic stop casually."],
    beforeCarryChecklist: ["Eligibility confirmed.", "Vehicle carry checked.", "Officer notification checked.", "Prohibited places checked.", "Signs checked.", "Legal-defense contact ready."]
  },

  IN: {
    name: "Indiana",
    lastReviewed: "May 2, 2026",
    profileStatus: "Expanded Travel State",
    summary: "Indiana is a high-priority Michigan travel state. Indiana has permitless carry for a proper person under Indiana law, but eligibility, restricted places, schools, government/security locations, and private property still matter.",
    quick: {
      reciprocity: "Michigan CPL treated as recognized; Indiana also has permitless carry for a proper person.",
      permitlessCarry: "Indiana permitless carry applies only to a proper person under Indiana law.",
      concealedCarry: "Eligible people may carry under Indiana law, but license status can still matter for travel and documentation.",
      openCarry: "Carry is generally permitted for eligible people, but restricted locations and conduct matter.",
      vehicleCarry: "Verify vehicle carry and transport rules before relying.",
      dutyToInform: "Verify current Indiana police-contact expectations before travel.",
      privateSigns: "Private property instructions and posted restrictions may matter.",
      forceLaw: "Indiana force law should be verified before relying on any summary."
    },
    travelAlerts: [
      "Permitless carry applies only if you meet Indiana eligibility requirements.",
      "Schools, courthouses, secure government locations, and private property can restrict carry.",
      "Do not assume Michigan vehicle rules apply.",
      "Know police-contact expectations before entering the state."
    ],
    legalSections: [
      { title: "Proper Person Standard", risk: "Eligibility Required", body: ["Indiana permitless carry does not mean anyone can carry.", "A person must still be legally eligible.", "Prohibited-person status, criminal history, and court orders can still disqualify a person."], source: "Indiana State Police firearms licensing framework." },
      { title: "Restricted Locations", risk: "Location Risk", body: ["Verify schools, school property, courthouses, secure government buildings, airports, correctional facilities, and posted/private locations.", "Do not assume a permitless carry state has few restricted places.", "Location mistakes can create serious exposure."], source: "Indiana Code framework." },
      { title: "Vehicle Carry", risk: "Travel Risk", body: ["Do not rely on Michigan vehicle carry rules while in Indiana.", "Verify whether the firearm may be loaded, accessible, concealed, or carried in a vehicle under Indiana law.", "Handle police contacts calmly and avoid reaching."], source: "Indiana firearms law framework." }
    ],
    decisionBlocks: [
      { title: "Before Carrying in Indiana", steps: ["1. Confirm you are a proper person under Indiana law.", "2. Confirm your destination is not restricted.", "3. Confirm vehicle carry rules.", "4. Confirm police-contact expectations.", "5. Leave private property if instructed."] }
    ],
    scenarios: [
      { title: "Crossing From Michigan Into Indiana", summary: "Rules change the moment you cross the state line.", guidance: ["Do not rely on Michigan assumptions.", "Confirm vehicle carry.", "Confirm destination restrictions."] },
      { title: "Private Property or Event Venue", summary: "Even in permissive carry states, property rules can matter.", guidance: ["Watch for signage.", "Follow security instructions.", "Leave if asked."] }
    ],
    commonMistakes: ["Assuming permitless carry means everyone can carry.", "Ignoring school/property restrictions.", "Assuming Michigan vehicle rules apply.", "Ignoring private property instructions."],
    beforeCarryChecklist: ["Proper person eligibility confirmed.", "Vehicle carry checked.", "Restricted places checked.", "Private property rules checked.", "Police-contact expectations checked."]
  },

  FL: {
    name: "Florida",
    lastReviewed: "May 2, 2026",
    profileStatus: "Expanded Travel State",
    summary: "Florida is a major travel state for Michigan residents. Florida has permitless concealed carry for qualified people, but prohibited places, airport/theme/event venues, alcohol locations, schools, government locations, and vehicle rules still matter.",
    quick: {
      reciprocity: "Michigan CPL treated as recognized; Florida also has permitless concealed carry for qualified people.",
      permitlessCarry: "Florida has permitless concealed carry for qualified people. Restrictions still apply.",
      concealedCarry: "Qualified people may carry concealed, but eligibility and prohibited places matter.",
      openCarry: "Open carry is generally restricted with limited exceptions. Verify before relying.",
      vehicleCarry: "Vehicle carry can be lawful but must be handled under Florida law.",
      dutyToInform: "Verify current Florida police-contact rules.",
      privateSigns: "Private property, event venue, resort, and theme park rules may matter.",
      forceLaw: "Florida has well-known self-defense laws, but every use-of-force decision must still be justified."
    },
    travelAlerts: [
      "Permitless carry does not mean every visitor may carry everywhere.",
      "Theme parks, event venues, airports, schools, government facilities, bars, and private property can create major restrictions.",
      "Open carry is not the same as concealed carry.",
      "Travelers should verify vehicle storage, hotel/resort rules, and venue rules before entering."
    ],
    legalSections: [
      { title: "Permitless Concealed Carry", risk: "Eligibility Required", body: ["Florida permitless carry applies only to qualified people.", "A Michigan CPL may still be useful for reciprocity and proof of training/background check status.", "Do not assume permitless carry overrides prohibited places."], source: "Florida statutory and law-enforcement guidance framework." },
      { title: "Open Carry", risk: "Often Misunderstood", body: ["Florida generally restricts open carry with limited exceptions.", "Do not assume that because concealed carry is allowed, open carry is also allowed.", "A visible firearm in public can create legal and police-contact risk."], source: "Florida firearms law framework." },
      { title: "Travel/Vacation Locations", risk: "Venue Rules", body: ["Theme parks, resorts, cruise terminals, airports, event venues, sports facilities, schools, government buildings, and alcohol-centered locations need extra verification.", "Private security instructions should be followed calmly.", "Do not argue with security staff over policy."], source: "Florida firearms and property framework." },
      { title: "Vehicle Carry", risk: "Road Trip Risk", body: ["Verify how Florida treats loaded, concealed, accessible, and stored firearms in vehicles.", "Hotel parking lots, rental cars, and valet situations create practical risk.", "Do not leave a firearm unsecured in a vehicle."], source: "Florida vehicle carry framework." }
    ],
    decisionBlocks: [
      { title: "Before Carrying in Florida", steps: ["1. Confirm you are legally qualified.", "2. Confirm whether you are carrying concealed or openly.", "3. Check destination restrictions.", "4. Check venue/property rules.", "5. Secure firearm during hotel, beach, pool, rental car, or resort activities."] }
    ],
    scenarios: [
      { title: "Theme Park / Resort Day", summary: "Vacation venues often have strict property rules and security screening.", guidance: ["Check rules before arrival.", "Do not bring a firearm to screening.", "Do not leave a firearm unsecured in a vehicle.", "Follow security instructions."] },
      { title: "Airport Travel", summary: "Airports require careful distinction between lawful checked transport and prohibited secure areas.", guidance: ["Follow airline/TSA procedures.", "Do not enter secure areas armed.", "Plan storage before arrival."] }
    ],
    commonMistakes: ["Assuming permitless carry applies to every visitor and every place.", "Confusing concealed carry with open carry.", "Ignoring theme park/resort/event rules.", "Leaving a firearm unsecured in a rental car or hotel room."],
    beforeCarryChecklist: ["Eligibility confirmed.", "Concealed vs open carry checked.", "Vehicle storage checked.", "Venue rules checked.", "Airport/security screening rules checked.", "Hotel/resort storage plan ready."]
  },

  TX: {
    name: "Texas",
    lastReviewed: "May 2, 2026",
    profileStatus: "Expanded Travel State",
    summary: "Texas is a major travel state with permitless carry, but it also has specific prohibited-place rules and signage rules. Michigan members should verify Texas signs, alcohol restrictions, schools, government locations, events, and vehicle carry before relying.",
    quick: {
      reciprocity: "Michigan CPL treated as recognized; Texas also has permitless carry for eligible people.",
      permitlessCarry: "Texas has permitless carry for eligible people, but restrictions still apply.",
      concealedCarry: "Eligible people may carry concealed, subject to prohibited places and signage.",
      openCarry: "Open carry can be lawful for eligible people but must comply with Texas rules.",
      vehicleCarry: "Vehicle carry can be lawful but must comply with Texas restrictions.",
      dutyToInform: "Verify Texas police-contact rules, especially if carrying under license.",
      privateSigns: "Texas signage rules are specific and important. Verify before entering posted property.",
      forceLaw: "Texas force law is detailed. Do not rely on slogans or myths."
    },
    travelAlerts: [
      "Texas signage rules can be very specific and should be taken seriously.",
      "Permitless carry does not override prohibited places.",
      "Alcohol-related locations, schools, polling places, courts, secure areas, and events may be restricted.",
      "Do not assume Texas is carry-anywhere because it is generally gun-friendly."
    ],
    legalSections: [
      { title: "Permitless Carry / License Carry", risk: "Eligibility Required", body: ["Texas permitless carry applies only to eligible people.", "A license may still matter for reciprocity, school-zone issues, and certain legal advantages.", "Prohibited-person status, intoxication, location restrictions, and signage can still make carry unlawful."], source: "Texas Penal Code Chapter 46 framework." },
      { title: "Texas Signage", risk: "Major Private Property Issue", body: ["Texas has specific statutory signage concepts that can restrict concealed carry, open carry, or both.", "Do not ignore signs because they look technical or confusing.", "If posted or instructed to leave, leave calmly."], source: "Texas Penal Code signage framework." },
      { title: "Prohibited Places", risk: "Location Restrictions", body: ["Verify schools, polling places, courts, racetracks, airports secure areas, correctional facilities, certain alcohol locations, high school/college/pro sporting events, and government meetings.", "A permit or permitless carry status does not erase prohibited places.", "Travelers should check destination-specific rules before arrival."], source: "Texas Penal Code 46.03 framework." },
      { title: "Vehicle Carry", risk: "Road Trip Risk", body: ["Vehicle carry may be lawful for eligible people, but the firearm must still be possessed lawfully and handled safely.", "Traffic stops should be handled with visible hands and calm communication.", "Do not leave firearms unsecured in vehicles."], source: "Texas vehicle carry framework." }
    ],
    decisionBlocks: [
      { title: "Before Carrying in Texas", steps: ["1. Confirm you are eligible.", "2. Confirm whether you are relying on permitless carry or license carry.", "3. Check prohibited places.", "4. Look for Texas statutory signs.", "5. Verify alcohol/event/school restrictions.", "6. Plan secure vehicle storage."] }
    ],
    scenarios: [
      { title: "Restaurant or Bar Area", summary: "Texas alcohol-location rules can be important, especially 51% locations.", guidance: ["Look for required signage.", "Avoid alcohol-centered locations while armed.", "Do not assume restaurant equals safe carry."] },
      { title: "Event Venue", summary: "Sports, concerts, fairs, and private venues can create restrictions.", guidance: ["Check event policy.", "Watch for security screening.", "Do not argue with staff."] }
    ],
    commonMistakes: ["Ignoring Texas signs.", "Assuming gun-friendly means carry-anywhere.", "Ignoring alcohol-location rules.", "Ignoring event and school restrictions.", "Leaving firearms unsecured in vehicles."],
    beforeCarryChecklist: ["Eligibility confirmed.", "Permitless/license status understood.", "Signs checked.", "Prohibited places checked.", "Alcohol restrictions checked.", "Vehicle storage plan ready."]
  }
};

states.forEach(function(s){
  if(!stateLawData[s[0]]){
    var status = "Verify recognition.";
    if(reciprocityData.MI.recognized.indexOf(s[0]) !== -1) status = "Michigan CPL treated as recognized in this app travel engine.";
    if(reciprocityData.MI.notRecognized.indexOf(s[0]) !== -1) status = "Michigan CPL treated as not recognized in this app travel engine.";
    stateLawData[s[0]] = starterProfile(s[0], s[1], status);
  }
});

function q(id){return document.getElementById(id)}
function setMsg(text){var msg=q("msg"); if(msg) msg.innerText=text||""}
function escapeHtml(value){return String(value||"").replaceAll("&","&amp;").replaceAll("<","&lt;").replaceAll(">","&gt;").replaceAll('"',"&quot;").replaceAll("'","&#039;")}
function stateName(abbr){var found=states.find(function(s){return s[0]===abbr});return found?found[1]:abbr}
function statusClass(status){if(status==="recognized")return"green";if(status==="restricted")return"yellow";if(status==="not_recognized")return"red";return"gray"}
function statusLabelByStatus(status){if(status==="recognized")return"Recognized";if(status==="restricted")return"Recognized with Restrictions";if(status==="not_recognized")return"Not Recognized";return"Not Yet Verified"}
function stateStatus(permitState,travelState){var data=reciprocityData[permitState];if(!data)return"unverified";if(travelState===permitState)return"recognized";if(data.recognized.indexOf(travelState)!==-1)return"recognized";if(data.restricted.indexOf(travelState)!==-1)return"restricted";if(data.notRecognized.indexOf(travelState)!==-1)return"not_recognized";return"unverified"}

function renderMap(permitState){
  return '<div class="mapLegend">' +
    '<span class="legendItem green">Recognized</span>' +
    '<span class="legendItem yellow">Recognized with Restrictions</span>' +
    '<span class="legendItem red">Not Recognized</span>' +
    '<span class="legendItem gray">Not Yet Verified</span>' +
  '</div>' +
  '<div class="mapGrid">' +
  mapOrder.map(function(abbr){
    var status=stateStatus(permitState,abbr);
    var cls=statusClass(status);
    var selected=selectedMapState===abbr?" selected":"";
    return '<div class="mapState '+cls+selected+'" onclick="selectMapState(\\''+abbr+'\\')">'+abbr+'</div>';
  }).join("") +
  '</div>';
}

function renderList(title, items, bullet){
  if(!items || !items.length) return "";
  var html='<h3 class="sectionTitle">'+escapeHtml(title)+'</h3><div class="legalItem">';
  items.forEach(function(item){ html += '<p>'+(bullet||"• ") + escapeHtml(item)+'</p>'; });
  html+='</div>';
  return html;
}

function renderLawProfile(abbr){
  var law=stateLawData[abbr];

  if(!law){
    return '<div class="detailBox"><h3>'+abbr+' — '+stateName(abbr)+'</h3><p><b>State law profile:</b> Not built yet.</p><p class="small">This state is still using the reciprocity-only travel warning.</p></div>';
  }

  var qk=law.quick||{};

  var html='<div class="detailBox">' +
    '<h3>'+abbr+' — '+escapeHtml(law.name||stateName(abbr))+'</h3>' +
    '<span class="lawPill green">'+escapeHtml(law.profileStatus||"Profile")+'</span>' +
    '<span class="lawPill gray">Reviewed: '+escapeHtml(law.lastReviewed||"Verify")+'</span>' +
    '<p>'+escapeHtml(law.summary||"")+'</p>';

  html+='<div class="profileGrid">' +
    '<div class="miniPanel"><b>Michigan CPL / Recognition</b><p class="small">'+escapeHtml(qk.reciprocity||"Verify recognition.")+'</p></div>' +
    '<div class="miniPanel"><b>Permitless Carry</b><p class="small">'+escapeHtml(qk.permitlessCarry||"Verify current law.")+'</p></div>' +
    '<div class="miniPanel"><b>Concealed Carry</b><p class="small">'+escapeHtml(qk.concealedCarry||"Verify current law.")+'</p></div>' +
    '<div class="miniPanel"><b>Open Carry</b><p class="small">'+escapeHtml(qk.openCarry||"Verify current law.")+'</p></div>' +
    '<div class="miniPanel"><b>Vehicle Carry</b><p class="small">'+escapeHtml(qk.vehicleCarry||"Verify current law.")+'</p></div>' +
    '<div class="miniPanel"><b>Duty to Inform</b><p class="small">'+escapeHtml(qk.dutyToInform||"Verify current law.")+'</p></div>' +
    '<div class="miniPanel"><b>Private Property / Signs</b><p class="small">'+escapeHtml(qk.privateSigns||"Verify current law.")+'</p></div>' +
    '<div class="miniPanel"><b>Use of Force</b><p class="small">'+escapeHtml(qk.forceLaw||"Verify current law.")+'</p></div>' +
  '</div>';

  html+=renderList("Red Flag Travel Alerts", law.travelAlerts);

  if(law.legalSections && law.legalSections.length){
    html+='<h3 class="sectionTitle">Detailed Legal Intelligence</h3>';
    law.legalSections.forEach(function(section){
      html+='<div class="legalItem"><h3>'+escapeHtml(section.title)+'</h3><span class="lawPill yellow">'+escapeHtml(section.risk||"Legal Topic")+'</span>';
      (section.body||[]).forEach(function(p){html+='<p>'+escapeHtml(p)+'</p>';});
      if(section.source) html+='<div class="legalSource">'+escapeHtml(section.source)+'</div>';
      html+='</div>';
    });
  }

  if(law.decisionBlocks && law.decisionBlocks.length){
    html+='<h3 class="sectionTitle">Decision Blocks</h3>';
    law.decisionBlocks.forEach(function(block){
      html+='<div class="legalItem"><h3>'+escapeHtml(block.title)+'</h3>';
      (block.steps||[]).forEach(function(step){html+='<p>'+escapeHtml(step)+'</p>';});
      html+='</div>';
    });
  }

  if(law.scenarios && law.scenarios.length){
    html+='<h3 class="sectionTitle">High-Risk Scenarios</h3>';
    law.scenarios.forEach(function(s){
      html+='<div class="scenario"><h3>'+escapeHtml(s.title)+'</h3><p>'+escapeHtml(s.summary||"")+'</p>';
      (s.guidance||[]).forEach(function(g){html+='<p class="small">• '+escapeHtml(g)+'</p>';});
      html+='</div>';
    });
  }

  html+=renderList("Common Mistakes", law.commonMistakes);
  html+=renderList("Before You Carry Checklist", law.beforeCarryChecklist, "☐ ");

  if(law.plainEnglishReality && law.plainEnglishReality.length){
    html+='<h3 class="sectionTitle">Plain English vs. Legal Reality</h3>';
    law.plainEnglishReality.forEach(function(item){
      html+='<div class="legalItem"><p><b>What people think:</b> '+escapeHtml(item.myth)+'</p><p><b>Reality:</b> '+escapeHtml(item.reality)+'</p></div>';
    });
  }

  html+='<p class="small"><b>Disclaimer:</b> Educational field reference only. Not legal advice. Verify current law before relying on any summary.</p></div>';
  return html;
}

function getStateDetailHtml(permitState, travelState){
  var status=stateStatus(permitState,travelState);
  var cls=statusClass(status);

  return '<div class="detailBox">' +
    '<h3>'+travelState+' — '+stateName(travelState)+'</h3>' +
    '<span class="detailStatus '+cls+'">'+statusLabelByStatus(status)+'</span>' +
    '<p><b>Travel meaning:</b> This color is a starting point only. It does not guarantee lawful carry in every place or situation.</p>' +
    '<p><b>Check before travel:</b> permit recognition, prohibited places, vehicle carry, duty to inform, signage/private property rules, alcohol restrictions, age restrictions, magazine/ammunition rules, local restrictions, tribal restrictions, federal property, and whether your permit must be resident or nonresident.</p>' +
  '</div>' + renderLawProfile(travelState);
}

function getReciprocityHtml(state){
  var data=reciprocityData[state];
  var selectedName=stateName(state);
  if(!selectedMapState) selectedMapState=state;

  if(!data){
    return '<div class="reciprocityTitle">'+selectedName+' Permit Profile</div>' +
      '<p><b>Status:</b> State-specific outbound reciprocity data has not been fully verified in this app yet.</p>' +
      '<div class="twoColumn"><div class="stickyMap">'+renderMap(state)+'</div><div>'+getStateDetailHtml(state,selectedMapState)+'</div></div>' +
      '<div class="warn">Before carrying outside your home state, verify destination-state recognition, prohibited locations, duty-to-inform rules, vehicle carry rules, age restrictions, permit residency requirements, local restrictions, federal restrictions, and private property rules.</div>';
  }

  return '<div class="reciprocityTitle">'+data.title+'</div>' +
    '<p><b>Selected permit:</b> '+selectedName+'</p>' +
    '<p><b>Last reviewed:</b> '+data.verifiedDate+'</p>' +
    '<p class="reciprocitySub">'+data.sourceNote+'</p>' +
    '<div class="twoColumn"><div class="stickyMap">'+renderMap(state)+'</div><div>'+getStateDetailHtml(state,selectedMapState)+'</div></div>' +
    '<h3>Critical Travel Warnings</h3>' +
    data.warnings.map(function(w){return '<p class="small">• '+escapeHtml(w)+'</p>';}).join("");
}

function selectMapState(abbr){
  selectedMapState=abbr;
  updateReciprocity();
}

function showAuth(){
  var isRegister=authMode==="register";
  q("app").innerHTML=
    '<div class="container">' +
      '<div class="brand">Prime Defense Training</div>' +
      '<h1>Prime Defense Protection</h1>' +
      '<p class="subtitle">Premium member-only protection dashboard for permit tracking, emergency tools, legal education, reciprocity, and defensive incident guidance.</p>' +
      '<div class="tabs">' +
        '<button id="loginTab" class="tab '+(!isRegister?'active':'')+'" type="button">Login</button>' +
        '<button id="registerTab" class="tab '+(isRegister?'active':'')+'" type="button">Register</button>' +
      '</div>' +
      (isRegister?'<input id="name" placeholder="Full Name" autocomplete="name">':'') +
      '<input id="email" placeholder="Membership Email" autocomplete="email">' +
      '<input id="password" type="password" placeholder="Password" autocomplete="'+(isRegister?'new-password':'current-password')+'">' +
      '<button id="submitBtn" class="primary" type="button">'+(isRegister?'Create Account':'Login')+'</button>' +
      '<div id="msg" class="msg"></div>' +
      '<p class="small">Use the same email address associated with your Prime Defense Protection membership.</p>' +
    '</div>';

  q("loginTab").onclick=function(){authMode="login";showAuth();};
  q("registerTab").onclick=function(){authMode="register";showAuth();};
  q("submitBtn").onclick=function(){if(authMode==="register") registerUser(); else loginUser();};
}

async function registerUser(){
  setMsg("Creating account and checking membership...");
  try{
    var res=await fetch("/api/register",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({name:q("name").value,email:q("email").value,password:q("password").value})});
    var data=await res.json();
    if(data.token){
      token=data.token;
      localStorage.setItem("pd_token",token);
      if(data.user&&data.user.accessAllowed) showDashboard(); else showLocked(data.user);
    } else setMsg(data.error||"Registration failed.");
  }catch(e){setMsg("Registration failed.");}
}

async function loginUser(){
  setMsg("Logging in and checking membership...");
  try{
    var res=await fetch("/api/login",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({email:q("email").value,password:q("password").value})});
    var data=await res.json();
    if(data.token){
      token=data.token;
      localStorage.setItem("pd_token",token);
      if(data.user&&data.user.accessAllowed) showDashboard(); else showLocked(data.user);
    } else setMsg(data.error||"Login failed.");
  }catch(e){setMsg("Login failed.");}
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
    var res=await fetch("/api/refresh-membership",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({token:token})});
    var user=await res.json();
    if(user.accessAllowed) showDashboard(); else showLocked(user);
  }catch(e){setMsg("Unable to refresh membership.");}
}

async function openBilling(){
  setMsg("Opening billing portal...");
  try{
    var res=await fetch("/api/billing-portal",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({token:token})});
    var data=await res.json();
    if(data.url) window.location.href=data.url; else setMsg(data.error||"Unable to open billing.");
  }catch(e){setMsg("Unable to open billing.");}
}

function showLocked(user){
  user=user||{};
  q("app").innerHTML=
    '<div class="lockbox">' +
      '<div class="brand">Membership Required</div>' +
      '<h1>Access Locked</h1>' +
      '<span class="status locked">'+escapeHtml(user.membershipLabel||"Membership Required")+'</span>' +
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
  var html="";
  states.forEach(function(s){
    html+='<option value="'+s[0]+'"'+(s[0]===selected?' selected':'')+'>'+s[1]+'</option>';
  });
  return html;
}

async function showDashboard(){
  try{
    var res=await fetch("/api/get-profile",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({token:token})});
    var user=await res.json();

    if(user.error){
      localStorage.removeItem("pd_token");
      token=null;
      showAuth();
      return;
    }

    if(!user.accessAllowed){
      showLocked(user);
      return;
    }

    currentUser=user;
    var selectedState=user.permitState||"MI";
    selectedMapState=selectedState;

    q("app").innerHTML=
      '<div class="dashboard">' +
        '<div class="hero">' +
          '<div class="brand">Prime Defense Protection</div>' +
          '<h1>Member Dashboard</h1>' +
          '<span class="status">'+escapeHtml(user.membershipLabel)+'</span>' +
          '<p class="subtitle">Welcome'+(user.name?', '+escapeHtml(user.name):'')+'. Your premium member dashboard for permit tracking, incident tools, reciprocity, and legal intelligence.</p>' +
          '<div class="badgeRow">' +
            '<span class="badge">Permit Profile</span>' +
            '<span class="badge">Clickable Map</span>' +
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
          '<h2>Clickable Reciprocity Map & State Detail Panel</h2>' +
          '<p class="small">Select your permit state. Click any state on the map to view reciprocity status and available legal profile data.</p>' +
          '<div class="grid">' +
            '<select id="state">'+buildStateOptions(selectedState)+'</select>' +
            '<input id="issue" type="date" value="'+escapeHtml(user.issueDate||'')+'">' +
            '<input id="exp" type="date" value="'+escapeHtml(user.expirationDate||'')+'">' +
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
            '<input id="ename" placeholder="Contact Name" value="'+escapeHtml(user.emergencyName||'')+'">' +
            '<input id="phone" placeholder="Contact Phone" value="'+escapeHtml(user.emergencyPhone||'')+'">' +
          '</div>' +
        '</div>' +

        '<button id="saveBtn" class="primary" type="button">Save Profile</button>' +
        '<button id="emergencyBtn" class="emergencyButton" type="button">911</button>' +
        '<div id="msg" class="msg"></div>' +
      '</div>';

    updateReciprocity();

    q("state").onchange=function(){selectedMapState=q("state").value;updateReciprocity();};
    q("saveBtn").onclick=saveProfile;
    q("logoutBtn").onclick=logout;
    q("refreshBtn").onclick=refreshMembership;
    q("emergencyBtn").onclick=openEmergency;
    q("shootingModeBtn").onclick=openEmergency;
    q("displayModeBtn").onclick=openDefensiveDisplay;
    q("aftermathBtn").onclick=openAftermath;
    q("miGuideBtn").onclick=function(){selectedMapState="MI";showStateLawFull("MI");};

  }catch(e){
    localStorage.removeItem("pd_token");
    token=null;
    showAuth();
  }
}

function updateReciprocity(){
  var stateEl=q("state");
  var box=q("reciprocityBox");
  if(!stateEl||!box) return;
  box.innerHTML=getReciprocityHtml(stateEl.value);
}

async function saveProfile(){
  setMsg("Saving...");
  try{
    var res=await fetch("/api/save-profile",{
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
    var data=await res.json();
    setMsg(data.error||data.message||"Saved.");
  }catch(e){setMsg("Save failed.");}
}

function showStateLawFull(abbr){
  q("app").innerHTML=
    '<div class="dashboard">' +
      '<div class="hero">' +
        '<div class="brand">Prime Defense Legal Intelligence</div>' +
        '<h1>'+stateName(abbr)+' State Law Engine</h1>' +
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
  var phone=q("phone")?q("phone").value:"";
  var name=q("ename")?q("ename").value:"";
  var cleanPhone=phone.replace(/[^0-9+]/g,"");

  q("app").innerHTML=
    '<div class="emergencyScreen"><div class="emergencyShell">' +
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
        '<h2>'+escapeHtml(name||"Emergency Contact")+'</h2>' +
        '<p class="small">'+escapeHtml(phone||"No phone saved")+'</p>' +
        (phone?'<button class="primary bigAction" type="button" onclick="window.location.href=\\'tel:'+cleanPhone+'\\'">CALL CONTACT</button>':'<div class="warn">No emergency contact saved.</div>') +
        '<div class="script">“I’ve been involved in a defensive incident. I’m safe. Do not discuss anything with anyone until I have legal guidance.”</div>' +
      '</div>' +

      '<div class="card">' +
        '<div class="brand">Step 4 — When Police Arrive</div>' +
        '<div class="script">Hands visible. Do not move unless instructed. Follow commands. Do not argue. Do not explain in detail.</div>' +
      '</div>' +

      '<button class="secondary bigAction" type="button" onclick="showDashboard()">EXIT EMERGENCY MODE</button>' +
    '</div></div>';
}

function openDefensiveDisplay(){
  q("app").innerHTML=
    '<div class="emergencyScreen"><div class="emergencyShell">' +
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
    '</div></div>';
}

function openAftermath(){
  q("app").innerHTML=
    '<div class="emergencyScreen"><div class="emergencyShell">' +
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
    '</div></div>';
}

if(token) showDashboard();
else showAuth();
</script>
</body>
</html>
`;

app.get("/", (req, res) => res.send(html));
app.use((req, res) => res.send(html));
app.listen(PORT, () => console.log("Running on port " + PORT));
