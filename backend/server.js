const express = require("express");
const cors = require("cors");
const Stripe = require("stripe");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const path = require("path");

const app = express();
const PORT = process.env.PORT || 4000;
const stripe = Stripe(process.env.STRIPE_SECRET_KEY || "sk_test_replace_me");
const JWT_SECRET = process.env.JWT_SECRET || "replace_this_with_a_long_random_secret";

app.use(cors({ origin: process.env.FRONTEND_URL || "*" }));

const db = {
  members: {},
  membersByEmail: {},
  stateLaws: {}
};

const STATES = [
  ["AL", "Alabama"], ["AK", "Alaska"], ["AZ", "Arizona"], ["AR", "Arkansas"], ["CA", "California"],
  ["CO", "Colorado"], ["CT", "Connecticut"], ["DE", "Delaware"], ["FL", "Florida"], ["GA", "Georgia"],
  ["HI", "Hawaii"], ["ID", "Idaho"], ["IL", "Illinois"], ["IN", "Indiana"], ["IA", "Iowa"],
  ["KS", "Kansas"], ["KY", "Kentucky"], ["LA", "Louisiana"], ["ME", "Maine"], ["MD", "Maryland"],
  ["MA", "Massachusetts"], ["MI", "Michigan"], ["MN", "Minnesota"], ["MS", "Mississippi"], ["MO", "Missouri"],
  ["MT", "Montana"], ["NE", "Nebraska"], ["NV", "Nevada"], ["NH", "New Hampshire"], ["NJ", "New Jersey"],
  ["NM", "New Mexico"], ["NY", "New York"], ["NC", "North Carolina"], ["ND", "North Dakota"], ["OH", "Ohio"],
  ["OK", "Oklahoma"], ["OR", "Oregon"], ["PA", "Pennsylvania"], ["RI", "Rhode Island"], ["SC", "South Carolina"],
  ["SD", "South Dakota"], ["TN", "Tennessee"], ["TX", "Texas"], ["UT", "Utah"], ["VT", "Vermont"],
  ["VA", "Virginia"], ["WA", "Washington"], ["WV", "West Virginia"], ["WI", "Wisconsin"], ["WY", "Wyoming"]
];

const LAW_CATEGORIES = {
  reciprocity: "Reciprocity",
  dutyToInform: "Duty to Inform",
  vehicleCarry: "Vehicle Carry",
  restrictedLocations: "Restricted Locations",
  signsEnforceable: "Signs Enforceable",
  openCarry: "Open Carry",
  constitutionalCarry: "Constitutional Carry",
  useOfForce: "Use of Force",
  lawEnforcementInteraction: "Law Enforcement Interaction",
  differentFromMichigan: "What’s Different from Michigan?"
};

function normalizeEmail(email) {
  return String(email || "").trim().toLowerCase();
}

function createMemberId() {
  return "mem_" + Math.random().toString(36).slice(2) + Date.now().toString(36);
}

function getMembershipLabel(status) {
  switch (status) {
    case "active": return "Active Protection Member";
    case "trialing": return "Trialing Protection Member";
    case "past_due": return "Past Due — Payment Issue";
    case "canceled": return "Canceled";
    case "unpaid": return "Unpaid — Access Restricted";
    case "incomplete": return "Incomplete Signup";
    case "not_found": return "No Active Membership Found";
    default: return "Membership Status Unknown";
  }
}

function isMembershipActive(status) {
  return status === "active" || status === "trialing";
}

function calculatePermitStatus(profile) {
  if (!profile || !profile.expirationDate) {
    return { status: "missing", label: "Permit Info Needed", message: "Add your permit state, issue date, and expiration date." };
  }
  const today = new Date();
  const expiration = new Date(profile.expirationDate + "T00:00:00");
  if (Number.isNaN(expiration.getTime())) {
    return { status: "invalid", label: "Invalid Expiration Date", message: "Please check the expiration date entered." };
  }
  const daysRemaining = Math.ceil((expiration - today) / (1000 * 60 * 60 * 24));
  if (daysRemaining < 0) return { status: "expired", label: "Expired", message: "Your permit appears to be expired. Review renewal requirements immediately.", daysRemaining };
  if (daysRemaining <= 183) return { status: "renewal_window", label: "Renewal Window", message: "Your permit is within the 6-month renewal window.", daysRemaining };
  return { status: "active", label: "Active", message: "Your permit appears active based on the expiration date entered.", daysRemaining };
}

function publicMember(member) {
  const permitProfile = member.permitProfile || { permitState: "MI", issueDate: "", expirationDate: "" };
  return {
    id: member.id,
    email: member.email,
    name: member.name,
    stripeCustomerId: member.stripeCustomerId,
    stripeSubscriptionId: member.stripeSubscriptionId,
    membershipStatus: member.membershipStatus,
    membershipLabel: getMembershipLabel(member.membershipStatus),
    accessAllowed: isMembershipActive(member.membershipStatus),
    currentPeriodEnd: member.currentPeriodEnd,
    permitProfile,
    permitStatus: calculatePermitStatus(permitProfile),
    lastCheckedAt: member.lastCheckedAt,
    updatedAt: member.updatedAt
  };
}

function signToken(member) {
  return jwt.sign({ memberId: member.id, email: member.email }, JWT_SECRET, { expiresIn: "30d" });
}

function requireAuth(req, res, next) {
  const auth = req.headers.authorization || "";
  const token = auth.startsWith("Bearer ") ? auth.slice(7) : null;
  if (!token) return res.status(401).json({ error: "Missing token" });
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const member = db.members[decoded.memberId];
    if (!member) return res.status(401).json({ error: "Member not found" });
    req.member = member;
    next();
  } catch {
    res.status(401).json({ error: "Invalid token" });
  }
}

function requireActiveMembership(req, res, next) {
  if (!isMembershipActive(req.member.membershipStatus)) {
    return res.status(403).json({ error: "Active membership required", member: publicMember(req.member) });
  }
  next();
}

async function findStripeCustomerByEmail(email) {
  const customers = await stripe.customers.list({ email: normalizeEmail(email), limit: 10 });
  if (!customers.data.length) return null;
  return customers.data.sort((a, b) => b.created - a.created)[0];
}

async function findMostRelevantSubscription(customerId) {
  const subscriptions = await stripe.subscriptions.list({ customer: customerId, status: "all", limit: 20 });
  if (!subscriptions.data.length) return null;
  const priority = ["active", "trialing", "past_due", "unpaid", "incomplete", "canceled"];
  return subscriptions.data.sort((a, b) => {
    const aRank = priority.indexOf(a.status) === -1 ? 999 : priority.indexOf(a.status);
    const bRank = priority.indexOf(b.status) === -1 ? 999 : priority.indexOf(b.status);
    if (aRank !== bRank) return aRank - bRank;
    return b.created - a.created;
  })[0];
}

async function syncMemberFromStripe(member) {
  const customer = await findStripeCustomerByEmail(member.email);
  if (!customer) {
    member.stripeCustomerId = null;
    member.stripeSubscriptionId = null;
    member.membershipStatus = "not_found";
    member.currentPeriodEnd = null;
  } else {
    const subscription = await findMostRelevantSubscription(customer.id);
    member.stripeCustomerId = customer.id;
    if (!subscription) {
      member.stripeSubscriptionId = null;
      member.membershipStatus = "not_found";
      member.currentPeriodEnd = null;
    } else {
      member.stripeSubscriptionId = subscription.id;
      member.membershipStatus = subscription.status;
      member.currentPeriodEnd = subscription.current_period_end ? new Date(subscription.current_period_end * 1000).toISOString() : null;
    }
  }
  member.lastCheckedAt = new Date().toISOString();
  member.updatedAt = new Date().toISOString();
  return member;
}

function seedStates() {
  STATES.forEach(([abbr, name]) => {
    const categories = {};
    Object.keys(LAW_CATEGORIES).forEach((key) => {
      categories[key] = {
        answer: key === "differentFromMichigan" ? `${name} comparison pending.` : "Pending official source sync.",
        details: "This section will be populated from official legal sources.",
        sourceName: "Pending official source mapping",
        sourceUrl: null,
        confidence: "pending"
      };
    });
    db.stateLaws[abbr] = { abbr, name, status: "Pending Sync", syncStatus: "pending", lastSynced: null, categories };
  });
}
seedStates();

app.post("/api/stripe/webhook", express.raw({ type: "application/json" }), async (req, res) => {
  const sig = req.headers["stripe-signature"];
  try {
    const event = stripe.webhooks.constructEvent(req.body, sig, process.env.STRIPE_WEBHOOK_SECRET || "whsec_replace_me");
    const obj = event.data.object;
    const customerId = obj.customer;
    if (customerId) {
      const member = Object.values(db.members).find(m => m.stripeCustomerId === customerId || m.stripeSubscriptionId === obj.id);
      if (member) await syncMemberFromStripe(member);
    }
    res.json({ received: true });
  } catch (err) {
    console.error("Webhook Error:", err.message);
    res.status(400).send(`Webhook Error: ${err.message}`);
  }
});

app.use(express.json());

app.post("/api/auth/register", async (req, res) => {
  try {
    const email = normalizeEmail(req.body.email);
    const password = String(req.body.password || "");
    const name = String(req.body.name || "Prime Defense Member").trim();
    if (!email || !password) return res.status(400).json({ error: "Email and password are required" });
    if (db.membersByEmail[email]) return res.status(409).json({ error: "An account already exists for this email" });
    const member = {
      id: createMemberId(), email, name, passwordHash: await bcrypt.hash(password, 12),
      stripeCustomerId: null, stripeSubscriptionId: null, membershipStatus: "unknown", currentPeriodEnd: null,
      permitProfile: { permitState: "MI", issueDate: "", expirationDate: "" },
      createdAt: new Date().toISOString(), updatedAt: new Date().toISOString(), lastCheckedAt: null
    };
    db.members[member.id] = member;
    db.membersByEmail[email] = member.id;
    await syncMemberFromStripe(member);
    res.json({ token: signToken(member), member: publicMember(member) });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Registration failed" });
  }
});

app.post("/api/auth/login", async (req, res) => {
  try {
    const email = normalizeEmail(req.body.email);
    const member = db.members[db.membersByEmail[email]];
    if (!member) return res.status(401).json({ error: "Invalid email or password" });
    const ok = await bcrypt.compare(String(req.body.password || ""), member.passwordHash);
    if (!ok) return res.status(401).json({ error: "Invalid email or password" });
    await syncMemberFromStripe(member);
    res.json({ token: signToken(member), member: publicMember(member) });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Login failed" });
  }
});

app.get("/api/member/me", requireAuth, (req, res) => res.json({ member: publicMember(req.member) }));

app.post("/api/member/refresh-stripe-status", requireAuth, async (req, res) => {
  await syncMemberFromStripe(req.member);
  res.json({ member: publicMember(req.member) });
});

app.post("/api/member/billing-portal", requireAuth, async (req, res) => {
  try {
    if (!req.member.stripeCustomerId) return res.status(404).json({ error: "No Stripe customer found for this member email" });
    const session = await stripe.billingPortal.sessions.create({
      customer: req.member.stripeCustomerId,
      return_url: process.env.FRONTEND_URL || "http://localhost:4000"
    });
    res.json({ url: session.url });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Unable to create billing portal session" });
  }
});

app.get("/api/member/permit", requireAuth, (req, res) => {
  const permitProfile = req.member.permitProfile || { permitState: "MI", issueDate: "", expirationDate: "" };
  res.json({ permitProfile, permitStatus: calculatePermitStatus(permitProfile) });
});

app.put("/api/member/permit", requireAuth, (req, res) => {
  req.member.permitProfile = {
    permitState: String(req.body.permitState || "MI").trim(),
    issueDate: String(req.body.issueDate || "").trim(),
    expirationDate: String(req.body.expirationDate || "").trim(),
    updatedAt: new Date().toISOString()
  };
  req.member.updatedAt = new Date().toISOString();
  res.json({ member: publicMember(req.member), permitProfile: req.member.permitProfile, permitStatus: calculatePermitStatus(req.member.permitProfile) });
});

app.get("/api/states", requireAuth, requireActiveMembership, (req, res) => {
  res.json(STATES.map(([abbr, name]) => ({ abbr, name, status: db.stateLaws[abbr]?.status || "Pending Sync", syncStatus: db.stateLaws[abbr]?.syncStatus || "pending" })));
});

app.get("/api/states/:abbr", requireAuth, requireActiveMembership, (req, res) => {
  const abbr = String(req.params.abbr || "").toUpperCase();
  const record = db.stateLaws[abbr];
  if (!record) return res.status(404).json({ error: "State not found" });
  res.json(record);
});

const frontendDist = path.join(__dirname, "../frontend/dist");
app.use(express.static(frontendDist));
app.get(/.*/, (req, res) => {
  res.sendFile(path.join(frontendDist, "index.html"));
});

app.listen(PORT, () => console.log(`Prime Defense app running on port ${PORT}`));
