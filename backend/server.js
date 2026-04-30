import express from "express";
import cors from "cors";
import Stripe from "stripe";

const app = express();
const stripe = new Stripe(process.env.STRIPE_SECRET_KEY);

app.use(cors());
app.use(express.json());

let members = [];

function calculatePermitStatus(profile) {
  if (!profile || !profile.expirationDate) {
    return { label: "Permit Info Needed", status: "missing" };
  }

  const today = new Date();
  const exp = new Date(profile.expirationDate);

  const days = Math.ceil((exp - today) / (1000 * 60 * 60 * 24));

  if (days < 0) return { label: "Expired", status: "expired" };
  if (days <= 183) return { label: "Renewal Window", status: "renewal_window" };
  return { label: "Active", status: "active" };
}

app.post("/api/auth/register", async (req, res) => {
  const { email, password, name } = req.body;

  const existing = members.find((m) => m.email === email);
  if (existing) return res.status(400).json({ error: "Account already exists" });

  const customer = await stripe.customers.list({ email });

  let status = "inactive";

  if (customer.data.length > 0) {
    const subs = await stripe.subscriptions.list({
      customer: customer.data[0].id,
      status: "all"
    });

    if (subs.data.length > 0) {
      const sub = subs.data[0];
      if (sub.status === "active") status = "active";
    }
  }

  const member = {
    email,
    password,
    name,
    membershipStatus: status,
    accessAllowed: status === "active",
    permitProfile: {
      permitState: "MI",
      issueDate: "",
      expirationDate: ""
    }
  };

  members.push(member);

  res.json({
    token: "demo-token",
    member
  });
});

app.post("/api/auth/login", (req, res) => {
  const { email, password } = req.body;

  const member = members.find((m) => m.email === email && m.password === password);

  if (!member) return res.status(401).json({ error: "Invalid email or password" });

  res.json({
    token: "demo-token",
    member
  });
});

app.get("/api/member/me", (req, res) => {
  const member = members[0];
  res.json({ member });
});

app.put("/api/member/permit", (req, res) => {
  const member = members[0];

  member.permitProfile = req.body;

  res.json({
    member,
    permitStatus: calculatePermitStatus(member.permitProfile)
  });
});

app.listen(4000, () => console.log("Server running"));
