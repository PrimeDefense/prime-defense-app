require('dotenv').config();

const path = require('path');
const express = require('express');
const cors = require('cors');
const Stripe = require('stripe');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const cron = require('node-cron');

const app = express();
const PORT = process.env.PORT || 4000;
const stripe = Stripe(process.env.STRIPE_SECRET_KEY || 'sk_test_replace_me');
const JWT_SECRET = process.env.JWT_SECRET || 'replace_this_with_a_long_secret';
const FRONTEND_URL = process.env.FRONTEND_URL || 'http://localhost:5173';

app.use(cors({ origin: FRONTEND_URL === '*' ? '*' : FRONTEND_URL }));

const db = {
  members: {},
  membersByEmail: {},
  stateLaws: {},
  syncRuns: [],
  changeHistory: []
};

function normalizeEmail(email) {
  return String(email || '').trim().toLowerCase();
}

function createId(prefix = 'id') {
  return `${prefix}_${Math.random().toString(36).slice(2)}${Date.now().toString(36)}`;
}

function isMembershipActive(status) {
  return status === 'active' || status === 'trialing';
}

function getMembershipLabel(status) {
  switch (status) {
    case 'active': return 'Active Protection Member';
    case 'trialing': return 'Trialing Protection Member';
    case 'past_due': return 'Past Due — Payment Issue';
    case 'canceled': return 'Canceled — Access Locked';
    case 'unpaid': return 'Unpaid — Access Restricted';
    case 'incomplete': return 'Incomplete Signup';
    case 'not_found': return 'No Active Membership Found';
    default: return 'Membership Status Unknown';
  }
}

function publicMember(member) {
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
    lastCheckedAt: member.lastCheckedAt,
    updatedAt: member.updatedAt
  };
}

function signToken(member) {
  return jwt.sign({ memberId: member.id, email: member.email }, JWT_SECRET, { expiresIn: '30d' });
}

function requireAuth(req, res, next) {
  const auth = req.headers.authorization || '';
  const token = auth.startsWith('Bearer ') ? auth.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'Missing token' });

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const member = db.members[decoded.memberId];
    if (!member) return res.status(401).json({ error: 'Member not found' });
    req.member = member;
    next();
  } catch (error) {
    return res.status(401).json({ error: 'Invalid token' });
  }
}

function requireActiveMembership(req, res, next) {
  if (!isMembershipActive(req.member.membershipStatus)) {
    return res.status(403).json({ error: 'Active membership required', member: publicMember(req.member) });
  }
  next();
}

async function findStripeCustomerByEmail(email) {
  const customers = await stripe.customers.list({ email: normalizeEmail(email), limit: 10 });
  if (!customers.data.length) return null;
  return customers.data.sort((a, b) => b.created - a.created)[0];
}

async function findMostRelevantSubscription(customerId) {
  const subscriptions = await stripe.subscriptions.list({ customer: customerId, status: 'all', limit: 20 });
  if (!subscriptions.data.length) return null;

  const priority = ['active', 'trialing', 'past_due', 'unpaid', 'incomplete', 'canceled'];
  return subscriptions.data.sort((a, b) => {
    const ar = priority.indexOf(a.status) === -1 ? 999 : priority.indexOf(a.status);
    const br = priority.indexOf(b.status) === -1 ? 999 : priority.indexOf(b.status);
    if (ar !== br) return ar - br;
    return b.created - a.created;
  })[0];
}

async function syncMemberFromStripe(member) {
  const customer = await findStripeCustomerByEmail(member.email);

  if (!customer) {
    member.stripeCustomerId = null;
    member.stripeSubscriptionId = null;
    member.membershipStatus = 'not_found';
    member.currentPeriodEnd = null;
  } else {
    const subscription = await findMostRelevantSubscription(customer.id);
    member.stripeCustomerId = customer.id;
    if (!subscription) {
      member.stripeSubscriptionId = null;
      member.membershipStatus = 'not_found';
      member.currentPeriodEnd = null;
    } else {
      member.stripeSubscriptionId = subscription.id;
      member.membershipStatus = subscription.status;
      member.currentPeriodEnd = subscription.current_period_end
        ? new Date(subscription.current_period_end * 1000).toISOString()
        : null;
    }
  }

  member.lastCheckedAt = new Date().toISOString();
  member.updatedAt = new Date().toISOString();
  return member;
}

function findMemberByStripeCustomerId(customerId) {
  return Object.values(db.members).find((m) => m.stripeCustomerId === customerId);
}

function findMemberByStripeSubscriptionId(subscriptionId) {
  return Object.values(db.members).find((m) => m.stripeSubscriptionId === subscriptionId);
}

async function handleStripeEvent(event) {
  switch (event.type) {
    case 'customer.subscription.created':
    case 'customer.subscription.updated':
    case 'customer.subscription.deleted': {
      const subscription = event.data.object;
      const member = findMemberByStripeCustomerId(subscription.customer) || findMemberByStripeSubscriptionId(subscription.id);
      if (!member) return;
      member.stripeSubscriptionId = subscription.id;
      member.membershipStatus = subscription.status;
      member.currentPeriodEnd = subscription.current_period_end
        ? new Date(subscription.current_period_end * 1000).toISOString()
        : null;
      member.lastCheckedAt = new Date().toISOString();
      member.updatedAt = new Date().toISOString();
      return;
    }
    case 'invoice.payment_succeeded':
    case 'invoice.payment_failed': {
      const invoice = event.data.object;
      const member = findMemberByStripeCustomerId(invoice.customer);
      if (member) await syncMemberFromStripe(member);
      return;
    }
    default:
      return;
  }
}

app.post('/api/stripe/webhook', express.raw({ type: 'application/json' }), async (req, res) => {
  const sig = req.headers['stripe-signature'];
  let event;

  try {
    event = stripe.webhooks.constructEvent(req.body, sig, process.env.STRIPE_WEBHOOK_SECRET || 'whsec_replace_me');
  } catch (err) {
    return res.status(400).send(`Webhook Error: ${err.message}`);
  }

  try {
    await handleStripeEvent(event);
    res.json({ received: true });
  } catch (error) {
    res.status(500).json({ error: 'Webhook processing failed' });
  }
});

app.use(express.json());

app.post('/api/auth/register', async (req, res) => {
  try {
    const email = normalizeEmail(req.body.email);
    const password = String(req.body.password || '');
    const name = String(req.body.name || 'Prime Defense Member').trim();

    if (!email || !password) return res.status(400).json({ error: 'Email and password are required' });
    if (db.membersByEmail[email]) return res.status(409).json({ error: 'An account already exists for this email' });

    const member = {
      id: createId('mem'),
      email,
      name,
      passwordHash: await bcrypt.hash(password, 12),
      stripeCustomerId: null,
      stripeSubscriptionId: null,
      membershipStatus: 'unknown',
      currentPeriodEnd: null,
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
      lastCheckedAt: null
    };

    db.members[member.id] = member;
    db.membersByEmail[email] = member.id;
    await syncMemberFromStripe(member);

    res.json({ token: signToken(member), member: publicMember(member) });
  } catch (error) {
    res.status(500).json({ error: 'Registration failed' });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const email = normalizeEmail(req.body.email);
    const password = String(req.body.password || '');
    const memberId = db.membersByEmail[email];
    const member = memberId ? db.members[memberId] : null;

    if (!member) return res.status(401).json({ error: 'Invalid email or password' });
    const ok = await bcrypt.compare(password, member.passwordHash);
    if (!ok) return res.status(401).json({ error: 'Invalid email or password' });

    await syncMemberFromStripe(member);
    res.json({ token: signToken(member), member: publicMember(member) });
  } catch (error) {
    res.status(500).json({ error: 'Login failed' });
  }
});

app.get('/api/member/me', requireAuth, (req, res) => {
  res.json({ member: publicMember(req.member) });
});

app.post('/api/member/refresh-stripe-status', requireAuth, async (req, res) => {
  try {
    await syncMemberFromStripe(req.member);
    res.json({ member: publicMember(req.member) });
  } catch (error) {
    res.status(500).json({ error: 'Unable to refresh Stripe status' });
  }
});

app.post('/api/member/billing-portal', requireAuth, async (req, res) => {
  try {
    if (!req.member.stripeCustomerId) return res.status(404).json({ error: 'No Stripe customer found for this member email' });
    const session = await stripe.billingPortal.sessions.create({
      customer: req.member.stripeCustomerId,
      return_url: FRONTEND_URL
    });
    res.json({ url: session.url });
  } catch (error) {
    res.status(500).json({ error: 'Unable to create billing portal session' });
  }
});

const STATES = [
  ['AL', 'Alabama'], ['AK', 'Alaska'], ['AZ', 'Arizona'], ['AR', 'Arkansas'], ['CA', 'California'],
  ['CO', 'Colorado'], ['CT', 'Connecticut'], ['DE', 'Delaware'], ['FL', 'Florida'], ['GA', 'Georgia'],
  ['HI', 'Hawaii'], ['ID', 'Idaho'], ['IL', 'Illinois'], ['IN', 'Indiana'], ['IA', 'Iowa'],
  ['KS', 'Kansas'], ['KY', 'Kentucky'], ['LA', 'Louisiana'], ['ME', 'Maine'], ['MD', 'Maryland'],
  ['MA', 'Massachusetts'], ['MI', 'Michigan'], ['MN', 'Minnesota'], ['MS', 'Mississippi'], ['MO', 'Missouri'],
  ['MT', 'Montana'], ['NE', 'Nebraska'], ['NV', 'Nevada'], ['NH', 'New Hampshire'], ['NJ', 'New Jersey'],
  ['NM', 'New Mexico'], ['NY', 'New York'], ['NC', 'North Carolina'], ['ND', 'North Dakota'], ['OH', 'Ohio'],
  ['OK', 'Oklahoma'], ['OR', 'Oregon'], ['PA', 'Pennsylvania'], ['RI', 'Rhode Island'], ['SC', 'South Carolina'],
  ['SD', 'South Dakota'], ['TN', 'Tennessee'], ['TX', 'Texas'], ['UT', 'Utah'], ['VT', 'Vermont'],
  ['VA', 'Virginia'], ['WA', 'Washington'], ['WV', 'West Virginia'], ['WI', 'Wisconsin'], ['WY', 'Wyoming']
];

const CATEGORY_LABELS = {
  reciprocity: 'Reciprocity',
  dutyToInform: 'Duty to Inform',
  vehicleCarry: 'Vehicle Carry',
  restrictedLocations: 'Restricted Locations',
  signsEnforceable: 'Signs Enforceable',
  openCarry: 'Open Carry',
  constitutionalCarry: 'Constitutional Carry',
  useOfForce: 'Use of Force',
  lawEnforcementInteraction: 'Law Enforcement Interaction',
  differentFromMichigan: 'What’s Different from Michigan?'
};

function createStateLaw(abbr, name) {
  const categories = {};
  for (const [key, label] of Object.entries(CATEGORY_LABELS)) {
    categories[key] = {
      answer: `${name} ${label}: mock field populated`,
      details: `This field will be connected to official ${name} legal-source data in the live version.`,
      sourceName: `${name} official legal resources`,
      sourceUrl: null,
      confidence: 'mock'
    };
  }

  if (abbr === 'OH') {
    categories.constitutionalCarry.answer = 'Permitless carry recognized — source-backed field needed';
    categories.openCarry.answer = 'Generally lawful — source-backed field needed';
    categories.signsEnforceable.answer = 'Posted-premises rules — source-backed field needed';
  }

  if (abbr === 'MI') {
    categories.reciprocity.answer = 'Home State: Michigan CPL baseline';
    categories.differentFromMichigan.answer = 'Michigan is the baseline for member comparisons';
  }

  return {
    abbr,
    name,
    status: 'Mock Data Active',
    syncStatus: 'mock',
    lastSynced: new Date().toISOString(),
    sourceSet: [`${name} official state resources`],
    categories
  };
}

function seedStates() {
  for (const [abbr, name] of STATES) {
    db.stateLaws[abbr] = createStateLaw(abbr, name);
  }
}
seedStates();

app.get('/api/states', requireAuth, requireActiveMembership, (req, res) => {
  res.json(STATES.map(([abbr, name]) => ({ abbr, name, status: db.stateLaws[abbr].status, syncStatus: db.stateLaws[abbr].syncStatus })));
});

app.get('/api/states/:abbr', requireAuth, requireActiveMembership, (req, res) => {
  const abbr = String(req.params.abbr || '').toUpperCase();
  const record = db.stateLaws[abbr];
  if (!record) return res.status(404).json({ error: 'State not found' });
  res.json(record);
});

app.get('/api/health', (req, res) => {
  res.json({ ok: true, service: 'Prime Defense Members API' });
});

cron.schedule('15 3 * * *', () => {
  db.syncRuns.push({ id: createId('sync'), status: 'mock_complete', at: new Date().toISOString() });
});

const frontendDist = path.join(__dirname, '..', 'frontend', 'dist');
app.use(express.static(frontendDist));
app.get('*', (req, res) => {
  res.sendFile(path.join(frontendDist, 'index.html'));
});

app.listen(PORT, () => {
  console.log(`Prime Defense Members app running on port ${PORT}`);
});
