const express = require('express');
const cors = require('cors');
const Stripe = require('stripe');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');

const app = express();
const PORT = process.env.PORT || 4000;
const stripe = Stripe(process.env.STRIPE_SECRET_KEY || 'sk_missing');
const JWT_SECRET = process.env.JWT_SECRET || 'change_this_secret';

// Stripe webhook must be before express.json
app.post('/api/stripe/webhook', express.raw({ type: 'application/json' }), async (req, res) => {
  const sig = req.headers['stripe-signature'];
  try {
    const event = stripe.webhooks.constructEvent(req.body, sig, process.env.STRIPE_WEBHOOK_SECRET || 'whsec_missing');
    await handleStripeEvent(event);
    res.json({ received: true });
  } catch (err) {
    console.error('Webhook error:', err.message);
    res.status(400).send(`Webhook Error: ${err.message}`);
  }
});

app.use(cors());
app.use(express.json());

const db = { members: {}, membersByEmail: {} };

const states = [
  ['AL','Alabama'],['AK','Alaska'],['AZ','Arizona'],['AR','Arkansas'],['CA','California'],['CO','Colorado'],['CT','Connecticut'],['DE','Delaware'],['FL','Florida'],['GA','Georgia'],['HI','Hawaii'],['ID','Idaho'],['IL','Illinois'],['IN','Indiana'],['IA','Iowa'],['KS','Kansas'],['KY','Kentucky'],['LA','Louisiana'],['ME','Maine'],['MD','Maryland'],['MA','Massachusetts'],['MI','Michigan'],['MN','Minnesota'],['MS','Mississippi'],['MO','Missouri'],['MT','Montana'],['NE','Nebraska'],['NV','Nevada'],['NH','New Hampshire'],['NJ','New Jersey'],['NM','New Mexico'],['NY','New York'],['NC','North Carolina'],['ND','North Dakota'],['OH','Ohio'],['OK','Oklahoma'],['OR','Oregon'],['PA','Pennsylvania'],['RI','Rhode Island'],['SC','South Carolina'],['SD','South Dakota'],['TN','Tennessee'],['TX','Texas'],['UT','Utah'],['VT','Vermont'],['VA','Virginia'],['WA','Washington'],['WV','West Virginia'],['WI','Wisconsin'],['WY','Wyoming']
];

function normalizeEmail(email) { return String(email || '').trim().toLowerCase(); }
function memberId() { return 'mem_' + Math.random().toString(36).slice(2) + Date.now().toString(36); }
function activeStatus(status) { return status === 'active' || status === 'trialing'; }
function label(status) {
  if (status === 'active') return 'Active Protection Member';
  if (status === 'trialing') return 'Trialing Protection Member';
  if (status === 'past_due') return 'Past Due — Payment Issue';
  if (status === 'canceled') return 'Canceled — Access Locked';
  if (status === 'unpaid') return 'Unpaid — Access Restricted';
  if (status === 'not_found') return 'No Active Membership Found';
  return 'Membership Status Unknown';
}
function permitStatus(profile) {
  if (!profile || !profile.expirationDate) return { status: 'missing', label: 'Permit Info Needed', message: 'Add your permit state, issue date, and expiration date.' };
  const exp = new Date(profile.expirationDate + 'T00:00:00');
  if (Number.isNaN(exp.getTime())) return { status: 'invalid', label: 'Invalid Date', message: 'Check the expiration date.' };
  const days = Math.ceil((exp - new Date()) / 86400000);
  if (days < 0) return { status: 'expired', label: 'Expired', message: 'Your permit appears expired.', daysRemaining: days };
  if (days <= 183) return { status: 'renewal_window', label: 'Renewal Window', message: 'Your permit is within the 6-month renewal window.', daysRemaining: days };
  return { status: 'active', label: 'Active', message: 'Your permit appears active based on the expiration date entered.', daysRemaining: days };
}
function publicMember(m) {
  return {
    id: m.id,
    email: m.email,
    name: m.name,
    stripeCustomerId: m.stripeCustomerId,
    stripeSubscriptionId: m.stripeSubscriptionId,
    membershipStatus: m.membershipStatus,
    membershipLabel: label(m.membershipStatus),
    accessAllowed: activeStatus(m.membershipStatus),
    permitProfile: m.permitProfile || { permitState: 'MI', issueDate: '', expirationDate: '' },
    permitStatus: permitStatus(m.permitProfile),
    lastCheckedAt: m.lastCheckedAt
  };
}
function signToken(m) { return jwt.sign({ id: m.id, email: m.email }, JWT_SECRET, { expiresIn: '30d' }); }
function auth(req, res, next) {
  const token = (req.headers.authorization || '').replace('Bearer ', '');
  if (!token) return res.status(401).json({ error: 'Missing token' });
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const m = db.members[decoded.id];
    if (!m) return res.status(401).json({ error: 'Member not found. Please register again.' });
    req.member = m;
    next();
  } catch { res.status(401).json({ error: 'Invalid token' }); }
}
function requireActive(req, res, next) {
  if (!activeStatus(req.member.membershipStatus)) return res.status(403).json({ error: 'Active membership required', member: publicMember(req.member) });
  next();
}
async function syncStripe(m) {
  const customers = await stripe.customers.list({ email: m.email, limit: 10 });
  const customer = customers.data.sort((a,b)=>b.created-a.created)[0];
  if (!customer) {
    m.stripeCustomerId = null; m.stripeSubscriptionId = null; m.membershipStatus = 'not_found'; m.lastCheckedAt = new Date().toISOString(); return m;
  }
  const subs = await stripe.subscriptions.list({ customer: customer.id, status: 'all', limit: 20 });
  const order = ['active','trialing','past_due','unpaid','incomplete','canceled'];
  const sub = subs.data.sort((a,b)=> (order.indexOf(a.status)<0?99:order.indexOf(a.status)) - (order.indexOf(b.status)<0?99:order.indexOf(b.status)) || b.created-a.created)[0];
  m.stripeCustomerId = customer.id;
  if (!sub) { m.stripeSubscriptionId = null; m.membershipStatus = 'not_found'; }
  else { m.stripeSubscriptionId = sub.id; m.membershipStatus = sub.status; }
  m.lastCheckedAt = new Date().toISOString(); return m;
}
async function handleStripeEvent(event) {
  const obj = event.data.object;
  if (event.type.startsWith('customer.subscription.')) {
    const m = Object.values(db.members).find(x => x.stripeCustomerId === obj.customer || x.stripeSubscriptionId === obj.id);
    if (m) { m.stripeSubscriptionId = obj.id; m.membershipStatus = obj.status; m.lastCheckedAt = new Date().toISOString(); }
  }
  if (event.type.startsWith('invoice.payment_')) {
    const m = Object.values(db.members).find(x => x.stripeCustomerId === obj.customer);
    if (m) await syncStripe(m);
  }
}

app.get('/health', (req,res)=>res.json({ ok: true, app: 'Prime Defense Members App' }));

app.post('/api/auth/register', async (req,res)=>{
  try {
    const email = normalizeEmail(req.body.email);
    const password = String(req.body.password || '');
    const name = String(req.body.name || 'Prime Defense Member');
    if (!email || !password) return res.status(400).json({ error: 'Email and password are required' });
    if (db.membersByEmail[email]) return res.status(409).json({ error: 'Account already exists. Use Login or restart service to clear temporary account.' });
    const m = { id: memberId(), email, name, passwordHash: await bcrypt.hash(password, 10), membershipStatus: 'unknown', permitProfile: { permitState: 'MI', issueDate: '', expirationDate: '' } };
    db.members[m.id] = m; db.membersByEmail[email] = m.id;
    await syncStripe(m);
    res.json({ token: signToken(m), member: publicMember(m) });
  } catch (e) { console.error(e); res.status(500).json({ error: 'Registration failed' }); }
});
app.post('/api/auth/login', async (req,res)=>{
  try {
    const email = normalizeEmail(req.body.email);
    const m = db.members[db.membersByEmail[email]];
    if (!m || !(await bcrypt.compare(String(req.body.password || ''), m.passwordHash))) return res.status(401).json({ error: 'Invalid email or password' });
    await syncStripe(m);
    res.json({ token: signToken(m), member: publicMember(m) });
  } catch { res.status(500).json({ error: 'Login failed' }); }
});
app.get('/api/member/me', auth, (req,res)=>res.json({ member: publicMember(req.member) }));
app.post('/api/member/refresh-stripe-status', auth, async (req,res)=>{ await syncStripe(req.member); res.json({ member: publicMember(req.member) }); });
app.post('/api/member/billing-portal', auth, async (req,res)=>{
  if (!req.member.stripeCustomerId) return res.status(404).json({ error: 'No Stripe customer found for this email' });
  const session = await stripe.billingPortal.sessions.create({ customer: req.member.stripeCustomerId, return_url: process.env.FRONTEND_URL || req.protocol + '://' + req.get('host') });
  res.json({ url: session.url });
});
app.put('/api/member/permit', auth, (req,res)=>{
  req.member.permitProfile = { permitState: req.body.permitState || 'MI', issueDate: req.body.issueDate || '', expirationDate: req.body.expirationDate || '' };
  res.json({ member: publicMember(req.member), permitStatus: permitStatus(req.member.permitProfile) });
});
app.get('/api/states', auth, requireActive, (req,res)=>res.json(states.map(([abbr,name])=>({abbr,name,status:'Mock Data Ready',syncStatus:'demo'}))));
app.get('/api/states/:abbr', auth, requireActive, (req,res)=>{
  const st = states.find(([a])=>a===String(req.params.abbr).toUpperCase());
  if (!st) return res.status(404).json({error:'State not found'});
  const [abbr,name]=st;
  const cat = (title, answer, details) => ({ answer, details, sourceName: `${name} official legal resources` });
  res.json({ abbr, name, status:'Mock Data Ready', syncStatus:'demo', lastSynced:'Mock data', categories:{
    reciprocity: cat('Reciprocity', `${name} reciprocity field populated`, `Shows whether a Michigan CPL is recognized in ${name}.`),
    dutyToInform: cat('Duty to Inform', `${name} duty-to-inform field populated`, `Shows whether and when members must notify law enforcement.`),
    vehicleCarry: cat('Vehicle Carry', `${name} vehicle carry guidance populated`, `Summarizes vehicle carry and transport rules.`),
    restrictedLocations: cat('Restricted Locations', `${name} restricted locations populated`, `Lists major places where carry is restricted or prohibited.`),
    signsEnforceable: cat('Signs Enforceable', `${name} signage field populated`, `Explains whether posted no-firearms signs have legal force.`),
    openCarry: cat('Open Carry', `${name} open carry field populated`, `Shows whether open carry is generally lawful and major limitations.`),
    constitutionalCarry: cat('Constitutional Carry', `${name} permitless carry field populated`, `Shows whether permitless carry is recognized and who qualifies.`),
    useOfForce: cat('Use of Force', 'High-level awareness only', `Summarizes major self-defense concepts without legal advice.`),
    lawEnforcementInteraction: cat('Law Enforcement Interaction', `${name} police-interaction field populated`, `Highlights interaction rules or differences from Michigan.`),
    differentFromMichigan: cat('Different From Michigan', `${name} vs Michigan comparison populated`, `Quick comparison for Michigan members traveling into ${name}.`)
  }});
});

const html = `<!doctype html><html><head><meta charset="UTF-8"/><meta name="viewport" content="width=device-width, initial-scale=1.0"/><title>Prime Defense Protection Member</title><style>
body{margin:0;background:radial-gradient(circle at top left,#3a0b0f 0,#111 34%,#050505 100%);color:#fff;font-family:Arial,Helvetica,sans-serif}button,input,select{font:inherit}.shell{max-width:1100px;margin:auto;padding:22px}.hero,.panel,.card{background:rgba(16,16,16,.96);border:1px solid rgba(255,255,255,.09);border-radius:24px;padding:24px;margin:18px 0;box-shadow:0 18px 50px rgba(0,0,0,.35)}.hero{background:linear-gradient(135deg,rgba(26,26,26,.98),rgba(8,8,8,.98));border-radius:28px}.brand{color:#ef233c;font-weight:900;letter-spacing:3px;font-size:12px}.title{font-size:clamp(36px,6vw,60px);line-height:.92;margin:12px 0}.h2{font-size:28px;margin:8px 0}.text{color:#cfcfcf;line-height:1.55}.row{display:flex;gap:12px;flex-wrap:wrap;justify-content:space-between;align-items:flex-start}.btn{border:0;border-radius:16px;background:#ef233c;color:white;padding:16px 20px;font-weight:900;cursor:pointer;margin:6px}.btn.dark{background:#161616;border:1px solid rgba(255,255,255,.16)}.btn.danger{background:#b00020}.badge{background:rgba(34,197,94,.13);border:1px solid rgba(34,197,94,.35);color:#8cffb0;border-radius:999px;padding:12px 16px;font-weight:900}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(250px,1fr));gap:14px}.states{display:grid;grid-template-columns:repeat(auto-fit,minmax(58px,1fr));gap:10px;margin-top:16px}.state{background:#090909;color:#fff;border:1px solid rgba(255,255,255,.12);border-radius:14px;padding:14px 10px;font-weight:900;cursor:pointer}.input{width:100%;box-sizing:border-box;padding:15px;border-radius:16px;border:1px solid rgba(255,255,255,.14);background:#080808;color:#fff;margin:8px 0}.warn{padding:16px;background:rgba(245,158,11,.12);border:1px solid rgba(245,158,11,.25);border-radius:18px;color:#ffe7b3;margin:14px 0}.success{padding:16px;background:rgba(34,197,94,.12);border:1px solid rgba(34,197,94,.25);border-radius:18px;color:#8cffb0;margin:14px 0}.script{font-size:clamp(24px,5vw,38px);line-height:1.15;font-weight:900}.small{font-size:12px;color:#9ca3af;border-top:1px solid rgba(255,255,255,.08);padding-top:10px;margin-top:10px}.hidden{display:none}.auth{max-width:760px;margin:auto;padding:28px 0}.activePill{display:inline-block;border-radius:999px;padding:9px 12px;font-size:12px;font-weight:900;background:rgba(255,255,255,.08);border:1px solid rgba(255,255,255,.12)}
</style></head><body><div id="app"></div><script>
const API=''; let token=localStorage.getItem('pd_token')||''; let member=null; let states=[]; let selectedState=null; let contact={name:'',phone:''};
const stateOptions=${JSON.stringify(states)};
async function req(path,opts={}){const r=await fetch(API+path,{...opts,headers:{'Content-Type':'application/json',...(token?{Authorization:'Bearer '+token}:{}),...(opts.headers||{})}});const d=await r.json().catch(()=>({}));if(!r.ok)throw new Error(d.error||'Request failed');return d;}
function el(html){document.getElementById('app').innerHTML=html} function esc(s){return String(s??'').replace(/[&<>]/g,m=>({'&':'&amp;','<':'&lt;','>':'&gt;'}[m]))}
function renderAuth(err=''){el('<div class="auth"><div class="brand">PRIME DEFENSE TRAINING</div><h1 class="title">Member Login</h1><p class="text">Use the same email used for your PDPP / Stripe membership.</p><div class="panel"><input id="name" class="input" placeholder="Full name (register only)"><input id="email" class="input" type="email" placeholder="Membership email"><input id="pw" class="input" type="password" placeholder="Password">'+(err?'<div class="warn">'+esc(err)+'</div>':'')+'<button class="btn" onclick="auth(\'login\')">Login</button><button class="btn dark" onclick="auth(\'register\')">Register</button></div></div>')}
async function auth(mode){try{const body={email:email.value,password:pw.value,name:name.value};const d=await req('/api/auth/'+mode,{method:'POST',body:JSON.stringify(body)});token=d.token;localStorage.setItem('pd_token',token);member=d.member;renderHome()}catch(e){renderAuth(e.message)}}
async function loadMe(){if(!token)return renderAuth();try{const d=await req('/api/member/me');member=d.member; if(!member.accessAllowed) return renderLocked(); renderHome()}catch{localStorage.removeItem('pd_token');token='';renderAuth()}}
function logout(){localStorage.removeItem('pd_token');token='';member=null;renderAuth()}
async function refresh(){try{const d=await req('/api/member/refresh-stripe-status',{method:'POST'});member=d.member; member.accessAllowed?renderHome():renderLocked()}catch(e){alert(e.message)}}
async function billing(){try{const d=await req('/api/member/billing-portal',{method:'POST'});location.href=d.url}catch(e){alert(e.message)}}
function renderLocked(){el('<div class="auth"><div class="brand">MEMBERSHIP REQUIRED</div><h1 class="title">Access Locked</h1><p class="text">Your membership needs attention before access can continue.</p><div class="panel"><div class="brand">CURRENT STATUS</div><h2 class="h2">'+esc(member.membershipLabel)+'</h2><p class="text">Signed in as '+esc(member.email)+'</p></div><button class="btn" onclick="refresh()">Refresh Membership Status</button><button class="btn" onclick="billing()">Update Billing</button><button class="btn dark" onclick="logout()">Logout</button></div>')}
async function loadStates(){try{states=await req('/api/states')}catch(e){states=[]}}
async function renderHome(){await loadStates(); const p=member.permitProfile||{permitState:'MI',issueDate:'',expirationDate:''}; const ps=member.permitStatus||{}; el('<div class="shell"><section class="hero"><div class="row"><div><div class="brand">PRIME DEFENSE TRAINING</div><h1 class="title">Prime Defense Protection Member</h1><p class="text">Premium member dashboard connected to Stripe membership status.</p></div><div class="badge">'+esc(member.membershipLabel)+'</div></div><button class="btn danger" onclick="renderEmergency(\'shooting\')">Emergency Mode: Shooting</button><button class="btn" onclick="renderEmergency(\'no-shots\')">Emergency Mode: No Shots Fired</button><button class="btn dark" onclick="renderAftermath()">Aftermath Mode</button></section><section class="panel"><div class="row"><div><div class="brand">MEMBERSHIP STATUS</div><h2 class="h2">'+esc(member.membershipLabel)+'</h2><p class="text">Signed in as '+esc(member.email)+'</p></div><div><button class="btn dark" onclick="refresh()">Refresh</button><button class="btn dark" onclick="billing()">Manage Billing</button><button class="btn dark" onclick="logout()">Logout</button></div></div></section><section class="panel"><div class="brand">MY PERMIT</div><h2 class="h2">Permit Profile <span class="activePill">'+esc(ps.label||'Permit Info Needed')+'</span></h2><p class="text">'+esc(ps.message||'Add your permit details.')+'</p><div class="grid"><label>Permit State<select class="input" id="permitState">'+stateOptions.map(s=>'<option value="'+s[0]+'" '+(p.permitState===s[0]?'selected':'')+'>'+s[1]+'</option>').join('')+'</select></label><label>Issue Date<input class="input" type="date" id="issueDate" value="'+esc(p.issueDate||'')+'"></label><label>Expiration Date<input class="input" type="date" id="expirationDate" value="'+esc(p.expirationDate||'')+'"></label></div><button class="btn" onclick="savePermit()">Save Permit</button></section><section class="panel"><div class="brand">MEMBER LEGAL INTELLIGENCE</div><h2 class="h2">Legal Updates</h2><p class="text">Michigan-focused updates and member alerts. National carry details stay inside each state page.</p></section><section class="panel"><div class="brand">RECIPROCITY GUIDE</div><h2 class="h2">State-by-State Carry Guide</h2><div class="states">'+states.map(s=>'<button class="state" onclick="openState(\''+s.abbr+'\')">'+s.abbr+'</button>').join('')+'</div></section><section class="panel"><div class="brand">EMERGENCY CONTACT</div><h2 class="h2">Family / Trusted Contact</h2><input class="input" id="cname" placeholder="Contact name" value="'+esc(contact.name)+'"><input class="input" id="cphone" placeholder="Phone number" value="'+esc(contact.phone)+'"><button class="btn dark" onclick="contact={name:cname.value,phone:cphone.value};renderHome()">Save Contact</button></section></div>')}
async function savePermit(){try{const d=await req('/api/member/permit',{method:'PUT',body:JSON.stringify({permitState:permitState.value,issueDate:issueDate.value,expirationDate:expirationDate.value})});member=d.member;renderHome()}catch(e){alert(e.message)}}
async function openState(abbr){try{selectedState=await req('/api/states/'+abbr);const cats=selectedState.categories;el('<div class="shell"><button class="btn dark" onclick="renderHome()">Back</button><div class="brand">RECIPROCITY GUIDE</div><h1 class="title">'+esc(selectedState.name)+'</h1><section class="panel"><div class="brand">STATUS</div><h2>'+esc(selectedState.status)+'</h2><p class="text">Sync status: '+esc(selectedState.syncStatus)+'</p></section><div class="grid">'+Object.entries(cats).map(([k,v])=>'<div class="card"><div class="brand">'+k.replace(/[A-Z]/g,' $&').toUpperCase()+'</div><h3>'+esc(v.answer)+'</h3><p class="text">'+esc(v.details)+'</p><div class="small">Source: '+esc(v.sourceName)+'</div></div>').join('')+'</div><div class="warn">Educational only. Not legal advice.</div></div>')}catch(e){alert(e.message)}}
function renderEmergency(mode){const shoot=mode==='shooting'; el('<div class="shell"><button class="btn dark" onclick="renderHome()">Exit</button><div class="brand">PRIME DEFENSE PROTECTION MEMBER</div><h1 class="title">Emergency Mode</h1><section class="panel"><div class="brand">STEP 1 — CALL 911</div>'+(shoot?'<div class="script">“I was attacked, feared for my life, and had to defend myself. Please send both police and an ambulance to this location.”</div><div class="warn">Secondary: “There has been a self-defense shooting at this location. Send help.”</div>':'<div class="script">“My name is [name], and I need to report an attack or possible attack at this location.”</div><div class="warn">“I have a permit to carry and exposed my firearm, but no shots were fired.”</div>')+'<button class="btn" onclick="location.href=\'tel:911\'">CALL 911</button></section><section class="panel"><div class="brand">STEP 2 — CALL USCCA</div><button class="btn" onclick="location.href=\'tel:${USCCA_PHONE}\'">CALL USCCA (${USCCA_DISPLAY})</button></section>'+(shoot?'<section class="panel"><div class="brand">STEP 3 — CONTACT FAMILY</div><h2>'+(contact.name||'No contact saved')+'</h2><p class="text">'+(contact.phone||'')+'</p>'+(contact.phone?'<button class="btn" onclick="location.href=\'tel:'+contact.phone.replace(/[^0-9+]/g,'')+'\'">CALL CONTACT</button>':'')+'<div class="script">“I’ve been involved in a defensive incident. I’m safe. Do not discuss anything with anyone until I have legal guidance.”</div></section>':'')+'</div>')}
function renderAftermath(){el('<div class="shell"><button class="btn dark" onclick="renderHome()">Exit</button><div class="brand">PRIME DEFENSE PROTECTION MEMBER</div><h1 class="title">Aftermath Mode</h1>'+['Keep your hands visible at all times. Follow commands immediately.','Keep statements brief and factual.','Avoid detailed explanations immediately after the event.','Do not discuss details with bystanders, media, or online.','You may not remember everything clearly right now. That is normal.'].map(x=>'<section class="panel"><p class="script">'+x+'</p></section>').join('')+'</div>')}
loadMe();
</script></body></html>`;

app.get('*', (req,res)=>res.send(html));

app.listen(PORT, () => console.log(`Prime Defense single-service app running on ${PORT}`));
