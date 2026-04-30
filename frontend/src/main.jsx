import React, { useEffect, useMemo, useState } from 'react';
import { createRoot } from 'react-dom/client';
import './styles.css';

const API_BASE = import.meta.env.VITE_API_BASE || '';
const USCCA_PHONE = '8776771919';
const USCCA_DISPLAY = '877-677-1919';

function apiHeaders(token) {
  return {
    'Content-Type': 'application/json',
    ...(token ? { Authorization: `Bearer ${token}` } : {})
  };
}

async function apiRequest(path, options = {}) {
  const response = await fetch(`${API_BASE}${path}`, options);
  const data = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(data.error || 'Request failed');
  return data;
}

function App() {
  const [token, setToken] = useState(() => localStorage.getItem('pd_token') || '');
  const [member, setMember] = useState(null);
  const [authMode, setAuthMode] = useState('login');
  const [form, setForm] = useState({ name: '', email: '', password: '' });
  const [screen, setScreen] = useState('home');
  const [states, setStates] = useState([]);
  const [selectedState, setSelectedState] = useState(null);
  const [selectedStateData, setSelectedStateData] = useState(null);
  const [search, setSearch] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const [emergencyContact, setEmergencyContact] = useState({ name: '', phone: '' });

  useEffect(() => {
    if (!token) return;
    apiRequest('/api/member/me', { headers: apiHeaders(token) })
      .then((data) => setMember(data.member))
      .catch(() => {
        localStorage.removeItem('pd_token');
        setToken('');
        setMember(null);
      });
  }, [token]);

  useEffect(() => {
    if (!token || !member?.accessAllowed) return;
    apiRequest('/api/states', { headers: apiHeaders(token) })
      .then((data) => setStates(data))
      .catch((err) => setError(err.message));
  }, [token, member?.accessAllowed]);

  const filteredStates = useMemo(() => {
    const q = search.toLowerCase().trim();
    if (!q) return states;
    return states.filter((s) => s.abbr.toLowerCase().includes(q) || s.name.toLowerCase().includes(q));
  }, [search, states]);

  async function submitAuth(e) {
    e.preventDefault();
    setError('');
    setLoading(true);
    try {
      const endpoint = authMode === 'register' ? '/api/auth/register' : '/api/auth/login';
      const payload = authMode === 'register'
        ? { name: form.name, email: form.email, password: form.password }
        : { email: form.email, password: form.password };
      const data = await apiRequest(endpoint, { method: 'POST', headers: apiHeaders(), body: JSON.stringify(payload) });
      localStorage.setItem('pd_token', data.token);
      setToken(data.token);
      setMember(data.member);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }

  async function refreshMembershipStatus() {
    setError('');
    setLoading(true);
    try {
      const data = await apiRequest('/api/member/refresh-stripe-status', { method: 'POST', headers: apiHeaders(token) });
      setMember(data.member);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }

  async function openBillingPortal() {
    setError('');
    setLoading(true);
    try {
      const data = await apiRequest('/api/member/billing-portal', { method: 'POST', headers: apiHeaders(token) });
      window.location.href = data.url;
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }

  function logout() {
    localStorage.removeItem('pd_token');
    setToken('');
    setMember(null);
    setStates([]);
    setScreen('home');
  }

  async function openState(state) {
    setError('');
    setSelectedState(state);
    setScreen('state');
    setSelectedStateData(null);
    try {
      const data = await apiRequest(`/api/states/${state.abbr}`, { headers: apiHeaders(token) });
      setSelectedStateData(data);
    } catch (err) {
      setError(err.message);
    }
  }

  if (!member) return <AuthScreen authMode={authMode} setAuthMode={setAuthMode} form={form} setForm={setForm} error={error} loading={loading} onSubmit={submitAuth} />;
  if (!member.accessAllowed) return <LockedScreen member={member} error={error} loading={loading} refreshMembershipStatus={refreshMembershipStatus} openBillingPortal={openBillingPortal} logout={logout} />;
  if (screen === 'state') return <StatePage state={selectedState} stateData={selectedStateData} error={error} back={() => setScreen('home')} />;
  if (screen === 'shooting' || screen === 'no-shots') return <EmergencyMode mode={screen} contact={emergencyContact} back={() => setScreen('home')} />;
  if (screen === 'aftermath') return <AftermathMode back={() => setScreen('home')} />;

  return (
    <div className="page"><main className="shell">
      <section className="hero"><div className="heroTop"><div><div className="brand">PRIME DEFENSE TRAINING</div><h1>Prime Defense Protection Member</h1><p>Premium member-only dashboard connected to Stripe membership status.</p></div><div className="badge"><span />{member.membershipLabel}</div></div><div className="actions"><button className="danger" onClick={() => setScreen('shooting')}>Emergency Mode: Shooting</button><button className="red" onClick={() => setScreen('no-shots')}>Emergency Mode: No Shots Fired</button><button className="dark" onClick={() => setScreen('aftermath')}>Aftermath Mode</button></div></section>
      <section className="panel"><div className="panelHeader"><div><div className="brand">MEMBERSHIP STATUS</div><h2>{member.membershipLabel}</h2><p>Signed in as {member.email}. Last checked: {member.lastCheckedAt || 'not checked'}</p></div><div><button className="dark" onClick={refreshMembershipStatus}>Refresh Status</button><button className="dark" onClick={openBillingPortal}>Manage Billing</button><button className="dark" onClick={logout}>Logout</button></div></div>{error && <div className="warning">{error}</div>}</section>
      <section className="panel"><div className="panelHeader"><div><div className="brand">MEMBER LEGAL INTELLIGENCE</div><h2>Legal Updates</h2><p>Michigan-focused updates and member alerts. National carry details stay inside each state page.</p></div><span className="pill">Michigan Focus</span></div><InfoCard title="Michigan CPL & Firearm Law Monitoring" tag="Member Alert" text="Updates affecting Michigan CPL holders, storage, prohibited locations, use-of-force education, and renewal rules will appear here after review." /><InfoCard title="Training Reminder" tag="Education" text="Legal updates are paired with practical reminders so members understand what changed and what it means in real life." /></section>
      <section className="panel"><div className="panelHeader"><div><div className="brand">RECIPROCITY GUIDE</div><h2>State-by-State Carry Guide</h2><p>State list is loaded from the protected backend API.</p></div><span className="pill">Members Only</span></div><input placeholder="Search state..." value={search} onChange={(e) => setSearch(e.target.value)} /><div className="mapBox"><h3>Clickable State Grid</h3><div className="stateGrid">{filteredStates.map((state) => <button key={state.abbr} onClick={() => openState(state)}>{state.abbr}</button>)}</div></div></section>
      <section className="panel"><div className="brand">EMERGENCY CONTACT</div><h2>Family / Trusted Contact</h2><p>This contact appears only in the shooting scenario under “Contact Family.”</p><div className="inputGrid"><input placeholder="Contact name" value={emergencyContact.name} onChange={(e) => setEmergencyContact({ ...emergencyContact, name: e.target.value })} /><input placeholder="Phone number" value={emergencyContact.phone} onChange={(e) => setEmergencyContact({ ...emergencyContact, phone: e.target.value })} /></div></section>
    </main></div>
  );
}

function AuthScreen({ authMode, setAuthMode, form, setForm, error, loading, onSubmit }) {
  return <div className="detailPage"><div className="authShell"><div className="brand">PRIME DEFENSE TRAINING</div><h1>Member Login</h1><p>Use the same email address used for your PDPP / Stripe membership.</p><form className="authCard" onSubmit={onSubmit}><div className="authTabs"><button type="button" className={authMode === 'login' ? 'tab active' : 'tab'} onClick={() => setAuthMode('login')}>Login</button><button type="button" className={authMode === 'register' ? 'tab active' : 'tab'} onClick={() => setAuthMode('register')}>Register</button></div>{authMode === 'register' && <input placeholder="Full name" value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} />}<input type="email" placeholder="Membership email" value={form.email} onChange={(e) => setForm({ ...form, email: e.target.value })} required /><input type="password" placeholder="Password" value={form.password} onChange={(e) => setForm({ ...form, password: e.target.value })} required />{error && <div className="warning">{error}</div>}<button className="call" type="submit" disabled={loading}>{loading ? 'Checking...' : 'Continue'}</button></form></div></div>;
}
function LockedScreen({ member, error, loading, refreshMembershipStatus, openBillingPortal, logout }) { return <div className="detailPage"><div className="authShell"><div className="brand">MEMBERSHIP REQUIRED</div><h1>Access Locked</h1><p>Your membership needs attention before access can continue.</p><section className="status"><div className="label">CURRENT STATUS</div><h2>{member.membershipLabel}</h2><p>Signed in as {member.email}</p></section>{error && <div className="warning">{error}</div>}<button className="call" onClick={refreshMembershipStatus} disabled={loading}>Refresh Membership Status</button><button className="red" onClick={openBillingPortal}>Update Billing</button><button className="dark" onClick={logout}>Logout</button></div></div>; }
function StatePage({ state, stateData, error, back }) { const categories = stateData?.categories || {}; const rows = Object.entries(categories).length ? Object.entries(categories) : [['loading', { answer: 'Loading...', details: 'Loading state law data from backend.' }]]; return <div className="detailPage"><div className="detailHeader"><div><div className="brand">RECIPROCITY GUIDE</div><h1>{state?.name || stateData?.name || 'State'}</h1><p>State carry guide for Prime Defense Protection Members.</p></div><button className="exit" onClick={back}>Back</button></div><section className="status"><div className="label">STATUS</div><h2>{stateData?.status || 'Loading'}</h2><p>Sync status: {stateData?.syncStatus || 'loading'}</p><small>Last synced: {stateData?.lastSynced || 'pending'}</small></section>{error && <div className="warning">{error}</div>}<section className="detailGrid">{rows.map(([key, item]) => <div key={key} className="detailCard"><div className="label">{key.replace(/([A-Z])/g, ' $1').toUpperCase()}</div><h3>{item.answer}</h3><p>{item.details}</p><small>Source: {item.sourceName || 'pending'}</small></div>)}</section><div className="warning">Educational information only. Not legal advice. Always verify current law before traveling or carrying outside Michigan.</div></div>; }
function EmergencyMode({ mode, contact, back }) { const isShooting = mode === 'shooting'; return <div className="detailPage"><div className="detailHeader"><div><div className="brand">PRIME DEFENSE PROTECTION MEMBER</div><h1>Emergency Mode</h1><p>{isShooting ? 'Defensive shooting guidance' : 'No shots fired reporting guidance'}</p></div><button className="exit" onClick={back}>Exit</button></div><section className="status"><div className="label">STEP 1 — CALL 911</div>{isShooting ? <><div className="script">“I was attacked, feared for my life, and had to defend myself. Please send both police and an ambulance to this location.”</div><div className="scriptSmall">Secondary: “There has been a self-defense shooting at this location. Send help.”</div></> : <><div className="script">“My name is [name], and I need to report an attack or possible attack at this location.”</div><div className="scriptSmall">“I have a permit to carry and exposed my firearm, but no shots were fired.”</div><div className="scriptSmall">“The person was [description] and left the area.”</div></>}<button className="call" onClick={() => (window.location.href = 'tel:911')}>CALL 911</button></section><section className="step"><div className="label">STEP 2 — CALL USCCA</div><p>Contact the USCCA Critical Response Team after calling 911.</p><button className="call" onClick={() => (window.location.href = `tel:${USCCA_PHONE}`)}>CALL USCCA ({USCCA_DISPLAY})</button></section>{isShooting && <section className="step"><div className="label">STEP 3 — CONTACT FAMILY</div>{contact.name || contact.phone ? <div><h3>{contact.name || 'Emergency Contact'}</h3><p>{contact.phone || 'No phone saved'}</p>{contact.phone && <button className="call" onClick={() => (window.location.href = `tel:${contact.phone.replace(/[^0-9+]/g, '')}`)}>CALL CONTACT</button>}</div> : <div className="warning">No emergency contact saved. Exit Emergency Mode and add one from the dashboard.</div>}<div className="scriptFamily">“I’ve been involved in a defensive incident. I’m safe. Do not discuss anything with anyone until I have legal guidance.”</div></section>}<div className="warning">Provide only necessary information. Follow dispatcher instructions. Detailed statements can be given later when appropriate.</div></div>; }
function AftermathMode({ back }) { const cards = [['When Police Arrive', ['Keep your hands visible at all times.', 'Follow all commands immediately.', 'Do not make sudden movements.', 'Expect to be treated as a potential threat until officers secure the scene.']], ['Initial Interaction', ['Keep statements brief and factual.', 'Point out evidence or witnesses if necessary.', 'Do not argue, debate, or try to explain everything on scene.']], ['Statement Control', ['You may be under extreme stress and adrenaline.', 'Avoid detailed explanations immediately after the event.', 'Do not speculate, guess, or fill silence with extra details.', 'Detailed statements can be provided later when appropriate and after legal guidance.']], ['What Not To Do', ['Do not make sudden movements toward your firearm or pockets.', 'Do not handle evidence unless instructed.', 'Do not discuss details with bystanders, media, or uninvolved parties.', 'Do not post about the incident online.']]]; return <div className="detailPage"><div className="detailHeader"><div><div className="brand">PRIME DEFENSE PROTECTION MEMBER</div><h1>Aftermath Mode</h1><p>Guidance for immediately after law enforcement arrives.</p></div><button className="exit" onClick={back}>Exit</button></div>{cards.map(([title, items], i) => <section key={title} className={i === 0 ? 'status' : 'step'}><div className="label">{title.toUpperCase()}</div><ul>{items.map(x => <li key={x}>{x}</li>)}</ul></section>)}<section className="step"><div className="label">MENTAL STATE REMINDER</div><div className="scriptFamily">You may not remember everything clearly right now. That is normal.</div></section><div className="warning">This guidance is educational only and is not legal advice. Follow lawful commands and consult legal counsel for direction.</div></div>; }
function InfoCard({ title, tag, text }) { return <div className="info"><div><strong>{title}</strong><span>{tag}</span></div><p>{text}</p></div>; }

createRoot(document.getElementById('root')).render(<App />);
