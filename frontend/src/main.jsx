import React, { useEffect, useMemo, useState } from "react";
import { createRoot } from "react-dom/client";
import "./styles.css";

const USCCA_PHONE = "8776771919";
const USCCA_DISPLAY = "877-677-1919";

const STATE_OPTIONS = [
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

function apiHeaders(token) {
  return { "Content-Type": "application/json", ...(token ? { Authorization: `Bearer ${token}` } : {}) };
}

async function apiRequest(path, options = {}) {
  const response = await fetch(path, options);
  const data = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(data.error || "Request failed");
  return data;
}

function statusDisplay(member) {
  if (!member) return { label: "Signed Out", access: false, message: "Please sign in." };
  if (member.accessAllowed) return { label: member.membershipLabel || "Active Protection Member", access: true, message: "Your membership is active." };
  return { label: member.membershipLabel || "Membership Required", access: false, message: "Your membership needs attention before access can continue." };
}

function localPermitStatus(profile) {
  if (!profile?.expirationDate) return { label: "Permit Info Needed", message: "Add your permit state, issue date, and expiration date.", status: "missing" };
  const today = new Date();
  const exp = new Date(profile.expirationDate + "T00:00:00");
  if (Number.isNaN(exp.getTime())) return { label: "Invalid Date", message: "Check the expiration date entered.", status: "invalid" };
  const days = Math.ceil((exp - today) / (1000 * 60 * 60 * 24));
  if (days < 0) return { label: "Expired", message: "Your permit appears expired. Review renewal requirements immediately.", status: "expired", daysRemaining: days };
  if (days <= 183) return { label: "Renewal Window", message: "Your permit is within the 6-month renewal window.", status: "renewal_window", daysRemaining: days };
  return { label: "Active", message: "Your permit appears active based on the expiration date entered.", status: "active", daysRemaining: days };
}

function App() {
  const [token, setToken] = useState(() => localStorage.getItem("pd_token") || "");
  const [member, setMember] = useState(null);
  const [authMode, setAuthMode] = useState("login");
  const [form, setForm] = useState({ name: "", email: "", password: "" });
  const [screen, setScreen] = useState("home");
  const [states, setStates] = useState([]);
  const [selectedState, setSelectedState] = useState(null);
  const [selectedStateData, setSelectedStateData] = useState(null);
  const [search, setSearch] = useState("");
  const [error, setError] = useState("");
  const [success, setSuccess] = useState("");
  const [loading, setLoading] = useState(false);
  const [emergencyContact, setEmergencyContact] = useState({ name: "", phone: "" });
  const [permitForm, setPermitForm] = useState({ permitState: "MI", issueDate: "", expirationDate: "" });
  const [permitStatus, setPermitStatus] = useState(localPermitStatus(permitForm));

  const display = statusDisplay(member);

  useEffect(() => {
    if (!token) return;
    apiRequest("/api/member/me", { headers: apiHeaders(token) })
      .then((data) => {
        setMember(data.member);
        const profile = data.member?.permitProfile || { permitState: "MI", issueDate: "", expirationDate: "" };
        setPermitForm({ permitState: profile.permitState || "MI", issueDate: profile.issueDate || "", expirationDate: profile.expirationDate || "" });
        setPermitStatus(data.member?.permitStatus || localPermitStatus(profile));
      })
      .catch(() => {
        localStorage.removeItem("pd_token");
        setToken("");
        setMember(null);
      });
  }, [token]);

  useEffect(() => {
    if (!token || !member?.accessAllowed) return;
    apiRequest("/api/states", { headers: apiHeaders(token) })
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
    setError("");
    setSuccess("");
    setLoading(true);
    try {
      const endpoint = authMode === "register" ? "/api/auth/register" : "/api/auth/login";
      const payload = authMode === "register" ? { name: form.name, email: form.email, password: form.password } : { email: form.email, password: form.password };
      const data = await apiRequest(endpoint, { method: "POST", headers: apiHeaders(), body: JSON.stringify(payload) });
      localStorage.setItem("pd_token", data.token);
      setToken(data.token);
      setMember(data.member);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }

  async function refreshMembershipStatus() {
    setError("");
    setLoading(true);
    try {
      const data = await apiRequest("/api/member/refresh-stripe-status", { method: "POST", headers: apiHeaders(token) });
      setMember(data.member);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }

  async function savePermitProfile(e) {
    e.preventDefault();
    setError("");
    setSuccess("");
    setLoading(true);
    try {
      const data = await apiRequest("/api/member/permit", { method: "PUT", headers: apiHeaders(token), body: JSON.stringify(permitForm) });
      setMember(data.member);
      setPermitStatus(data.permitStatus || localPermitStatus(permitForm));
      setSuccess("Permit profile saved.");
    } catch (err) {
      setError(err.message);
      setPermitStatus(localPermitStatus(permitForm));
    } finally {
      setLoading(false);
    }
  }

  async function openBillingPortal() {
    setError("");
    setLoading(true);
    try {
      const data = await apiRequest("/api/member/billing-portal", { method: "POST", headers: apiHeaders(token) });
      window.location.href = data.url;
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }

  function logout() {
    localStorage.removeItem("pd_token");
    setToken("");
    setMember(null);
    setStates([]);
    setScreen("home");
  }

  async function openState(state) {
    setError("");
    setSelectedState(state);
    setScreen("state");
    setSelectedStateData(null);
    try {
      const data = await apiRequest(`/api/states/${state.abbr}`, { headers: apiHeaders(token) });
      setSelectedStateData(data);
    } catch (err) {
      setError(err.message);
    }
  }

  if (!member) return <AuthScreen authMode={authMode} setAuthMode={setAuthMode} form={form} setForm={setForm} error={error} loading={loading} onSubmit={submitAuth} />;
  if (!member.accessAllowed) return <LockedScreen member={member} display={display} error={error} loading={loading} refreshMembershipStatus={refreshMembershipStatus} openBillingPortal={openBillingPortal} logout={logout} />;
  if (screen === "state") return <StatePage state={selectedState} stateData={selectedStateData} error={error} back={() => setScreen("home")} />;
  if (screen === "shooting" || screen === "no-shots") return <EmergencyMode mode={screen} contact={emergencyContact} back={() => setScreen("home")} />;
  if (screen === "aftermath") return <AftermathMode back={() => setScreen("home")} />;

  return (
    <div className="page">
      <main className="shell">
        <section className="hero">
          <div className="heroTop">
            <div>
              <div className="brand">PRIME DEFENSE TRAINING</div>
              <h1 className="title">Prime Defense Protection Member</h1>
              <p className="subtitle">Premium member-only dashboard connected to your Stripe membership status.</p>
            </div>
            <div className="badge"><span className="dot"></span>{member.membershipLabel}</div>
          </div>
          <div className="actions">
            <button className="dangerButton" onClick={() => setScreen("shooting")}>Emergency Mode: Shooting</button>
            <button className="redButton" onClick={() => setScreen("no-shots")}>Emergency Mode: No Shots Fired</button>
            <button className="darkButton" onClick={() => setScreen("aftermath")}>Aftermath Mode</button>
          </div>
        </section>

        <section className="panel">
          <div className="panelHeader">
            <div><div className="brand">MEMBERSHIP STATUS</div><h2>{member.membershipLabel}</h2><p>Signed in as {member.email}. Stripe status last checked: {member.lastCheckedAt || "not checked"}</p></div>
            <div><button className="darkButton" onClick={refreshMembershipStatus}>Refresh Status</button><button className="darkButton" onClick={openBillingPortal}>Manage Billing</button><button className="darkButton" onClick={logout}>Logout</button></div>
          </div>
          {error && <div className="warning">{error}</div>}
          {success && <div className="success">{success}</div>}
        </section>

        <section className="panel">
          <div className="panelHeader"><div><div className="brand">MY PERMIT</div><h2>Permit Profile</h2><p>Save your permit state, issue date, and expiration date so the app can show renewal status.</p></div><PermitStatusBadge status={permitStatus} /></div>
          <form className="formGrid" onSubmit={savePermitProfile}>
            <label>Permit State<select className="input" value={permitForm.permitState} onChange={(e) => setPermitForm({ ...permitForm, permitState: e.target.value })}>{STATE_OPTIONS.map(([abbr, name]) => <option key={abbr} value={abbr}>{name}</option>)}</select></label>
            <label>Issue Date<input className="input" type="date" value={permitForm.issueDate} onChange={(e) => setPermitForm({ ...permitForm, issueDate: e.target.value })} /></label>
            <label>Expiration Date<input className="input" type="date" value={permitForm.expirationDate} onChange={(e) => setPermitForm({ ...permitForm, expirationDate: e.target.value })} /></label>
            <button className="redButton" type="submit" disabled={loading}>{loading ? "Saving..." : "Save Permit"}</button>
          </form>
          <div className="permitSummary"><strong>{permitStatus?.label || "Permit Info Needed"}</strong><p>{permitStatus?.message || "Add permit details to calculate status."}</p>{typeof permitStatus?.daysRemaining === "number" && <div className="sourceNote">Days remaining: {permitStatus.daysRemaining}</div>}<div className="sourceNote">For Michigan renewals, members should track the 6-month renewal window before expiration.</div></div>
        </section>

        <section className="panel"><div className="brand">MEMBER LEGAL INTELLIGENCE</div><h2>Legal Updates</h2><InfoCard title="Michigan CPL & Firearm Law Monitoring" tag="Member Alert" text="Updates affecting Michigan CPL holders, storage, prohibited locations, use-of-force education, and renewal rules will appear here after review." /><InfoCard title="Training Reminder" tag="Education" text="Legal updates are paired with practical reminders so members understand what changed and what it means in real life." /></section>

        <section className="panel"><div className="brand">RECIPROCITY GUIDE</div><h2>State-by-State Carry Guide</h2><p>State list is loaded from the protected backend API.</p><input className="input" placeholder="Search state..." value={search} onChange={(e) => setSearch(e.target.value)} /><div className="mapBox"><h3>Clickable State Grid</h3><div className="stateGrid">{filteredStates.map((state) => <button key={state.abbr} className="stateButton" onClick={() => openState(state)}>{state.abbr}</button>)}</div></div></section>

        <section className="panel"><div className="brand">EMERGENCY CONTACT</div><h2>Family / Trusted Contact</h2><p>This contact appears only in the shooting scenario under “Contact Family.”</p><div className="inputGrid"><input className="input" placeholder="Contact name" value={emergencyContact.name} onChange={(e) => setEmergencyContact({ ...emergencyContact, name: e.target.value })} /><input className="input" placeholder="Phone number" value={emergencyContact.phone} onChange={(e) => setEmergencyContact({ ...emergencyContact, phone: e.target.value })} /></div></section>
      </main>
    </div>
  );
}

function PermitStatusBadge({ status }) {
  const cls = status?.status === "active" ? "permitBadgeGreen" : status?.status === "renewal_window" ? "permitBadgeYellow" : status?.status === "expired" ? "permitBadgeRed" : "permitBadgeNeutral";
  return <span className={cls}>{status?.label || "Permit Info Needed"}</span>;
}

function AuthScreen({ authMode, setAuthMode, form, setForm, error, loading, onSubmit }) {
  return <div className="detailPage"><div className="authShell"><div className="brand">PRIME DEFENSE TRAINING</div><h1 className="detailTitle">Member Login</h1><p className="detailSubtitle">Use the same email address used for your PDPP / Stripe membership.</p><form className="authCard" onSubmit={onSubmit}><div className="authTabs"><button type="button" className={authMode === "login" ? "authTabActive" : "authTab"} onClick={() => setAuthMode("login")}>Login</button><button type="button" className={authMode === "register" ? "authTabActive" : "authTab"} onClick={() => setAuthMode("register")}>Register</button></div>{authMode === "register" && <input className="input" placeholder="Full name" value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} />}<input className="input" type="email" placeholder="Membership email" value={form.email} onChange={(e) => setForm({ ...form, email: e.target.value })} required /><input className="input" type="password" placeholder="Password" value={form.password} onChange={(e) => setForm({ ...form, password: e.target.value })} required />{error && <div className="warning">{error}</div>}<button className="callBtn" type="submit" disabled={loading}>{loading ? "Checking..." : "Continue"}</button></form></div></div>;
}

function LockedScreen({ member, display, error, loading, refreshMembershipStatus, openBillingPortal, logout }) {
  return <div className="detailPage"><div className="authShell"><div className="brand">MEMBERSHIP REQUIRED</div><h1 className="detailTitle">Access Locked</h1><p className="detailSubtitle">{display.message}</p><section className="statusBanner"><div className="stepLabel">CURRENT STATUS</div><h2>{member.membershipLabel}</h2><p>Signed in as {member.email}</p></section>{error && <div className="warning">{error}</div>}<button className="callBtn" onClick={refreshMembershipStatus} disabled={loading}>Refresh Membership Status</button><button className="redButton" onClick={openBillingPortal}>Update Billing</button><button className="darkButton" onClick={logout}>Logout</button></div></div>;
}

function StatePage({ state, stateData, error, back }) {
  const categories = stateData?.categories || {};
  const rows = Object.entries(categories).length ? Object.entries(categories) : [["loading", { answer: "Loading...", details: "Loading state law data from backend." }]];
  return <div className="detailPage"><div className="detailHeader"><div><div className="brand">RECIPROCITY GUIDE</div><h1 className="detailTitle">{state?.name || stateData?.name || "State"}</h1><p className="detailSubtitle">State carry guide for Prime Defense Protection Members.</p></div><button className="exitBtn" onClick={back}>Back</button></div><section className="statusBanner"><div className="stepLabel">STATUS</div><h2>{stateData?.status || "Loading"}</h2><p>Sync status: {stateData?.syncStatus || "loading"}</p><div className="sourceNote">Last synced: {stateData?.lastSynced || "pending"}</div></section>{error && <div className="warning">{error}</div>}<section className="detailGrid">{rows.map(([key, item]) => <div key={key} className="detailCard"><div className="stepLabel">{key.replace(/([A-Z])/g, " $1").toUpperCase()}</div><h3>{item.answer}</h3><p>{item.details}</p><div className="sourceNote">Source: {item.sourceName || "pending"}</div></div>)}</section><div className="warning">Educational information only. Not legal advice. Always verify current law before traveling or carrying outside Michigan.</div></div>;
}

function EmergencyMode({ mode, contact, back }) {
  const isShooting = mode === "shooting";
  return <div className="detailPage"><div className="detailHeader"><div><div className="brand">PRIME DEFENSE PROTECTION MEMBER</div><h1 className="detailTitle">Emergency Mode</h1><p className="detailSubtitle">{isShooting ? "Defensive shooting guidance" : "No shots fired reporting guidance"}</p></div><button className="exitBtn" onClick={back}>Exit</button></div><section className="statusBanner"><div className="stepLabel">STEP 1 — CALL 911</div>{isShooting ? <><div className="scriptPrimary">“I was attacked, feared for my life, and had to defend myself. Please send both police and an ambulance to this location.”</div><div className="scriptSecondary">Secondary: “There has been a self-defense shooting at this location. Send help.”</div></> : <><div className="scriptPrimary">“My name is [name], and I need to report an attack or possible attack at this location.”</div><div className="scriptSecondary">“I have a permit to carry and exposed my firearm, but no shots were fired.”</div><div className="scriptSecondary">“The person was [description] and left the area.”</div></>}<button className="call911Btn" onClick={() => (window.location.href = "tel:911")}>CALL 911</button></section><section className="stepBlock"><div className="stepLabel">STEP 2 — CALL USCCA</div><p>Contact the USCCA Critical Response Team after calling 911.</p><button className="callBtn" onClick={() => (window.location.href = `tel:${USCCA_PHONE}`)}>CALL USCCA ({USCCA_DISPLAY})</button></section>{isShooting && <section className="stepBlock"><div className="stepLabel">STEP 3 — CONTACT FAMILY</div>{contact.name || contact.phone ? <div className="savedContactBox"><div className="sourceNote">Saved Emergency Contact</div><div className="savedName">{contact.name || "Emergency Contact"}</div><p>{contact.phone || "No phone saved"}</p>{contact.phone && <button className="callBtn" onClick={() => (window.location.href = `tel:${contact.phone.replace(/[^0-9+]/g, "")}`)}>CALL {contact.name || "CONTACT"}</button>}</div> : <div className="warning">No emergency contact saved. Exit Emergency Mode and add one from the dashboard.</div>}<div className="scriptFamily">“I’ve been involved in a defensive incident. I’m safe. Do not discuss anything with anyone until I have legal guidance.”</div></section>}<div className="warning">Provide only necessary information. Follow dispatcher instructions. Detailed statements can be given later when appropriate.</div></div>;
}

function AftermathMode({ back }) {
  const cards = [["When Police Arrive", ["Keep your hands visible at all times.", "Follow all commands immediately.", "Do not make sudden movements.", "Expect to be treated as a potential threat until officers secure the scene."]], ["Initial Interaction", ["Keep statements brief and factual.", "Point out evidence or witnesses if necessary.", "Do not argue, debate, or try to explain everything on scene."]], ["Statement Control", ["You may be under extreme stress and adrenaline.", "Avoid detailed explanations immediately after the event.", "Do not speculate, guess, or fill silence with extra details.", "Detailed statements can be provided later when appropriate and after legal guidance."]], ["What Not To Do", ["Do not make sudden movements toward your firearm or pockets.", "Do not handle evidence unless instructed.", "Do not discuss details with bystanders, media, or uninvolved parties.", "Do not post about the incident online."]]];
  return <div className="detailPage"><div className="detailHeader"><div><div className="brand">PRIME DEFENSE PROTECTION MEMBER</div><h1 className="detailTitle">Aftermath Mode</h1><p className="detailSubtitle">Guidance for immediately after law enforcement arrives.</p></div><button className="exitBtn" onClick={back}>Exit</button></div>{cards.map(([title, items], i) => <section key={title} className={i === 0 ? "statusBanner" : "stepBlock"}><div className="stepLabel">{title.toUpperCase()}</div><ul>{items.map(x => <li key={x}>{x}</li>)}</ul></section>)}<section className="stepBlock"><div className="stepLabel">MENTAL STATE REMINDER</div><div className="scriptFamily">You may not remember everything clearly right now. That is normal.</div></section><div className="warning">This guidance is educational only and is not legal advice. Follow lawful commands and consult legal counsel for direction.</div></div>;
}

function InfoCard({ title, tag, text }) {
  return <div className="infoCard"><div className="infoTop"><strong>{title}</strong><span className="tag">{tag}</span></div><p>{text}</p></div>;
}

createRoot(document.getElementById("root")).render(<App />);
