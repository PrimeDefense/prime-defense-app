import React, { useEffect, useMemo, useState } from "react";

const API_BASE = "http://localhost:4000";
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
  return {
    "Content-Type": "application/json",
    ...(token ? { Authorization: `Bearer ${token}` } : {})
  };
}

async function apiRequest(path, options = {}) {
  const response = await fetch(`${API_BASE}${path}`, options);
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

export default function App() {
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
        setPermitForm({
          permitState: profile.permitState || "MI",
          issueDate: profile.issueDate || "",
          expirationDate: profile.expirationDate || ""
        });
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
      const data = await apiRequest("/api/member/permit", {
        method: "PUT",
        headers: apiHeaders(token),
        body: JSON.stringify(permitForm)
      });
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
    <div style={styles.page}>
      <main style={styles.shell}>
        <section style={styles.hero}>
          <div style={styles.heroTop}>
            <div>
              <div style={styles.brand}>PRIME DEFENSE TRAINING</div>
              <h1 style={styles.title}>Prime Defense Protection Member</h1>
              <p style={styles.subtitle}>Premium member-only dashboard connected to your Stripe membership status.</p>
            </div>
            <div style={styles.badge}><span style={styles.dot}></span>{member.membershipLabel}</div>
          </div>
          <div style={styles.actions}>
            <button style={styles.dangerButton} onClick={() => setScreen("shooting")}>Emergency Mode: Shooting</button>
            <button style={styles.redButton} onClick={() => setScreen("no-shots")}>Emergency Mode: No Shots Fired</button>
            <button style={styles.darkButton} onClick={() => setScreen("aftermath")}>Aftermath Mode</button>
          </div>
        </section>

        <section style={styles.panel}>
          <div style={styles.panelHeader}>
            <div>
              <div style={styles.brand}>MEMBERSHIP STATUS</div>
              <h2 style={styles.h2}>{member.membershipLabel}</h2>
              <p style={styles.text}>Signed in as {member.email}. Stripe status last checked: {member.lastCheckedAt || "not checked"}</p>
            </div>
            <div>
              <button style={styles.darkButton} onClick={refreshMembershipStatus}>Refresh Status</button>
              <button style={styles.darkButton} onClick={openBillingPortal}>Manage Billing</button>
              <button style={styles.darkButton} onClick={logout}>Logout</button>
            </div>
          </div>
          {error && <div style={styles.warning}>{error}</div>}
          {success && <div style={styles.success}>{success}</div>}
        </section>

        <section style={styles.panel}>
          <div style={styles.panelHeader}>
            <div>
              <div style={styles.brand}>MY PERMIT</div>
              <h2 style={styles.h2}>Permit Profile</h2>
              <p style={styles.text}>Save your permit state, issue date, and expiration date so the app can show renewal status.</p>
            </div>
            <PermitStatusBadge status={permitStatus} />
          </div>

          <form style={styles.formGrid} onSubmit={savePermitProfile}>
            <label style={styles.fieldLabel}>Permit State
              <select style={styles.input} value={permitForm.permitState} onChange={(e) => setPermitForm({ ...permitForm, permitState: e.target.value })}>
                {STATE_OPTIONS.map(([abbr, name]) => <option key={abbr} value={abbr}>{name}</option>)}
              </select>
            </label>
            <label style={styles.fieldLabel}>Issue Date
              <input style={styles.input} type="date" value={permitForm.issueDate} onChange={(e) => setPermitForm({ ...permitForm, issueDate: e.target.value })} />
            </label>
            <label style={styles.fieldLabel}>Expiration Date
              <input style={styles.input} type="date" value={permitForm.expirationDate} onChange={(e) => setPermitForm({ ...permitForm, expirationDate: e.target.value })} />
            </label>
            <div style={styles.permitActionBox}>
              <button style={styles.redButton} type="submit" disabled={loading}>{loading ? "Saving..." : "Save Permit"}</button>
            </div>
          </form>

          <div style={styles.permitSummary}>
            <strong>{permitStatus?.label || "Permit Info Needed"}</strong>
            <p style={styles.text}>{permitStatus?.message || "Add permit details to calculate status."}</p>
            {typeof permitStatus?.daysRemaining === "number" && <div style={styles.sourceNote}>Days remaining: {permitStatus.daysRemaining}</div>}
            <div style={styles.sourceNote}>For Michigan renewals, members should track the 6-month renewal window before expiration.</div>
          </div>
        </section>

        <section style={styles.panel}>
          <div style={styles.panelHeader}>
            <div>
              <div style={styles.brand}>MEMBER LEGAL INTELLIGENCE</div>
              <h2 style={styles.h2}>Legal Updates</h2>
              <p style={styles.text}>Michigan-focused updates and member alerts. National carry details stay inside each state page.</p>
            </div>
            <span style={styles.smallPill}>Michigan Focus</span>
          </div>
          <InfoCard title="Michigan CPL & Firearm Law Monitoring" tag="Member Alert" text="Updates affecting Michigan CPL holders, storage, prohibited locations, use-of-force education, and renewal rules will appear here after review." />
          <InfoCard title="Training Reminder" tag="Education" text="Legal updates are paired with practical reminders so members understand what changed and what it means in real life." />
        </section>

        <section style={styles.panel}>
          <div style={styles.panelHeader}>
            <div>
              <div style={styles.brand}>RECIPROCITY GUIDE</div>
              <h2 style={styles.h2}>State-by-State Carry Guide</h2>
              <p style={styles.text}>State list is loaded from the protected backend API.</p>
            </div>
            <span style={styles.smallPill}>Members Only</span>
          </div>
          <input style={styles.input} placeholder="Search state..." value={search} onChange={(e) => setSearch(e.target.value)} />
          <div style={styles.mapBox}>
            <h3 style={styles.mapTitle}>Clickable State Grid</h3>
            <div style={styles.stateGrid}>{filteredStates.map((state) => <button key={state.abbr} style={styles.stateButton} onClick={() => openState(state)}>{state.abbr}</button>)}</div>
          </div>
        </section>

        <section style={styles.panel}>
          <div style={styles.brand}>EMERGENCY CONTACT</div>
          <h2 style={styles.h2}>Family / Trusted Contact</h2>
          <p style={styles.text}>This contact appears only in the shooting scenario under “Contact Family.”</p>
          <div style={styles.inputGrid}>
            <input style={styles.input} placeholder="Contact name" value={emergencyContact.name} onChange={(e) => setEmergencyContact({ ...emergencyContact, name: e.target.value })} />
            <input style={styles.input} placeholder="Phone number" value={emergencyContact.phone} onChange={(e) => setEmergencyContact({ ...emergencyContact, phone: e.target.value })} />
          </div>
        </section>
      </main>
    </div>
  );
}

function PermitStatusBadge({ status }) {
  const label = status?.label || "Permit Info Needed";
  let style = styles.permitBadgeNeutral;
  if (status?.status === "active") style = styles.permitBadgeGreen;
  if (status?.status === "renewal_window") style = styles.permitBadgeYellow;
  if (status?.status === "expired") style = styles.permitBadgeRed;
  return <span style={style}>{label}</span>;
}

function AuthScreen({ authMode, setAuthMode, form, setForm, error, loading, onSubmit }) {
  return <div style={styles.detailPage}><div style={styles.authShell}><div style={styles.brand}>PRIME DEFENSE TRAINING</div><h1 style={styles.detailTitle}>Member Login</h1><p style={styles.detailSubtitle}>Use the same email address used for your PDPP / Stripe membership.</p><form style={styles.authCard} onSubmit={onSubmit}><div style={styles.authTabs}><button type="button" style={authMode === "login" ? styles.authTabActive : styles.authTab} onClick={() => setAuthMode("login")}>Login</button><button type="button" style={authMode === "register" ? styles.authTabActive : styles.authTab} onClick={() => setAuthMode("register")}>Register</button></div>{authMode === "register" && <input style={styles.input} placeholder="Full name" value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} />}<input style={styles.input} type="email" placeholder="Membership email" value={form.email} onChange={(e) => setForm({ ...form, email: e.target.value })} required /><input style={styles.input} type="password" placeholder="Password" value={form.password} onChange={(e) => setForm({ ...form, password: e.target.value })} required />{error && <div style={styles.warning}>{error}</div>}<button style={styles.callBtn} type="submit" disabled={loading}>{loading ? "Checking..." : "Continue"}</button></form></div></div>;
}

function LockedScreen({ member, display, error, loading, refreshMembershipStatus, openBillingPortal, logout }) {
  return <div style={styles.detailPage}><div style={styles.authShell}><div style={styles.brand}>MEMBERSHIP REQUIRED</div><h1 style={styles.detailTitle}>Access Locked</h1><p style={styles.detailSubtitle}>{display.message}</p><section style={styles.statusBanner}><div style={styles.stepLabel}>CURRENT STATUS</div><h2 style={styles.statusTitle}>{member.membershipLabel}</h2><p style={styles.text}>Signed in as {member.email}</p></section>{error && <div style={styles.warning}>{error}</div>}<button style={styles.callBtn} onClick={refreshMembershipStatus} disabled={loading}>Refresh Membership Status</button><button style={styles.redButton} onClick={openBillingPortal}>Update Billing</button><button style={styles.darkButton} onClick={logout}>Logout</button></div></div>;
}

function StatePage({ state, stateData, error, back }) {
  const categories = stateData?.categories || {};
  const rows = Object.entries(categories).length ? Object.entries(categories) : [["loading", { answer: "Loading...", details: "Loading state law data from backend." }]];
  return <div style={styles.detailPage}><div style={styles.detailHeader}><div><div style={styles.brand}>RECIPROCITY GUIDE</div><h1 style={styles.detailTitle}>{state?.name || stateData?.name || "State"}</h1><p style={styles.detailSubtitle}>State carry guide for Prime Defense Protection Members.</p></div><button style={styles.exitBtn} onClick={back}>Back</button></div><section style={styles.statusBanner}><div style={styles.stepLabel}>STATUS</div><h2 style={styles.statusTitle}>{stateData?.status || "Loading"}</h2><p style={styles.text}>Sync status: {stateData?.syncStatus || "loading"}</p><div style={styles.sourceNote}>Last synced: {stateData?.lastSynced || "pending"}</div></section>{error && <div style={styles.warning}>{error}</div>}<section style={styles.detailGrid}>{rows.map(([key, item]) => <div key={key} style={styles.detailCard}><div style={styles.stepLabel}>{key.replace(/([A-Z])/g, " $1").toUpperCase()}</div><h3 style={styles.factAnswer}>{item.answer}</h3><p style={styles.text}>{item.details}</p><div style={styles.sourceNote}>Source: {item.sourceName || "pending"}</div></div>)}</section><div style={styles.warning}>Educational information only. Not legal advice. Always verify current law before traveling or carrying outside Michigan.</div></div>;
}

function EmergencyMode({ mode, contact, back }) {
  const isShooting = mode === "shooting";
  return <div style={styles.detailPage}><div style={styles.detailHeader}><div><div style={styles.brand}>PRIME DEFENSE PROTECTION MEMBER</div><h1 style={styles.detailTitle}>Emergency Mode</h1><p style={styles.detailSubtitle}>{isShooting ? "Defensive shooting guidance" : "No shots fired reporting guidance"}</p></div><button style={styles.exitBtn} onClick={back}>Exit</button></div><section style={styles.statusBanner}><div style={styles.stepLabel}>STEP 1 — CALL 911</div>{isShooting ? <><div style={styles.scriptPrimary}>“I was attacked, feared for my life, and had to defend myself. Please send both police and an ambulance to this location.”</div><div style={styles.scriptSecondary}>Secondary: “There has been a self-defense shooting at this location. Send help.”</div></> : <><div style={styles.scriptPrimary}>“My name is [name], and I need to report an attack or possible attack at this location.”</div><div style={styles.scriptSecondary}>“I have a permit to carry and exposed my firearm, but no shots were fired.”</div><div style={styles.scriptSecondary}>“The person was [description] and left the area.”</div></>}<button style={styles.call911Btn} onClick={() => (window.location.href = "tel:911")}>CALL 911</button></section><section style={styles.stepBlock}><div style={styles.stepLabel}>STEP 2 — CALL USCCA</div><p style={styles.text}>Contact the USCCA Critical Response Team after calling 911.</p><button style={styles.callBtn} onClick={() => (window.location.href = `tel:${USCCA_PHONE}`)}>CALL USCCA ({USCCA_DISPLAY})</button></section>{isShooting && <section style={styles.stepBlock}><div style={styles.stepLabel}>STEP 3 — CONTACT FAMILY</div>{contact.name || contact.phone ? <div style={styles.savedContactBox}><div style={styles.sourceNote}>Saved Emergency Contact</div><div style={styles.savedName}>{contact.name || "Emergency Contact"}</div><div style={styles.text}>{contact.phone || "No phone saved"}</div>{contact.phone && <button style={styles.callBtn} onClick={() => (window.location.href = `tel:${contact.phone.replace(/[^0-9+]/g, "")}`)}>CALL {contact.name || "CONTACT"}</button>}</div> : <div style={styles.warning}>No emergency contact saved. Exit Emergency Mode and add one from the dashboard.</div>}<div style={styles.scriptFamily}>“I’ve been involved in a defensive incident. I’m safe. Do not discuss anything with anyone until I have legal guidance.”</div></section>}<div style={styles.warning}>Provide only necessary information. Follow dispatcher instructions. Detailed statements can be given later when appropriate.</div></div>;
}

function AftermathMode({ back }) {
  const cards = [["When Police Arrive", ["Keep your hands visible at all times.", "Follow all commands immediately.", "Do not make sudden movements.", "Expect to be treated as a potential threat until officers secure the scene."]], ["Initial Interaction", ["Keep statements brief and factual.", "Point out evidence or witnesses if necessary.", "Do not argue, debate, or try to explain everything on scene."]], ["Statement Control", ["You may be under extreme stress and adrenaline.", "Avoid detailed explanations immediately after the event.", "Do not speculate, guess, or fill silence with extra details.", "Detailed statements can be provided later when appropriate and after legal guidance."]], ["What Not To Do", ["Do not make sudden movements toward your firearm or pockets.", "Do not handle evidence unless instructed.", "Do not discuss details with bystanders, media, or uninvolved parties.", "Do not post about the incident online."]]];
  return <div style={styles.detailPage}><div style={styles.detailHeader}><div><div style={styles.brand}>PRIME DEFENSE PROTECTION MEMBER</div><h1 style={styles.detailTitle}>Aftermath Mode</h1><p style={styles.detailSubtitle}>Guidance for immediately after law enforcement arrives.</p></div><button style={styles.exitBtn} onClick={back}>Exit</button></div>{cards.map(([title, items], i) => <section key={title} style={i === 0 ? styles.statusBanner : styles.stepBlock}><div style={styles.stepLabel}>{title.toUpperCase()}</div><ul style={styles.list}>{items.map(x => <li key={x}>{x}</li>)}</ul></section>)}<section style={styles.stepBlock}><div style={styles.stepLabel}>MENTAL STATE REMINDER</div><div style={styles.scriptFamily}>You may not remember everything clearly right now. That is normal.</div></section><div style={styles.warning}>This guidance is educational only and is not legal advice. Follow lawful commands and consult legal counsel for direction.</div></div>;
}

function InfoCard({ title, tag, text }) { return <div style={styles.infoCard}><div style={styles.infoTop}><strong>{title}</strong><span style={styles.tag}>{tag}</span></div><p style={styles.text}>{text}</p></div>; }

const styles = {
  page: { minHeight: "100vh", background: "radial-gradient(circle at top left, #3a0b0f 0, #111 34%, #050505 100%)", color: "#fff", fontFamily: "Arial, Helvetica, sans-serif" }, shell: { maxWidth: 1100, margin: "0 auto", padding: 22 }, hero: { background: "linear-gradient(135deg, rgba(26,26,26,.98), rgba(8,8,8,.98))", border: "1px solid rgba(255,255,255,.09)", padding: 28, borderRadius: 28, boxShadow: "0 24px 70px rgba(0,0,0,.55)" }, heroTop: { display: "flex", justifyContent: "space-between", alignItems: "flex-start", flexWrap: "wrap", gap: 20 }, brand: { color: "#ef233c", fontWeight: 900, letterSpacing: 3, fontSize: 12 }, title: { fontSize: "clamp(34px, 5vw, 56px)", lineHeight: ".95", margin: "12px 0" }, subtitle: { color: "#d0d0d0", maxWidth: 760, fontSize: 17, lineHeight: 1.6 }, badge: { background: "rgba(34,197,94,.13)", border: "1px solid rgba(34,197,94,.35)", color: "#8cffb0", borderRadius: 999, padding: "12px 16px", fontWeight: 900 }, dot: { display: "inline-block", width: 9, height: 9, background: "#22c55e", borderRadius: "50%", marginRight: 8 }, actions: { display: "flex", flexWrap: "wrap", gap: 12, marginTop: 26 }, dangerButton: { border: "none", borderRadius: 16, background: "#b00020", color: "white", padding: "16px 20px", fontSize: 16, fontWeight: 900, cursor: "pointer" }, redButton: { border: "none", borderRadius: 16, background: "#ef233c", color: "white", padding: "16px 20px", fontSize: 16, fontWeight: 900, cursor: "pointer", marginRight: 10, marginTop: 10 }, darkButton: { border: "1px solid rgba(255,255,255,.16)", borderRadius: 16, background: "#161616", color: "white", padding: "16px 20px", fontSize: 16, fontWeight: 900, cursor: "pointer", marginRight: 10, marginTop: 10 }, panel: { marginTop: 18, background: "rgba(16,16,16,.96)", border: "1px solid rgba(255,255,255,.09)", padding: 24, borderRadius: 24, boxShadow: "0 18px 50px rgba(0,0,0,.35)" }, panelHeader: { display: "flex", justifyContent: "space-between", alignItems: "flex-start", gap: 16, flexWrap: "wrap" }, h2: { margin: "8px 0", fontSize: 26 }, text: { color: "#cfcfcf", lineHeight: 1.55, marginTop: 0 }, smallPill: { background: "rgba(239,35,60,.12)", border: "1px solid rgba(239,35,60,.28)", color: "#ffd0d6", borderRadius: 999, padding: "9px 12px", fontSize: 12, fontWeight: 900 }, infoCard: { marginTop: 14, background: "rgba(0,0,0,.28)", border: "1px solid rgba(255,255,255,.08)", borderRadius: 18, padding: 16 }, infoTop: { display: "flex", justifyContent: "space-between", gap: 12, alignItems: "center", flexWrap: "wrap" }, tag: { background: "rgba(239,35,60,.14)", color: "#ffb8c0", border: "1px solid rgba(239,35,60,.25)", borderRadius: 999, padding: "6px 10px", fontSize: 12, fontWeight: 800 }, input: { width: "100%", boxSizing: "border-box", padding: 15, borderRadius: 16, border: "1px solid rgba(255,255,255,.14)", background: "#080808", color: "#fff", fontSize: 16, marginTop: 10 }, inputGrid: { display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(220px, 1fr))", gap: 12, marginTop: 16 }, formGrid: { display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(220px, 1fr))", gap: 14, marginTop: 16, alignItems: "end" }, fieldLabel: { color: "#cfcfcf", fontWeight: 800, fontSize: 14 }, permitActionBox: { display: "flex", alignItems: "end" }, permitSummary: { marginTop: 16, background: "rgba(0,0,0,.28)", border: "1px solid rgba(255,255,255,.08)", borderRadius: 18, padding: 16 }, permitBadgeNeutral: { background: "rgba(255,255,255,.08)", border: "1px solid rgba(255,255,255,.12)", color: "#fff", borderRadius: 999, padding: "9px 12px", fontSize: 12, fontWeight: 900 }, permitBadgeGreen: { background: "rgba(34,197,94,.14)", border: "1px solid rgba(34,197,94,.35)", color: "#8cffb0", borderRadius: 999, padding: "9px 12px", fontSize: 12, fontWeight: 900 }, permitBadgeYellow: { background: "rgba(245,158,11,.14)", border: "1px solid rgba(245,158,11,.35)", color: "#ffe7b3", borderRadius: 999, padding: "9px 12px", fontSize: 12, fontWeight: 900 }, permitBadgeRed: { background: "rgba(239,35,60,.14)", border: "1px solid rgba(239,35,60,.35)", color: "#ffb8c0", borderRadius: 999, padding: "9px 12px", fontSize: 12, fontWeight: 900 }, success: { maxWidth: 980, margin: "12px 0 0", padding: 16, background: "rgba(34,197,94,.12)", border: "1px solid rgba(34,197,94,.25)", borderRadius: 18, color: "#8cffb0", lineHeight: 1.5, fontSize: 14 }, mapBox: { marginTop: 16, background: "radial-gradient(circle at top, rgba(239,35,60,.16), rgba(0,0,0,.35))", border: "1px solid rgba(255,255,255,.08)", borderRadius: 22, padding: 20 }, mapTitle: { fontSize: 24, fontWeight: 900, margin: "0 0 8px" }, stateGrid: { display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(58px, 1fr))", gap: 10, marginTop: 16 }, stateButton: { border: "1px solid rgba(255,255,255,.12)", borderRadius: 14, background: "#090909", color: "white", padding: "14px 10px", fontWeight: 900, cursor: "pointer" }, detailPage: { minHeight: "100vh", padding: 20, background: "radial-gradient(circle at top, #32070b 0, #050505 42%, #000 100%)", color: "#fff", fontFamily: "Arial, Helvetica, sans-serif" }, detailHeader: { display: "flex", justifyContent: "space-between", alignItems: "flex-start", gap: 16, flexWrap: "wrap", maxWidth: 980, margin: "0 auto 18px" }, detailTitle: { color: "#fff", fontSize: "clamp(40px, 8vw, 72px)", lineHeight: ".9", margin: "8px 0" }, detailSubtitle: { color: "#d0d0d0", margin: 0, fontSize: 16 }, exitBtn: { background: "#262626", color: "#fff", border: "1px solid rgba(255,255,255,.14)", padding: "12px 16px", borderRadius: 14, fontWeight: 800, cursor: "pointer" }, statusBanner: { maxWidth: 980, margin: "0 auto 16px", padding: 22, background: "rgba(176,0,32,.22)", border: "1px solid rgba(239,35,60,.45)", borderRadius: 24, boxShadow: "0 18px 50px rgba(0,0,0,.45)" }, stepBlock: { maxWidth: 980, margin: "0 auto 16px", padding: 22, background: "rgba(16,16,16,.96)", border: "1px solid rgba(255,255,255,.09)", borderRadius: 24, boxShadow: "0 18px 50px rgba(0,0,0,.4)" }, stepLabel: { color: "#ef233c", fontWeight: 900, letterSpacing: 2, fontSize: 12, marginBottom: 12 }, statusTitle: { fontSize: "clamp(24px, 4vw, 36px)", margin: "0 0 8px" }, sourceNote: { marginTop: 12, paddingTop: 10, borderTop: "1px solid rgba(255,255,255,.08)", color: "#9ca3af", fontSize: 12, lineHeight: 1.4 }, detailGrid: { maxWidth: 980, margin: "0 auto 16px", display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(260px, 1fr))", gap: 14 }, detailCard: { background: "rgba(16,16,16,.96)", border: "1px solid rgba(255,255,255,.09)", borderRadius: 22, padding: 20, boxShadow: "0 14px 40px rgba(0,0,0,.35)", minHeight: 210 }, factAnswer: { fontSize: 20, lineHeight: 1.25, margin: "0 0 10px", color: "#fff" }, warning: { maxWidth: 980, margin: "0 auto 16px", padding: 16, background: "rgba(245,158,11,.12)", border: "1px solid rgba(245,158,11,.25)", borderRadius: 18, color: "#ffe7b3", lineHeight: 1.5, fontSize: 14 }, scriptPrimary: { fontSize: "clamp(24px, 5vw, 38px)", lineHeight: 1.15, fontWeight: 900, marginBottom: 14 }, scriptSecondary: { fontSize: "clamp(17px, 3vw, 22px)", color: "#f1f1f1", lineHeight: 1.35, marginBottom: 10, background: "rgba(0,0,0,.22)", border: "1px solid rgba(255,255,255,.08)", borderRadius: 16, padding: 14 }, scriptFamily: { fontSize: "clamp(20px, 4vw, 30px)", lineHeight: 1.2, fontWeight: 900, marginTop: 16 }, call911Btn: { marginTop: 12, width: "100%", background: "#ef233c", color: "#fff", padding: 20, border: "none", borderRadius: 18, fontWeight: 900, fontSize: 22, cursor: "pointer" }, callBtn: { marginTop: 10, width: "100%", background: "#ef233c", color: "#fff", padding: 18, border: "none", borderRadius: 18, fontWeight: 900, fontSize: 18, cursor: "pointer" }, savedContactBox: { background: "rgba(239,35,60,.11)", border: "1px solid rgba(239,35,60,.25)", borderRadius: 18, padding: 16, marginBottom: 16 }, savedName: { fontSize: 24, fontWeight: 900 }, list: { margin: 0, paddingLeft: 20, lineHeight: 1.7, color: "#e5e5e5", fontSize: 16 }, authShell: { maxWidth: 760, margin: "0 auto", padding: "28px 0" }, authCard: { marginTop: 22, background: "rgba(16,16,16,.96)", border: "1px solid rgba(255,255,255,.09)", padding: 24, borderRadius: 24, boxShadow: "0 18px 50px rgba(0,0,0,.4)", display: "grid", gap: 14 }, authTabs: { display: "grid", gridTemplateColumns: "1fr 1fr", gap: 10 }, authTab: { border: "1px solid rgba(255,255,255,.12)", borderRadius: 14, background: "#111", color: "#ccc", padding: 13, fontWeight: 900, cursor: "pointer" }, authTabActive: { border: "1px solid rgba(239,35,60,.45)", borderRadius: 14, background: "rgba(239,35,60,.18)", color: "#fff", padding: 13, fontWeight: 900, cursor: "pointer" }
};
