// === KEEP YOUR EXISTING IMPORTS & BACKEND (DO NOT CHANGE ABOVE YOUR HTML) ===

// ONLY replace your HTML section with this ↓↓↓

const html = `
<!DOCTYPE html>
<html>
<head>
<title>Prime Defense Protection</title>
<meta name="viewport" content="width=device-width, initial-scale=1.0">

<style>
body{
margin:0;
font-family:Arial;
background:#0b0b0b;
color:white;
}

/* HEADER */
.topbar{
display:flex;
justify-content:space-between;
align-items:center;
padding:15px;
background:#111;
border-bottom:1px solid #222;
}

.brand{
color:#ff2a2a;
font-weight:900;
letter-spacing:2px;
}

/* DASHBOARD */
.container{
max-width:900px;
margin:20px auto;
padding:20px;
}

.card{
background:#111;
padding:20px;
border-radius:12px;
margin-bottom:15px;
}

/* BUTTONS */
button{
padding:12px;
border:none;
border-radius:8px;
cursor:pointer;
font-weight:bold;
}

.primary{background:#ff2a2a;color:white;width:100%}
.secondary{background:#222;color:white}

/* EMERGENCY BUTTON */
.emergencyBtn{
position:fixed;
bottom:20px;
right:20px;
background:red;
color:white;
font-size:18px;
padding:20px;
border-radius:50%;
box-shadow:0 0 20px red;
}

/* FULL SCREEN EMERGENCY */
.emergencyScreen{
position:fixed;
top:0;
left:0;
width:100%;
height:100%;
background:black;
z-index:9999;
padding:20px;
overflow:auto;
}

.emergencyTitle{
color:red;
font-size:28px;
font-weight:900;
margin-bottom:20px;
}

.bigBtn{
width:100%;
margin:10px 0;
padding:20px;
font-size:18px;
}

/* INPUT */
input,select{
width:100%;
padding:12px;
margin:5px 0;
border-radius:8px;
border:none;
background:#222;
color:white;
}
</style>
</head>

<body>

<div id="app"></div>

<script>

var token = localStorage.getItem("pd_token");

/* ================= STATES ================= */

var states = [
"AL","AK","AZ","AR","CA","CO","CT","DE","FL","GA",
"HI","ID","IL","IN","IA","KS","KY","LA","ME","MD",
"MA","MI","MN","MS","MO","MT","NE","NV","NH","NJ",
"NM","NY","NC","ND","OH","OK","OR","PA","RI","SC",
"SD","TN","TX","UT","VT","VA","WA","WV","WI","WY"
];

/* SIMPLE reciprocity demo (we will upgrade later) */
function getReciprocity(state){
if(state==="MI") return "Recognized in ~39 states";
if(state==="FL") return "Recognized in ~37 states";
if(state==="TX") return "Recognized in ~36 states";
return "Varies by state — verify before travel";
}

/* ================= UI ================= */

function dashboard(user){

document.getElementById("app").innerHTML = \`
<div class="topbar">
<div class="brand">PRIME DEFENSE PROTECTION</div>
<button onclick="logout()">Logout</button>
</div>

<div class="container">

<div class="card">
<h2>Permit Profile</h2>

<select id="state"></select>
<input id="issue" placeholder="Issue Date">
<input id="exp" placeholder="Expiration Date">

<div id="reciprocity" style="margin-top:10px;color:#ccc;"></div>
</div>

<div class="card">
<h2>Emergency Contact</h2>
<input id="ename" placeholder="Name">
<input id="phone" placeholder="Phone">
</div>

<button class="primary" onclick="save()">Save Profile</button>

</div>

<button class="emergencyBtn" onclick="openEmergency()">911</button>
\`;

populateStates(user);
}

/* ================= STATES UI ================= */

function populateStates(user){

var select = document.getElementById("state");

states.forEach(s=>{
var opt = document.createElement("option");
opt.value = s;
opt.text = s;
select.appendChild(opt);
});

select.value = user.permitState || "MI";

updateReciprocity();

select.addEventListener("change", updateReciprocity);
}

function updateReciprocity(){
var state = document.getElementById("state").value;
document.getElementById("reciprocity").innerText = getReciprocity(state);
}

/* ================= SAVE ================= */

async function save(){
await fetch("/api/save-profile",{
method:"POST",
headers:{"Content-Type":"application/json"},
body:JSON.stringify({
token:token,
permitState:document.getElementById("state").value,
issueDate:document.getElementById("issue").value,
expirationDate:document.getElementById("exp").value,
emergencyName:document.getElementById("ename").value,
emergencyPhone:document.getElementById("phone").value
})
});
alert("Saved");
}

/* ================= EMERGENCY MODE ================= */

function openEmergency(){

document.body.innerHTML = \`
<div class="emergencyScreen">

<div class="emergencyTitle">EMERGENCY MODE</div>

<button class="bigBtn primary" onclick="call911()">CALL 911</button>

<button class="bigBtn secondary" onclick="callUSCCA()">CALL USCCA</button>

<button class="bigBtn secondary" onclick="callContact()">CALL EMERGENCY CONTACT</button>

<div style="margin-top:20px;">
<b>What to say:</b><br><br>
"I was attacked and feared for my life. Send police and medical."<br><br>

<b>Then STOP talking.</b>
</div>

<button class="bigBtn" onclick="location.reload()">EXIT</button>

</div>
\`;
}

function call911(){
window.location.href="tel:911";
}

function callUSCCA(){
window.location.href="tel:8006749779";
}

async function callContact(){
const res = await fetch("/api/get-profile",{
method:"POST",
headers:{"Content-Type":"application/json"},
body:JSON.stringify({token})
});
const user = await res.json();

if(user.emergencyPhone){
window.location.href="tel:"+user.emergencyPhone;
}else{
alert("No contact saved");
}
}

/* ================= AUTH ================= */

async function load(){

if(!token){
document.body.innerHTML = "<h2 style='padding:20px;'>Login required</h2>";
return;
}

const res = await fetch("/api/get-profile",{
method:"POST",
headers:{"Content-Type":"application/json"},
body:JSON.stringify({token})
});

const user = await res.json();

if(user.error){
localStorage.removeItem("pd_token");
location.reload();
return;
}

if(!user.accessAllowed){
document.body.innerHTML = "<h2 style='padding:20px;'>Membership required</h2>";
return;
}

dashboard(user);
}

function logout(){
localStorage.removeItem("pd_token");
location.reload();
}

load();

</script>
</body>
</html>
`;

// === DO NOT CHANGE BELOW ===
app.get("/", (req,res)=>res.send(html));
app.use((req,res)=>res.send(html));
