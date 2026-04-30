import express from "express";

const app = express();
const PORT = process.env.PORT || 4000;

const html = `
<!DOCTYPE html>
<html>
<head>
  <title>Prime Defense App</title>
</head>
<body style="background:black;color:white;font-family:sans-serif;text-align:center;padding-top:100px;">
  <h1>Prime Defense Protection</h1>
  <p>App is LIVE</p>
</body>
</html>
`;

app.get("/", (req, res) => {
  res.send(html);
});

app.use((req, res) => {
  res.send(html);
});

app.listen(PORT, () => {
  console.log("Server running on port " + PORT);
});
