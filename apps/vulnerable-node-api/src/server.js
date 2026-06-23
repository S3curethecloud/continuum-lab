const express = require("express");
const searchRouter = require("./routes/search");

const app = express();
const port = process.env.PORT || 3000;

app.use(express.json());

app.get("/health", (_req, res) => {
  res.json({
    status: "ok",
    service: "customer-api",
    lab: "continuum-lab",
    external_targeting: false
  });
});

app.use("/api", searchRouter);

app.listen(port, "0.0.0.0", () => {
  console.log(`Continuum Lab vulnerable-node-api listening on port ${port}`);
});
