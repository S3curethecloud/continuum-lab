const express = require("express");

const router = express.Router();

const customers = [
  {
    id: 1,
    name: "Ada Lovelace",
    email: "ada@example.test",
    tier: "gold"
  },
  {
    id: 2,
    name: "Grace Hopper",
    email: "grace@example.test",
    tier: "platinum"
  },
  {
    id: 3,
    name: "Katherine Johnson",
    email: "katherine@example.test",
    tier: "gold"
  }
];

/**
 * INTENTIONALLY VULNERABLE LAB CODE
 *
 * This route demonstrates unsafe SQL-style query construction for scanner,
 * reasoning, remediation, and evidence-generation workflows.
 *
 * Safety boundary:
 * - local lab only
 * - no real database
 * - no real customer data
 * - no real credentials
 * - no external targeting
 */
router.get("/customers/search", (req, res) => {
  const searchTerm = req.query.q || "";

  // FIND-001 target:
  // This is intentionally unsafe and should be replaced with parameterized query logic.
  const unsafeQuery = "SELECT id, name, email, tier FROM customers WHERE name LIKE '%" + searchTerm + "%'";

  const normalized = String(searchTerm).toLowerCase();
  const results = customers.filter((customer) => {
    return customer.name.toLowerCase().includes(normalized);
  });

  res.json({
    warning: "intentionally vulnerable lab route",
    safe_for: "local Continuum Lab only",
    external_targeting: false,
    query_preview: unsafeQuery,
    results
  });
});

module.exports = router;
