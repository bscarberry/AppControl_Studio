import { Router, Request, Response } from "express";
import { z } from "zod";
import { parseWdacXml } from "../services/xml-parser.js";
import { generateWdacXml } from "../services/xml-generator.js";
import { comparePolicies } from "../services/policy-comparator.js";
import { explainPolicy } from "../services/policy-explainer.js";
import { buildPolicyFromEvents } from "../services/policy-builder.js";
import { proposeRules } from "../services/rule-engine.js";
import { POLICY_RULE_OPTIONS } from "@appcontrol/shared";
import type { ParsedCiEvent } from "@appcontrol/shared";

export const policyRouter = Router();

// ---------------------------------------------------------------------------
// Parse XML -> Policy model
// ---------------------------------------------------------------------------
policyRouter.post("/parse", (req: Request, res: Response) => {
  const schema = z.object({
    xml: z.string().min(1),
    fileName: z.string().optional(),
  });

  const parsed = schema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ ok: false, error: { code: "VALIDATION", message: parsed.error.message } });
    return;
  }

  try {
    const result = parseWdacXml(parsed.data.xml, parsed.data.fileName);
    res.json({ ok: true, data: result });
  } catch (err) {
    res.status(422).json({
      ok: false,
      error: { code: "PARSE_ERROR", message: (err as Error).message },
    });
  }
});

// ---------------------------------------------------------------------------
// Generate XML from Policy model
// ---------------------------------------------------------------------------
policyRouter.post("/generate", (req: Request, res: Response) => {
  try {
    const policy = req.body.policy;
    if (!policy) {
      res.status(400).json({ ok: false, error: { code: "VALIDATION", message: "policy is required" } });
      return;
    }
    const xml = generateWdacXml(policy);
    res.json({
      ok: true,
      data: { xml, xmlSizeBytes: Buffer.byteLength(xml, "utf8") },
    });
  } catch (err) {
    res.status(422).json({
      ok: false,
      error: { code: "GENERATE_ERROR", message: (err as Error).message },
    });
  }
});

// ---------------------------------------------------------------------------
// Compare two policies
// ---------------------------------------------------------------------------
policyRouter.post("/compare", (req: Request, res: Response) => {
  const schema = z.object({
    leftXml: z.string().min(1),
    rightXml: z.string().min(1),
  });

  const parsed = schema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ ok: false, error: { code: "VALIDATION", message: parsed.error.message } });
    return;
  }

  try {
    const left = parseWdacXml(parsed.data.leftXml, "left");
    const right = parseWdacXml(parsed.data.rightXml, "right");
    const comparison = comparePolicies(left.policy, right.policy);
    res.json({ ok: true, data: { comparison } });
  } catch (err) {
    res.status(422).json({
      ok: false,
      error: { code: "COMPARE_ERROR", message: (err as Error).message },
    });
  }
});

// ---------------------------------------------------------------------------
// Explain a policy in human-readable terms
// ---------------------------------------------------------------------------
policyRouter.post("/explain", (req: Request, res: Response) => {
  try {
    const policy = req.body.policy;
    if (!policy) {
      res.status(400).json({ ok: false, error: { code: "VALIDATION", message: "policy is required" } });
      return;
    }
    const explanation = explainPolicy(policy);
    res.json({ ok: true, data: explanation });
  } catch (err) {
    res.status(422).json({
      ok: false,
      error: { code: "EXPLAIN_ERROR", message: (err as Error).message },
    });
  }
});

// ---------------------------------------------------------------------------
// Create policy from events
// ---------------------------------------------------------------------------
policyRouter.post("/from-events", (req: Request, res: Response) => {
  const schema = z.object({
    events: z.array(z.unknown()),
    template: z.enum(["default-windows", "allow-microsoft", "deny-by-default", "blank"]).optional(),
    policyName: z.string().min(1).max(256),
    preferPublisherRules: z.boolean().default(true),
    includePathRules: z.boolean().default(false),
    auditMode: z.boolean().default(true),
  });

  const parsed = schema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ ok: false, error: { code: "VALIDATION", message: parsed.error.message } });
    return;
  }

  try {
    const { policy, buildLog } = buildPolicyFromEvents(parsed.data as Parameters<typeof buildPolicyFromEvents>[0]);
    const xml = generateWdacXml(policy);
    res.json({
      ok: true,
      data: {
        policy,
        xml,
        ruleCount: policy.fileRules.length + policy.signers.length,
        buildLog,
      },
    });
  } catch (err) {
    res.status(422).json({
      ok: false,
      error: { code: "BUILD_ERROR", message: (err as Error).message },
    });
  }
});

// ---------------------------------------------------------------------------
// Rule generation engine: CI events → candidate WDAC rules
// ---------------------------------------------------------------------------
policyRouter.post("/propose-rules", (req: Request, res: Response) => {
  const schema = z.object({
    events: z.array(z.unknown()),
    preferSignerRules: z.boolean().default(true),
    scopeSignerRules: z.boolean().default(true),
    includePathRules: z.boolean().default(false),
    includeDenyRules: z.boolean().default(false),
  });

  const parsed = schema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ ok: false, error: { code: "VALIDATION", message: parsed.error.message } });
    return;
  }

  try {
    const changes = proposeRules({
      ...parsed.data,
      events: parsed.data.events as ParsedCiEvent[],
    });
    res.json({ ok: true, data: { changes } });
  } catch (err) {
    res.status(422).json({
      ok: false,
      error: { code: "RULE_ENGINE_ERROR", message: (err as Error).message },
    });
  }
});

// ---------------------------------------------------------------------------
// Get all policy rule options
// ---------------------------------------------------------------------------
policyRouter.get("/options", (_req: Request, res: Response) => {
  const options = Object.entries(POLICY_RULE_OPTIONS).map(([value, def]) => ({
    value: parseInt(value, 10),
    name: def.name,
    description: def.description,
    critical: "critical" in def ? Boolean(def.critical) : false,
  }));
  res.json({ ok: true, data: { options } });
});
