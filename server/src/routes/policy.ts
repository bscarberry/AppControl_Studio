import { Router, Request, Response } from "express";
import { z } from "zod";
import crypto from "crypto";
import { parseWdacXml } from "../services/xml-parser.js";
import { generateWdacXml } from "../services/xml-generator.js";
import { comparePolicies } from "../services/policy-comparator.js";
import { explainPolicy } from "../services/policy-explainer.js";
import { buildPolicyFromEvents } from "../services/policy-builder.js";
import { proposeRules } from "../services/rule-engine.js";
import { simulateBinary } from "../services/policy-simulator.js";
import { semanticComparePolicies } from "../services/semantic-comparator.js";
import { ingestAdvancedHunting } from "../services/advanced-hunting-ingestor.js";
import { mergePolicies } from "../services/policy-merger.js";
import { convertAppLockerToWdac } from "../services/applocker-converter.js";
import { validateXmlInput } from "../middleware/xml-validator.js";
import { getAuditLogger, hashInput } from "../services/audit-logger.js";
import { DEFAULT_CONFIG } from "../config/security-config.js";
import { POLICY_RULE_OPTIONS } from "@appcontrol/shared";
import type { ParsedCiEvent } from "@appcontrol/shared";

export const policyRouter = Router();

// Validation config reference — uses defaults; app.ts loads and applies full config
const valCfg = DEFAULT_CONFIG.validation;

// ---------------------------------------------------------------------------
// Helper — reject XML that fails security pre-checks
// ---------------------------------------------------------------------------

function rejectBadXml(xml: string, res: Response): boolean {
  const check = validateXmlInput(xml, valCfg);
  if (!check.valid) {
    getAuditLogger().log("VALIDATION_REJECTED", {
      succeeded: false,
      errorCode: check.code,
      errorMessage: check.error,
      inputSizeBytes: Buffer.byteLength(xml, "utf8"),
    });
    res.status(422).json({
      ok: false,
      error: { code: check.code ?? "XML_INVALID", message: check.error },
    });
    return true;
  }
  return false;
}

// ---------------------------------------------------------------------------
// Parse XML → Policy model
// ---------------------------------------------------------------------------

policyRouter.post("/parse", (req: Request, res: Response) => {
  const schema = z.object({ xml: z.string().min(1), fileName: z.string().optional() });
  const parsed = schema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ ok: false, error: { code: "VALIDATION", message: parsed.error.message } });
    return;
  }

  if (rejectBadXml(parsed.data.xml, res)) return;

  const start = Date.now();
  const logger = getAuditLogger();
  try {
    const result = parseWdacXml(parsed.data.xml, parsed.data.fileName);
    logger.log("POLICY_LOADED", {
      role: req.userRole,
      inputHash: hashInput(parsed.data.xml),
      inputSizeBytes: Buffer.byteLength(parsed.data.xml, "utf8"),
      outputSummary: `fileRules=${result.policy.fileRules.length} signers=${result.policy.signers.length} warnings=${result.diagnostics?.length ?? 0}`,
      durationMs: Date.now() - start,
      succeeded: true,
    });
    res.json({ ok: true, data: result });
  } catch (err) {
    logger.log("POLICY_LOADED", {
      role: req.userRole,
      inputHash: hashInput(parsed.data.xml),
      inputSizeBytes: Buffer.byteLength(parsed.data.xml, "utf8"),
      durationMs: Date.now() - start,
      succeeded: false,
      errorCode: "PARSE_ERROR",
      errorMessage: (err as Error).message,
    });
    res.status(422).json({ ok: false, error: { code: "PARSE_ERROR", message: (err as Error).message } });
  }
});

// ---------------------------------------------------------------------------
// Generate XML from Policy model
// ---------------------------------------------------------------------------

policyRouter.post("/generate", (req: Request, res: Response) => {
  const start = Date.now();
  const logger = getAuditLogger();
  try {
    const policy = req.body.policy;
    if (!policy) {
      res.status(400).json({ ok: false, error: { code: "VALIDATION", message: "policy is required" } });
      return;
    }
    const xml = generateWdacXml(policy);
    logger.log("POLICY_GENERATED", {
      role: req.userRole,
      outputSummary: `xmlBytes=${Buffer.byteLength(xml, "utf8")} policyId=${String(policy.policyId ?? "").substring(0, 8)}`,
      durationMs: Date.now() - start,
      succeeded: true,
    });
    res.json({ ok: true, data: { xml, xmlSizeBytes: Buffer.byteLength(xml, "utf8") } });
  } catch (err) {
    logger.log("POLICY_GENERATED", {
      role: req.userRole,
      durationMs: Date.now() - start,
      succeeded: false,
      errorCode: "GENERATE_ERROR",
      errorMessage: (err as Error).message,
    });
    res.status(422).json({ ok: false, error: { code: "GENERATE_ERROR", message: (err as Error).message } });
  }
});

// ---------------------------------------------------------------------------
// Compare two policies (structural)
// ---------------------------------------------------------------------------

policyRouter.post("/compare", (req: Request, res: Response) => {
  const schema = z.object({ leftXml: z.string().min(1), rightXml: z.string().min(1) });
  const parsed = schema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ ok: false, error: { code: "VALIDATION", message: parsed.error.message } });
    return;
  }
  if (rejectBadXml(parsed.data.leftXml, res) || rejectBadXml(parsed.data.rightXml, res)) return;

  const start = Date.now();
  const logger = getAuditLogger();
  try {
    const left = parseWdacXml(parsed.data.leftXml, "left");
    const right = parseWdacXml(parsed.data.rightXml, "right");
    const comparison = comparePolicies(left.policy, right.policy);
    logger.log("POLICY_COMPARED", {
      role: req.userRole,
      inputHash: hashInput(parsed.data.leftXml + "||" + parsed.data.rightXml),
      outputSummary: `added=${comparison.fileRuleDiffs.filter(c => c.status === "added").length} removed=${comparison.fileRuleDiffs.filter(c => c.status === "removed").length}`,
      durationMs: Date.now() - start,
      succeeded: true,
    });
    res.json({ ok: true, data: { comparison } });
  } catch (err) {
    logger.log("POLICY_COMPARED", {
      role: req.userRole,
      durationMs: Date.now() - start,
      succeeded: false,
      errorCode: "COMPARE_ERROR",
      errorMessage: (err as Error).message,
    });
    res.status(422).json({ ok: false, error: { code: "COMPARE_ERROR", message: (err as Error).message } });
  }
});

// ---------------------------------------------------------------------------
// Semantic comparison
// ---------------------------------------------------------------------------

policyRouter.post("/semantic-compare", (req: Request, res: Response) => {
  const schema = z.object({ leftXml: z.string().min(1), rightXml: z.string().min(1) });
  const parsed = schema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ ok: false, error: { code: "VALIDATION", message: parsed.error.message } });
    return;
  }
  if (rejectBadXml(parsed.data.leftXml, res) || rejectBadXml(parsed.data.rightXml, res)) return;

  const start = Date.now();
  const logger = getAuditLogger();
  try {
    const left = parseWdacXml(parsed.data.leftXml, "left");
    const right = parseWdacXml(parsed.data.rightXml, "right");
    const diff = semanticComparePolicies(left.policy, right.policy);
    logger.log("POLICY_SEMANTIC_COMPARED", {
      role: req.userRole,
      inputHash: hashInput(parsed.data.leftXml + "||" + parsed.data.rightXml),
      outputSummary: `verdict=${diff.riskAssessment.verdict} delta=${diff.riskAssessment.totalRiskDelta} added=${diff.addedRules.length} removed=${diff.removedRules.length} modified=${diff.modifiedRules.length}`,
      durationMs: Date.now() - start,
      succeeded: true,
    });
    res.json({ ok: true, data: { diff } });
  } catch (err) {
    logger.log("POLICY_SEMANTIC_COMPARED", {
      role: req.userRole,
      durationMs: Date.now() - start,
      succeeded: false,
      errorCode: "SEMANTIC_COMPARE_ERROR",
      errorMessage: (err as Error).message,
    });
    res.status(422).json({ ok: false, error: { code: "SEMANTIC_COMPARE_ERROR", message: (err as Error).message } });
  }
});

// ---------------------------------------------------------------------------
// Explain policy
// ---------------------------------------------------------------------------

policyRouter.post("/explain", (req: Request, res: Response) => {
  const start = Date.now();
  const logger = getAuditLogger();
  try {
    const policy = req.body.policy;
    if (!policy) {
      res.status(400).json({ ok: false, error: { code: "VALIDATION", message: "policy is required" } });
      return;
    }
    const explanation = explainPolicy(policy);
    logger.log("POLICY_EXPLAINED", {
      role: req.userRole,
      outputSummary: `mode=${explanation.effectiveMode} riskFlags=${explanation.riskFlags.length}`,
      durationMs: Date.now() - start,
      succeeded: true,
    });
    res.json({ ok: true, data: explanation });
  } catch (err) {
    logger.log("POLICY_EXPLAINED", {
      role: req.userRole,
      durationMs: Date.now() - start,
      succeeded: false,
      errorCode: "EXPLAIN_ERROR",
      errorMessage: (err as Error).message,
    });
    res.status(422).json({ ok: false, error: { code: "EXPLAIN_ERROR", message: (err as Error).message } });
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
    policyType: z.enum(["Base", "Supplemental"]).optional(),
    basePolicyId: z.string().optional(),
    ruleSelections: z.array(z.object({
      fileKey: z.string(),
      ruleType: z.enum(["publisher", "fileAttrib", "hash", "path", "skip"]),
    })).optional(),
    defaultRuleType: z.enum(["publisher", "fileAttrib", "hash", "path", "skip"]).optional(),
    preferPublisherRules: z.boolean().default(true),
    includePathRules: z.boolean().default(false),
    auditMode: z.boolean().default(true),
  });
  const parsed = schema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ ok: false, error: { code: "VALIDATION", message: parsed.error.message } });
    return;
  }

  const start = Date.now();
  const logger = getAuditLogger();
  try {
    const { policy, buildLog } = buildPolicyFromEvents(parsed.data as Parameters<typeof buildPolicyFromEvents>[0]);
    const xml = generateWdacXml(policy);
    logger.log("POLICY_BUILT_FROM_EVENTS", {
      role: req.userRole,
      inputSizeBytes: parsed.data.events.length,
      outputSummary: `rules=${policy.fileRules.length + policy.signers.length} template=${parsed.data.template ?? "default"} auditMode=${parsed.data.auditMode}`,
      durationMs: Date.now() - start,
      succeeded: true,
    });
    res.json({ ok: true, data: { policy, xml, ruleCount: policy.fileRules.length + policy.signers.length, buildLog } });
  } catch (err) {
    logger.log("POLICY_BUILT_FROM_EVENTS", {
      role: req.userRole,
      durationMs: Date.now() - start,
      succeeded: false,
      errorCode: "BUILD_ERROR",
      errorMessage: (err as Error).message,
    });
    res.status(422).json({ ok: false, error: { code: "BUILD_ERROR", message: (err as Error).message } });
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

  const start = Date.now();
  const logger = getAuditLogger();
  try {
    const changes = proposeRules({ ...parsed.data, events: parsed.data.events as ParsedCiEvent[] });
    logger.log("RULES_PROPOSED", {
      role: req.userRole,
      inputSizeBytes: parsed.data.events.length,
      outputSummary: `proposed=${changes.rules.length} warnings=${changes.globalWarnings.length}`,
      durationMs: Date.now() - start,
      succeeded: true,
    });
    res.json({ ok: true, data: { changes } });
  } catch (err) {
    logger.log("RULES_PROPOSED", {
      role: req.userRole,
      durationMs: Date.now() - start,
      succeeded: false,
      errorCode: "RULE_ENGINE_ERROR",
      errorMessage: (err as Error).message,
    });
    res.status(422).json({ ok: false, error: { code: "RULE_ENGINE_ERROR", message: (err as Error).message } });
  }
});

// ---------------------------------------------------------------------------
// Advanced Hunting ingest — JSON/CSV → deduplicated binaries + rule candidates
// ---------------------------------------------------------------------------

policyRouter.post("/ingest-advanced-hunting", (req: Request, res: Response) => {
  const schema = z.object({
    format: z.enum(["json", "csv", "auto"]),
    content: z.string().min(1),
    preferPublisherRules: z.boolean().optional(),
    scopePublisherRules: z.boolean().optional(),
    includePathRules: z.boolean().optional(),
    effect: z.enum(["Allow", "Deny"]).optional(),
  });
  const parsed = schema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ ok: false, error: { code: "VALIDATION", message: parsed.error.message } });
    return;
  }

  const start = Date.now();
  const logger = getAuditLogger();
  try {
    const result = ingestAdvancedHunting(parsed.data);
    logger.log("HUNTING_INGESTED", {
      role: req.userRole,
      inputHash: hashInput(parsed.data.content),
      inputSizeBytes: Buffer.byteLength(parsed.data.content, "utf8"),
      outputSummary: `schema=${result.stats.detectedSchema} rows=${result.stats.totalRowsParsed} binaries=${result.stats.uniqueBinaries} candidates=${result.ruleCandidates.length}`,
      durationMs: Date.now() - start,
      succeeded: true,
    });
    res.json({ ok: true, data: result });
  } catch (err) {
    logger.log("HUNTING_INGESTED", {
      role: req.userRole,
      inputHash: hashInput(parsed.data.content),
      inputSizeBytes: Buffer.byteLength(parsed.data.content, "utf8"),
      durationMs: Date.now() - start,
      succeeded: false,
      errorCode: "INGEST_ERROR",
      errorMessage: (err as Error).message,
    });
    res.status(422).json({ ok: false, error: { code: "INGEST_ERROR", message: (err as Error).message } });
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

// ---------------------------------------------------------------------------
// Binary simulation — evaluate allow/block against a policy
// ---------------------------------------------------------------------------

policyRouter.post("/simulate", (req: Request, res: Response) => {
  const binarySchema = z.object({
    sha256: z.string().regex(/^[0-9a-fA-F]{64}$/).optional(),
    sha1: z.string().regex(/^[0-9a-fA-F]{40}$/).optional(),
    signerName: z.string().max(512).optional(),
    rootCertTbs: z.string().max(512).optional(),
    issuerName: z.string().max(512).optional(),
    originalFileName: z.string().max(512).optional(),
    internalName: z.string().max(512).optional(),
    productName: z.string().max(512).optional(),
    fileVersion: z.string().max(64).optional(),
    filePath: z.string().max(4096).optional(),
    isKernelMode: z.boolean().optional(),
  });
  const schema = z.object({
    binary: binarySchema,
    policy: z.record(z.unknown()),
  });
  const parsed = schema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ ok: false, error: { code: "VALIDATION", message: parsed.error.message } });
    return;
  }

  const start = Date.now();
  const logger = getAuditLogger();
  try {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const result = simulateBinary(parsed.data.binary, parsed.data.policy as any);
    logger.log("POLICY_LOADED", {
      role: req.userRole,
      outputSummary: `simulate verdict=${result.verdict} matchedBy=${result.matchedBy ?? "none"} steps=${result.steps.length}`,
      durationMs: Date.now() - start,
      succeeded: true,
    });
    res.json({ ok: true, data: { result } });
  } catch (err) {
    logger.log("POLICY_LOADED", {
      role: req.userRole,
      durationMs: Date.now() - start,
      succeeded: false,
      errorCode: "SIMULATE_ERROR",
      errorMessage: (err as Error).message,
    });
    res.status(422).json({ ok: false, error: { code: "SIMULATE_ERROR", message: (err as Error).message } });
  }
});

// ---------------------------------------------------------------------------
// Merge multiple policies (WDAC Wizard parity: up to 15 policies)
// ---------------------------------------------------------------------------

policyRouter.post("/merge", (req: Request, res: Response) => {
  const schema = z.object({
    xmlFiles: z.array(z.string().min(1)).min(2).max(15),
    friendlyName: z.string().optional(),
  });
  const parsed = schema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ ok: false, error: { code: "INVALID_REQUEST", message: parsed.error.message } });
    return;
  }

  const start = Date.now();
  const logger = getAuditLogger();

  try {
    for (const xml of parsed.data.xmlFiles) {
      if (rejectBadXml(xml, res)) return;
    }

    const policies = parsed.data.xmlFiles.map((xml, i) => {
      const { policy, diagnostics } = parseWdacXml(xml, `policy-${i + 1}.xml`);
      return policy;
    });

    const { policy, log, stats } = mergePolicies(policies, parsed.data.friendlyName);
    const xml = generateWdacXml(policy);

    logger.log("POLICY_GENERATED", {
      role: req.userRole,
      outputSummary: `merge: ${stats.inputPolicies} policies → ${stats.dedupedFileRules} file rules, ${stats.dedupedSigners} signers`,
      durationMs: Date.now() - start,
      succeeded: true,
    });

    res.json({ ok: true, data: { policy, xml, mergeLog: log, stats } });
  } catch (err) {
    logger.log("POLICY_GENERATED", {
      role: req.userRole,
      durationMs: Date.now() - start,
      succeeded: false,
      errorCode: "MERGE_ERROR",
      errorMessage: (err as Error).message,
    });
    res.status(422).json({ ok: false, error: { code: "MERGE_ERROR", message: (err as Error).message } });
  }
});

// ---------------------------------------------------------------------------
// Certificate file → publisher metadata (for AddSignerDialog)
// ---------------------------------------------------------------------------

policyRouter.post("/cert-info", (req: Request, res: Response) => {
  const schema = z.object({
    certBase64: z.string().min(1),
    fileName: z.string().optional(),
  });
  const parsed = schema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ ok: false, error: { code: "INVALID_REQUEST", message: parsed.error.message } });
    return;
  }

  try {
    const buf = Buffer.from(parsed.data.certBase64, "base64");

    // Support PEM wrapping
    let derBuf = buf;
    const pemStr = buf.toString("ascii");
    if (pemStr.includes("-----BEGIN CERTIFICATE-----")) {
      const b64 = pemStr
        .replace(/-----BEGIN CERTIFICATE-----|-----END CERTIFICATE-----|\s/g, "");
      derBuf = Buffer.from(b64, "base64");
    }

    // Node.js built-in X.509 (available since Node 15.6)
    const cert = new crypto.X509Certificate(derBuf);

    // Extract CN from subject/issuer distinguished name strings
    const extractCN = (dn: string): string => {
      const m = dn.match(/CN=([^,]+)/i);
      return m ? m[1].trim() : dn;
    };

    // Compute TBSCertificate SHA-256 hash (the "TBS hash" used in WdacSignerRule.certRoot)
    // Node's X509Certificate.raw is the full DER. We need to hash just the TBSCertificate
    // portion. The TBS starts after the outer SEQUENCE wrapper.
    // Full DER: SEQUENCE { TBSCertificate, signatureAlgorithm, signatureValue }
    // To extract TBS: skip the outer SEQUENCE tag+length, read the next SEQUENCE
    let tbsHash = "";
    try {
      const der = cert.raw;
      // Skip outer SEQUENCE tag (0x30) and length
      let offset = 0;
      if (der[offset] !== 0x30) throw new Error("Not a SEQUENCE");
      offset++;
      // Parse length
      if (der[offset] & 0x80) {
        const numLen = der[offset] & 0x7f;
        offset += 1 + numLen;
      } else {
        offset++;
      }
      // Now at TBSCertificate SEQUENCE
      const tbsStart = offset;
      if (der[offset] !== 0x30) throw new Error("TBS is not a SEQUENCE");
      offset++;
      let tbsLen = 0;
      if (der[offset] & 0x80) {
        const numLen = der[offset] & 0x7f;
        for (let i = 0; i < numLen; i++) {
          tbsLen = (tbsLen << 8) | der[offset + 1 + i];
        }
        offset += 1 + numLen;
      } else {
        tbsLen = der[offset];
        offset++;
      }
      const tbsEnd = offset + tbsLen;
      const tbsBytes = der.slice(tbsStart, tbsEnd);
      tbsHash = crypto.createHash("sha256").update(tbsBytes).digest("hex").toUpperCase();
    } catch {
      // Fallback: hash the whole cert raw bytes
      tbsHash = crypto.createHash("sha256").update(cert.raw).digest("hex").toUpperCase();
    }

    // Detect code signing EKU (1.3.6.1.5.5.7.3.3)
    const ekuRaw = cert.infoAccessAIA ?? "";
    const isCodeSigning = cert.toString().includes("1.3.6.1.5.5.7.3.3")
      || (cert as unknown as Record<string, unknown>).extendedKeyUsage?.toString().includes("Code Signing") ?? false;

    // Detect CA (basic constraints)
    const isCa = cert.ca;

    res.json({
      ok: true,
      data: {
        subjectCN: extractCN(cert.subject),
        subjectDN: cert.subject,
        issuerCN: extractCN(cert.issuer),
        issuerDN: cert.issuer,
        tbsHash,
        serialNumber: cert.serialNumber,
        notBefore: cert.validFrom,
        notAfter: cert.validTo,
        isCodeSigning,
        isCa,
      },
    });
  } catch (err) {
    res.status(422).json({ ok: false, error: { code: "CERT_PARSE_ERROR", message: (err as Error).message } });
  }
});

// ---------------------------------------------------------------------------
// AppLocker XML → WDAC Policy conversion
// ---------------------------------------------------------------------------

policyRouter.post("/convert-applocker", (req: Request, res: Response) => {
  const schema = z.object({
    appLockerXml: z.string().min(1),
    includeDenyRules: z.boolean().optional(),
  });
  const parsed = schema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ ok: false, error: { code: "INVALID_REQUEST", message: parsed.error.message } });
    return;
  }

  const start = Date.now();
  const logger = getAuditLogger();

  try {
    const result = convertAppLockerToWdac(
      parsed.data.appLockerXml,
      parsed.data.includeDenyRules ?? false
    );

    logger.log("POLICY_GENERATED", {
      role: req.userRole,
      outputSummary: `applocker-convert: ${result.stats.publisherRules}p ${result.stats.hashRules}h ${result.stats.pathRules}pa rules`,
      durationMs: Date.now() - start,
      succeeded: true,
    });

    res.json({ ok: true, data: result });
  } catch (err) {
    logger.log("POLICY_GENERATED", {
      role: req.userRole,
      durationMs: Date.now() - start,
      succeeded: false,
      errorCode: "APPLOCKER_CONVERT_ERROR",
      errorMessage: (err as Error).message,
    });
    res.status(422).json({ ok: false, error: { code: "APPLOCKER_CONVERT_ERROR", message: (err as Error).message } });
  }
});
