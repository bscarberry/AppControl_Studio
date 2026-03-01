/**
 * XML Security Validator
 *
 * Pre-parse checks that reject malicious or malformed XML before it reaches
 * the full XML parser. Fast, regex/string based — no DOM construction.
 *
 * Mitigations:
 *   XML bomb (billion laughs)  — blocked by forbidding <!ENTITY / <!DOCTYPE
 *   Oversized documents        — checked against configurable byte limit
 *   Element count explosion    — heuristic count of '<' characters
 *   Path traversal in content  — not a risk here (content is processed
 *                                in-memory, never used as a file path)
 *
 * Note: This is a defence-in-depth layer. The XML parser itself also
 * rejects malformed input; this validator catches known attack patterns
 * before any allocation occurs.
 */

import type { ValidationConfig } from "../config/security-config.js";

export interface XmlValidationResult {
  valid: boolean;
  /** User-safe error description (never contains raw XML content) */
  error?: string;
  /** Machine-readable code for audit logging */
  code?: string;
}

/**
 * Validate a raw XML string before parsing.
 * Returns {valid: true} when the document passes all checks.
 */
export function validateXmlInput(
  xml: string,
  config: ValidationConfig
): XmlValidationResult {
  // 1. Size limit
  const byteLen = Buffer.byteLength(xml, "utf8");
  if (byteLen > config.maxXmlSizeBytes) {
    return {
      valid: false,
      code: "XML_TOO_LARGE",
      error: `XML document is ${Math.round(byteLen / 1024 / 1024 * 10) / 10} MB — ` +
             `maximum allowed is ${Math.round(config.maxXmlSizeBytes / 1024 / 1024)} MB`,
    };
  }

  // 2. DTD / external entity declarations — XML bomb vector
  //    WDAC policy XML never requires DOCTYPE or ENTITY declarations.
  if (/<!DOCTYPE/i.test(xml)) {
    return {
      valid: false,
      code: "XML_DOCTYPE_FORBIDDEN",
      error: "DOCTYPE declarations are not permitted in policy XML",
    };
  }
  if (/<!ENTITY/i.test(xml)) {
    return {
      valid: false,
      code: "XML_ENTITY_FORBIDDEN",
      error: "ENTITY declarations are not permitted in policy XML",
    };
  }

  // 3. Processing instructions that could trigger external loads
  //    (e.g. <?xml-stylesheet href="..."?>)
  if (/<\?xml-stylesheet/i.test(xml)) {
    return {
      valid: false,
      code: "XML_PI_FORBIDDEN",
      error: "xml-stylesheet processing instructions are not permitted",
    };
  }

  // 4. Element count heuristic (count '<' that are not '</')
  //    A fully formed WDAC policy with 10k rules has ~50k elements at most.
  const openTagCount = (xml.match(/</g) ?? []).length;
  if (openTagCount > config.maxXmlElements) {
    return {
      valid: false,
      code: "XML_TOO_MANY_ELEMENTS",
      error: `XML document contains more than ${config.maxXmlElements.toLocaleString()} elements`,
    };
  }

  // 5. Nesting depth heuristic — protect against stack overflow in recursive parsers
  let depth = 0;
  let maxDepth = 0;
  for (let i = 0; i < xml.length - 1; i++) {
    if (xml[i] === "<") {
      if (xml[i + 1] === "/") {
        depth--;
      } else if (xml[i + 1] !== "!" && xml[i + 1] !== "?") {
        // Skip self-closing tags (<Foo />)
        const tagEnd = xml.indexOf(">", i);
        if (tagEnd !== -1 && xml[tagEnd - 1] === "/") {
          i = tagEnd;
        } else {
          depth++;
          if (depth > maxDepth) maxDepth = depth;
        }
      }
    }
  }
  if (maxDepth > config.maxXmlNestingDepth) {
    return {
      valid: false,
      code: "XML_NESTING_TOO_DEEP",
      error: `XML nesting depth (${maxDepth}) exceeds maximum allowed (${config.maxXmlNestingDepth})`,
    };
  }

  return { valid: true };
}
