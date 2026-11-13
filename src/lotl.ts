import { certificateFingerprintSha256 } from "./certs.js";
import { parseCompactJades } from "./json/jades.js";
import type { PointerEvidence, PointerInfo } from "./types.js";
import { parseXml } from "./xml/parse.js";

const TSL_NS = "http://uri.etsi.org/02231/v2#";
const ADDITIONAL_TYPES_NS = "http://uri.etsi.org/02231/v2/additionaltypes#";
const TSL_TYPE_RADIX = "http://uri.etsi.org/TrstSvc/TrustedList/TSLType/";
const EU_LOTL_TYPE = `${TSL_TYPE_RADIX}EUlistofthelists`;

export type LotlFormat = "json" | "xml";

export class LotlParseError extends SyntaxError {
  constructor(
    message: string,
    public readonly format: LotlFormat | "unknown",
  ) {
    super(message);
    this.name = "LotlParseError";
  }
}

export interface ParsedLotl {
  format: LotlFormat;
  raw: unknown;
  pointers: PointerInfo[];
  summary: {
    schemeOperatorName?: string;
    schemeName?: string;
    loteType?: string;
    sequenceNumber?: number;
    issueDateTime?: string;
    nextUpdate?: string;
    pointerCount: number;
    uniqueLocationCount: number;
    duplicateLocations: string[];
  };
}

type LotlSummaryFields = Omit<
  ParsedLotl["summary"],
  "pointerCount" | "uniqueLocationCount" | "duplicateLocations"
>;

/** Evidence for a pointer synthesized outside a LoTL (single-artifact assessment): no LoTL row exists. */
export function emptyPointerEvidence(): PointerEvidence {
  return { serviceDigitalIdentityCount: 0, qualifierSetCount: 0, certificateMaterial: [] };
}

export function parseLotl(text: string): ParsedLotl {
  const trimmed = text.trimStart();
  if (!trimmed) {
    throw new LotlParseError("LoTL input is empty.", "unknown");
  }
  return trimmed.startsWith("<") ? parseLotlXml(text) : parseLotlJson(text);
}

export function parseLotlJson(text: string): ParsedLotl {
  let raw: unknown;
  if (looksLikeCompactJws(text)) {
    const compact = parseCompactJades(text);
    if (compact.detachedPayload) {
      throw new LotlParseError("Detached compact JAdES LoTL input is unsupported without external payload bytes.", "json");
    }
    if (!compact.serializationValid || compact.parsedPayload === undefined) {
      throw new LotlParseError(`Invalid compact JAdES LoTL: ${compact.errors.join("; ") || "payload unavailable"}`, "json");
    }
    raw = compact.parsedPayload;
  } else {
    try {
      raw = JSON.parse(text) as unknown;
    } catch (cause) {
      throw new LotlParseError(
        `Invalid JSON LoTL: ${cause instanceof Error ? cause.message : String(cause)}`,
        "json",
      );
    }
  }
  const lote = getPath(raw, ["LoTE"]);
  const info = getPath(lote, ["ListAndSchemeInformation"]);
  if (!isRecord(raw) || Array.isArray(raw) || !isRecord(lote) || Array.isArray(lote) || !isRecord(info) || Array.isArray(info)) {
    throw new LotlParseError("JSON LoTL must contain LoTE.ListAndSchemeInformation objects.", "json");
  }
  const loteType = firstString(getPath(info, ["LoTEType"]));
  if (!loteType || !JSON_LOTL_TYPE_SEGMENT.test(loteType)) {
    throw new LotlParseError("JSON LoTL must declare a recognized list-of-trusted-lists type.", "json");
  }
  const pointerValue = getPath(info, ["PointersToOtherLoTE"]);
  if (!Array.isArray(pointerValue) || pointerValue.length === 0) {
    throw new LotlParseError("JSON LoTL must contain a non-empty PointersToOtherLoTE array.", "json");
  }
  const pointers = pointerValue.map((pointer, zeroIndex): PointerInfo => {
    if (!isRecord(pointer) || Array.isArray(pointer)) {
      throw new LotlParseError(`JSON LoTL pointer ${zeroIndex + 1} must be an object.`, "json");
    }
    const location = stringValue(getPath(pointer, ["LoTELocation"]));
    if (!location) {
      throw new LotlParseError(`JSON LoTL pointer ${zeroIndex + 1} must contain one non-empty LoTELocation.`, "json");
    }
    const identities = asArray(getPath(pointer, ["ServiceDigitalIdentities"]));
    const certificateMaterial = jsonCertificateMaterial(identities);
    return {
      index: zeroIndex + 1,
      location,
      declared: {
        mimeType: qualifierValue(pointer, "MimeType"),
        loteType: qualifierValue(pointer, "LoTEType"),
        schemeOperatorName: firstString(getPath(pointer, ["SchemeOperatorName"])),
        schemeTerritory: firstString(getPath(pointer, ["SchemeTerritory"])),
        pointerCertificateFingerprintsSha256: certificateFingerprints(certificateMaterial),
      },
      evidence: {
        serviceDigitalIdentityCount: identities.length,
        qualifierSetCount: asArray(getPath(pointer, ["LoTEQualifiers"])).length,
        certificateMaterial,
      },
      raw: pointer,
    };
  });

  return parsedLotl(
    "json",
    raw,
    pointers,
    {
      schemeOperatorName: firstString(getPath(info, ["SchemeOperatorName"])),
      schemeName: firstString(getPath(info, ["SchemeName"])),
      loteType: firstString(getPath(info, ["LoTEType"])),
      sequenceNumber: numberValue(getPath(info, ["LoTESequenceNumber"])),
      issueDateTime: firstString(getPath(info, ["ListIssueDateTime"])),
      nextUpdate: firstString(getPath(info, ["NextUpdate"])),
    },
  );
}

function parseLotlXml(text: string): ParsedLotl {
  let parsed: ReturnType<typeof parseXml>;
  try {
    parsed = parseXml(text);
  } catch (cause) {
    throw new LotlParseError(
      `Invalid XML LoTL: ${cause instanceof Error ? cause.message : String(cause)}`,
      "xml",
    );
  }
  if (!parsed.document || parsed.errors.length > 0) {
    throw new LotlParseError(
      `Invalid XML LoTL: ${parsed.errors.join("; ") || "XML document could not be parsed."}`,
      "xml",
    );
  }

  const document = parsed.document;
  const root = document.documentElement;
  if (localName(root) !== "TrustServiceStatusList" || root.namespaceURI !== TSL_NS) {
    throw new LotlParseError(
      "XML LoTL must have a TrustServiceStatusList root in the canonical ETSI TS 119 612 namespace.",
      "xml",
    );
  }

  const scheme = exactlyOne(
    directChildren(root, "SchemeInformation"),
    "XML LoTL must contain exactly one direct SchemeInformation element.",
  );
  const type = requiredText(
    exactlyOne(
      directChildren(scheme, "TSLType"),
      "XML LoTL must contain exactly one direct TSLType element.",
    ),
    "XML LoTL TSLType must be non-empty.",
  );
  const territory = firstDirectText(scheme, "SchemeTerritory") ?? "";
  if (!acceptedLotlType(type, territory)) {
    throw new LotlParseError(
      `XML LoTL TSLType '${type}' is not an ETSI list-of-lists type for SchemeTerritory '${territory}'.`,
      "xml",
    );
  }

  const pointersContainer = exactlyOne(
    directChildren(scheme, "PointersToOtherTSL"),
    "XML LoTL must contain exactly one direct, non-empty PointersToOtherTSL element.",
  );
  const pointerElements = directChildren(pointersContainer, "OtherTSLPointer");
  if (pointerElements.length === 0) {
    throw new LotlParseError(
      "XML LoTL must contain one direct, non-empty PointersToOtherTSL sequence.",
      "xml",
    );
  }

  const pointers = pointerElements.map((pointer, zeroIndex): PointerInfo => {
    const locations = directChildren(pointer, "TSLLocation");
    const location = locations.length === 1 ? elementText(locations[0]) : undefined;
    if (!location) {
      throw new LotlParseError(
        `XML LoTL pointer ${zeroIndex + 1} must contain exactly one non-empty TSLLocation.`,
        "xml",
      );
    }

    const additionalInformation = directChildren(pointer, "AdditionalInformation");
    const qualifierContainers = additionalInformation.length === 1
      ? directChildren(additionalInformation[0], "OtherInformation")
      : [];
    const qualifier = (name: string, namespace = TSL_NS): Element | undefined =>
      qualifierContainers.flatMap((container) => descendants(container, name, namespace))[0];
    const identities = directChildren(pointer, "ServiceDigitalIdentities");
    const certificateMaterial = identities
      .flatMap((identity) => descendants(identity, "X509Certificate", TSL_NS))
      .flatMap((certificate) => {
        const encoded = elementText(certificate);
        return encoded ? [encoded] : [];
      });

    const operator = qualifier("SchemeOperatorName");
    return {
      index: zeroIndex + 1,
      location,
      declared: {
        mimeType: elementText(qualifier("MimeType", ADDITIONAL_TYPES_NS)),
        loteType: elementText(qualifier("TSLType")),
        schemeOperatorName: elementText(
          operator && descendants(operator, "Name", TSL_NS)[0],
        ),
        schemeTerritory: elementText(qualifier("SchemeTerritory")),
        pointerCertificateFingerprintsSha256: certificateFingerprints(certificateMaterial),
      },
      evidence: {
        serviceDigitalIdentityCount: identities.reduce(
          (count, container) => count + directChildren(container, "ServiceDigitalIdentity").length,
          0,
        ),
        qualifierSetCount: additionalInformation.filter(
          (information) => directChildren(information, "OtherInformation").length > 0,
        ).length,
        certificateMaterial,
      },
      raw: pointer,
    };
  });

  const operator = directChildren(scheme, "SchemeOperatorName")[0];
  const name = directChildren(scheme, "SchemeName")[0];
  const nextUpdate = directChildren(scheme, "NextUpdate")[0];
  return parsedLotl("xml", document, pointers, {
    schemeOperatorName: elementText(
      operator && directChildren(operator, "Name")[0],
    ),
    schemeName: elementText(name && directChildren(name, "Name")[0]),
    loteType: type,
    sequenceNumber: numberValue(firstDirectText(scheme, "TSLSequenceNumber")),
    issueDateTime: firstDirectText(scheme, "ListIssueDateTime"),
    nextUpdate: elementText(
      nextUpdate && directChildren(nextUpdate, "dateTime")[0],
    ),
  });
}

function parsedLotl(
  format: LotlFormat,
  raw: unknown,
  pointers: PointerInfo[],
  summary: LotlSummaryFields,
): ParsedLotl {
  const counts = new Map<string, number>();
  for (const pointer of pointers) {
    counts.set(pointer.location, (counts.get(pointer.location) ?? 0) + 1);
  }
  return {
    format,
    raw,
    pointers,
    summary: {
      ...summary,
      pointerCount: pointers.length,
      uniqueLocationCount: counts.size,
      duplicateLocations: [...counts.entries()]
        .filter(([, count]) => count > 1)
        .map(([location]) => location),
    },
  };
}

// The final URI segment must name a list of lists (WE BUILD WP4 EUListOfTrustedLists,
// TS 119 612 EUlistofthelists, or a generic ListOfLists); LoTE types are rejected.
const JSON_LOTL_TYPE_SEGMENT = /(?:^|[/#:])[A-Za-z]*(?:ListOfTrustedLists|ListOfLists|ListOfTheLists)$/i;

function looksLikeCompactJws(text: string): boolean {
  return /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*\.[A-Za-z0-9_-]+$/.test(text.trim());
}

function acceptedLotlType(type: string, territory: string): boolean {
  if (type === EU_LOTL_TYPE) return territory === "EU";
  const match = type.match(
    /^http:\/\/uri\.etsi\.org\/TrstSvc\/TrustedList\/TSLType\/([A-Z][A-Z0-9-]*)listofthelists$/,
  );
  return Boolean(match && match[1] !== "EU" && match[1] === territory);
}

function directChildren(parent: Node | undefined, name: string): Element[] {
  if (!parent) return [];
  return Array.from(parent.childNodes).filter((child): child is Element => {
    if (child.nodeType !== 1) return false;
    const element = child as Element;
    return element.namespaceURI === TSL_NS && localName(element) === name;
  });
}

function descendants(
  parent: Element,
  name: string,
  namespace: string,
): Element[] {
  return Array.from(parent.getElementsByTagNameNS(namespace, name));
}

function exactlyOne(elements: Element[], message: string): Element {
  if (elements.length !== 1) throw new LotlParseError(message, "xml");
  return elements[0];
}

function requiredText(element: Element, message: string): string {
  const value = elementText(element);
  if (!value) throw new LotlParseError(message, "xml");
  return value;
}

function firstDirectText(parent: Element, name: string): string | undefined {
  return elementText(directChildren(parent, name)[0]);
}

function elementText(element: Element | undefined): string | undefined {
  const value = element?.textContent?.trim();
  return value || undefined;
}

function localName(element: Element): string {
  return element.localName || element.nodeName;
}

export function getPath(value: unknown, path: string[]): unknown {
  let current = value;
  for (const part of path) {
    if (!isRecord(current)) {
      return undefined;
    }
    current = current[part];
  }
  return current;
}

export function asArray(value: unknown): unknown[] {
  if (Array.isArray(value)) return value;
  if (value === undefined || value === null) return [];
  return [value];
}

export function stringValue(value: unknown): string | undefined {
  if (typeof value === "string" && value.trim()) return value.trim();
  if (isRecord(value)) {
    for (const key of ["value", "uriValue", "#text", "_", "$t"]) {
      const nested = value[key];
      if (typeof nested === "string" && nested.trim()) return nested.trim();
    }
  }
  return undefined;
}

export function numberValue(value: unknown): number | undefined {
  if (typeof value === "number" && Number.isFinite(value)) return value;
  if (typeof value === "string" && value.trim() && Number.isFinite(Number(value))) {
    return Number(value);
  }
  return undefined;
}

export function firstString(...values: unknown[]): string | undefined {
  for (const value of values) {
    const direct = stringValue(value);
    if (direct) return direct;
    for (const item of asArray(value)) {
      const nested = stringValue(item);
      if (nested) return nested;
    }
  }
  return undefined;
}

export function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}

function qualifierValue(pointer: unknown, name: "LoTEType" | "MimeType"): string | undefined {
  for (const qualifier of asArray(getPath(pointer, ["LoTEQualifiers"]))) {
    const value = stringValue(getPath(qualifier, [name]));
    if (value) return value;
  }
  return undefined;
}

function jsonCertificateMaterial(identities: unknown[]): string[] {
  const material: string[] = [];
  const visit = (value: unknown, certificateContext: boolean): void => {
    if (typeof value === "string") {
      if (certificateContext && value.trim()) material.push(value.trim());
      return;
    }
    if (Array.isArray(value)) {
      value.forEach((entry) => visit(entry, certificateContext));
      return;
    }
    if (!isRecord(value)) return;
    // A TS 119 602 PKIObject carries the certificate in `val`; `encoding` and `specRef` are URIs, not material.
    if (certificateContext && Object.hasOwn(value, "val")) {
      visit(value.val, true);
      return;
    }
    for (const [key, nested] of Object.entries(value)) {
      if (certificateContext && (key === "encoding" || key === "specRef")) continue;
      visit(nested, certificateContext || /X509Certificate|certificate/i.test(key));
    }
  };
  identities.forEach((identity) => visit(identity, false));
  return material;
}

function certificateFingerprints(material: readonly string[]): string[] {
  const fingerprints = new Set<string>();
  for (const encoded of material) {
    const fingerprint = certificateFingerprintSha256(encoded);
    if (fingerprint) fingerprints.add(fingerprint);
  }
  return [...fingerprints].sort();
}
