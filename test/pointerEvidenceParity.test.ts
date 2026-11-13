import { readFile } from "node:fs/promises";
import { describe, expect, it } from "vitest";
import { runAuditFromContent } from "../src/audit.js";
import { certificateFingerprintSha256 } from "../src/certs.js";
import type { AuditReport, CheckResult, TrustedListAuditResult } from "../src/types.js";

const WALLET = "http://uri.etsi.org/19602/LoTEType/EUWalletProvidersList";
const WRPAC = "http://uri.etsi.org/19602/LoTEType/EUWRPACProvidersList";
const MALFORMED_CERTIFICATE = Buffer.from("not-a-certificate").toString("base64");

async function testCertificate(): Promise<string> {
  const compact = await readFile("test/fixtures/lotl-jades-compact.jws", "utf8");
  const header = JSON.parse(Buffer.from(compact.split(".")[0], "base64url").toString("utf8")) as { x5c: string[] };
  return header.x5c[0];
}

function jsonLotl(certificate: string): string {
  return JSON.stringify({
    LoTE: {
      ListAndSchemeInformation: {
        LoTEType: "http://uri.etsi.org/19602/LoTLType/EUListOfTrustedLists",
        SchemeOperatorName: [{ lang: "en", value: "WE BUILD WP4" }],
        SchemeName: [{ lang: "en", value: "WE BUILD WP4 parity LoTL" }],
        SchemeTerritory: "EU",
        PointersToOtherLoTE: [
          {
            LoTELocation: "https://example.test/complete.xml",
            ServiceDigitalIdentities: [{ X509Certificates: [{ val: certificate }] }],
            LoTEQualifiers: [{ LoTEType: WALLET, MimeType: "application/xml" }],
          },
          {
            LoTELocation: "https://example.test/missing-identities.xml",
            LoTEQualifiers: [{ LoTEType: WRPAC, MimeType: "application/xml" }],
          },
          {
            LoTELocation: "https://example.test/malformed-certificate.xml",
            ServiceDigitalIdentities: [{ X509Certificates: [{ val: MALFORMED_CERTIFICATE }] }],
          },
        ],
      },
    },
  });
}

function xmlLotl(certificate: string): string {
  const qualifiers = (type: string) => `<AdditionalInformation>
          <OtherInformation><TSLType>${type}</TSLType></OtherInformation>
          <OtherInformation><at:MimeType>application/xml</at:MimeType></OtherInformation>
        </AdditionalInformation>`;
  const identity = (value: string) => `<ServiceDigitalIdentities>
          <ServiceDigitalIdentity><DigitalId><X509Certificate>${value}</X509Certificate></DigitalId></ServiceDigitalIdentity>
        </ServiceDigitalIdentities>`;
  return `<?xml version="1.0" encoding="UTF-8"?>
<TrustServiceStatusList xmlns="http://uri.etsi.org/02231/v2#" xmlns:at="http://uri.etsi.org/02231/v2/additionaltypes#" Id="PARITY-LOTL" TSLTag="http://uri.etsi.org/19612/TSLTag">
  <SchemeInformation>
    <TSLVersionIdentifier>6</TSLVersionIdentifier>
    <TSLSequenceNumber>1</TSLSequenceNumber>
    <TSLType>http://uri.etsi.org/TrstSvc/TrustedList/TSLType/EUlistofthelists</TSLType>
    <SchemeOperatorName><Name xml:lang="en">WE BUILD WP4</Name></SchemeOperatorName>
    <SchemeName><Name xml:lang="en">WE BUILD WP4 parity LoTL</Name></SchemeName>
    <SchemeTerritory>EU</SchemeTerritory>
    <PointersToOtherTSL>
      <OtherTSLPointer>
        ${identity(certificate)}
        <TSLLocation>https://example.test/complete.xml</TSLLocation>
        ${qualifiers(WALLET)}
      </OtherTSLPointer>
      <OtherTSLPointer>
        <TSLLocation>https://example.test/missing-identities.xml</TSLLocation>
        ${qualifiers(WRPAC)}
      </OtherTSLPointer>
      <OtherTSLPointer>
        ${identity(MALFORMED_CERTIFICATE)}
        <TSLLocation>https://example.test/malformed-certificate.xml</TSLLocation>
      </OtherTSLPointer>
    </PointersToOtherTSL>
    <ListIssueDateTime>2026-08-01T00:00:00Z</ListIssueDateTime>
    <NextUpdate><dateTime>2026-12-01T00:00:00Z</dateTime></NextUpdate>
  </SchemeInformation>
</TrustServiceStatusList>`;
}

function pointerCheck(result: TrustedListAuditResult, id: string): CheckResult | undefined {
  return result.ts119612.checks.find((check) => check.id === id);
}

function readinessCheck(report: AuditReport, id: string): CheckResult | undefined {
  return report.fixtureReadiness.checks.find((check) => check.id === id);
}

async function audit(content: string, rpacChain?: string): Promise<AuditReport> {
  const result = await runAuditFromContent(content, {
    concurrency: 1,
    timeoutMs: 1_000,
    strict: false,
    includeJsonLoteChecks: true,
    fetch: false,
    rpacChain,
  }, "0.0.0-test");
  return result.json;
}

describe("JSON and XML LoTL pointer evidence parity", () => {
  it("reports the same identity, qualifier, certificate and candidate-anchor evidence for equivalent bindings", async () => {
    const certificate = await testCertificate();
    const fingerprint = certificateFingerprintSha256(certificate);
    const reports = { json: await audit(jsonLotl(certificate)), xml: await audit(xmlLotl(certificate)) };

    for (const [binding, report] of Object.entries(reports)) {
      expect(report.input.kind, binding).toBe(binding);
      expect(report.weBuildProfile.recognized, binding).toBe(true);
      expect(report.lotl.pointerCount, binding).toBe(3);
      expect(report.weBuildProfile.pointerConsistency, binding).toMatchObject({
        pointersMissingServiceDigitalIdentities: 1,
        pointersMissingQualifiers: 1,
        pointerCertificatesParsed: 1,
        pointerCertificatesInvalidAtAssessment: 0,
      });

      const [complete, missingIdentities, malformed] = report.results;
      expect(malformed.declared.pointerCertificateFingerprintsSha256).toEqual(reports.json.results[2].declared.pointerCertificateFingerprintsSha256);
      expect(complete.declared.pointerCertificateFingerprintsSha256, binding).toEqual([fingerprint]);
      expect(pointerCheck(complete, "we_build.pointer.service_digital_identities"), binding).toMatchObject({ status: "pass", evidence: 1 });
      expect(pointerCheck(complete, "we_build.pointer.lote_qualifiers"), binding).toMatchObject({ status: "pass", evidence: 1 });
      expect(pointerCheck(complete, "we_build.pointer.certificate_evidence"), binding).toMatchObject({
        status: "pass",
        evidence: expect.objectContaining({ present: 1, parsed: 1, invalidAtAssessment: 0 }),
      });

      expect(pointerCheck(missingIdentities, "we_build.pointer.service_digital_identities"), binding).toMatchObject({ status: "warn", evidence: 0 });
      expect(pointerCheck(missingIdentities, "we_build.pointer.lote_qualifiers"), binding).toMatchObject({ status: "pass", evidence: 1 });
      expect(pointerCheck(missingIdentities, "we_build.pointer.certificate_evidence"), binding).toMatchObject({ status: "not_checked" });

      // Declared fingerprints hash the published bytes; they say nothing about parseability.
      expect(malformed.declared.pointerCertificateFingerprintsSha256, binding).toHaveLength(1);
      expect(pointerCheck(malformed, "we_build.pointer.service_digital_identities"), binding).toMatchObject({ status: "pass", evidence: 1 });
      expect(pointerCheck(malformed, "we_build.pointer.lote_qualifiers"), binding).toMatchObject({ status: "warn", evidence: 0 });
      expect(pointerCheck(malformed, "we_build.pointer.certificate_evidence"), binding).toMatchObject({
        status: "warn",
        evidence: expect.objectContaining({ present: 1, parsed: 0 }),
      });

      expect(readinessCheck(report, "fixture_readiness.trust_anchor_extractable"), binding).toMatchObject({ status: "pass", evidence: 1 });
      expect(readinessCheck(report, "fixture_readiness.rpac_chain_assessed"), binding).toMatchObject({ status: "not_checked" });
    }
  });

  it("uses XML pointer certificate material, not only fingerprints, as candidate anchors without establishing signer trust", async () => {
    const certificate = await testCertificate();

    const chains: Record<string, unknown> = {};
    for (const [binding, content] of [["json", jsonLotl(certificate)], ["xml", xmlLotl(certificate)]] as const) {
      const report = await audit(content, certificate);

      expect(readinessCheck(report, "fixture_readiness.rpac_chain_assessed"), binding).toMatchObject({
        status: "pass",
        evidence: expect.objectContaining({ trustedByTlLote: true }),
      });
      chains[binding] = report.fixtureReadiness.rpacChain;
      const rootChecks = [...(report.lotlAssessment?.ts119612.checks ?? []), ...(report.lotlAssessment?.ts119602.checks ?? [])];
      expect(rootChecks.filter((check) => /signer_trust$/.test(check.id) && check.status === "pass"), binding).toEqual([]);
    }
    expect(chains.xml).toEqual(chains.json);
  });

  it("finds no candidate anchors when every pointer certificate is malformed", async () => {
    for (const [binding, content] of [["json", jsonLotl(MALFORMED_CERTIFICATE)], ["xml", xmlLotl(MALFORMED_CERTIFICATE)]] as const) {
      const report = await audit(content);

      expect(report.weBuildProfile.pointerConsistency.pointerCertificatesParsed, binding).toBe(0);
      expect(readinessCheck(report, "fixture_readiness.trust_anchor_extractable"), binding).toMatchObject({ status: "warn", evidence: 0 });
    }
  });
});
