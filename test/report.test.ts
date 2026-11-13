import { mkdtemp, readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { runAudit, runAuditFromContent } from "../src/audit.js";

const originalFetch = globalThis.fetch;

async function signedFixture(): Promise<string> {
  return readFile("test/fixtures/tsl-signed-unsupported.xml", "utf8");
}

describe("runAudit", () => {
  afterEach(() => {
    globalThis.fetch = originalFetch;
    vi.restoreAllMocks();
  });

  it("writes JSON and Markdown reports without treating JSON LoTE as TS 119 612 failure", async () => {
    const xml = await signedFixture();
    const json = await readFile("test/fixtures/json-lote.json", "utf8");
    globalThis.fetch = vi.fn(async (input: RequestInfo | URL) => {
      const url = String(input);
      if (url.endsWith("/tl.xml")) {
        return new Response(xml, {
          status: 200,
          headers: { "content-type": "application/xml" },
        });
      }
      if (url.endsWith("/lote.json")) {
        return new Response(json, {
          status: 200,
          headers: { "content-type": "application/json" },
        });
      }
      return new Response("missing", { status: 404, statusText: "Not Found" });
    }) as typeof fetch;

    const outDir = await mkdtemp(join(tmpdir(), "we-build-tl-audit-test-"));
    const report = await runAudit(
      {
        input: "test/fixtures/lotl.json",
        outDir,
        concurrency: 2,
        timeoutMs: 1000,
        strict: false,
        includeJsonLoteChecks: true,
        fetch: true,
      },
      "0.0.0-test",
    );

    expect(report.summary.totalPointers).toBe(3);
    expect(report.summary.fetched).toBe(2);
    expect(report.summary.fetchFailed).toBe(1);
    expect(report.summary.jsonArtifacts).toBe(1);
    expect(report.schemaVersion).toBe(7);
    expect(report.lotlAssessment).toMatchObject({
      detected: { format: "json", artifactKind: "json_lotl" },
      fetch: { attempted: false },
    });
    expect(report.lotlAssessment?.ts119602.checks.map((check) => check.id)).toContain("ts119602.binding.json_schema");
    expect(report.results[0]).toMatchObject({
      id: expect.stringMatching(/^artifact-001-[a-f0-9]{12}$/),
      source: "https://example.test/tl.xml",
      detected: { artifactKind: "ts119612_xml_tsl" },
      standardApplicability: {
        ts119612: "applicable",
        ts119602: "not_applicable",
        weBuildProfile: "not_applicable",
        eudiTrustRole: "not_applicable",
      },
      referenceProfiles: {
        eudiRiTs119612: { applicability: "not_applicable", recognized: false },
        weBuildTs119612: { applicability: "not_applicable", recognized: false },
      },
      ts119612Coverage: {
        ledger: { total: 69, applicable: 69, partial: 45, notImplemented: 8 },
        completeVerdictEligible: false,
      },
    });
    expect(report.results[1].ts119612.conformanceLevel).toBe("not_applicable");
    expect(report.results[1].ts119612.mandatoryFailures).toEqual([]);
    expect(report.results[1].ts119602).toMatchObject({
      applicable: true,
      conformanceLevel: "non_conformant",
    });
    expect(report.results[1].ts119602Classification).toMatchObject({
      dataModel: "ts119602",
      binding: "scheme_explicit_json",
      bindingStatus: "selected",
    });
    expect(report.results[1].ts119602Coverage).toMatchObject({
      selection: { binding: "scheme_explicit_json", schemeMode: "explicit" },
      ledger: { total: 81 },
      completeVerdictEligible: false,
    });
    expect(report.results[1].ts119602Coverage?.requirements).toHaveLength(81);
    expect(report.summary.ts119602.nonConformant).toBe(1);
    expect(report.summary.ts119602.unsupported).toBe(0);
    expect(report.results[1].standardApplicability).toEqual({
      ts119612: "not_applicable",
      ts119602: "applicable",
      weBuildProfile: "applicable",
      eudiTrustRole: "unknown",
    });
    const reportJson = await readFile(join(outDir, "report.json"), "utf8");
    expect(JSON.parse(reportJson)).toEqual(report);
    expect(reportJson).toContain("\"structure.scheme_information\"");
    expect(reportJson).toContain("\"schema.xsd\"");
    expect(reportJson).toContain("\"json_lote.version_identifier\"");
    expect(reportJson).toContain("\"ts119602.binding.json_schema\"");
    const markdown = await readFile(join(outDir, "report.md"), "utf8");
    expect(markdown).toContain("TS 119 602");
    expect(markdown).toContain("**structure.scheme_information**");
    expect(markdown).toContain("**structure.trust_service_provider_list**");
    expect(markdown).toContain("**schema.xsd**");
    expect(markdown).toContain("**signature.signing_certificate_present**");
    expect(markdown).toContain("### Certificate evidence");
    expect(markdown).toContain("Source: xml_signature");
    expect(markdown).toContain("## LoTL assessment");
    const rootSection = markdown.slice(markdown.indexOf("## LoTL assessment"), markdown.indexOf("## WE BUILD profile"));
    expect(rootSection).toContain("**ts119602.binding.json_schema**");
    expect(rootSection).toContain("- Source: test/fixtures/lotl.json");
    expect(JSON.parse(reportJson).lotlAssessment.ts119602.checks.map((check: { id: string }) => check.id)).toContain("ts119602.binding.json_schema");
    expect(markdown).toContain("**json_lote.pointers.service_digital_identities**");
    expect(markdown).toContain("### ETSI TS 119 602 assessment");
    expect(markdown).toContain("### EUDI RI TS 119 612 reference profile");
    expect(markdown).toContain("### WE BUILD TS 119 612 reference profile");
    expect(markdown).toContain("### ETSI TS 119 612 ledger coverage");
    expect(markdown).toContain("### ETSI TS 119 602 ledger coverage");
    expect(markdown).toContain("| ts119612.operations.availability | applicable | not_implemented | contextual | not_implemented | none |");
    expect(markdown).toContain("TS 119 602 classification: data model=ts119602; binding=scheme_explicit_json (selected)");
    expect(markdown).toContain("Can this trust-list bundle be used as a wallet trust fixture?");
    expect(markdown).toContain("## FCAF trusted_authorities fixture readiness");
    expect(report.fcafTrustedAuthorities.scenarios).toHaveLength(8);
    expect(markdown).toContain("## Negative fixture descriptors");
    expect(report.negativeFixtureDescriptors).toHaveLength(8);
    for (const result of report.results) {
      for (const finding of [...result.ts119612.checks, ...result.ts119602.checks]) {
        expect(markdown).toContain(`**${finding.id}** (${finding.status}; ${finding.severity})`);
      }
      for (const requirement of result.ts119612Coverage?.requirements ?? []) {
        expect(markdown).toContain(`| ${requirement.requirementId} |`);
      }
      for (const requirement of result.ts119602Coverage?.requirements ?? []) {
        expect(markdown).toContain(`| ${requirement.requirementId} |`);
      }
    }
  });

  it("adds WE BUILD list-type and pointer-consistency summary from a reduced fixture", async () => {
    const [xml, json] = await Promise.all([
      readFile("test/fixtures/tsl-valid-ish.xml", "utf8"),
      readFile("test/fixtures/json-lote.json", "utf8"),
    ]);
    globalThis.fetch = vi.fn(async (input: RequestInfo | URL) => {
      const url = String(input);
      return new Response(url.endsWith(".xml") ? xml : json, {
        status: 200,
        headers: { "content-type": url.endsWith(".xml") ? "application/xml" : "application/json" },
      });
    }) as typeof fetch;
    const outDir = await mkdtemp(join(tmpdir(), "we-build-profile-test-"));
    const report = await runAudit({
      input: "test/fixtures/we-build-lotl-profile.json",
      outDir,
      concurrency: 2,
      timeoutMs: 1000,
      strict: false,
      includeJsonLoteChecks: true,
      fetch: true,
    }, "0.0.0-test");
    expect(report.weBuildProfile).toMatchObject({
      recognized: true,
      listTypeCounts: { EUWalletProvidersList: 1, EUWRPACProvidersList: 1, unknown: 1 },
      roleCounts: { wallet_provider: 1, wrpac_provider: 1, unknown: 1 },
      pointerConsistency: { declaredMimeMismatches: 1, duplicateLocations: 2 },
    });
    expect(report.results[0].ts119612.checks).toEqual(expect.arrayContaining([
      expect.objectContaining({ id: "we_build.pointer.declared_mime_matches_detected", status: "warn" }),
    ]));
    await expect(readFile(join(outDir, "report.md"), "utf8")).resolves.toContain("## WE BUILD profile");
  });

  it("derives generic EAA and QEAA observations from exact current services in both LoTL bindings", async () => {
    const child = (await readFile("test/fixtures/eudi-ri-ts119612-tl.xml", "utf8"))
      .replace("http://uri.etsi.org/Svc/Svctype/CA/RPaccess", "http://uri.etsi.org/TrstSvc/Svctype/EAA")
      .replace("http://uri.etsi.org/Svc/Svctype/Provider/Wallet", "http://uri.etsi.org/TrstSvc/Svctype/EAA/Q");
    const jsonLotl = JSON.parse(await readFile("test/fixtures/lotl.json", "utf8"));
    const information = jsonLotl.LoTE.ListAndSchemeInformation;
    information.LoTEType = "http://uri.etsi.org/19602/LoTLType/EUListOfTrustedLists";
    information.PointersToOtherLoTE = [{
      LoTELocation: "https://example.test/mixed.xml",
      LoTEQualifiers: [{ LoTEType: "http://uri.etsi.org/TrstSvc/TrustedList/TSLType/EUgeneric", MimeType: "application/xml" }],
    }];
    const xmlLotl = (await readFile("test/fixtures/lotl-ts119612.xml", "utf8"))
      .replace("https://example.test/member-state.xml", "https://example.test/mixed.xml")
      .replace("Example Commission", "WE BUILD WP4")
      .replace("EU:Example List of Trusted Lists", "WE BUILD WP4");
    globalThis.fetch = vi.fn(async () => new Response(child, {
      status: 200,
      headers: { "content-type": "application/xml" },
    })) as typeof fetch;

    for (const content of [JSON.stringify(jsonLotl), xmlLotl]) {
      const result = await runAuditFromContent(content, {
        concurrency: 1,
        timeoutMs: 1000,
        strict: false,
        includeJsonLoteChecks: true,
        fetch: true,
      }, "0.0.0-test");

      expect(result.json.weBuildProfile.roleCounts).toEqual({ unknown: 1 });
      expect(result.json.weBuildProfile.observedRoleCounts).toEqual({ eaa_provider: 1, qeaa_provider: 1 });
      expect(result.json.results[0].ts119612.checks).toContainEqual(expect.objectContaining({
        id: "we_build.pointer.observed_roles",
        status: "pass",
        evidence: expect.objectContaining({
          observedRoles: ["eaa_provider", "qeaa_provider"],
          currentServiceTypeIdentifiers: [
            "http://uri.etsi.org/TrstSvc/Svctype/EAA",
            "http://uri.etsi.org/TrstSvc/Svctype/EAA/Q",
          ],
        }),
      }));
      expect(result.json.summary).toMatchObject({ totalPointers: 1, fetched: 1, fetchFailed: 0 });
    }
  });

  it("does not infer generic roles without fetched evidence or from unrelated services", async () => {
    const lotl = JSON.parse(await readFile("test/fixtures/lotl.json", "utf8"));
    const information = lotl.LoTE.ListAndSchemeInformation;
    information.LoTEType = "http://uri.etsi.org/19602/LoTLType/EUListOfTrustedLists";
    information.PointersToOtherLoTE = [{
      LoTELocation: "https://example.test/unrelated.xml",
      LoTEQualifiers: [{ LoTEType: "http://uri.etsi.org/TrstSvc/TrustedList/TSLType/EUgeneric", MimeType: "application/xml" }],
    }];
    const unrelated = (await readFile("test/fixtures/tsl-valid-ish.xml", "utf8"));
    globalThis.fetch = vi.fn(async () => new Response(unrelated, {
      status: 200,
      headers: { "content-type": "application/xml" },
    })) as typeof fetch;
    const options = { concurrency: 1, timeoutMs: 1000, strict: false, includeJsonLoteChecks: true };

    const fetched = await runAuditFromContent(JSON.stringify(lotl), { ...options, fetch: true }, "0.0.0-test");
    expect(fetched.json.weBuildProfile.observedRoleCounts).toEqual({});
    expect(fetched.json.weBuildProfile.roleCounts).toEqual({ unknown: 1 });
    expect(fetched.json.results[0].ts119612.checks).toContainEqual(expect.objectContaining({
      id: "we_build.pointer.observed_roles",
      status: "warn",
      evidence: expect.objectContaining({ observedRoles: [], outcome: "no_observed_role" }),
    }));

    const unfetched = await runAuditFromContent(JSON.stringify(lotl), { ...options, fetch: false }, "0.0.0-test");
    expect(unfetched.json.weBuildProfile.observedRoleCounts).toEqual({});
    expect(unfetched.json.results[0].ts119612.checks).toContainEqual(expect.objectContaining({
      id: "we_build.pointer.observed_roles",
      status: "not_checked",
    }));

    globalThis.fetch = vi.fn(async () => new Response("missing", { status: 404 })) as typeof fetch;
    const failed = await runAuditFromContent(JSON.stringify(lotl), { ...options, fetch: true }, "0.0.0-test");
    expect(failed.json.weBuildProfile.observedRoleCounts).toEqual({});
    expect(failed.json.results[0].ts119612.checks).toContainEqual(expect.objectContaining({
      id: "we_build.pointer.observed_roles",
      status: "not_checked",
    }));
    expect(failed.json.summary.fetchFailed).toBe(1);
  });

  it("separates QEAA-only, declared-QEAA mismatch, and unrelated observations per pointer", async () => {
    const base = await readFile("test/fixtures/eudi-ri-ts119612-tl.xml", "utf8");
    const qeaaOnly = base
      .replace("http://uri.etsi.org/Svc/Svctype/CA/RPaccess", "http://uri.etsi.org/TrstSvc/Svctype/EAA/Q")
      .replace("http://uri.etsi.org/Svc/Svctype/Provider/Wallet", "http://uri.etsi.org/TrstSvc/Svctype/EAA/Q");
    const eaaOnly = base
      .replace("http://uri.etsi.org/Svc/Svctype/CA/RPaccess", "http://uri.etsi.org/TrstSvc/Svctype/EAA")
      .replace("http://uri.etsi.org/Svc/Svctype/Provider/Wallet", "http://uri.etsi.org/TrstSvc/Svctype/EAA");
    const lotl = JSON.parse(await readFile("test/fixtures/lotl.json", "utf8"));
    lotl.LoTE.ListAndSchemeInformation.LoTEType = "http://uri.etsi.org/19602/LoTLType/EUListOfTrustedLists";
    lotl.LoTE.ListAndSchemeInformation.PointersToOtherLoTE = [
      { LoTELocation: "https://example.test/qeaa.xml", LoTEQualifiers: [{ LoTEType: "http://uri.etsi.org/TrstSvc/TrustedList/TSLType/EUgeneric", MimeType: "application/xml" }] },
      { LoTELocation: "https://example.test/declared-qeaa.xml", LoTEQualifiers: [{ LoTEType: "https://example.test/LoTEType/QEAAProvidersList", MimeType: "application/xml" }] },
    ];
    globalThis.fetch = vi.fn(async (input: RequestInfo | URL) => new Response(String(input).endsWith("/qeaa.xml") ? qeaaOnly : eaaOnly, {
      status: 200,
      headers: { "content-type": "application/xml" },
    })) as typeof fetch;

    const result = await runAuditFromContent(JSON.stringify(lotl), {
      concurrency: 1, timeoutMs: 1000, strict: false, includeJsonLoteChecks: true, fetch: true,
    }, "0.0.0-test");

    expect(result.json.weBuildProfile.roleCounts).toEqual({ unknown: 1, qeaa_provider: 1 });
    expect(result.json.weBuildProfile.observedRoleCounts).toEqual({ qeaa_provider: 1, eaa_provider: 1 });
    expect(result.json.results.map((child) => child.location)).toEqual(["https://example.test/qeaa.xml", "https://example.test/declared-qeaa.xml"]);
    expect(result.json.results[0].ts119612.checks).toContainEqual(expect.objectContaining({
      id: "we_build.pointer.observed_roles",
      status: "pass",
      evidence: expect.objectContaining({ declaredRole: "unknown", observedRoles: ["qeaa_provider"], outcome: "observed" }),
    }));
    expect(result.json.results[1].ts119612.checks).toContainEqual(expect.objectContaining({
      id: "we_build.pointer.observed_roles",
      status: "warn",
      evidence: expect.objectContaining({ declaredRole: "qeaa_provider", observedRoles: ["eaa_provider"], outcome: "declared_observed_mismatch" }),
    }));
  });

  it("audits an enveloping compact JWS LoTL loaded from a URL and assesses the signed bytes", async () => {
    const compact = await readFile("test/fixtures/lotl-jades-compact.jws", "utf8");
    const fetchMock = vi.fn(async () => new Response(compact, {
      status: 200,
      headers: { "content-type": "application/jose" },
    }));
    globalThis.fetch = fetchMock as typeof fetch;
    const outDir = await mkdtemp(join(tmpdir(), "we-build-jws-lotl-test-"));

    const report = await runAudit({
      input: "https://example.test/lotl.jws",
      outDir,
      concurrency: 1,
      timeoutMs: 1000,
      strict: false,
      includeJsonLoteChecks: true,
      fetch: false,
    }, "0.0.0-test");

    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(report.input).toMatchObject({ source: "https://example.test/lotl.jws", kind: "url" });
    expect(report.summary).toMatchObject({ totalPointers: 3, fetched: 0 });
    expect(report.results).toHaveLength(3);
    expect(report.lotlAssessment).toMatchObject({ detected: { format: "jws", artifactKind: "json_lotl" } });
    expect(report.lotlAssessment?.ts119602.checks).toEqual(expect.arrayContaining([
      expect.objectContaining({ id: "json_lote.signature.jades_payload_match", status: "pass" }),
      expect.objectContaining({ id: "json_lote.signature.jades_cryptographic_verification_result", status: "pass" }),
      expect.objectContaining({ id: "json_lote.signature.jades_signer_trust", status: "not_checked" }),
    ]));
    await expect(readFile(join(outDir, "report.md"), "utf8")).resolves.toContain("## LoTL assessment");
  });
});
