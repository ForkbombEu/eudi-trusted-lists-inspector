import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { runAudit, runAuditFromContent } from "../src/audit.js";

const temporaryDirectories: string[] = [];

afterEach(async () => {
  await Promise.all(temporaryDirectories.splice(0).map((directory) => rm(directory, { recursive: true, force: true })));
});

describe("XML LoTL audit inputs", () => {
  it("audits ETSI TS 119 612 XML supplied as request content", async () => {
    const content = await readFile("test/fixtures/lotl-ts119612.xml", "utf8");

    const result = await runAuditFromContent(content, {
      concurrency: 1,
      timeoutMs: 1_000,
      strict: false,
      includeJsonLoteChecks: true,
      fetch: false,
    }, "0.0.0-test");

    expect(result.json.input).toMatchObject({ source: "request-body", kind: "xml" });
    expect(result.json.summary).toMatchObject({ totalPointers: 1, fetched: 0 });
    expect(result.json.lotlAssessment).toMatchObject({
      detected: { format: "xml", artifactKind: "ts119612_xml_lotl" },
      fetch: { attempted: false },
    });
    expect(result.json.lotlAssessment?.ts119612.checks.map((check) => check.id)).toContain("schema.xsd");
    expect(result.json.lotlAssessment?.ts119612.checks).toContainEqual(expect.objectContaining({
      id: "ts119612.structure.tsl_tag",
      status: "pass",
    }));
    expect(result.markdown).toContain("## LoTL assessment");
    expect(result.json.results).toHaveLength(1);
    expect(result.json.results[0]).toMatchObject({
      location: "https://example.test/member-state.xml",
      fetch: { attempted: false },
    });
  });

  it.each([
    ["absent", (xml: string) => xml.replace(/\sTSLTag="[^"]*"/, ""), null],
    ["invalid", (xml: string) => xml.replace(/TSLTag="[^"]*"/, 'TSLTag="https://example.test/other"'), "https://example.test/other"],
  ] as const)("reports an %s root TSLTag in the LoTL assessment without changing child counts", async (outcome, mutate, observed) => {
    const content = mutate(await readFile("test/fixtures/lotl-ts119612.xml", "utf8"));

    const result = await runAuditFromContent(content, {
      concurrency: 1,
      timeoutMs: 1_000,
      strict: false,
      includeJsonLoteChecks: true,
      fetch: false,
    }, "0.0.0-test");

    expect(result.json.lotlAssessment?.ts119612.checks).toContainEqual(expect.objectContaining({
      id: "ts119612.structure.tsl_tag",
      status: "fail",
      severity: "critical",
      evidence: expect.objectContaining({ outcome, observed, expected: "http://uri.etsi.org/19612/TSLTag" }),
    }));
    expect(result.markdown).toContain("**ts119612.structure.tsl_tag** (fail; critical)");
    expect(result.json.summary).toMatchObject({ totalPointers: 1, fetched: 0 });
    expect(result.json.results).toHaveLength(1);
  });

  it("assesses an enveloping compact JWS LoTL without trusting its signer implicitly", async () => {
    const payload = await readFile("test/fixtures/lotl.json", "utf8");
    const header = Buffer.from(JSON.stringify({ alg: "RS256" })).toString("base64url");
    const compact = `${header}.${Buffer.from(payload).toString("base64url")}.AA`;

    const result = await runAuditFromContent(compact, {
      concurrency: 1,
      timeoutMs: 1_000,
      strict: false,
      includeJsonLoteChecks: true,
      fetch: false,
    }, "0.0.0-test");

    expect(result.json.lotlAssessment).toMatchObject({
      detected: { format: "jws", artifactKind: "json_lotl" },
    });
    expect(result.json.lotlAssessment?.ts119602.checks).toEqual(expect.arrayContaining([
      expect.objectContaining({ id: "json_lote.signature.jades_payload_match", status: "pass" }),
      expect.objectContaining({ id: "json_lote.signature.jades_cryptographic_verification_result", status: "not_checked" }),
      expect.objectContaining({ id: "json_lote.signature.jades_signer_trust", status: "not_checked" }),
    ]));
    expect(result.json.summary.totalPointers).toBe(3);
    expect(result.json.results).toHaveLength(3);
  });

  it("verifies signed LoTL bytes without implying configured signer trust", async () => {
    const compact = await readFile("test/fixtures/lotl-jades-compact.jws", "utf8");
    const options = {
      concurrency: 1,
      timeoutMs: 1_000,
      strict: false,
      includeJsonLoteChecks: true,
      fetch: false,
    };

    const unconfigured = await runAuditFromContent(compact, options, "0.0.0-test");
    expect(unconfigured.json.lotlAssessment?.ts119602.checks).toEqual(expect.arrayContaining([
      expect.objectContaining({ id: "json_lote.signature.jades_cryptographic_verification_result", status: "pass" }),
      expect.objectContaining({ id: "json_lote.signature.jades_signer_trust", status: "not_checked" }),
    ]));

    const distrusted = await runAuditFromContent(compact, {
      ...options,
      context: { dereference: false, trustedSignerFingerprintsSha256: ["00".repeat(32)] },
    }, "0.0.0-test");
    expect(distrusted.json.lotlAssessment?.ts119602.checks).toEqual(expect.arrayContaining([
      expect.objectContaining({ id: "json_lote.signature.jades_cryptographic_verification_result", status: "pass" }),
      expect.objectContaining({ id: "json_lote.signature.jades_signer_trust", status: "fail" }),
    ]));
    expect(distrusted.json.summary.totalPointers).toBe(3);
  });

  it("keeps WE BUILD child diagnostics when the compatibility root fails its own checks", async () => {
    const content = await readFile("test/fixtures/list_of_trusted_lists.json", "utf8");

    const result = await runAuditFromContent(content, {
      concurrency: 1,
      timeoutMs: 1_000,
      strict: false,
      includeJsonLoteChecks: true,
      fetch: false,
    }, "0.0.0-test");

    expect(result.json.lotlAssessment?.ts119602.checks).toEqual(expect.arrayContaining([
      expect.objectContaining({ id: "ts119602.binding.json_schema", status: "fail" }),
      expect.objectContaining({ id: "json_lote.signature.jades_compact_serialization", status: "fail" }),
    ]));
    expect(result.json.weBuildProfile.recognized).toBe(true);
    expect(result.json.summary.totalPointers).toBe(10);
    expect(result.json.results).toHaveLength(10);
    expect(result.json.results[0].ts119612.checks.map((check) => check.id)).toContain("we_build.pointer.list_type");
  });

  it("audits an ETSI TS 119 612 XML file and writes reports", async () => {
    const outDir = await mkdtemp(join(tmpdir(), "eudi-trust-inspector-xml-lotl-"));
    temporaryDirectories.push(outDir);

    const report = await runAudit({
      input: "test/fixtures/lotl-ts119612.xml",
      outDir,
      concurrency: 1,
      timeoutMs: 1_000,
      strict: false,
      includeJsonLoteChecks: true,
      fetch: false,
      contextual: false,
    }, "0.0.0-test");

    expect(report.input).toMatchObject({ source: "test/fixtures/lotl-ts119612.xml", kind: "file" });
    expect(report.summary.totalPointers).toBe(1);
    await expect(readFile(join(outDir, "report.json"), "utf8")).resolves.toContain('"totalPointers": 1');
    await expect(readFile(join(outDir, "report.md"), "utf8")).resolves.toContain("https://example.test/member-state.xml");
  });
});
