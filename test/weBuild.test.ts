import { readFile } from "node:fs/promises";
import { describe, expect, it } from "vitest";
import { parseLotlJson } from "../src/lotl.js";
import { assessWeBuildProfile, classifyWeBuildListType } from "../src/profiles/weBuild.js";
import { createUnknownTs119602Classification } from "../src/standards/ts119602Classification.js";
import type { TrustedListAuditResult } from "../src/types.js";

function result(index: number, format: TrustedListAuditResult["detected"]["format"]): TrustedListAuditResult {
  return {
    id: `artifact-${index}`,
    index,
    source: `https://example.test/${index}`,
    location: `https://example.test/${index}`,
    declared: { pointerCertificateFingerprintsSha256: [] },
    fetch: { attempted: true, ok: true },
    detected: { format, artifactKind: format === "xml" ? "ts119612_xml_tsl" : "json_lote" },
    ts119602Classification: createUnknownTs119602Classification(),
    standardApplicability: { ts119612: "unknown", ts119602: "unknown", weBuildProfile: "applicable", eudiTrustRole: "unknown" },
    ts119612: { applicable: false, conformanceLevel: "not_applicable", score: null, checks: [], mandatoryFailures: [], warnings: [] },
    ts119602: { applicable: format === "json", conformanceLevel: format === "json" ? "not_checked" : "not_applicable", score: null, checks: [], mandatoryFailures: [], warnings: [] },
  };
}

describe("WE BUILD profile", () => {
  it("classifies implemented list types", () => {
    expect(classifyWeBuildListType("http://uri.etsi.org/19602/LoTEType/EUWalletProvidersList").role).toBe("wallet_provider");
    expect(classifyWeBuildListType("http://uri.etsi.org/19602/LoTEType/EUPIDProvidersList").role).toBe("pid_provider");
    expect(classifyWeBuildListType("http://uri.etsi.org/19602/LoTEType/EUWRPACProvidersList").role).toBe("wrpac_provider");
    expect(classifyWeBuildListType("http://uri.etsi.org/19602/LoTEType/EUWRPRCProvidersList").role).toBe("wrprc_provider");
    expect(classifyWeBuildListType("http://uri.etsi.org/19602/LoTEType/EUPubEAAProvidersList").role).toBe("pub_eaa_provider");
    expect(classifyWeBuildListType("http://uri.etsi.org/19602/LoTEType/EURegistrarsAndRegistersList").role).toBe("registrar_or_register");
    expect(classifyWeBuildListType("http://uri.etsi.org/19602/LoTEType/EUgeneric")).toEqual({ listType: "EUgeneric", role: "unknown" });
    expect(classifyWeBuildListType(undefined, "ts119612_xml_tsl").role).toBe("unknown");
  });

  it("summarizes roles and pointer consistency for a reduced WE BUILD LoTL", async () => {
    const [lotlText, signedXml] = await Promise.all([
      readFile("test/fixtures/we-build-lotl-profile.json", "utf8"),
      readFile("test/fixtures/tsl-signed-unsupported.xml", "utf8"),
    ]);
    const certificate = signedXml.match(/<ds:X509Certificate>([^<]+)<\/ds:X509Certificate>/)?.[1];
    if (!certificate) throw new Error("Signed fixture must contain a certificate.");
    const raw = JSON.parse(lotlText) as { LoTE: { ListAndSchemeInformation: { PointersToOtherLoTE: Array<{ ServiceDigitalIdentities: Array<{ X509Certificates: string[] }> }> } } };
    raw.LoTE.ListAndSchemeInformation.PointersToOtherLoTE[0].ServiceDigitalIdentities[0].X509Certificates = [certificate];
    const lotl = parseLotlJson(JSON.stringify(raw));
    const results = [result(1, "json"), result(2, "xml"), result(3, "json")];
    const summary = assessWeBuildProfile(lotl, results, new Date("2026-08-01T00:00:00Z"));
    expect(summary).toMatchObject({
      recognized: true,
      listTypeCounts: { EUWalletProvidersList: 1, EUWRPACProvidersList: 1, unknown: 1 },
      roleCounts: { wallet_provider: 1, wrpac_provider: 1, unknown: 1 },
      pointerConsistency: { declaredMimeMismatches: 1, duplicateLocations: 2, pointersMissingServiceDigitalIdentities: 1, pointersMissingQualifiers: 1, pointerCertificatesParsed: 1, pointerCertificatesInvalidAtAssessment: 0 },
    });
    expect(results[0].ts119612.checks).toEqual(expect.arrayContaining([
      expect.objectContaining({ id: "we_build.pointer.declared_mime_matches_detected", status: "warn" }),
      expect.objectContaining({ id: "we_build.pointer.duplicate_location", status: "warn" }),
      expect.objectContaining({ id: "we_build.pointer.certificate_evidence", status: "pass" }),
    ]));
  });

  it("correlates compacted results by original pointer index", async () => {
    const lotl = parseLotlJson(await readFile("test/fixtures/we-build-lotl-profile.json", "utf8"));
    lotl.pointers = lotl.pointers.slice(0, 2).map((pointer, index) => ({ ...pointer, index: index + 2 }));
    const results = [result(2, "json"), result(3, "xml")];

    const summary = assessWeBuildProfile(lotl, results);

    expect(summary.roleCounts).toMatchObject({ wallet_provider: 1, wrpac_provider: 1 });
    expect(results[0].ts119612.checks).toContainEqual(expect.objectContaining({
      id: "we_build.pointer.list_type",
      evidence: expect.objectContaining({ listType: "EUWalletProvidersList", role: "wallet_provider" }),
    }));
    expect(results[1].ts119612.checks).toContainEqual(expect.objectContaining({
      id: "we_build.pointer.list_type",
      evidence: expect.objectContaining({ listType: "EUWRPACProvidersList", role: "wrpac_provider" }),
    }));
  });

  it("counts deduplicated observed roles only from current-service evidence", async () => {
    const lotl = parseLotlJson(await readFile("test/fixtures/we-build-lotl-profile.json", "utf8"));
    lotl.pointers = [lotl.pointers[0], lotl.pointers[0], lotl.pointers[0]].map((pointer, index) => ({
      ...pointer,
      index: index + 1,
      location: `https://example.test/generic-${index}.xml`,
      declared: { ...pointer.declared, loteType: "http://uri.etsi.org/TrstSvc/TrustedList/TSLType/EUgeneric" },
    }));
    const eaa = result(1, "xml");
    eaa.extracted = { currentServiceTypeIdentifiers: ["http://uri.etsi.org/TrstSvc/Svctype/EAA", "http://uri.etsi.org/TrstSvc/Svctype/EAA"] };
    const mixed = result(2, "xml");
    mixed.extracted = { currentServiceTypeIdentifiers: ["http://uri.etsi.org/TrstSvc/Svctype/EAA", "http://uri.etsi.org/TrstSvc/Svctype/EAA/Q"] };
    const missing = result(3, "xml");
    missing.fetch = { attempted: false, ok: true };

    const summary = assessWeBuildProfile(lotl, [eaa, mixed, missing]);

    expect(summary.roleCounts).toEqual({ unknown: 3 });
    expect(summary.observedRoleCounts).toEqual({ eaa_provider: 2, qeaa_provider: 1 });
    expect(eaa.ts119612.checks).toContainEqual(expect.objectContaining({
      id: "we_build.pointer.observed_roles",
      status: "pass",
      evidence: expect.objectContaining({ observedRoles: ["eaa_provider"] }),
    }));
    expect(mixed.ts119612.checks).toContainEqual(expect.objectContaining({
      id: "we_build.pointer.observed_roles",
      evidence: expect.objectContaining({ observedRoles: ["eaa_provider", "qeaa_provider"] }),
    }));
    expect(missing.ts119612.checks).toContainEqual(expect.objectContaining({
      id: "we_build.pointer.observed_roles",
      status: "not_checked",
    }));
  });
});
