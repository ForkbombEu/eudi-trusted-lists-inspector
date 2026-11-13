# EUDI Trust Inspector

## Intro

EUDI Trust Inspector is a deterministic CLI, API, and browser UI for assessing EUDI and WE BUILD trusted-list inputs, including JSON, enveloping compact JWS, and ETSI TS 119 612 XML Lists of Trusted Lists. It helps operators distinguish parsed facts, implemented technical checks, evidence limits, and unsupported claims without presenting itself as a legal conformance authority.

## Technical specs

TypeScript on Node.js with Fastify for the HTTP adapter. The assessment core is reused by the CLI and API; OpenAPI 3.1 is authored in YAML and served as YAML or derived JSON. XML, JSON LoTE/LoTL, JAdES, certificate-chain, and fixture-readiness checks remain explicit assessment domains.

## HOW to run

```sh
npm ci
npm test
npm run build
npm run api
```

The API listens on `http://127.0.0.1:3000` by default. Use `npm run dev:api` for source-mode development. Copy `.env-example` to `.env` to set `HOST`, `PORT`, `PUBLIC_BASE_URL`, CORS, and audit defaults.

## Quick GUI guide

The homepage introduces the assessment in a compact hero followed by the audit form. Its header links to the API documentation, raw OpenAPI document, and project repository.

### LoTL

Provide a JSON, enveloping compact JWS, or ETSI TS 119 612 XML LoTL URL, or upload a local XML, JSON, or JWS file. The **LoTL assessment** group assesses the root's own schema, structure, and signature evidence independently of child results and counters. XML child-list locations are read only from `PointersToOtherTSL/OtherTSLPointer/TSLLocation`; `DistributionPoints` describe publication locations for the current list and are not traversed as child lists. The result groups findings by fetched TrustedList and separates pass, warning, failure, and not-final states.

WE BUILD generic pointers do not declare QEAA status. Exact current-service `Svctype/EAA` and `Svctype/EAA/Q` values produce separate observed EAA and QEAA roles only when fetched XML evidence is available. A mixed list contributes one pointer count to each observed role, regardless of how many matching services it contains. Each child's `we_build.pointer.observed_roles` finding records the declared role, observed roles and exact current-service types: it passes when observations exist and agree, warns on a declared/observed mismatch or when a fetched list shows no EUDI role, and stays `not_checked` when the target was not fetched, failed or is not a recognized TS 119 612 TL. Declared `roleCounts` and `observedRoleCounts` are reported separately. Pointer identity, qualifier-set and pointer-certificate counts, and fixture-readiness candidate anchors, come from the same parsed pointer evidence for JSON and XML LoTLs, so equivalent lists report the same values in either binding. A parseable pointer certificate is only a candidate anchor; it never establishes signer trust. A JSON LoTL must declare a list-of-lists `LoTEType` and a non-empty pointer array; a pointer row without a usable `LoTELocation` rejects the request with its one-based row number instead of producing a partial audit.

### TrustedList XML/JSON

Provide a TrustedList URL, upload XML/JSON/JWS, or paste content. The UI renders findings, the complete JSON result, and available Markdown. TS 119 602 findings identify blank, incorrectly nested, or forbidden-control-character current and historical service names and warn when distinct entities share their first information URI; the URI warning is an interoperability observation, not a schema or trust failure.

For signed LoTL/LoTE inputs, the embedded `ds:KeyInfo` signing certificate is compared with every applicable `ServiceDigitalIdentity` certificate. The exact-certificate check passes when any candidate matches; certificate ordering does not affect the result.

## CLI Examples

| Function                     | Example                                                                                                                             |
| ---------------------------- | ----------------------------------------------------------------------------------------------------------------------------------- |
| Audit local LoTL             | `node dist/cli.js --input ./list_of_trusted_lists.json --out-dir ./audit-output --concurrency 4 --timeout-ms 15000`                 |
| Audit ETSI XML LoTL          | `node dist/cli.js --input ./eu-lotl.xml --out-dir ./audit-output --concurrency 4 --timeout-ms 15000`                                |
| Audit compact JWS LoTL       | `node dist/cli.js --input ./lotl.jws --out-dir ./audit-output --concurrency 4 --timeout-ms 15000`                                  |
| Audit a URL                  | `node dist/cli.js --input https://webuild-consortium.github.io/wp4-trust-group/list_of_trusted_lists.json --out-dir ./audit-output` |
| Use a named reference source | `node dist/cli.js --reference-source we-build-lotl-json --out-dir ./audit-output`                                                   |

## API Examples

| Function                 | Example                                                                                                                                                                                  |
| ------------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Health                   | `curl http://127.0.0.1:3000/healthz`                                                                                                                                                     |
| Audit a LoTL URL         | `curl -X POST http://127.0.0.1:3000/api/v1/audit/url -H 'content-type: application/json' -d '{"url":"https://webuild-consortium.github.io/wp4-trust-group/list_of_trusted_lists.json"}'` |
| Audit ETSI XML LoTL URL  | `curl -X POST http://127.0.0.1:3000/api/v1/audit/url -H 'content-type: application/json' -d '{"url":"https://ec.europa.eu/tools/lotl/eu-lotl.xml","options":{"fetch":false}}'`        |
| Assess a TrustedList URL | `curl -X POST http://127.0.0.1:3000/api/v1/artifact/assess-url -H 'content-type: application/json' -d '{"url":"https://example.org/trusted-list.xml"}'`                                  |
| Parse a LoTL             | `curl -X POST http://127.0.0.1:3000/api/v1/lotl/parse -H 'content-type: application/json' -d '{"lotl":{"LoTE":{"ListAndSchemeInformation":{"LoTEType":"http://uri.etsi.org/19602/LoTLType/EUListOfTrustedLists","PointersToOtherLoTE":[{"LoTELocation":"https://example.test/tl.xml"}]}}}}'` |

For canonical TS 119 612 V2.4.1 TLs and LoTLs, the root must carry the unqualified `TSLTag="http://uri.etsi.org/19612/TSLTag"`; schema validation and the exact registered-value check are reported independently. Detached compact JWS LoTL input is rejected because its payload is unavailable.

Interactive documentation is at `/docs`; `/openapi.yaml` is the authoritative machine-readable document and `/openapi.json` is derived from it.
