import { vulnerabilities2SARIF } from "../src/sarif"
import { Report } from "../src/report";
const fixtureReport: Report = require("../tests/fixtures/report-test-v1.json"); // require is needed here, otherwise the import statement adds a .default attribute to the json
const fixtureSarif = require("../tests/fixtures/sarif-test.json"); // require is needed here, otherwise the import statement adds a .default attribute to the json

describe("input parsing", () => {
  describe("when the result contains vulnerabilities", () => {
    it("returns the sarif format", () => {
      const someReport: Report = fixtureReport;
      const groupByPackage = false;
      const sarifGenerated = vulnerabilities2SARIF(someReport, groupByPackage)

      expect(sarifGenerated).toEqual(fixtureSarif);
    })
  })

  describe("when the result does not contain vulnerabilities", () => {
    it("returns the sarif format with the minimal response", () => {
      let someReportWithoutVulns: Report = removeVulnsFromReport(fixtureReport);

      const groupByPackage = false;
      const sarifGenerated = vulnerabilities2SARIF(someReportWithoutVulns, groupByPackage)

      expect(sarifGenerated).toEqual({
        "$schema": "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json",
        version: "2.1.0",
        runs: [{
          tool: {
            driver: {
              name: "sysdig-cli-scanner",
              fullName: "Sysdig Vulnerability CLI Scanner",
              informationUri: "https://docs.sysdig.com/en/docs/installation/sysdig-secure/install-vulnerability-cli-scanner",
              version: "6.1.2",
              semanticVersion: "6.1.2",
              dottedQuadFileVersion: "6.1.2.0",
              rules: []
            }
          },
          logicalLocations: [
            {
              name: "container-image",
              fullyQualifiedName: "container-image",
              kind: "namespace"
            }
          ],
          results: [],
          columnKind: "utf16CodeUnits",
          properties: {
            architecture: "amd64",
            baseOs: "alpine 3.18.0",
            digest: "sha256:345ba1354949b1c66802fef1d048e89399d6f0116d4eea31d81c789b69b30b29",
            imageId: "sha256:2208f3cc77d0c6bc66fd8ff18e25628df8e9d759e7aa82fe9c7c84f254ff0237",
            layersCount: 45,
            os: "linux",
            pullString: "jenkins/jenkins:2.401.1-alpine",
            resultId: "184768dcba2c920060cded4596d76970",
            resultUrl: "https://us2.app.sysdig.com/secure/#/vulnerabilities/results/184768dcba2c920060cded4596d76970/overview",
            size: 259845632,
          }
        }]
      });
    })
  })
})

const removeVulnsFromReport = (report: Report): Report => {
  return {
    ...report,
    result: {
      ...report.result,
      packages: Object.fromEntries(Object.entries(report.result.packages).map(([key, pkg]) => ([key, {
        ...pkg,
        vulnerabilitiesRefs: [],
      }])))
    }
  };
};


describe("SARIF filtering", () => {
  it("respects minSeverity", () => {
    const sarif = vulnerabilities2SARIF(fixtureReport, false, { minSeverity: "critical" });

    expect(JSON.stringify(sarif)).toContain("\"critical\"");
    expect(JSON.stringify(sarif)).toContain("CVE-2023-38545");
    expect(JSON.stringify(sarif)).not.toContain("\"high\"");
    expect(JSON.stringify(sarif)).not.toContain("CVE-2023-38039");
    expect(JSON.stringify(sarif)).not.toContain("\"medium\"");
    expect(JSON.stringify(sarif)).not.toContain("CVE-2023-42364");
  });

  it("respects packageTypes", () => {
    const sarif = vulnerabilities2SARIF(fixtureReport, false, { packageTypes: ["os"] });
    expect(JSON.stringify(sarif)).toContain("CVE-2023-42365");
    expect(JSON.stringify(sarif)).not.toContain("CVE-2023-42503");
  });

  it("respects excludeAccepted", () => {
    const sarif = vulnerabilities2SARIF(fixtureReport, false, { excludeAccepted: true });
    expect(JSON.stringify(sarif)).not.toContain("CVE-2016-1000027");
  });
});
