import { vulnerabilities2SARIF } from "../src/sarif"
import { Report } from "../src/report";
const fixtureReport: Report = require("../tests/fixtures/report-test.json"); // require is needed here, otherwise the import statement adds a .default attribute to the json
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
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        version: "2.1.0",
        runs: [{
          tool: {
            driver: {
              name: "sysdig-cli-scanner",
              fullName: "Sysdig Vulnerability CLI Scanner",
              informationUri: "https://docs.sysdig.com/en/docs/installation/sysdig-secure/install-vulnerability-cli-scanner",
              version: "5.1.2",
              semanticVersion: "5.1.2",
              dottedQuadFileVersion: "5.1.2.0",
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
            layersCount: 12,
            os: "linux",
            pullString: "jenkins/jenkins:2.401.1-alpine",
            resultId: "17e69f1c42f0d322164d17ab30e34730",
            resultUrl: "https://secure.sysdig.com/#/vulnerabilities/results/17e69f1c42f0d322164d17ab30e34730/overview",
            size: 259845632,
          }
        }]
      });
    })
  })
})

const removeVulnsFromReport = (report: Report): Report => {
  report.result.packages = report.result.packages.map(pkg => ({
    ...pkg,
    vulns: [],
  }));
  return report;

}
