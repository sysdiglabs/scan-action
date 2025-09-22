import { filterPackages, Package, FilterOptions, Severity } from '../src/report';
import { Report } from '../src/report';
import { Vulnerability } from '../src/report';
const fixtureReport : Report = require("../tests/fixtures/report-test-v1.json"); // require is needed here, otherwise the import statement adds a .default attribute to the json

const newBasePkg = (vulnerabilitiesRefs: String[]  = [], type = "os") => ({
  type,
  name: "foo",
  version: "1.0",
  path: "/foo",
  vulnerabilitiesRefs
} as Package);

const newVuln = (severity: string, riskAcceptRefs: string[] = []): Vulnerability => ({
  name: "CVE-1234",
  severity: severity,
  cvssScore: { version: "3.1", score: 7.5, vector: "AV:N/AC:L/..." },
  mainProvider: "sysdig",
  disclosureDate: "2023-01-01",
  exploitable: true,
  fixVersion: "1.2",
  providersMetadata: { "vulndb": {publicationDate: "2023-01-01" }},
  riskAcceptRefs: riskAcceptRefs,
  packageRef: ""
});

const mockVulns: {[key:string]: Vulnerability} = {
  "id-high": newVuln("high"),
  "id-low": newVuln("low"),
};

describe("filterPackages", () => {

  it("filters by minSeverity", () => {
    const pkgs: {[key:string]: Package} = {
      "pkg1": newBasePkg(["id-high"]),
      "pkg2": newBasePkg(["id-low"]),
    };

    const filters: FilterOptions = { minSeverity: "high" };
    const result = Object.values(filterPackages(pkgs, mockVulns, filters));
    expect(result.length).toBe(1);
    expect(mockVulns[result[0].vulnerabilitiesRefs[0]].severity).toBe("high");
  });

  it("filters by packageTypes", () => {
    const pkgs = {
      "pkg1": newBasePkg(["id-high"], "os"),
      "pkg2": newBasePkg(["id-high"], "java"),
    };

    const filters: FilterOptions = { packageTypes: ["java"] };
    const result = Object.values(filterPackages(pkgs, mockVulns, filters));
    expect(result.length).toBe(1);
    expect(result[0].type).toBe("java");
  });

  it("filters by notPackageTypes", () => {
    const pkgs = {
      "pkg1": newBasePkg(["id-high"], "os"),
      "pkg2": newBasePkg(["id-high"], "java"),
    };

    const filters: FilterOptions = { notPackageTypes: ["os"] };
    const result =  Object.values(filterPackages(pkgs, mockVulns, filters));
    expect(result.length).toBe(1);
    expect(result[0].type).toBe("java");
  });

  it("filters out accepted risks if excludeAccepted is true", () => {
    const vulnsWithAcceptedRisk: {[key:string]: Vulnerability} = {
      "id-high": newVuln("high", ["some-accepted-risk"]),
      "id-low": newVuln("low"),
    };

    const pkgs = {
      "pkg1": newBasePkg(["id-high"], "os"),
      "pkg2": newBasePkg(["id-low"], "java"),
    };

    const filters: FilterOptions = { excludeAccepted: true };
    const result =  Object.values(filterPackages(pkgs, vulnsWithAcceptedRisk, filters));
    expect(result.length).toBe(1);
    expect(vulnsWithAcceptedRisk[result[0].vulnerabilitiesRefs[0]].riskAcceptRefs).toEqual([]);
  });

  it("removes packages with no vulns after filtering", () => {
    const vulnsWithAcceptedRisk: {[key:string]: Vulnerability} = {
      "id-high": newVuln("high", ["some-accepted-risk"]),
      "id-low": newVuln("low"),
    };

    const pkgs = {
      "pkg1": newBasePkg(["id-high"], "os"),
    };

    const filters: FilterOptions = { excludeAccepted: true };
    const result = Object.values(filterPackages(pkgs, vulnsWithAcceptedRisk, filters));
    expect(result.length).toBe(0);
  });
});

describe("filterPackages with fixture report", () => {

  it("should return only packages with critical vulnerabilities", () => {
    const filters: FilterOptions = { minSeverity: "Critical" as Severity };
    const pkgs = fixtureReport.result.packages;
    const vulns = fixtureReport.result.vulnerabilities;
    const result = filterPackages(pkgs, vulns, filters);

    expect(
      Object.values(result).every(pkg =>
        pkg.vulnerabilitiesRefs.every(ref => vulns[ref].severity.toLowerCase() === "critical")
      )
    ).toBe(true);

    // ref of CVE-2023-38545 (critical)
    expect(JSON.stringify(result)).toContain("f869c8ec-eda5-4725-82e4-d6588d3312a0");
    // ref of CVE-2024-50349 is low
    expect(JSON.stringify(result)).not.toContain("9caf0bbd-304b-4cc9-be2a-452205252daf");
  });

  it("should exclude packages with only accepted risks when excludeAccepted is true", () => {
    const filters: FilterOptions = { excludeAccepted: true, minSeverity: "High" as Severity };
    const pkgs = fixtureReport.result.packages;
    const vulns = fixtureReport.result.vulnerabilities;
    const result = filterPackages(pkgs, vulns, filters);

    // Vuln with accepted risks should be removed
    expect(
      Object.values(result).some(pkg =>
        pkg.vulnerabilitiesRefs.some(ref => (vulns[ref].riskAcceptRefs && vulns[ref].riskAcceptRefs.length > 0))
      )
    ).toBe(false);
  });

  it("should filter by packageTypes", () => {
    const filters: FilterOptions = { packageTypes: ["os"] };
    const pkgs = fixtureReport.result.packages;
    const vulns = fixtureReport.result.vulnerabilities;
    const result = filterPackages(pkgs, vulns, filters);

    // All packages must be "os"
    expect(Object.values(result).every(pkg => pkg.type === "os")).toBe(true);
  });

  it("should filter out 'os' packages when notPackageTypes is ['os']", () => {
    const filters: FilterOptions = { notPackageTypes: ["os"] };
    const pkgs = fixtureReport.result.packages;
    const vulns = fixtureReport.result.vulnerabilities;
    const result = filterPackages(pkgs, vulns, filters);

    // No package must be "os"
    expect(Object.values(result).every(pkg => pkg.type !== "os")).toBe(true);
  });

});
