import { filterPackages, Package, FilterOptions, Severity } from '../src/report';
import { Report } from '../src/report';
import { Vuln } from '../src/report';
const fixtureReport : Report = require("../tests/fixtures/report-test.json"); // require is needed here, otherwise the import statement adds a .default attribute to the json

const basePkg = (vulns: Vuln[] = [], type = "os") => ({
  type,
  name: "foo",
  version: "1.0",
  path: "/foo",
  vulns
} as Package);

const vuln = (severity: string, acceptedRisks: any[] = []): Vuln => ({
  name: "CVE-1234",
  severity: { value: severity, sourceName: "sysdig" },
  cvssScore: { value: { version: "3.1", score: 7.5, vector: "AV:N/AC:L/..." }, sourceName: "sysdig" },
  disclosureDate: "2023-01-01",
  exploitable: true,
  fixedInVersion: "1.2",
  publishDateByVendor: { vulndb: "2023-01-01" },
  acceptedRisks,
});

describe("filterPackages", () => {

  it("filters by minSeverity", () => {
    const pkgs = [
      basePkg([vuln("high")]),
      basePkg([vuln("low")]),
    ];
    const filters: FilterOptions = { minSeverity: "high" };
    const result = filterPackages(pkgs, filters);
    expect(result.length).toBe(1);
    expect(result[0].vulns?.[0].severity.value).toBe("high");
  });

  it("filters by packageTypes", () => {
    const pkgs = [
      basePkg([vuln("high")], "os"),
      basePkg([vuln("high")], "java"),
    ];
    const filters: FilterOptions = { packageTypes: ["java"] };
    const result = filterPackages(pkgs, filters);
    expect(result.length).toBe(1);
    expect(result[0].type).toBe("java");
  });

  it("filters by notPackageTypes", () => {
    const pkgs = [
      basePkg([vuln("high")], "os"),
      basePkg([vuln("high")], "java"),
    ];
    const filters: FilterOptions = { notPackageTypes: ["os"] };
    const result = filterPackages(pkgs, filters);
    expect(result.length).toBe(1);
    expect(result[0].type).toBe("java");
  });

  it("filters out accepted risks if excludeAccepted is true", () => {
    const pkgs = [
      basePkg([vuln("high", [{ index: 1, ref: "ref", id: "id" }])]),
      basePkg([vuln("high", [])]),
    ];
    const filters: FilterOptions = { excludeAccepted: true };
    const result = filterPackages(pkgs, filters);
    expect(result.length).toBe(1);
    expect(result[0].vulns?.[0].acceptedRisks).toEqual([]);
  });

  it("removes packages with no vulns after filtering", () => {
    const pkgs = [
      basePkg([vuln("low", [{ index: 1, ref: "ref", id: "id" }])]),
    ];
    const filters: FilterOptions = { excludeAccepted: true };
    const result = filterPackages(pkgs, filters);
    expect(result.length).toBe(0);
  });
});

describe("filterPackages with fixture report", () => {

  it("should return only packages with critical vulnerabilities", () => {
    const filters: FilterOptions = { minSeverity: "Critical" as Severity };
    const pkgs = fixtureReport.result.packages;
    const result = filterPackages(pkgs, filters);

    expect(
      result.every(pkg => 
        pkg.vulns?.some(v => v.severity.value.toLowerCase() === "critical")
      )
    ).toBe(true);

    // CVE-2023-38545 is critical
    expect(JSON.stringify(result)).toContain("CVE-2023-38545");
    // CVE-2023-38546 is low
    expect(JSON.stringify(result)).not.toContain("CVE-2023-38546");
  });

  it("should exclude packages with only accepted risks when excludeAccepted is true", () => {
    const filters: FilterOptions = { excludeAccepted: true, minSeverity: "High" as Severity };
    const pkgs = fixtureReport.result.packages;
    const result = filterPackages(pkgs, filters);

    // Vuln with accepted risks should be removed
    expect(
      result.some(pkg =>
        pkg.vulns?.some(v => (v.acceptedRisks && v.acceptedRisks.length > 0))
      )
    ).toBe(false);
  });

  it("should filter by packageTypes", () => {
    const filters: FilterOptions = { packageTypes: ["os"] };
    const pkgs = fixtureReport.result.packages;
    const result = filterPackages(pkgs, filters);

    // All packages must be "os"
    expect(result.every(pkg => pkg.type === "os")).toBe(true);
  });

  it("should filter out 'os' packages when notPackageTypes is ['os']", () => {
    const filters: FilterOptions = { notPackageTypes: ["os"] };
    const pkgs = fixtureReport.result.packages;
    const result = filterPackages(pkgs, filters);

    // No package must be "os"
    expect(result.every(pkg => pkg.type !== "os")).toBe(true);
  });

  it("should remove packages with no vulns after filtering", () => {
    const filters: FilterOptions = { minSeverity: "Critical" as Severity };
    const pkgs = fixtureReport.result.packages;
    const result = filterPackages(pkgs, filters);

    // All packages must have at least on critical
    expect(result.every(pkg => pkg.vulns && pkg.vulns.length > 0)).toBe(true);
  });
});