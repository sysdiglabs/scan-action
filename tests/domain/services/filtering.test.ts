import { FilterOptions, filterPackages } from '../../../src/domain/services/filtering';
import { Package, PackageType, Severity, Vulnerability, Layer, AcceptedRisk, AcceptedRiskReason, Version } from '../../../src/domain/scanresult';

const newVuln = (name: string, severity: Severity): Vulnerability => {
    return new Vulnerability(name, severity, 0, new Date(), null, false, new Version("1.1"));
};

const newLayer = (digest: string = "sha256:dummy"): Layer => {
    return new Layer(digest, 0, null, "cmd");
}

const newPkg = (name: string, type: PackageType, vulnerabilities: Vulnerability[] = []): Package => {
    const pkg = new Package(name, type, name, new Version("1.0"), "/foo", newLayer());
    vulnerabilities.forEach(v => pkg.addVulnerability(v));
    return pkg;
};

const newAcceptedRisk = (): AcceptedRisk => {
    return new AcceptedRisk("id", AcceptedRiskReason.RiskOwned, "desc", null, true, new Date(), new Date());
}


describe("filterPackages", () => {
    const highVuln = newVuln("CVE-high", Severity.High);
    const lowVuln = newVuln("CVE-low", Severity.Low);

    it("filters by minSeverity", () => {
        const pkgs = [
            newPkg("pkg1", PackageType.Os, [highVuln, lowVuln]),
            newPkg("pkg2", PackageType.Os, [lowVuln]),
        ];

        const filters: FilterOptions = { minSeverity: Severity.High };
        const result = filterPackages(pkgs, filters);
        expect(result.length).toBe(1);
        expect(result[0].name).toBe("pkg1");
    });

    it("filters by packageTypes", () => {
        const pkgs = [
            newPkg("pkg1", PackageType.Os, [highVuln]),
            newPkg("pkg2", PackageType.Java, [highVuln]),
        ];

        const filters: FilterOptions = { packageTypes: ["java"] };
        const result = filterPackages(pkgs, filters);
        expect(result.length).toBe(1);
        expect(result[0].name).toBe("pkg2");
    });

    it("filters by notPackageTypes", () => {
        const pkgs = [
            newPkg("pkg1", PackageType.Os, [highVuln]),
            newPkg("pkg2", PackageType.Java, [highVuln]),
        ];

        const filters: FilterOptions = { notPackageTypes: ["os"] };
        const result = filterPackages(pkgs, filters);
        expect(result.length).toBe(1);
        expect(result[0].name).toBe("pkg2");
    });

    it("filters out accepted risks if excludeAccepted is true", () => {
        const pkgWithAcceptedRisk = newPkg("pkg1", PackageType.Os, [highVuln]);
        pkgWithAcceptedRisk.addAcceptedRisk(newAcceptedRisk());

        const pkgWithoutAcceptedRisk = newPkg("pkg2", PackageType.Java, [lowVuln]);

        const pkgs = [pkgWithAcceptedRisk, pkgWithoutAcceptedRisk];

        const filters: FilterOptions = { excludeAccepted: true };
        const result = filterPackages(pkgs, filters);
        expect(result.length).toBe(1);
        expect(result[0].name).toBe("pkg2");
    });

    it("returns empty array if all packages are filtered out", () => {
        const pkgs = [
            newPkg("pkg1", PackageType.Os, [lowVuln]),
        ];

        const filters: FilterOptions = { minSeverity: Severity.High };
        const result = filterPackages(pkgs, filters);
        expect(result.length).toBe(0);
    });

    it("should not filter if no filters are provided", () => {
        const pkgs = [
            newPkg("pkg1", PackageType.Os, [highVuln]),
            newPkg("pkg2", PackageType.Java, [lowVuln]),
        ];

        const filters: FilterOptions = {};
        const result = filterPackages(pkgs, filters);
        expect(result.length).toBe(2);
    });
});
