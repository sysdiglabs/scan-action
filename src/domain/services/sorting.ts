import { Package, Severity } from "../scanresult";

export function sortPackagesByVulnSeverity(packages: Package[]): Package[] {
    return packages.sort((a, b) => {
        for (const severity of Severity.getValues()) {
            const aCount = a.getVulnerabilities().filter(v => v.severity.isEqualTo(severity)).length;
            const bCount = b.getVulnerabilities().filter(v => v.severity.isEqualTo(severity)).length;
            if (aCount !== bCount) {
                return bCount - aCount;
            }
        }
        return 0;
    });
}
