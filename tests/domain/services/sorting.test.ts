import { sortPackagesByVulnSeverity } from '../../../src/domain/services/sorting';
import { Package } from '../../../src/domain/scanresult/Package';
import { PackageType } from '../../../src/domain/scanresult/PackageType';
import { Version } from '../../../src/domain/scanresult/Version';
import { Vulnerability } from '../../../src/domain/scanresult/Vulnerability';
import { Severity } from '../../../src/domain/scanresult/Severity';
import { Layer } from '../../../src/domain/scanresult/Layer';

describe('sorting', () => {
    const dummyLayer = new Layer('sha256:dummy', 0, BigInt(0), 'dummy command');

    function createPackage(name: string, severities: Severity[]): Package {
        const pkg = new Package('id-' + name, PackageType.Javascript, name, new Version('1.0.0'), '/path', dummyLayer);
        severities.forEach((sev, index) => {
            const vuln = new Vulnerability(`CVE-${name}-${index}`, sev, 5.0, new Date(), null, false, null);
            pkg.addVulnerability(vuln);
        });
        return pkg;
    }

    it('should sort packages by critical vulnerabilities', () => {
        const p1 = createPackage('p1', [Severity.High]);
        const p2 = createPackage('p2', [Severity.Critical]);

        const sorted = sortPackagesByVulnSeverity([p1, p2]);

        expect(sorted[0].name).toBe('p2');
        expect(sorted[1].name).toBe('p1');
    });

    it('should sort by high vulnerabilities when criticals are equal', () => {
        const p1 = createPackage('p1', [Severity.Critical, Severity.Medium]);
        const p2 = createPackage('p2', [Severity.Critical, Severity.High]);

        const sorted = sortPackagesByVulnSeverity([p1, p2]);

        expect(sorted[0].name).toBe('p2');
        expect(sorted[1].name).toBe('p1');
    });

    it('should sort correctly with multiple packages', () => {
        const p1 = createPackage('p1', [Severity.Medium]);
        const p2 = createPackage('p2', [Severity.Critical]);
        const p3 = createPackage('p3', [Severity.High, Severity.High]);
        const p4 = createPackage('p4', [Severity.High, Severity.Low]);

        // Expected order:
        // p2 (1 Crit)
        // p3 (2 High)
        // p4 (1 High)
        // p1 (0 Crit, 0 High)

        const sorted = sortPackagesByVulnSeverity([p1, p2, p3, p4]);

        expect(sorted.map(p => p.name)).toEqual(['p2', 'p3', 'p4', 'p1']);
    });

    it('should maintain order for identical severity counts (stable sort usually preferred but implementation might vary, mostly checking no crash)', () => {
        const p1 = createPackage('p1', [Severity.High]);
        const p2 = createPackage('p2', [Severity.High]);

        const sorted = sortPackagesByVulnSeverity([p1, p2]);
        expect(sorted.length).toBe(2);
        // The current implementation uses Array.sort which is stable in modern JS engines,
        // but if the comparison function returns 0, order is preserved.
        // We just ensure both are present.
        expect(sorted).toContain(p1);
        expect(sorted).toContain(p2);
    });
});
