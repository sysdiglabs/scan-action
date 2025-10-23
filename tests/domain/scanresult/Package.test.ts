import { Package } from '../../../src/domain/scanresult/Package';
import { PackageType } from '../../../src/domain/scanresult/PackageType';
import { Version } from '../../../src/domain/scanresult/Version';
import { Vulnerability } from '../../../src/domain/scanresult/Vulnerability';
import { Severity } from '../../../src/domain/scanresult/Severity';
import { Layer } from '../../../src/domain/scanresult/Layer';

describe('Package', () => {
  const dummyLayer = new Layer('sha256:dummy', 0, BigInt(0), 'dummy command');

  describe('suggestedFixVersion', () => {
    it('should return undefined if there are no vulnerabilities', () => {
      const pkg = new Package('id1', PackageType.Javascript, 'test-pkg', new Version('1.0.0'), '/path', dummyLayer);
      expect(pkg.suggestedFixVersion()).toBeUndefined();
    });

    it('should return undefined if no vulnerabilities are fixable', () => {
      const pkg = new Package('id1', PackageType.Javascript, 'test-pkg', new Version('1.0.0'), '/path', dummyLayer);
      const vuln = new Vulnerability('CVE-1', Severity.High, 7.5, new Date(), null, false, null);
      pkg.addVulnerability(vuln);
      expect(pkg.suggestedFixVersion()).toBeUndefined();
    });

    it('should return the only available fix version', () => {
      const pkg = new Package('id1', PackageType.Javascript, 'test-pkg', new Version('1.0.0'), '/path', dummyLayer);
      const vuln = new Vulnerability('CVE-1', Severity.High, 7.5, new Date(), null, false, new Version('1.0.1'));
      pkg.addVulnerability(vuln);
      expect(pkg.suggestedFixVersion()?.toString()).toBe('1.0.1');
    });

    it('should choose the version that fixes more critical vulnerabilities', () => {
      const pkg = new Package('id1', PackageType.Javascript, 'test-pkg', new Version('1.0.0'), '/path', dummyLayer);
      // Fix for 1.1
      pkg.addVulnerability(new Vulnerability('CVE-1', Severity.Critical, 9.0, new Date(), null, false, new Version('1.1.0')));
      pkg.addVulnerability(new Vulnerability('CVE-2', Severity.High, 7.5, new Date(), null, false, new Version('1.1.0')));
      // Fix for 1.2
      pkg.addVulnerability(new Vulnerability('CVE-3', Severity.Critical, 9.1, new Date(), null, false, new Version('1.2.0')));
      pkg.addVulnerability(new Vulnerability('CVE-4', Severity.Critical, 9.8, new Date(), null, false, new Version('1.2.0')));

      // Score 1.1.0: {Crit: 1, High: 1}
      // Score 1.2.0: {Crit: 2, High: 0}
      // 1.2.0 wins
      expect(pkg.suggestedFixVersion()?.toString()).toBe('1.2.0');
    });

    it('should choose the version that fixes more high vulnerabilities when criticals are tied', () => {
      const pkg = new Package('id1', PackageType.Javascript, 'test-pkg', new Version('1.0.0'), '/path', dummyLayer);
      // Fix for 1.1
      pkg.addVulnerability(new Vulnerability('CVE-1', Severity.Critical, 9.0, new Date(), null, false, new Version('1.1.0')));
      pkg.addVulnerability(new Vulnerability('CVE-2', Severity.High, 7.5, new Date(), null, false, new Version('1.1.0')));
      pkg.addVulnerability(new Vulnerability('CVE-6', Severity.High, 7.5, new Date(), null, false, new Version('1.1.0')));
      // Fix for 1.2
      pkg.addVulnerability(new Vulnerability('CVE-3', Severity.Critical, 9.1, new Date(), null, false, new Version('1.2.0')));
      pkg.addVulnerability(new Vulnerability('CVE-4', Severity.High, 8.0, new Date(), null, false, new Version('1.2.0')));

      // Score 1.1.0: {Crit: 1, High: 2}
      // Score 1.2.0: {Crit: 1, High: 1}
      // 1.1.0 wins
      expect(pkg.suggestedFixVersion()?.toString()).toBe('1.1.0');
    });

    it('should choose the lower version when vulnerability counts are identical', () => {
      const pkg = new Package('id1', PackageType.Javascript, 'test-pkg', new Version('1.0.0'), '/path', dummyLayer);
      // Fix for 1.1
      pkg.addVulnerability(new Vulnerability('CVE-1', Severity.Critical, 9.0, new Date(), null, false, new Version('1.1.0')));
      // Fix for 1.2
      pkg.addVulnerability(new Vulnerability('CVE-2', Severity.Critical, 9.1, new Date(), null, false, new Version('1.2.0')));

      // Scores are identical ({Crit: 1}), 1.1.0 is lower version
      expect(pkg.suggestedFixVersion()?.toString()).toBe('1.1.0');
    });

    it('should handle complex scenario from prompt correctly (non-cumulative)', () => {
      const pkg = new Package('id1', PackageType.Javascript, 'libreria-X', new Version('1.0'), '/path', dummyLayer);
      const vulnA = new Vulnerability('A', Severity.Critical, 9.0, new Date(), null, false, new Version('1.1'));
      const vulnB = new Vulnerability('B', Severity.High, 8.0, new Date(), null, false, new Version('1.1'));
      const vulnC = new Vulnerability('C', Severity.Critical, 9.5, new Date(), null, false, new Version('1.2'));
      pkg.addVulnerability(vulnA);
      pkg.addVulnerability(vulnB);
      pkg.addVulnerability(vulnC);

      // Candidate 1.1 fixes A (Crit) and B (High). Score: {Crit: 1, High: 1}
      // Candidate 1.2 fixes C (Crit). Score: {Crit: 1, High: 0}
      // Criticals are tied. 1.1 wins because it fixes more Highs.
      expect(pkg.suggestedFixVersion()?.toString()).toBe('1.1');
    });
  });
});
