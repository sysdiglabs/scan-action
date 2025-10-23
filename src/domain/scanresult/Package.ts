import { AcceptedRisk } from './AcceptedRisk';
import { Layer } from './Layer';
import { PackageType } from './PackageType';
import { Severity } from './Severity';
import { Version } from './Version';
import { Vulnerability } from './Vulnerability';

export class Package {
  private readonly vulnerabilities: Set<Vulnerability> = new Set();
  private readonly acceptedRisks: Set<AcceptedRisk> = new Set();

  constructor(
    readonly id: string,
    public readonly packageType: PackageType,
    public readonly name: string,
    public readonly version: Version,
    public readonly path: string,
    public readonly foundInLayer: Layer
  ) { }

  addVulnerability(vulnerability: Vulnerability) {
    if (!this.vulnerabilities.has(vulnerability)) {
      this.vulnerabilities.add(vulnerability);
      vulnerability.addFoundInPackage(this);
    }
  }

  getVulnerabilities(): Vulnerability[] {
    return Array.from(this.vulnerabilities);
  }

  addAcceptedRisk(risk: AcceptedRisk) {
    if (!this.acceptedRisks.has(risk)) {
      this.acceptedRisks.add(risk);
      risk.addForPackage(this);
    }
  }

  getAcceptedRisks(): AcceptedRisk[] {
    return Array.from(this.acceptedRisks);
  }

  suggestedFixVersion(): Version | undefined {
    const vulnerabilities = this.getVulnerabilities();
    if (vulnerabilities.length === 0) {
      return undefined;
    }

    const candidateVersions = vulnerabilities
      .filter((vuln) => vuln.fixVersion)
      .map((vuln) => vuln.fixVersion!)
      .reduce((unique: Version[], item: Version) => {
        if (!unique.some((v) => v.equals(item))) {
          unique.push(item);
        }
        return unique;
      }, []);

    if (candidateVersions.length === 0) {
      return undefined;
    }

    const severityOrder = [
      Severity.Critical,
      Severity.High,
      Severity.Medium,
      Severity.Low,
      Severity.Negligible,
      Severity.Unknown,
    ];

    const scores = new Map<Version, Map<Severity, number>>();

    for (const candidate of candidateVersions) {
      const score = new Map<Severity, number>();
      for (const severity of severityOrder) {
        score.set(severity, 0);
      }

      for (const vuln of vulnerabilities) {
        if (vuln.fixVersion && vuln.fixVersion.equals(candidate)) { // fixVersion == candidate
          const currentCount = score.get(vuln.severity) || 0;
          score.set(vuln.severity, currentCount + 1);
        }
      }
      scores.set(candidate, score);
    }

    candidateVersions.sort((a, b) => {
      const scoreA = scores.get(a)!;
      const scoreB = scores.get(b)!;

      for (const severity of severityOrder) {
        const countA = scoreA.get(severity)!;
        const countB = scoreB.get(severity)!;
        if (countA !== countB) {
          return countB - countA; // Higher count is better
        }
      }

      // If scores are identical, lower version is better
      return a.greaterThan(b) ? 1 : (a.lessThan(b) ? -1 : 0);
    });

    return candidateVersions[0];
  }
}
