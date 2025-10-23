import { AcceptedRisk } from './AcceptedRisk';
import { Layer } from './Layer';
import { PackageType } from './PackageType';
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
}
