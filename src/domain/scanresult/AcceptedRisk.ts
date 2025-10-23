import { AcceptedRiskReason } from './AcceptedRiskReason';
import { Package } from './Package';
import { Vulnerability } from './Vulnerability';

export class AcceptedRisk {
  private readonly assignedToVulnerabilities: Set<Vulnerability> = new Set();
  private readonly assignedToPackages: Set<Package> = new Set();

  constructor(
    public readonly id: string,
    public readonly reason: AcceptedRiskReason,
    public readonly description: string,
    public readonly expirationDate: Date | null,
    public readonly isActive: boolean,
    public readonly createdAt: Date,
    public readonly updatedAt: Date
  ) {}

  addForVulnerability(vulnerability: Vulnerability) {
    if (!this.assignedToVulnerabilities.has(vulnerability)) {
      this.assignedToVulnerabilities.add(vulnerability);
      vulnerability.addAcceptedRisk(this);
    }
  }

  getVulnerabilities(): Vulnerability[] {
    return Array.from(this.assignedToVulnerabilities);
  }

  addForPackage(pkg: Package) {
    if (!this.assignedToPackages.has(pkg)) {
      this.assignedToPackages.add(pkg);
      pkg.addAcceptedRisk(this);
    }
  }

  getPackages(): Package[] {
    return Array.from(this.assignedToPackages);
  }
}
