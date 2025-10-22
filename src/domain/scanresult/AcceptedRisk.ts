import { AcceptedRiskReason } from './AcceptedRiskReason';
import { Package } from './Package';
import { Vulnerability } from './Vulnerability';

export class AcceptedRisk {
  private readonly assignedToVulnerabilities: WeakSet<Vulnerability> = new WeakSet();
  private readonly assignedToPackages: WeakSet<Package> = new WeakSet();

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

  addForPackage(pkg: Package) {
    if (!this.assignedToPackages.has(pkg)) {
      this.assignedToPackages.add(pkg);
      pkg.addAcceptedRisk(this);
    }
  }
}
