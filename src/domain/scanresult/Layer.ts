import { Package } from './Package';
import { Vulnerability } from './Vulnerability';

export class Layer {
  private readonly packages: Set<Package> = new Set();

  constructor(
    public readonly digest: string,
    public readonly index: number,
    public readonly size: bigint | null,
    public readonly command: string
  ) {}

  addPackage(pkg: Package) {
    this.packages.add(pkg);
  }

  getPackages(): Package[] {
    return Array.from(this.packages);
  }

  getVulnerabilities(): Vulnerability[] {
    const vulnerabilities = new Set<Vulnerability>();
    for (const pkg of this.packages) {
      for (const vuln of pkg.getVulnerabilities()) {
        vulnerabilities.add(vuln);
      }
    }
    return Array.from(vulnerabilities);
  }
}
