import { AcceptedRisk } from './AcceptedRisk';
import { AcceptedRiskReason } from './AcceptedRiskReason';
import { Architecture } from './Architecture';
import { EvaluationResult } from './EvaluationResult';
import { Layer } from './Layer';
import { OperatingSystem } from './OperatingSystem';
import { Package } from './Package';
import { PackageType } from './PackageType';
import { Policy } from './Policy';
import { PolicyBundle } from './PolicyBundle';
import { ScanType } from './ScanType';
import { Severity } from './Severity';
import { Version } from './Version';
import { Vulnerability } from './Vulnerability';

export class Metadata {
  constructor(
    public readonly pullString: string,
    public readonly imageId: string,
    public readonly digest: string | null,
    public readonly baseOs: OperatingSystem,
    public readonly sizeInBytes: bigint,
    public readonly architecture: Architecture,
    public readonly labels: Record<string, string>,
    public readonly createdAt: Date
  ) { }
}

export class ScanResult {
  public readonly metadata: Metadata;
  private readonly layers: Layer[] = [];
  private readonly packages: Set<Package> = new Set();
  private readonly vulnerabilities: Map<string, Vulnerability> = new Map();
  private readonly policies: Map<string, Policy> = new Map();
  private readonly policyBundles: Map<string, PolicyBundle> = new Map();
  private readonly acceptedRisks: Map<string, AcceptedRisk> = new Map();
  private readonly evaluationResult: EvaluationResult;

  constructor(
    public readonly scanType: ScanType,
    pullString: string,
    imageId: string,
    digest: string | null,
    baseOs: OperatingSystem,
    sizeInBytes: bigint,
    architecture: Architecture,
    labels: Record<string, string>,
    createdAt: Date,
    evaluationResult: EvaluationResult
  ) {
    this.metadata = new Metadata(
      pullString,
      imageId,
      digest,
      baseOs,
      sizeInBytes,
      architecture,
      labels,
      createdAt
    );
    this.evaluationResult = evaluationResult;
  }

  addLayer(digest: string, index: number, size: bigint | null, command: string): Layer {
    const layer = new Layer(digest, index, size, command);
    this.layers.push(layer);
    return layer;
  }

  findLayerByDigest(digest: string): Layer | undefined {
    return this.layers.find((l) => l.digest === digest);
  }

  getLayers(): Layer[] {
    return [...this.layers].sort((a, b) => a.index - b.index);
  }

  addPackage(
    id: string,
    packageType: PackageType,
    name: string,
    version: string,
    path: string,
    foundInLayer: Layer
  ): Package {
    const pkg = new Package(id, packageType, name, new Version(version), path, foundInLayer);
    foundInLayer.addPackage(pkg);
    this.packages.add(pkg);
    return pkg;
  }

  getPackages(): Package[] {
    return Array.from(this.packages);
  }

  findPackageByID(id: string): Package | undefined {
    return this.getPackages().find(p => p.id == id)
  }

  addVulnerability(
    cve: string,
    severity: Severity,
    cvssScore: number,
    disclosureDate: Date,
    solutionDate: Date | null,
    exploitable: boolean,
    fixVersion: string | null
  ): Vulnerability {
    if (this.vulnerabilities.has(cve)) {
      return this.vulnerabilities.get(cve)!;
    }
    const vuln = new Vulnerability(
      cve,
      severity,
      cvssScore,
      disclosureDate,
      solutionDate,
      exploitable,
      fixVersion ? new Version(fixVersion) : null
    );
    this.vulnerabilities.set(cve, vuln);
    return vuln;
  }

  findVulnerabilityByCve(cve: string): Vulnerability | undefined {
    return this.vulnerabilities.get(cve);
  }

  getVulnerabilities(): Vulnerability[] {
    return Array.from(this.vulnerabilities.values());
  }

  addPolicy(id: string, name: string, createdAt: Date, updatedAt: Date): Policy {
    if (this.policies.has(id)) {
      return this.policies.get(id)!;
    }
    const policy = new Policy(id, name, createdAt, updatedAt);
    this.policies.set(id, policy);
    return policy;
  }

  findPolicyById(id: string): Policy | undefined {
    return this.policies.get(id);
  }

  getPolicies(): Policy[] {
    return Array.from(this.policies.values());
  }

  addPolicyBundle(id: string, name: string, policy: Policy): PolicyBundle {
    let bundle = this.policyBundles.get(id);
    if (!bundle) {
      bundle = new PolicyBundle(id, name);
      this.policyBundles.set(id, bundle);
    }
    bundle.addPolicy(policy);
    return bundle;
  }

  findPolicyBundleById(id: string): PolicyBundle | undefined {
    return this.policyBundles.get(id);
  }

  getPolicyBundles(): PolicyBundle[] {
    return Array.from(this.policyBundles.values());
  }

  addAcceptedRisk(
    id: string,
    reason: AcceptedRiskReason,
    description: string,
    expirationDate: Date | null,
    isActive: boolean,
    createdAt: Date,
    updatedAt: Date
  ): AcceptedRisk {
    if (this.acceptedRisks.has(id)) {
      return this.acceptedRisks.get(id)!;
    }
    const risk = new AcceptedRisk(
      id,
      reason,
      description,
      expirationDate,
      isActive,
      createdAt,
      updatedAt
    );
    this.acceptedRisks.set(id, risk);
    return risk;
  }

  findAcceptedRiskById(id: string): AcceptedRisk | undefined {
    return this.acceptedRisks.get(id);
  }

  getAcceptedRisks(): AcceptedRisk[] {
    return Array.from(this.acceptedRisks.values());
  }

  getEvaluationResult(): EvaluationResult {
    return this.evaluationResult;
  }
}
