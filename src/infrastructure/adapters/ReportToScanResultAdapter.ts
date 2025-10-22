/* eslint-disable @typescript-eslint/no-explicit-any */
import { Report, Result as ReportResult, Metadata as ReportMetadata } from '../../domain/entities/report';
import {
  AcceptedRisk,
  AcceptedRiskReason,
  Architecture,
  EvaluationResult,
  Family,
  Layer,
  OperatingSystem,
  Package,
  PackageType,
  Policy,
  PolicyBundle,
  PolicyBundleRule,
  ScanResult,
  ScanType,
  Severity,
  Vulnerability,
} from '../../domain/scanresult';

// Helper interfaces to provide better typing than `any` for vulnerabilities and risks
interface JsonVulnerability {
  name: string;
  severity: string;
  disclosureDate: string;
  solutionDate?: string;
  exploitable: boolean;
  fixVersion?: string;
  riskAcceptRefs?: string[];
}

interface JsonRiskAccept {
  id: string;
  reason: string;
  description: string;
  expirationDate?: string;
  status: string;
  createdAt: string;
  updatedAt: string;
}

// --- Mappers from String to Domain Enum ---

function mapStringToSeverity(severity: string): Severity {
  switch (severity.toLowerCase()) {
    case 'critical':
      return Severity.Critical;
    case 'high':
      return Severity.High;
    case 'medium':
      return Severity.Medium;
    case 'low':
      return Severity.Low;
    case 'negligible':
      return Severity.Negligible;
    default:
      return Severity.Unknown;
  }
}

function mapStringToPackageType(type: string): PackageType {
  switch (type.toLowerCase()) {
    case 'c#':
      return PackageType.CSharp;
    case 'golang':
      return PackageType.Golang;
    case 'java':
      return PackageType.Java;
    case 'javascript':
      return PackageType.Javascript;
    case 'os':
      return PackageType.Os;
    case 'php':
      return PackageType.Php;
    case 'python':
      return PackageType.Python;
    case 'ruby':
      return PackageType.Ruby;
    case 'rust':
      return PackageType.Rust;
    default:
      return PackageType.Unknown;
  }
}

function mapStringToArchitecture(arch: string): Architecture {
  switch (arch.toLowerCase()) {
    case 'amd64':
      return Architecture.Amd64;
    case 'arm64':
      return Architecture.Arm64;
    default:
      return Architecture.Unknown;
  }
}

function mapStringToFamily(os: string): Family {
  switch (os.toLowerCase()) {
    case 'linux':
      return Family.Linux;
    case 'darwin':
      return Family.Darwin;
    case 'windows':
      return Family.Windows;
    default:
      return Family.Unknown;
  }
}

function mapStringToAcceptedRiskReason(reason: string): AcceptedRiskReason {
  const reasonMap: { [key: string]: AcceptedRiskReason } = {
    riskowned: AcceptedRiskReason.RiskOwned,
    risktransferred: AcceptedRiskReason.RiskTransferred,
    riskavoided: AcceptedRiskReason.RiskAvoided,
    riskmitigated: AcceptedRiskReason.RiskMitigated,
    risknotrelevant: AcceptedRiskReason.RiskNotRelevant,
    custom: AcceptedRiskReason.Custom,
  };
  return reasonMap[reason.toLowerCase()] || AcceptedRiskReason.Unknown;
}

function mapStringToEvaluationResult(result: string): EvaluationResult {
  return result.toLowerCase() === 'failed' ? EvaluationResult.Failed : EvaluationResult.Passed;
}

// --- Adapter Class ---

export class ReportToScanResultAdapter {
  public toScanResult(report: Report): ScanResult {
    const scanResult = this.createScanResult(report.result.metadata);
    const reportResult = report.result;

    this.addLayers(reportResult, scanResult);
    this.addAcceptedRisks(reportResult, scanResult);
    this.addVulnerabilities(reportResult, scanResult);
    this.addPackages(reportResult, scanResult);
    this.addPolicies(reportResult, scanResult);

    return scanResult;
  }

  private createScanResult(metadata: ReportMetadata): ScanResult {
    return new ScanResult(
      ScanType.Docker, // Assuming Docker scan type as in the Rust code
      metadata.pullString,
      metadata.imageId,
      metadata.digest,
      new OperatingSystem(mapStringToFamily(metadata.os), metadata.baseOs),
      BigInt(metadata.size),
      mapStringToArchitecture(metadata.architecture),
      metadata.labels ?? {},
      new Date(metadata.createdAt)
    );
  }

  private addLayers(reportResult: ReportResult, scanResult: ScanResult): void {
    for (const layerData of Object.values(reportResult.layers)) {
      scanResult.addLayer(
        layerData.digest ?? '',
        layerData.index,
        layerData.size ? BigInt(layerData.size) : null,
        layerData.command ?? ''
      );
    }
  }

  private addAcceptedRisks(reportResult: ReportResult, scanResult: ScanResult): void {
    for (const riskData of Object.values(reportResult.riskAccepts ?? {}) as JsonRiskAccept[]) {
      scanResult.addAcceptedRisk(
        riskData.id,
        mapStringToAcceptedRiskReason(riskData.reason),
        riskData.description,
        riskData.expirationDate ? new Date(riskData.expirationDate) : null,
        riskData.status.toLowerCase() === 'active',
        new Date(riskData.createdAt),
        new Date(riskData.updatedAt)
      );
    }
  }

  private addVulnerabilities(reportResult: ReportResult, scanResult: ScanResult): void {
    for (const vulnData of Object.values(reportResult.vulnerabilities) as JsonVulnerability[]) {
      const vulnerability = scanResult.addVulnerability(
        vulnData.name,
        mapStringToSeverity(vulnData.severity),
        new Date(vulnData.disclosureDate),
        vulnData.solutionDate ? new Date(vulnData.solutionDate) : null,
        vulnData.exploitable,
        vulnData.fixVersion ?? null
      );

      if (vulnData.riskAcceptRefs) {
        for (const riskRef of vulnData.riskAcceptRefs) {
          const riskData = reportResult.riskAccepts?.[riskRef];
          if (riskData) {
            const risk = scanResult.findAcceptedRiskById(riskData.id);
            if (risk) {
              vulnerability.addAcceptedRisk(risk);
            }
          }
        }
      }
    }
  }

  private addPackages(reportResult: ReportResult, scanResult: ScanResult): void {
    for (const pkgData of Object.values(reportResult.packages)) {
      const layerRef = reportResult.layers[pkgData.layerRef];
      if (!layerRef) continue;

      const layer = scanResult.findLayerByDigest(layerRef.digest ?? '');
      if (!layer) continue;

      const pkg = scanResult.addPackage(
        mapStringToPackageType(pkgData.type),
        pkgData.name,
        pkgData.version,
        pkgData.path,
        layer
      );

      if (pkgData.vulnerabilitiesRefs) {
        for (const vulnRef of pkgData.vulnerabilitiesRefs) {
          const jsonVuln = reportResult.vulnerabilities[vulnRef] as JsonVulnerability;
          if (jsonVuln) {
            const vulnerability = scanResult.findVulnerabilityByCve(jsonVuln.name);
            if (vulnerability) {
              pkg.addVulnerability(vulnerability);

              // Replicate indirect risk association from Rust code
              if (jsonVuln?.riskAcceptRefs) {
                for (const riskRef of jsonVuln.riskAcceptRefs) {
                  const riskData = reportResult.riskAccepts?.[riskRef];
                  if (riskData) {
                    const risk = scanResult.findAcceptedRiskById(riskData.id);
                    if (risk) {
                      pkg.addAcceptedRisk(risk);
                    }
                  }
                }
              }
            }
          }
        }
      }
    }
  }

  private addPolicies(reportResult: ReportResult, scanResult: ScanResult): void {
    for (const policyData of reportResult.policies.evaluations) {
      const policy = scanResult.addPolicy(
        policyData.identifier,
        policyData.name,
        new Date(policyData.createdAt),
        new Date(policyData.updatedAt)
      );

      for (const bundleData of policyData.bundles) {
        const bundle = scanResult.addPolicyBundle(
          bundleData.identifier,
          bundleData.name,
          policy
        );

        for (const ruleData of bundleData.rules) {
          const rule = new PolicyBundleRule(
            String(ruleData.ruleId),
            ruleData.description,
            mapStringToEvaluationResult(ruleData.evaluationResult),
            bundle
          );
          bundle.addRule(rule);

          for (const failureData of ruleData.failures ?? []) {
            if (ruleData.failureType === 'imageConfigFailure') {
              rule.addImageConfigFailure(failureData.remediation ?? 'N/A');
            } else if (ruleData.failureType === 'pkgVulnFailure') {
              rule.addPkgVulnFailure(
                this.getFailureMessage(
                  reportResult,
                  failureData.packageRef,
                  failureData.vulnerabilityRef
                )
              );
            }
          }
        }
      }
    }
  }

  private getFailureMessage(
    reportResult: ReportResult,
    packageRef: string,
    vulnerabilityRef: string
  ): string {
    const pkg = reportResult.packages[packageRef];
    const vuln = reportResult.vulnerabilities[vulnerabilityRef] as JsonVulnerability;

    if (pkg && vuln) {
      return `${vuln.name} found in ${pkg.name} (${pkg.version})`;
    }
    return `vuln ref ${vulnerabilityRef} found in package ref ${packageRef}`;
  }
}
