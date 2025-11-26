/* eslint-disable @typescript-eslint/no-explicit-any */
import { JsonScanResultV1, JsonResult as ReportResult, JsonMetadata as ReportMetadata, JsonLayer as JsonLayer, JsonRiskAccept, JsonVulnerability } from './JsonScanResultV1';
import {
  AcceptedRiskReason,
  Architecture,
  EvaluationResult,
  Family,
  OperatingSystem,
  PackageType,
  PolicyBundleRuleImageConfig,
  PolicyBundleRulePkgVuln,
  ScanResult,
  ScanType,
  Severity,
} from '../../domain/scanresult';

// Helper interfaces to provide better typing than `any` for vulnerabilities and risks
export class JsonScanResultV1ToScanResultAdapter {
  public toScanResult(report: JsonScanResultV1): ScanResult {
    const scanResult = this.createScanResult(report);
    const reportResult = report.result;

    this.addLayers(reportResult, scanResult);
    this.addAcceptedRisks(reportResult, scanResult);
    this.addVulnerabilities(reportResult, scanResult);
    this.addPackages(reportResult, scanResult);
    this.addPolicies(reportResult, scanResult);

    return scanResult;
  }

  private createScanResult(report: JsonScanResultV1): ScanResult {
    const metadata = report.result.metadata;
    return new ScanResult(
      ScanType.Docker, // Assuming Docker scan type as in the Rust code
      metadata.pullString,
      metadata.imageId,
      metadata.digest,
      new OperatingSystem(Family.fromString(metadata.os), metadata.baseOs),
      BigInt(metadata.size),
      Architecture.fromString(metadata.architecture),
      metadata.labels ?? {},
      new Date(metadata.createdAt),
      EvaluationResult.fromString(report.result.policies.globalEvaluation)
    );
  }

  private addLayers(reportResult: ReportResult, scanResult: ScanResult): void {
    for (const layerData of Object.values(reportResult.layers) as JsonLayer[]) {
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
        AcceptedRiskReason.fromString(riskData.reason),
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
        Severity.fromString(vulnData.severity),
        vulnData.cvssScore.score,
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
    for (const key in reportResult.packages) {
      const pkgData = reportResult.packages[key];
      const JsonLayer = reportResult.layers[pkgData.layerRef];
      if (!JsonLayer) continue;

      const layer = scanResult.findLayerByDigest(JsonLayer.digest ?? '');
      if (!layer) continue;

      const pkg = scanResult.addPackage(
        key,
        PackageType.fromString(pkgData.type),
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

          if (ruleData.failureType === 'imageConfigFailure') {
            const rule = new PolicyBundleRuleImageConfig(
              String(ruleData.ruleId),
              ruleData.description,
              EvaluationResult.fromString(ruleData.evaluationResult),
              bundle
            );
            for (const failureData of ruleData.failures ?? []) {
              rule.addFailure(failureData.remediation ?? 'N/A');
            }
            bundle.addRule(rule);
          }

          if (ruleData.failureType === 'pkgVulnFailure') {
            const rule = new PolicyBundleRulePkgVuln(
              String(ruleData.ruleId),
              ruleData.description,
              EvaluationResult.fromString(ruleData.evaluationResult),
              bundle
            );
            for (const failureData of ruleData.failures ?? []) {
              const pkg = scanResult.findPackageByID(failureData.packageRef)!;
              let jsonVuln = reportResult.vulnerabilities[failureData.vulnerabilityRef] as JsonVulnerability;
              const vuln = scanResult.findVulnerabilityByCve(jsonVuln.name)!;

              rule.addFailure(
                failureData.description || "",
                pkg,
                vuln
              );
            }

            bundle.addRule(rule);
          }
        }
      }
    }
  }

}
