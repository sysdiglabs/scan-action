import * as core from "@actions/core";
import { FilterOptions, filterPackages, Package, Severity, isSeverityGte, Report, Rule } from "./report";
import { ActionInputs } from "./action";

const EVALUATION: any = {
  "failed": "❌",
  "passed": "✅"
}

export async function generateSummary(opts: ActionInputs, data: Report, filters?: FilterOptions) {
  const filteredPkgs = filterPackages(data.result.packages, filters || {});
  let filteredData = { ...data, result: { ...data.result, packages: filteredPkgs } };

  core.summary.emptyBuffer().clear();
  core.summary.addHeading(`Scan Results for ${opts.overridePullString || opts.imageTag}`);

  addVulnTableToSummary(filteredData, filters?.minSeverity);
  addVulnsByLayerTableToSummary(filteredData);

  if (!opts.standalone) {
    addReportToSummary(data);
  }

  await core.summary.write({ overwrite: true });
}

const SEVERITY_LABELS: Record<Severity, string> = {
  critical: "🟣 Critical",
  high: "🔴 High",
  medium: "🟠 Medium",
  low: "🟡 Low",
  negligible: "⚪ Negligible"
};

function countVulnsBySeverity(
  packages: Package[],
  minSeverity?: Severity
): {
  total: Record<Severity, number>;
  fixable: Record<Severity, number>;
} {
  // Inicializamos todas las severidades
  const result = {
    total: { critical: 0, high: 0, medium: 0, low: 0, negligible: 0 },
    fixable: { critical: 0, high: 0, medium: 0, low: 0, negligible: 0 }
  };

  for (const pkg of packages) {
    for (const vuln of pkg.vulns ?? []) {
      const sev = vuln.severity.value.toLowerCase() as Severity;
      // Solo cuenta si cumple el minSeverity (o no hay minSeverity)
      if (!minSeverity || isSeverityGte(sev, minSeverity)) {
        result.total[sev]++;
        if (vuln.fixedInVersion || pkg.suggestedFix) {
          result.fixable[sev]++;
        }
      }
    }
  }
  return result;
}

function addVulnTableToSummary(
  data: Report,
  minSeverity?: Severity
) {
  const pkgs = data.result.packages;
  // Lista completa de severidades en orden, de mayor a menor
  const SEVERITY_ORDER: Severity[] = ["critical", "high", "medium", "low", "negligible"];

  // Solo mostramos las severidades >= minSeverity
  const visibleSeverities = SEVERITY_ORDER.filter(sev =>
    !minSeverity || isSeverityGte(sev, minSeverity)
  );

  const totalVulns = countVulnsBySeverity(pkgs, minSeverity);

  core.summary.addHeading(`Vulnerabilities summary`, 2);
  core.summary.addTable([
    [
      { data: '', header: true },
      ...visibleSeverities.map(s => ({ data: SEVERITY_LABELS[s], header: true }))
    ],
    [
      { data: '⚠️ Total Vulnerabilities', header: true },
      ...visibleSeverities.map(s => `${totalVulns.total[s] ?? 0}`)
    ],
    [
      { data: '🔧 Fixable Vulnerabilities', header: true },
      ...visibleSeverities.map(s => `${totalVulns.fixable[s] ?? 0}`)
    ],
  ]);
}

function addVulnsByLayerTableToSummary(data: Report) {
  if (!Array.isArray(data.result.layers) || data.result.layers.length === 0) {
    return;
  }

  core.summary.addHeading(`Package vulnerabilities per layer`, 2);

  let packagesPerLayer: { [key: string]: Package[] } = {};
  data.result.packages.forEach(layerPackage => {
    if (layerPackage.layerDigest) {
      packagesPerLayer[layerPackage.layerDigest] = (packagesPerLayer[layerPackage.layerDigest] ?? []).concat(layerPackage)
    }
  });

  data.result.layers.forEach((layer, index) => {
    core.summary.addCodeBlock(`LAYER ${index} - ${layer.command.replace(/\$/g, "&#36;").replace(/\&/g, '&amp;')}`);
    if (!layer.digest) {
      return;
    }

    let packagesWithVulns = (packagesPerLayer[layer.digest] ?? []).filter(pkg => pkg.vulns);
    if (packagesWithVulns.length === 0) {
      return;
    }

    let orderedPackagesBySeverity = packagesWithVulns.sort((a, b) => {
      const getSeverityCount = (pkg: Package, severity: string) =>
        pkg.vulns?.filter((vul: any) => vul.severity.value === severity).length || 0;

      const severities = ['Critical', 'High', 'Medium', 'Low', 'Negligible'];
      for (const severity of severities) {
        const countA = getSeverityCount(a, severity);
        const countB = getSeverityCount(b, severity);
        if (countA !== countB) {
          return countB - countA;
        }
      }
      return 0;
    });

    core.summary.addTable([
      [
        { data: 'Package', header: true },
        { data: 'Type', header: true },
        { data: 'Version', header: true },
        { data: 'Suggested fix', header: true },
        { data: '🟣 Critical', header: true },
        { data: '🔴 High', header: true },
        { data: '🟠 Medium', header: true },
        { data: '🟡 Low', header: true },
        { data: '⚪ Negligible', header: true },
        { data: 'Exploit', header: true },
      ],
      ...orderedPackagesBySeverity.map(layerPackage => {
        let criticalVulns = layerPackage.vulns?.filter(vuln => vuln.severity.value.toLowerCase() == 'critical').length ?? 0;
        let highVulns = layerPackage.vulns?.filter(vuln => vuln.severity.value.toLowerCase() == 'high').length ?? 0;
        let mediumVulns = layerPackage.vulns?.filter(vuln => vuln.severity.value.toLowerCase() == 'medium').length ?? 0;
        let lowVulns = layerPackage.vulns?.filter(vuln => vuln.severity.value.toLowerCase() == 'low').length ?? 0;
        let negligibleVulns = layerPackage.vulns?.filter(vuln => vuln.severity.value.toLowerCase() == 'negligible').length ?? 0;
        let exploits = layerPackage.vulns?.filter(vuln => vuln.exploitable).length ?? 0;
        return [
          { data: layerPackage.name },
          { data: layerPackage.type },
          { data: layerPackage.version },
          { data: layerPackage.suggestedFix || "" },
          { data: criticalVulns.toString() },
          { data: highVulns.toString() },
          { data: mediumVulns.toString() },
          { data: lowVulns.toString() },
          { data: negligibleVulns.toString() },
          { data: exploits.toString() },
        ]
      })
    ]);
  });
}

function addReportToSummary(data: Report) {
  let policyEvaluations = data.result.policyEvaluations;
  let packages = data.result.packages;

  core.summary.addHeading("Policy evaluation summary", 2)
  core.summary.addRaw(`Evaluation result: ${data.result.policyEvaluationsResult} ${EVALUATION[data.result.policyEvaluationsResult]}`);


  let table: { data: string, header?: boolean }[][] = [[
    { data: 'Policy', header: true },
    { data: 'Evaluation', header: true },
  ]];

  policyEvaluations.forEach(policy => {
    table.push([
      { data: `${policy.name}` },
      { data: `${EVALUATION[policy.evaluationResult]}` },
    ]);
  });

  core.summary.addTable(table);

  core.summary.addHeading("Policy failures", 2)

  policyEvaluations.forEach(policy => {
    if (policy.evaluationResult != "passed") {
      core.summary.addHeading(`Policy: ${policy.name}`, 3)
      policy.bundles.forEach(bundle => {
        core.summary.addHeading(`Rule Bundle: ${bundle.name}`, 4)

        bundle.rules.forEach(rule => {
          core.summary.addHeading(`Rule: ${rule.description}`, 5)

          if (rule.evaluationResult != "passed") {
            if (rule.failureType == "pkgVulnFailure") {
              getRulePkgMessage(rule, packages)
            } else {
              getRuleImageMessage(rule)
            }
          }
        });
      });
    }
  });

}

function getRulePkgMessage(rule: Rule, packages: Package[]) {
  let table: { data: string, header?: boolean }[][] = [[
    { data: 'Severity', header: true },
    { data: 'Package', header: true },
    { data: 'CVSS Score', header: true },
    { data: 'CVSS Version', header: true },
    { data: 'CVSS Vector', header: true },
    { data: 'Fixed Version', header: true },
    { data: 'Exploitable', header: true }]];

  rule.failures?.forEach(failure => {
    let pkgIndex = failure.pkgIndex ?? 0;
    let vulnInPkgIndex = failure.vulnInPkgIndex ?? 0;

    let pkg = packages[pkgIndex];
    let vuln = pkg.vulns?.at(vulnInPkgIndex);

    if (vuln) {
      table.push([
        { data: `${vuln.severity.value.toString()}` },
        { data: `${pkg.name}` },
        { data: `${vuln.cvssScore.value.score}` },
        { data: `${vuln.cvssScore.value.version}` },
        { data: `${vuln.cvssScore.value.vector}` },
        { data: `${pkg.suggestedFix || "No fix available"}` },
        { data: `${vuln.exploitable}` },
      ]);
    }
  });

  core.summary.addTable(table);
}

function getRuleImageMessage(rule: Rule) {
  let message: string[] = [];


  rule.failures?.map(failure => failure.remediation);
  rule.failures?.forEach(failure => {
    message.push(`${failure.remediation}`)
  });

  core.summary.addList(message);
}
