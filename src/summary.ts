import * as core from "@actions/core";
import { FilterOptions, filterPackages, Package, Vulnerability, Severity, isSeverityGte, Report, Rule, Layer, SeverityNames } from "./report";
import { ActionInputs } from "./action";

const EVALUATION: any = {
  "failed": "❌",
  "passed": "✅"
}

export async function generateSummary(opts: ActionInputs, data: Report, filters?: FilterOptions) {
  const filteredPkgs = filterPackages(data.result.packages, data.result.vulnerabilities, filters || {});
  let filteredData = { ...data, result: { ...data.result, packages: filteredPkgs } };

  core.summary.emptyBuffer().clear();
  core.summary.addHeading(`Scan Results for ${opts.overridePullString || opts.imageTag}`);

  addVulnTableToSummary(filteredData, filters?.minSeverity);
  addVulnsByLayerTableToSummary(filteredData, filters?.minSeverity);

  if (!opts.standalone) {
    addReportToSummary(data);
  }

  await core.summary.write({ overwrite: true });
}

const SEVERITY_ORDER: Severity[] = ["critical", "high", "medium", "low", "negligible"];

const SEVERITY_LABELS: Record<Severity, string> = {
  critical: "🟣 Critical",
  high: "🔴 High",
  medium: "🟠 Medium",
  low: "🟡 Low",
  negligible: "⚪ Negligible"
};

function countVulnsBySeverity(
  packages:  { [key: string]: Package },
  vulnerabilities: { [key: string]: Vulnerability },
  minSeverity?: Severity
): {
  total: Record<Severity, number>;
  fixable: Record<Severity, number>;
} {
  const result = {
    total: { critical: 0, high: 0, medium: 0, low: 0, negligible: 0 },
    fixable: { critical: 0, high: 0, medium: 0, low: 0, negligible: 0 }
  };

  for (const pkg of Object.values(packages)) {
    for (const vulnRef of pkg.vulnerabilitiesRefs ?? []) {
      const vuln = vulnerabilities[vulnRef];
      const sev = vuln.severity.toLowerCase() as Severity;
      if (!minSeverity || isSeverityGte(sev, minSeverity)) {
        result.total[sev]++;
        if (vuln.fixVersion || pkg.suggestedFix) {
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
  const vulns = data.result.vulnerabilities;

  const visibleSeverities = SEVERITY_ORDER.filter(sev =>
    !minSeverity || isSeverityGte(sev, minSeverity)
  );

  const totalVulns = countVulnsBySeverity(pkgs, vulns, minSeverity);

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

function findLayerByDigestOrRef(data: Report, refOrDigest: string): (Layer | undefined) {
    const layer = refOrDigest ? data.result.layers[refOrDigest] : undefined;
    if (layer) return layer;

    return Object.values(data.result.layers).find(layer => {
      return layer.digest && layer.digest === refOrDigest;
    });

}

function addVulnsByLayerTableToSummary(data: Report, minSeverity?: Severity) {
  const visibleSeverities = SEVERITY_ORDER.filter(sev =>
    !minSeverity || isSeverityGte(sev, minSeverity)
  );

  core.summary.addHeading(`Package vulnerabilities per layer`, 2);

  let packagesPerLayer: { [digest: string]: Package[] } = {};
  Object.values(data.result.packages).forEach(pkg => {
    const layer = findLayerByDigestOrRef(data, pkg.layerRef);
    if (layer && layer.digest) {
      packagesPerLayer[layer.digest] = (packagesPerLayer[layer.digest] ?? []).concat(pkg);
    }
  });

  const orderedLayers = Object.values(data.result.layers).sort((a, b) => a.index - b.index);

  orderedLayers.forEach(layer => {
    core.summary.addCodeBlock(`LAYER ${layer.index} - ${layer.command.replace(/\$/g, "&#36;").replace(/\&/g, '&amp;')}`);
    if (!layer.digest) {
      return;
    }

    let packagesWithVulns = (packagesPerLayer[layer.digest] ?? []).filter(pkg => pkg.vulnerabilitiesRefs && pkg.vulnerabilitiesRefs.length > 0);
    if (packagesWithVulns.length === 0) {
      return;
    }

    let orderedPackagesBySeverity = packagesWithVulns.sort((a, b) => {
      const getSeverityVector = (pkg: Package) =>
        SeverityNames.map(severity =>
          pkg.vulnerabilitiesRefs?.filter(ref => {
            const vul = data.result.vulnerabilities[ref];
            return vul.severity.toLowerCase() === severity;
          }).length ?? 0
        );

      const aVector = getSeverityVector(a);
      const bVector = getSeverityVector(b);

      for (let i = 0; i < SeverityNames.length; i++) {
        if (aVector[i] !== bVector[i]) {
          return bVector[i] - aVector[i];
        }
      }
      return 0;
    });

    let tableData = orderedPackagesBySeverity.map(pkg => {
        return [
          { data: pkg.name },
          { data: pkg.type },
          { data: pkg.version },
          { data: pkg.suggestedFix || "" },
          ...visibleSeverities.map(s =>
            `${
              pkg.vulnerabilitiesRefs.filter(vulnRef => {
                const vuln = data.result.vulnerabilities[vulnRef];
                return vuln.severity.toLowerCase() === s;
              }).length ?? 0
            }`
          ),
          `${pkg.vulnerabilitiesRefs.filter(vulnRef => {
              const vuln = data.result.vulnerabilities[vulnRef];
              return vuln.exploitable;
          }).length ?? 0}`,
        ];
      });

    core.summary.addTable([
      [
        { data: 'Package', header: true },
        { data: 'Type', header: true },
        { data: 'Version', header: true },
        { data: 'Suggested fix', header: true },
        ...visibleSeverities.map(s => ({ data: SEVERITY_LABELS[s], header: true })),
        { data: 'Exploit', header: true },
      ],
      ...tableData
    ]);
  });
}

function addReportToSummary(data: Report) {
  let policyEvaluations = data.result.policies.evaluations;
  let packages = data.result.packages;
  let vulns = data.result.vulnerabilities;

  core.summary.addHeading("Policy evaluation summary", 2)
  core.summary.addRaw(`Evaluation result: ${data.result.policies.globalEvaluation} ${EVALUATION[data.result.policies.globalEvaluation]}`);


  let table: { data: string, header?: boolean }[][] = [[
    { data: 'Policy', header: true },
    { data: 'Evaluation', header: true },
  ]];

  policyEvaluations.forEach(policy => {
    table.push([
      { data: `${policy.name}` },
      { data: `${EVALUATION[policy.evaluation]}` },
    ]);
  });

  core.summary.addTable(table);

  core.summary.addHeading("Policy failures", 2)

  policyEvaluations.forEach(policy => {
    if (policy.evaluation != "passed") {
      core.summary.addHeading(`Policy: ${policy.name}`, 3)
      policy.bundles.forEach(bundle => {
        core.summary.addHeading(`Rule Bundle: ${bundle.name}`, 4)

        bundle.rules.forEach(rule => {
          core.summary.addHeading(`Rule: ${rule.description}`, 5)

          if (rule.evaluationResult != "passed") {
            if (rule.failureType == "pkgVulnFailure") {
              getRulePkgMessage(rule, packages, vulns)
            } else {
              getRuleImageMessage(rule)
            }
          }
        });
      });
    }
  });

}

function getRulePkgMessage(rule: Rule, packages: { [key:string]: Package}, vulns: { [key: string]: Vulnerability}) {
  let table: { data: string, header?: boolean }[][] = [[
    { data: 'Severity', header: true },
    { data: 'Package', header: true },
    { data: 'CVE ID', header: true },
    { data: 'CVSS Score', header: true },
    { data: 'CVSS Version', header: true },
    { data: 'CVSS Vector', header: true },
    { data: 'Fixed Version', header: true },
    { data: 'Exploitable', header: true }]];

  rule.failures?.forEach(failure => {
    let pkgRef = failure.packageRef ?? 0;
    let vulnRef = failure.vulnerabilityRef ?? 0;

    let pkg = packages[pkgRef];
    let vuln = vulns[vulnRef];

    if (vuln) {
      table.push([
        { data: `${vuln.severity}` },
        { data: `${pkg.name}` },
        { data: `${vuln.name}` },
        { data: `${vuln.cvssScore.score}` },
        { data: `${vuln.cvssScore.version}` },
        { data: `${vuln.cvssScore.vector}` },
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
