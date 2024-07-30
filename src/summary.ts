import * as core from "@actions/core";
import { Package, Report, Rule } from "./report";
import { ActionInputs } from "./action";

const EVALUATION: any = {
  "failed": "❌",
  "passed": "✅"
}

export async function generateSummary(opts: ActionInputs, data: Report) {
  core.summary.emptyBuffer().clear();
  core.summary.addHeading(`Scan Results for ${opts.overridePullString || opts.imageTag}`);

  addVulnTableToSummary(data);

  addVulnsByLayerTableToSummary(data);

  if (!opts.standalone) {
    core.summary.addBreak()
      .addRaw(`Policies evaluation: ${data.result.policyEvaluationsResult} ${EVALUATION[data.result.policyEvaluationsResult]}`);

    addReportToSummary(data);
  }

  await core.summary.write({ overwrite: true });
}

function addVulnTableToSummary(data: Report) {
  let totalVuln = data.result.vulnTotalBySeverity;
  let fixableVuln = data.result.fixableVulnTotalBySeverity;

  core.summary.addBreak;
  core.summary.addTable([
    [{ data: '', header: true }, { data: '🟣 Critical', header: true }, { data: '🔴 High', header: true }, { data: '🟠 Medium', header: true }, { data: '🟡 Low', header: true }, { data: '⚪ Negligible', header: true }],
    [{ data: '⚠️ Total Vulnerabilities', header: true }, `${totalVuln.critical}`, `${totalVuln.high}`, `${totalVuln.medium}`, `${totalVuln.low}`, `${totalVuln.negligible}`],
    [{ data: '🔧 Fixable Vulnerabilities', header: true }, `${fixableVuln.critical}`, `${fixableVuln.high}`, `${fixableVuln.medium}`, `${fixableVuln.low}`, `${fixableVuln.negligible}`],
  ]);
}


function addVulnsByLayerTableToSummary(data: Report) {
  if (!data.result.layers) {
    return
  }
  core.summary.addSeparator();
  core.summary.addHeading(`Package vulnerabilities per layer`)

  let packagesPerLayer: { [key: string]: Package[] } = {}
  data.result.packages.forEach(layerPackage => {
    if (layerPackage.layerDigest) {
      packagesPerLayer[layerPackage.layerDigest] = (packagesPerLayer[layerPackage.layerDigest] ?? []).concat(layerPackage)
    }
  })

  data.result.layers.forEach((layer, index) => {
    core.summary.addCodeBlock(`LAYER ${index} - ${layer.command.replace(new RegExp('\$', 'g'), "&#36;").replace(new RegExp('\&', 'g'), '&amp;')}`);
    if (!layer.digest) {
      return;
    }

    let packagesWithVulns = (packagesPerLayer[layer.digest] ?? [])
      .filter(pkg => pkg.vulns);
    if (packagesWithVulns.length == 0) {
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
    })

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
    ])
  })
}

function addReportToSummary(data: Report) {
  let policyEvaluations = data.result.policyEvaluations;
  let packages = data.result.packages;

  policyEvaluations.forEach(policy => {
    core.summary.addSeparator()
    core.summary.addHeading(`${EVALUATION[policy.evaluationResult]} Policy: ${policy.name}`, 2)

    if (policy.evaluationResult != "passed") {
      policy.bundles.forEach(bundle => {
        core.summary.addHeading(`Rule Bundle: ${bundle.name}`, 3)

        bundle.rules.forEach(rule => {
          core.summary.addHeading(`${EVALUATION[rule.evaluationResult]} Rule: ${rule.description}`, 5)

          if (rule.evaluationResult != "passed") {
            if (rule.failureType == "pkgVulnFailure") {
              getRulePkgMessage(rule, packages)
            } else {
              getRuleImageMessage(rule)
            }
          }
          core.summary.addBreak()
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
