import * as core from "@actions/core";
import { IReportPresenter } from "../../application/ports/IReportPresenter";
import { FilterOptions } from "../../domain/services/filtering";
import { isImageRule, isPkgRule, PolicyBundleRuleImageConfig, PolicyBundleRulePkgVuln, ScanResult, Severity } from "../../domain/scanresult";

const EVALUATION_RESULT_AS_EMOJI: any = {
  "failed": "❌",
  "passed": "✅"
}

export class SummaryReportPresenter implements IReportPresenter {
  private static severities = [
    { sev: Severity.Critical, label: "🟣 Critical" },
    { sev: Severity.High, label: "🔴 High" },
    { sev: Severity.Medium, label: "🟠 Medium" },
    { sev: Severity.Low, label: "🟡 Low" },
    { sev: Severity.Negligible, label: "⚪ Negligible" },
  ];

  async generateReport(data: ScanResult, _groupByPackage: boolean, filters?: FilterOptions) {

    core.summary.emptyBuffer().clear();
    core.summary.addHeading(`Scan Results for ${data.metadata.pullString}`);

    this.addVulnTableToSummary(data, filters);
    this.addVulnsByLayerTableToSummary(data, filters?.minSeverity || Severity.Unknown);
    this.addReportToSummary(data);

    await core.summary.write({ overwrite: true });
  }


  private addVulnTableToSummary(
    data: ScanResult,
    filters?: FilterOptions
  ) {
    const minSeverity = filters?.minSeverity ?? Severity.Unknown;
    const vulns = data.getVulnerabilities()
      .filter(v => v.severity.isMoreSevereThanOrEqualTo(minSeverity));

    let colsToDisplay = SummaryReportPresenter.severities.filter(s => s.sev.isMoreSevereThanOrEqualTo(minSeverity));

    const headerRow = [{ data: "", header: true }].concat(
      colsToDisplay.map(c => ({ data: c.label, header: true }))
    );

    const countBySeverity = (sev: Severity) => vulns.filter(v => v.severity === sev).length;
    const totalRow = [{ data: "⚠️ Total Vulnerabilities", header: true }].concat(
      colsToDisplay.map(c => ({ data: countBySeverity(c.sev).toString(), header: false }))
    );

    const countFixableBySeverity = (sev: Severity) => vulns.filter(v => v.severity === sev && v.isFixable()).length;
    const fixableRow = [{ data: "🔧 Fixable Vulnerabilities", header: true }].concat(
      colsToDisplay.map(c => ({ data: countFixableBySeverity(c.sev).toString(), header: false }))
    );

    core.summary.addHeading("Vulnerabilities summary", 2);
    core.summary.addTable([headerRow, totalRow, fixableRow]);
  }



  private addVulnsByLayerTableToSummary(data: ScanResult, minSeverity: Severity) {
    core.summary.addHeading(`Package vulnerabilities per layer`, 2);
    const orderedLayers = data.getLayers().sort((a, b) => a.index - b.index);

    orderedLayers.forEach(layer => {
      const vulnerablePackages = layer
        .getPackages()
        .filter(p => p
          .getVulnerabilities()
          .filter(v => v.severity.isMoreSevereThanOrEqualTo(minSeverity))
          .length > 0
        );

      const vulnerablePackagesSortedBySeverity = vulnerablePackages
        .sort((a, b) => {
          const sortedSeveritiesInA = a
            .getVulnerabilities()
            .filter(v => v.severity.isMoreSevereThanOrEqualTo(minSeverity))
            .map(v => v.severity.asNumber())
            .sort((va, vb) => va - vb);
          const sortedSeveritiesInB = b
            .getVulnerabilities()
            .filter(v => v.severity.isMoreSevereThanOrEqualTo(minSeverity))
            .map(v => v.severity.asNumber())
            .sort((va, vb) => va - vb);

          const minLength = Math.min(sortedSeveritiesInA.length, sortedSeveritiesInB.length);
          for (let i = 0; i < minLength; i++) {
            if (sortedSeveritiesInA[i] !== sortedSeveritiesInB[i]) return sortedSeveritiesInA[i] - sortedSeveritiesInB[i];
          }

          return sortedSeveritiesInA.length - sortedSeveritiesInB.length;
        });


      let colsToDisplay = SummaryReportPresenter.severities.filter(s => s.sev.isMoreSevereThanOrEqualTo(minSeverity));


      const packageRows = vulnerablePackagesSortedBySeverity.map(pkg => {
        const vulns = pkg.getVulnerabilities();
        const countBySeverity = (sev: Severity) => vulns.filter(v => v.severity === sev).length;
        const fixedInVersions = vulns.map(v => v.fixVersion).join(", ") || "";



        return [
          { data: pkg.name },
          { data: pkg.packageType.toString() },
          { data: pkg.version },
          { data: fixedInVersions },
        ].concat(
          colsToDisplay.map(c => ({ data: countBySeverity(c.sev).toString() })),
        ).concat(
          { data: vulns.filter(v => v.exploitable).length.toString() }
        );
      });

      core.summary.addCodeBlock(`LAYER ${layer.index} - ${layer.command.replace(/\$/g, "&#36;").replace(/\&/g, '&amp;')}`);

      if (packageRows.length > 0) {
        core.summary.addTable([
          [
            { data: 'Package', header: true },
            { data: 'Type', header: true },
            { data: 'Version', header: true },
            { data: 'Suggested fix', header: true },
            ...colsToDisplay.map(c => ({ data: c.label, header: true })),
            { data: 'Exploits', header: true },
          ],
          ...packageRows
        ]);
      }
    });
  }

  private addReportToSummary(data: ScanResult) {
    let policies = data.getPolicies();
    if (policies.length == 0) {
      return
    }

    core.summary.addHeading("Policy evaluation summary", 2)
    core.summary.addRaw(`Evaluation result: ${data.getEvaluationResult().toString()} ${EVALUATION_RESULT_AS_EMOJI[data.getEvaluationResult().toString()]}`);

    let table: { data: string, header?: boolean }[][] = [[
      { data: 'Policy', header: true },
      { data: 'Evaluation', header: true },
    ]];

    policies.forEach(policy => {
      table.push([
        { data: `${policy.name}` },
        { data: `${EVALUATION_RESULT_AS_EMOJI[policy.getEvaluationResult().toString()]}` },
      ]);
    });

    core.summary.addTable(table);

    core.summary.addHeading("Policy failures", 2)

    policies.forEach(policy => {
      if (policy.getEvaluationResult().isFailed()) {
        core.summary.addHeading(`Policy: ${policy.name}`, 3)
        policy.getBundles().forEach(bundle => {
          core.summary.addHeading(`Rule Bundle: ${bundle.name}`, 4)
          bundle.getRules().forEach(rule => {
            core.summary.addHeading(`Rule: ${rule.description}`, 5)
            if (rule.evaluationResult.isFailed()) {
              if (isPkgRule(rule)) {
                this.getRulePkgMessage(rule)
              }
              if (isImageRule(rule)) {
                this.getRuleImageMessage(rule)
              }
            }
          });
        });
      }
    });

  }

  private getRulePkgMessage(rule: PolicyBundleRulePkgVuln) {
    let table: { data: string, header?: boolean }[][] = [[
      { data: 'Severity', header: true },
      { data: 'Package', header: true },
      { data: 'CVE ID', header: true },
      { data: 'CVSS Score', header: true },
      { data: 'Fixed Version', header: true },
      { data: 'Exploitable', header: true }
    ]];

    rule.getFailures().forEach(failure => {
      table.push([
        { data: `${failure.vuln.severity}` },
        { data: `${failure.pkg.name}` },
        { data: `${failure.vuln.cve}` },
        { data: `${failure.vuln.cvssScore}` },
        { data: `${failure.vuln.fixVersion || "No fix available"}` },
        { data: `${failure.vuln.exploitable}` },
      ]);
    });

    core.summary.addTable(table);
  }

  private getRuleImageMessage(rule: PolicyBundleRuleImageConfig) {
    const reasons = rule.getFailures().map(failure => failure.reason())
    core.summary.addList(reasons);
  }
}
