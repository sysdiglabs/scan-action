import { IReportPresenter } from "../../application/ports/IReportPresenter";
import { FilterOptions, filterPackages } from "../../domain/services/filtering";
import { sortPackagesByVulnSeverity } from "../../domain/services/sorting";
import { isImageRule, isPkgRule, PolicyBundleRuleImageConfig, PolicyBundleRulePkgVuln, ScanResult, Severity, Vulnerability } from "../../domain/scanresult";
import { ISummary } from "./ISummary";

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

  constructor(private readonly summary: ISummary) {}

  async generateReport(data: ScanResult, _groupByPackage: boolean, filters?: FilterOptions) {
    this.summary.addHeading(`Scan Results for ${data.metadata.pullString}`);

    this.addVulnTableToSummary(data, filters);
    this.addVulnsByLayerTableToSummary(data, filters);
    this.addPolicyReportToSummary(data);
  }


  private addVulnTableToSummary(
    data: ScanResult,
    filters?: FilterOptions
  ) {
    const packages = data.getPackages();
    const filteredPackages = filterPackages(packages, filters);

    const vulnerabilitiesMap = new Map<string, Vulnerability>();
    filteredPackages.forEach(p => {
      p.getVulnerabilities().forEach(v => {
        vulnerabilitiesMap.set(v.cve, v);
      });
    });

    const minSeverity = filters?.minSeverity ?? Severity.Unknown;
    const vulns = Array.from(vulnerabilitiesMap.values())
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

    this.summary.addHeading("Vulnerabilities summary", 2);
    this.summary.addTable([headerRow, totalRow, fixableRow]);
  }



  private addVulnsByLayerTableToSummary(data: ScanResult, filters?: FilterOptions) {
    const minSeverity = filters?.minSeverity ?? Severity.Unknown;

    this.summary.addHeading(`Package vulnerabilities per layer`, 2);
    const orderedLayers = data.getLayers().sort((a, b) => a.index - b.index);

    orderedLayers.forEach(layer => {
      const layerPackages = layer.getPackages();
      const filteredLayerPackages = filterPackages(layerPackages, filters);

      const vulnerablePackages = filteredLayerPackages
        .filter(p => p
          .getVulnerabilities()
          .filter(v => v.severity.isMoreSevereThanOrEqualTo(minSeverity))
          .length > 0
        );

      const vulnerablePackagesSortedBySeverity = sortPackagesByVulnSeverity(vulnerablePackages);


      let colsToDisplay = SummaryReportPresenter.severities.filter(s => s.sev.isMoreSevereThanOrEqualTo(minSeverity));


      const packageRows = vulnerablePackagesSortedBySeverity.map(pkg => {
        const vulns = pkg.getVulnerabilities();
        const countBySeverity = (sev: Severity) => vulns.filter(v => v.severity === sev).length;



        return [
          { data: pkg.name },
          { data: pkg.packageType.toString() },
          { data: pkg.version.toString() },
          { data: pkg.suggestedFixVersion()?.toString() || "None" },
        ].concat(
          colsToDisplay.map(c => ({ data: countBySeverity(c.sev).toString() })),
        ).concat(
          { data: vulns.filter(v => v.exploitable).length.toString() }
        );
      });

      this.summary.addCodeBlock(`LAYER ${layer.index} - ${layer.command.replace(/\$/g, "&#36;").replace(/\&/g, '&amp;')}`);

      if (packageRows.length > 0) {
        this.summary.addTable([
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

  private addPolicyReportToSummary(data: ScanResult) {
    let policies = data.getPolicies();
    if (policies.length == 0) {
      return
    }

    this.summary.addHeading("Policy evaluation summary", 2)
    this.summary.addRaw(`Evaluation result: ${data.getEvaluationResult().toString()} ${EVALUATION_RESULT_AS_EMOJI[data.getEvaluationResult().toString()]}`);

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

    this.summary.addTable(table);

    this.summary.addHeading("Policy failures", 2)

    policies.forEach(policy => {
      if (policy.getEvaluationResult().isFailed()) {
        this.summary.addHeading(`Policy: ${policy.name}`, 3)
        policy.getBundles().forEach(bundle => {
          this.summary.addHeading(`Rule Bundle: ${bundle.name}`, 4)
          bundle.getRules().forEach(rule => {
            this.summary.addHeading(`Rule: ${rule.description}`, 5)
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
        { data: `${failure.vuln.fixVersion?.toString() || "No fix available"}` },
        { data: `${failure.vuln.exploitable}` },
      ]);
    });

    this.summary.addTable(table);
  }

  private getRuleImageMessage(rule: PolicyBundleRuleImageConfig) {
    const reasons = rule.getFailures().map(failure => failure.reason())
    this.summary.addList(reasons);
  }
}
