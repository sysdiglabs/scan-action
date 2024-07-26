import * as core from '@actions/core';
import fs from 'fs';
import { Package, Priority, Report, Rule, SeverityValue } from './src/report';
import { generateSARIFReport } from './src/sarif';
import { cliScannerName, cliScannerResult, cliScannerURL, composeFlags, executeScan, pullScanner, ScanExecutionResult, vmMode } from './src/scanner';
import { ActionInputs, defaultSecureEndpoint, parseActionInputs, printOptions, validateInput } from './src/action';



const EVALUATION: any = {
  "failed": "❌",
  "passed": "✅"
}

export class ExecutionError extends Error {
  constructor(stdout: string, stderr: string) {
    super("execution error\n\nstdout: " + stdout + "\n\nstderr: " + stderr);
  }
}


function writeReport(reportData: string) {
  fs.writeFileSync("./report.json", reportData);
  core.setOutput("scanReport", "./report.json");
}


export async function run() {

  try {
    let opts = parseActionInputs();
    validateInput(opts)
    printOptions(opts);
    let scanFlags = composeFlags(opts); // FIXME(fede) this also modifies the opts.cliScannerURL, which is something we don't want

    let scanResult: ScanExecutionResult;
    // Download CLI Scanner from 'cliScannerURL'
    let retCode = await pullScanner(opts.cliScannerURL);
    if (retCode == 0) {
      // Execute Scanner
      scanResult = await executeScan(scanFlags);

      retCode = scanResult.ReturnCode;
      if (retCode == 0 || retCode == 1) {
        // Transform Scan Results to other formats such as SARIF
        if (opts.mode && opts.mode == vmMode) {
          await processScanResult(scanResult, opts);
        }
      } else {
        core.error("Terminating scan. Scanner couldn't be executed.")
      }
    } else {
      core.error("Terminating scan. Scanner couldn't be pulled.")
    }

    if (opts.stopOnFailedPolicyEval && retCode == 1) {
      core.setFailed(`Stopping because Policy Evaluation was FAILED.`);
    } else if (opts.standalone && retCode == 0) {
      core.info("Policy Evaluation was OMITTED.");
    } else if (retCode == 0) {
      core.info("Policy Evaluation was PASSED.");
    } else if (opts.stopOnProcessingError && retCode > 1) {
      core.setFailed(`Stopping because the scanner terminated with an error.`);
    } // else: Don't stop regardless the outcome.

  } catch (error) {
    if (core.getInput('stop-on-processing-error') == 'true') {
      core.setFailed("Unexpected error");
    }
    core.error(error as string);
  }
}


function filterResult(report: Report, severity: SeverityValue) {
  let filter_num: number = Priority[severity];

  report.result.packages.forEach(pkg => {
    if (pkg.vulns) pkg.vulns = pkg.vulns.filter((vuln) => Priority[vuln.severity.value] <= filter_num);
  });
  return report;
}

export async function processScanResult(result: ScanExecutionResult, opts: ActionInputs) {
  writeReport(result.Output);

  let report: Report;
  try {
    report = JSON.parse(result.Output);
  } catch (error) {
    core.error("Error parsing analysis JSON report: " + error + ". Output was: " + result.Output);
    throw new ExecutionError(result.Output, result.Error);
  }

  if (report) {
    if (opts.severityAtLeast) {
      report = filterResult(report, opts.severityAtLeast);
    }

    generateSARIFReport(report, opts.groupByPackage);

    if (!opts.skipSummary) {
      core.info("Generating Summary...")

      await generateSummary(opts, report);

    } else {
      core.info("Skipping Summary...")
    }
  }
}


async function generateSummary(opts: ActionInputs, data: Report) {

  core.summary.emptyBuffer().clear();
  core.summary.addHeading(`Scan Results for ${opts.overridePullString || opts.imageTag}`);

  addVulnTableToSummary(data);

  if (!opts.standalone) {
    core.summary.addBreak()
      .addRaw(`Policies evaluation: ${data.result.policyEvaluationsResult} ${EVALUATION[data.result.policyEvaluationsResult]}`);

    addReportToSummary(data);
  }

  await core.summary.write({ overwrite: true });
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

function addReportToSummary(data: Report) {
  let policyEvaluations = data.result.policyEvaluations;
  let packages = data.result.packages;

  policyEvaluations.forEach(policy => {
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

export {
  parseActionInputs,
  validateInput,
  cliScannerURL,
  defaultSecureEndpoint,
  composeFlags,
  pullScanner,
  cliScannerName,
  executeScan,
  cliScannerResult,
};

if (require.main === module) {
  run();
}
