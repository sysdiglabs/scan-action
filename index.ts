import * as core from '@actions/core';
import fs from 'fs';
import { generateSARIFReport } from './src/sarif';
import { cliScannerName, cliScannerResult, cliScannerURL, executeScan, numericPriorityForSeverity, pullScanner, ScanExecutionResult, ScanMode } from './src/scanner';
import { ActionInputs, defaultSecureEndpoint } from './src/action';
import { generateSummary } from './src/summary';
import { Report } from './src/report';

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
    let opts = ActionInputs.parseActionInputs();
    opts.printOptions();
    let scanFlags = opts.composeFlags();

    let scanResult: ScanExecutionResult;
    // Download CLI Scanner from 'cliScannerURL'
    let retCode = await pullScanner(opts.cliScannerURL);
    if (retCode == 0) {
      // Execute Scanner
      scanResult = await executeScan(scanFlags);

      retCode = scanResult.ReturnCode;
      if (retCode == 0 || retCode == 1) {
        // Transform Scan Results to other formats such as SARIF

        if (opts.mode == ScanMode.vm) {
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


function filterResult(report: Report, severity: string) {
  let filter_num: number = numericPriorityForSeverity(severity) ?? 5;

  report.result.packages.forEach(pkg => {
    if (pkg.vulns) pkg.vulns = pkg.vulns.filter((vuln) => numericPriorityForSeverity(vuln.severity.value) ?? 5 <= filter_num);
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

export {
  cliScannerURL,
  defaultSecureEndpoint,
  pullScanner,
  cliScannerName,
  executeScan,
  cliScannerResult,
};

if (require.main === module) {
  run();
}
