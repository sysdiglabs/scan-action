import * as core from '@actions/core';
import fs from 'fs';
import { Package, Priority, Report, Rule, SeverityValue } from './src/report';
import { generateSARIFReport } from './src/sarif';
import { cliScannerName, cliScannerResult, cliScannerURL, composeFlags, executeScan, pullScanner, ScanExecutionResult, vmMode } from './src/scanner';
import { ActionInputs, defaultSecureEndpoint, parseActionInputs, printOptions, validateInput } from './src/action';
import { generateSummary } from './src/summary';

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
