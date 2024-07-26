import * as core from '@actions/core';
import * as exec from '@actions/exec';
import fs from 'fs';
const performance = require('perf_hooks').performance;
import process from 'process';
import os from 'os';
import { Package, Priority, Report, Rule, SeverityValue} from './src/report'; 
import { generateSARIFReport } from './src/sarif';

const vmMode = "vm"
const iacMode = "iac"

function getRunArch() {
  let arch = "unknown";
  if (os.arch() == "x64") {
    arch = "amd64";
  } else if (os.arch() == "arm64") {
    arch = "arm64";
  }
  return arch;
}

function getRunOS() {
  let os_name = "unknown";
  if (os.platform() == "linux") {
    os_name = "linux";
  } else if (os.platform() == "darwin") {
    os_name = "darwin";
  }
  return os_name;
}

const cliScannerVersion = "1.13.0"
export const cliScannerName = "sysdig-cli-scanner"
const cliScannerOS = getRunOS()
const cliScannerArch = getRunArch()
const cliScannerURLBase = "https://download.sysdig.com/scanning/bin/sysdig-cli-scanner";
export const cliScannerURL = `${cliScannerURLBase}/${cliScannerVersion}/${cliScannerOS}/${cliScannerArch}/${cliScannerName}`
export const cliScannerResult = "scan-result.json"

export const defaultSecureEndpoint = "https://secure.sysdig.com/"


const EVALUATION: any = {
  "failed": "❌",
  "passed": "✅"
}

export class ExecutionError extends Error {
  constructor(stdout: string, stderr: string) {
    super("execution error\n\nstdout: " + stdout + "\n\nstderr: " + stderr);
  }
}

export interface ActionInputs {
  cliScannerURL: string;
  cliScannerVersion: string;
  registryUser: string;
  registryPassword: string;
  stopOnFailedPolicyEval: boolean;
  stopOnProcessingError: boolean;
  standalone: boolean;
  dbPath: string;
  skipUpload: boolean;
  skipSummary: boolean;
  usePolicies: string;
  overridePullString: string;
  imageTag: string;
  sysdigSecureToken: string;
  sysdigSecureURL: string;
  sysdigSkipTLS: boolean;
  severityAtLeast?: SeverityValue;
  groupByPackage: boolean;
  extraParameters: string;
  mode: string;
  recursive: boolean;
  minimumSeverity: string;
  iacScanPath: string;
}

export function parseActionInputs() : ActionInputs {
  return {
    cliScannerURL: core.getInput('cli-scanner-url') || cliScannerURL,
    cliScannerVersion: core.getInput('cli-scanner-version'),
    registryUser: core.getInput('registry-user'),
    registryPassword: core.getInput('registry-password'),
    stopOnFailedPolicyEval: core.getInput('stop-on-failed-policy-eval') == 'true',
    stopOnProcessingError: core.getInput('stop-on-processing-error') == 'true',
    standalone: core.getInput('standalone') == 'true',
    dbPath: core.getInput('db-path'),
    skipUpload: core.getInput('skip-upload') == 'true',
    skipSummary: core.getInput('skip-summary') == 'true',
    usePolicies: core.getInput('use-policies'),
    overridePullString: core.getInput('override-pullstring'),
    imageTag: core.getInput('image-tag'),
    sysdigSecureToken: core.getInput('sysdig-secure-token'),
    sysdigSecureURL: core.getInput('sysdig-secure-url') || defaultSecureEndpoint,
    sysdigSkipTLS: core.getInput('sysdig-skip-tls') == 'true',
    severityAtLeast: core.getInput('severity-at-least') as SeverityValue || undefined,
    groupByPackage: core.getInput('group-by-package') == 'true',
    extraParameters: core.getInput('extra-parameters'),
    mode: core.getInput('mode') || vmMode,
    recursive: core.getInput('recursive') == 'true',
    minimumSeverity: core.getInput('minimum-severity'),
    iacScanPath: core.getInput('iac-scan-path') || './'
  }
}


function printOptions(opts: ActionInputs) {
  if (opts.standalone) {
    core.info(`[!] Running in Standalone Mode.`);
  }

  if (opts.sysdigSecureURL) {
    core.info('Sysdig Secure URL: ' + opts.sysdigSecureURL);
  }

  if (opts.registryUser && opts.registryPassword) {
    core.info(`Using specified Registry credentials.`);
  }

  core.info(`Stop on Failed Policy Evaluation: ${opts.stopOnFailedPolicyEval}`);

  core.info(`Stop on Processing Error: ${opts.stopOnProcessingError}`);

  if (opts.skipUpload) {
    core.info(`Skipping scan results upload to Sysdig Secure...`);
  }

  if (opts.dbPath) {
    core.info(`DB Path: ${opts.dbPath}`);
  }

  core.info(`Sysdig skip TLS: ${opts.sysdigSkipTLS}`);

  if (opts.severityAtLeast) {
    core.info(`Severity level: ${opts.severityAtLeast}`);
  }

  core.info('Analyzing image: ' + opts.imageTag);

  if (opts.overridePullString) {
    core.info(` * Image PullString will be overwritten as ${opts.overridePullString}`);
  }

  if (opts.skipSummary) {
    core.info("This run will NOT generate a SUMMARY.");
  }
}

interface ComposeFlags {
    envvars: {
        [key: string]: string;
    };
    flags: string;
}

export function composeFlags(opts: ActionInputs): ComposeFlags {
  let envvars: { [key: string]: string } = {}
  envvars['SECURE_API_TOKEN'] = opts.sysdigSecureToken || "";

  let flags = ""

  if (opts.registryUser) {
    envvars['REGISTRY_USER'] = opts.registryUser;
  }

  if (opts.registryPassword) {
    envvars['REGISTRY_PASSWORD'] = opts.registryPassword;
  }

  if (opts.standalone) {
    flags += " --standalone";
  }

  if (opts.sysdigSecureURL) {
    flags += ` --apiurl ${opts.sysdigSecureURL}`;
  }

  if (opts.dbPath) {
    flags += ` --dbpath=${opts.dbPath}`;
  }

  if (opts.skipUpload) {
    flags += ' --skipupload';
  }

  if (opts.usePolicies) {
    flags += ` --policy=${opts.usePolicies}`;
  }

  if (opts.sysdigSkipTLS) {
    flags += ` --skiptlsverify`;
  }

  if (opts.overridePullString) {
    flags += ` --override-pullstring=${opts.overridePullString}`;
  }

  if (opts.extraParameters) {
    flags += ` ${opts.extraParameters}`;
  }

  if (opts.mode && opts.mode == iacMode) {
    flags += ` --iac`;
  }

  if (opts.recursive && opts.mode == iacMode) {
    flags += ` -r`;
  }

  if (opts.minimumSeverity && opts.mode == iacMode) {
    flags += ` -f=${opts.minimumSeverity}`;
  }

  if (opts.mode && opts.mode == vmMode) {
    flags += ` --json-scan-result=${cliScannerResult}`
    flags += ` ${opts.imageTag}`;
  }

  if (opts.mode && opts.mode == iacMode) {
    flags += ` ${opts.iacScanPath}`;
  }

  return {
    envvars: envvars,
    flags: flags
  }
}

function writeReport(reportData: string) {
  fs.writeFileSync("./report.json", reportData);
  core.setOutput("scanReport", "./report.json");
}

export function validateInput(opts: ActionInputs) {
  if (!opts.standalone && !opts.sysdigSecureToken) {
    core.setFailed("Sysdig Secure Token is required for standard execution, please set your token or remove the standalone input.");
    throw new Error("Sysdig Secure Token is required for standard execution, please set your token or remove the standalone input.");
  }

  if (opts.mode && opts.mode == vmMode && !opts.imageTag) {
    core.setFailed("image-tag is required for VM mode.");
    throw new Error("image-tag is required for VM mode.");
  }

  if (opts.mode && opts.mode == iacMode && opts.iacScanPath == "") {
    core.setFailed("iac-scan-path can't be empty, please specify the path you want to scan your manifest resources.");
    throw new Error("iac-scan-path can't be empty, please specify the path you want to scan your manifest resources.");
  }
}

export async function run() {

  try {
    let opts = parseActionInputs();
    validateInput(opts)
    printOptions(opts);
    let scanFlags = composeFlags(opts);

    // If custom scanner version is specified
    if (opts.cliScannerVersion && opts.cliScannerURL == cliScannerURL) {
      opts.cliScannerURL = `${cliScannerURLBase}/${opts.cliScannerVersion}/${cliScannerOS}/${cliScannerArch}/${cliScannerName}`
    }

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

export async function pullScanner(scannerURL: string) {
  let start = performance.now();
  core.info('Pulling cli-scanner from: ' + scannerURL);
  let cmd = `wget ${scannerURL} -O ./${cliScannerName}`;
  let retCode = await exec.exec(cmd, undefined, { silent: true });

  if (retCode == 0) {
    cmd = `chmod u+x ./${cliScannerName}`;
    await exec.exec(cmd, undefined, { silent: true });
  } else {
    core.error(`Falied to pull scanner using "${scannerURL}"`)
  }

  core.info("Scanner pull took " + Math.round(performance.now() - start) + " milliseconds.");
  return retCode;
}

interface ScanExecutionResult {
    ReturnCode: number;
    Output: string;
    Error: string;
}

export async function executeScan(scanFlags: ComposeFlags): Promise<ScanExecutionResult> {
  let {envvars, flags} = scanFlags;
  let execOutput = '';
  let errOutput = '';


  const scanOptions: exec.ExecOptions = {
    env: envvars,
    silent: true,
    ignoreReturnCode: true,
    listeners: {
      stdout: (data: Buffer) => {
        process.stdout.write(data);
      },
      stderr: (data: Buffer) => {
        process.stderr.write(data);
      }
    }
  };

  const catOptions: exec.ExecOptions = {
    silent: true,
    ignoreReturnCode: true,
    listeners: {
      stdout: (data) => {
        execOutput += data.toString();
      },
      stderr: (data) => {
        errOutput += data.toString();
      }
    }
  }

  let start = performance.now();
  let cmd = `./${cliScannerName} ${flags}`;
  core.info("Executing: " + cmd);
  let retCode = await exec.exec(cmd, undefined, scanOptions);
  core.info("Image analysis took " + Math.round(performance.now() - start) + " milliseconds.");

  if (retCode == 0 || retCode == 1) {
    cmd = `cat ./${cliScannerResult}`;
    await exec.exec(cmd, undefined, catOptions);
  }
  return { ReturnCode: retCode, Output: execOutput, Error: errOutput };
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
  let table : { data: string, header?: boolean}[][] = [[
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
      { data: `${pkg.name}`},
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

module.exports = {
  ExecutionError,
  parseActionInputs,
  composeFlags,
  pullScanner,
  executeScan,
  processScanResult,
  run,
  validateInput,
  cliScannerName,
  cliScannerResult,
  cliScannerVersion,
  cliScannerArch,
  cliScannerOS,
  cliScannerURLBase,
  cliScannerURL,
  defaultSecureEndpoint
};

if (require.main === module) {
  run();
}
