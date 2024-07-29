import * as core from '@actions/core';
import { cliScannerURL, iacMode, vmMode } from './scanner';

export const defaultSecureEndpoint = "https://secure.sysdig.com/"

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
  severityAtLeast?: string;
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
    severityAtLeast: core.getInput('severity-at-least') || undefined,
    groupByPackage: core.getInput('group-by-package') == 'true',
    extraParameters: core.getInput('extra-parameters'),
    mode: core.getInput('mode') || vmMode,
    recursive: core.getInput('recursive') == 'true',
    minimumSeverity: core.getInput('minimum-severity'),
    iacScanPath: core.getInput('iac-scan-path') || './'
  }
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

export function printOptions(opts: ActionInputs) {
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
