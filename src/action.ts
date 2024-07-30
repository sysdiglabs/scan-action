import * as core from '@actions/core';
import { cliScannerResult, cliScannerURL, ComposeFlags, ScanMode, scannerURLForVersion } from './scanner';

export const defaultSecureEndpoint = "https://secure.sysdig.com/"

interface ActionInputParameters {
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
  mode: ScanMode;
  recursive: boolean;
  minimumSeverity: string;
  iacScanPath: string;
}

export class ActionInputs {
  private readonly _params: ActionInputParameters;
  public get params(): ActionInputParameters {
    return this._params;
  }
  private constructor(params: ActionInputParameters) {
    ActionInputs.validateInputs(params);
    this._params = params;
  }

  static from(any: any): ActionInputs {
    return new ActionInputs(any as ActionInputParameters);
  }

  static fromJSON(jsonContents: string): ActionInputs {
    return ActionInputs.from(JSON.parse(jsonContents))
  }

  static parseActionInputs(): ActionInputs {
    return ActionInputs.overridingParsedActionInputs({});
  }

  static overridingParsedActionInputs(overrides: { [key: string]: any }) {

    const params: ActionInputParameters = {
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
      mode: ScanMode.fromString(core.getInput('mode')) || ScanMode.vm,
      recursive: core.getInput('recursive') == 'true',
      minimumSeverity: core.getInput('minimum-severity'),
      iacScanPath: core.getInput('iac-scan-path') || './',
    };

    const overridenParams = {
      ...params,
      ...overrides,
    };


    return ActionInputs.from(overridenParams);
  }

  get cliScannerURL(): string {
    return this.params.cliScannerURL
  }

  get mode() {
    return this.params.mode;
  }

  get stopOnProcessingError() {
    return this.params.stopOnProcessingError
  }

  get standalone() {
    return this.params.standalone
  }

  get stopOnFailedPolicyEval() {
    return this.params.stopOnFailedPolicyEval
  }

  get skipSummary() {
    return this.params.skipSummary
  }

  get groupByPackage(): boolean {
    return this.params.groupByPackage
  }

  get severityAtLeast() {
    return this.params.severityAtLeast
  }

  get imageTag() {
    return this.params.imageTag
  }

  get overridePullString() {
    return this.params.overridePullString
  }

  private static validateInputs(params: ActionInputParameters) {
    if (!params.standalone && !params.sysdigSecureToken) {
      core.setFailed("Sysdig Secure Token is required for standard execution, please set your token or remove the standalone input.");
      throw new Error("Sysdig Secure Token is required for standard execution, please set your token or remove the standalone input.");
    }

    if (params.mode && params.mode == ScanMode.vm && !params.imageTag) {
      core.setFailed("image-tag is required for VM mode.");
      throw new Error("image-tag is required for VM mode.");
    }

    if (params.mode && params.mode == ScanMode.iac && params.iacScanPath == "") {
      core.setFailed("iac-scan-path can't be empty, please specify the path you want to scan your manifest resources.");
      throw new Error("iac-scan-path can't be empty, please specify the path you want to scan your manifest resources.");
    }
  }

  // FIXME(fede) this also modifies the opts.cliScannerURL, which is something we don't want
  public composeFlags(): ComposeFlags {
    if (this.params.cliScannerVersion && this.params.cliScannerURL == cliScannerURL) {
      this.params.cliScannerURL = scannerURLForVersion(this.params.cliScannerVersion)
    }

    let envvars: { [key: string]: string } = {}
    envvars['SECURE_API_TOKEN'] = this.params.sysdigSecureToken || "";

    let flags = ""

    if (this.params.registryUser) {
      envvars['REGISTRY_USER'] = this.params.registryUser;
    }

    if (this.params.registryPassword) {
      envvars['REGISTRY_PASSWORD'] = this.params.registryPassword;
    }

    if (this.params.standalone) {
      flags += " --standalone";
    }

    if (this.params.sysdigSecureURL) {
      flags += ` --apiurl ${this.params.sysdigSecureURL}`;
    }

    if (this.params.dbPath) {
      flags += ` --dbpath=${this.params.dbPath}`;
    }

    if (this.params.skipUpload) {
      flags += ' --skipupload';
    }

    if (this.params.usePolicies) {
      flags += ` --policy=${this.params.usePolicies}`;
    }

    if (this.params.sysdigSkipTLS) {
      flags += ` --skiptlsverify`;
    }

    if (this.params.overridePullString) {
      flags += ` --override-pullstring=${this.params.overridePullString}`;
    }

    if (this.params.extraParameters) {
      flags += ` ${this.params.extraParameters}`;
    }

    if (this.params.mode == ScanMode.iac) {
      flags += ` --iac`;

      if (this.params.recursive) {
        flags += ` -r`;
      }
      if (this.params.minimumSeverity) {
        flags += ` -f=${this.params.minimumSeverity}`;
      }

      flags += ` ${this.params.iacScanPath}`;
    }

    if (this.params.mode == ScanMode.vm) {
      flags += ` --json-scan-result=${cliScannerResult}`
      flags += ` ${this.params.imageTag}`;
    }

    return {
      envvars: envvars,
      flags: flags
    }
  }

  public printOptions() {
    if (this.params.standalone) {
      core.info(`[!] Running in Standalone Mode.`);
    }

    if (this.params.sysdigSecureURL) {
      core.info('Sysdig Secure URL: ' + this.params.sysdigSecureURL);
    }

    if (this.params.registryUser && this.params.registryPassword) {
      core.info(`Using specified Registry credentials.`);
    }

    core.info(`Stop on Failed Policy Evaluation: ${this.params.stopOnFailedPolicyEval}`);

    core.info(`Stop on Processing Error: ${this.params.stopOnProcessingError}`);

    if (this.params.skipUpload) {
      core.info(`Skipping scan results upload to Sysdig Secure...`);
    }

    if (this.params.dbPath) {
      core.info(`DB Path: ${this.params.dbPath}`);
    }

    core.info(`Sysdig skip TLS: ${this.params.sysdigSkipTLS}`);

    if (this.params.severityAtLeast) {
      core.info(`Severity level: ${this.params.severityAtLeast}`);
    }

    core.info('Analyzing image: ' + this.params.imageTag);

    if (this.params.overridePullString) {
      core.info(` * Image PullString will be overwritten as ${this.params.overridePullString}`);
    }

    if (this.params.skipSummary) {
      core.info("This run will NOT generate a SUMMARY.");
    }
  }
}

