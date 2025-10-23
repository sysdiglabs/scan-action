import * as core from '@actions/core';
import { cliScannerURL } from '../sysdig/SysdigCliScannerConstants';
import { ScanMode } from '../../application/ports/ScannerDTOs';
import { Severity } from '../../domain/scanresult';

export const defaultSecureEndpoint = "https://secure.sysdig.com/"

interface ActionInputParameters {
  cliScannerURL: string;
  cliScannerVersion?: string;
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
  packageTypes?: string;
  notPackageTypes?: string;
  excludeAccepted?: boolean;
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
      cliScannerVersion: core.getInput('cli-scanner-version') || undefined,
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
      packageTypes: core.getInput('package-types') || undefined,
      notPackageTypes: core.getInput('not-package-types') || undefined,
      excludeAccepted: core.getInput('exclude-accepted') === 'true',
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

  get packageTypes() {
    return this.params.packageTypes;
  }
  get notPackageTypes() {
    return this.params.notPackageTypes;
  }
  get excludeAccepted() {
    return this.params.excludeAccepted;
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

    if (params.severityAtLeast && params.severityAtLeast.toLowerCase() !== 'any' && Severity.fromString(params.severityAtLeast) === Severity.Unknown) {
      core.setFailed(`Invalid severity-at-least value "${params.severityAtLeast}". Allowed values: any, critical, high, medium, low, negligible.`);
      throw new Error(`Invalid severity-at-least value "${params.severityAtLeast}". Allowed values: any, critical, high, medium, low, negligible.`);
    }
  }
}
