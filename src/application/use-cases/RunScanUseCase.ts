import * as core from '@actions/core';
import { ScanMode, ScanExecutionResult } from '../ports/ScannerDTOs';
import { IInputProvider } from '../ports/IInputProvider';
import { IScanner } from '../ports/IScanner';
import { IReportPresenter } from '../ports/IReportPresenter';
import { IReportRepository } from '../ports/IReportRepository';
import { Report } from '../../domain/entities/report';
import { FilterOptions } from '../../domain/services/filtering';
import { Severity } from '../../domain/value-objects/severity';
import { ExecutionError } from '../errors/ExecutionError';
import { ScanConfig } from '../ports/ScanConfig';

export class RunScanUseCase {
  constructor(
    private readonly inputProvider: IInputProvider,
    private readonly scanner: IScanner,
    private readonly reportPresenters: IReportPresenter[],
    private readonly reportRepository: IReportRepository
    ) {}

  private parseCsvList(str?: string): string[] {
    if (!str) return [];
    return str.split(",").map(s => s.trim()).filter(s => !!s);
  }

  async execute(): Promise<void> {
    try {
      const config = this.inputProvider.getInputs();
      this.printOptions(config);

      let scanResult: ScanExecutionResult;
      // Download CLI Scanner from 'cliScannerURL'
      let retCode = await this.scanner.pullScanner(config.cliScannerURL, config.cliScannerVersion);
      if (retCode == 0) {
        // Execute Scanner
        scanResult = await this.scanner.executeScan(config);

        retCode = scanResult.ReturnCode;
        if (retCode == 0 || retCode == 1) {
          // Transform Scan Results to other formats such as SARIF
          if (config.mode == ScanMode.vm) {
            this.reportRepository.writeReport(scanResult.Output);

            let report: Report;
            try {
              report = JSON.parse(scanResult.Output);
            } catch (error) {
              core.error("Error parsing analysis JSON report: " + error + ". Output was: " + scanResult.Output);
              throw new ExecutionError(scanResult.Output, scanResult.Error);
            }

            if (report) {
              const filters: FilterOptions = {
                minSeverity: (config.severityAtLeast && config.severityAtLeast.toLowerCase() !== "any")
                  ? config.severityAtLeast.toLowerCase() as Severity
                  : undefined,
                packageTypes: this.parseCsvList(config.packageTypes),
                notPackageTypes: this.parseCsvList(config.notPackageTypes),
                excludeAccepted: config.excludeAccepted,
              };

              for (const presenter of this.reportPresenters) {
                presenter.generateReport(report, config.groupByPackage, filters);
              }
            }
          }
        } else {
          core.error("Terminating scan. Scanner couldn't be executed.")
        }
      } else {
        core.error("Terminating scan. Scanner couldn't be pulled.")
      }

      if (config.stopOnFailedPolicyEval && retCode == 1) {
        core.setFailed(`Stopping because Policy Evaluation was FAILED.`);
      } else if (config.standalone && retCode == 0) {
        core.info("Policy Evaluation was OMITTED.");
      } else if (retCode == 0) {
        core.info("Policy Evaluation was PASSED.");
      } else if (config.stopOnProcessingError && retCode > 1) {
        core.setFailed(`Stopping because the scanner terminated with an error.`);
      } // else: Don't stop regardless the outcome.


    } catch (error) {
      if (core.getInput('stop-on-processing-error') == 'true') {
        core.setFailed(`Unexpected error: ${error instanceof Error ? error.stack : String(error)}`);
      }
      core.error(`Unexpected error: ${error instanceof Error ? error.stack : String(error)}`);
    }
  }

  private printOptions(config: ScanConfig) {
    if (config.standalone) {
      core.info(`[!] Running in Standalone Mode.`);
    }

    if (config.sysdigSecureURL) {
      core.info('Sysdig Secure URL: ' + config.sysdigSecureURL);
    }

    if (config.registryUser && config.registryPassword) {
      core.info(`Using specified Registry credentials.`);
    }

    core.info(`Stop on Failed Policy Evaluation: ${config.stopOnFailedPolicyEval}`);

    core.info(`Stop on Processing Error: ${config.stopOnProcessingError}`);

    if (config.skipUpload) {
      core.info(`Skipping scan results upload to Sysdig Secure...`);
    }

    if (config.dbPath) {
      core.info(`DB Path: ${config.dbPath}`);
    }

    core.info(`Sysdig skip TLS: ${config.sysdigSkipTLS}`);

    if (config.severityAtLeast) {
      core.info(`Severity level: ${config.severityAtLeast}`);
    }

    if (config.packageTypes) {
      core.info(`Package types included: ${config.packageTypes}`);
    }

    if (config.notPackageTypes) {
      core.info(`Package types excluded: ${config.notPackageTypes}`);
    }

    if (config.excludeAccepted !== undefined) {
      core.info(`Exclude vulnerabilities with accepted risks: ${config.excludeAccepted}`);
    }

    core.info('Analyzing image: ' + config.imageTag);

    if (config.overridePullString) {
      core.info(` * Image PullString will be overwritten as ${config.overridePullString}`);
    }

    if (config.skipSummary) {
      core.info("This run will NOT generate a SUMMARY.");
    }
  }
}
