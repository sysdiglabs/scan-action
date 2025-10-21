import * as core from '@actions/core';
import { ScanMode, ScanExecutionResult } from '../../scanner';
import { IInputProvider } from '../ports/IInputProvider';
import { IScanner } from '../ports/IScanner';
import { IReportPresenter } from '../ports/IReportPresenter';
import { IReportRepository } from '../ports/IReportRepository';
import { Report } from '../../domain/entities/report';
import { FilterOptions } from '../../domain/services/filtering';
import { Severity } from '../../domain/value-objects/severity';
import { ExecutionError } from '../../scanner';

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
      const opts = this.inputProvider.getInputs();
      opts.printOptions();
      const scanFlags = opts.composeFlags();

      let scanResult: ScanExecutionResult;
      // Download CLI Scanner from 'cliScannerURL'
      let retCode = await this.scanner.pullScanner(opts.cliScannerURL);
      if (retCode == 0) {
        // Execute Scanner
        scanResult = await this.scanner.executeScan(scanFlags);

        retCode = scanResult.ReturnCode;
        if (retCode == 0 || retCode == 1) {
          // Transform Scan Results to other formats such as SARIF
          if (opts.mode == ScanMode.vm) {
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
                minSeverity: (opts.severityAtLeast && opts.severityAtLeast.toLowerCase() !== "any")
                  ? opts.severityAtLeast.toLowerCase() as Severity
                  : undefined,
                packageTypes: this.parseCsvList(opts.packageTypes),
                notPackageTypes: this.parseCsvList(opts.notPackageTypes),
                excludeAccepted: opts.excludeAccepted,
              };

              for (const presenter of this.reportPresenters) {
                presenter.generateReport(report, opts.groupByPackage, filters);
              }
            }
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
        core.setFailed(`Unexpected error: ${error instanceof Error ? error.stack : String(error)}`);
      }
      core.error(`Unexpected error: ${error instanceof Error ? error.stack : String(error)}`);
    }
  }
}
