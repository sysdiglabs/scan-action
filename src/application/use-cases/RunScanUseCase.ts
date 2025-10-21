import * as core from '@actions/core';
import { ScanMode, ScanExecutionResult } from '../../scanner';
import { IInputProvider } from '../ports/IInputProvider';
import { IScanner } from '../ports/IScanner';
import { IReportPresenter } from '../ports/IReportPresenter';
import { IReportRepository } from '../ports/IReportRepository';
import { processScanResult } from '../../..'; // Temporal import

export class RunScanUseCase {
  constructor(
    private readonly inputProvider: IInputProvider,
    private readonly scanner: IScanner,
    private readonly reportPresenters: IReportPresenter[],
    private readonly reportRepository: IReportRepository
    ) {}

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
            await processScanResult(scanResult, opts); // This will be replaced
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
