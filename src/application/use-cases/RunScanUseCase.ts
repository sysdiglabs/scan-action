import * as core from '@actions/core';
import { ScanMode } from '../../scanner';
import { IInputProvider } from '../ports/IInputProvider';
import { run, processScanResult } from '../../..'; // Temporal import

export class RunScanUseCase {
  constructor(private readonly inputProvider: IInputProvider) {}

  async execute(): Promise<void> {
    try {
      const opts = this.inputProvider.getInputs();
      opts.printOptions();
      const scanFlags = opts.composeFlags();

      // La lógica de pullScanner, executeScan y processScanResult
      // se moverá aquí desde 'index.ts' y se reemplazará por
      // llamadas a los puertos (IScanner, IReportPresenter, etc.)
      // en los siguientes pasos.
      // Por ahora, mantenemos la llamada a la lógica antigua.
      await run();

    } catch (error) {
      if (core.getInput('stop-on-processing-error') == 'true') {
        core.setFailed(`Unexpected error: ${error instanceof Error ? error.stack : String(error)}`);
      }
      core.error(`Unexpected error: ${error instanceof Error ? error.stack : String(error)}`);
    }
  }
}
