import { ActionInputs } from '../../action';
import { processScanResult, run } from '../../..';
import { IInputProvider } from '../ports/IInputProvider';

export class RunScanUseCase {
  constructor(private readonly inputProvider: IInputProvider) {}

  async execute(): Promise<void> {
    // Por ahora, llamamos a la lógica antigua directamente.
    // Esto será refactorizado en los siguientes pasos.
    await run();
  }
}
