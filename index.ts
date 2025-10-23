import * as core from '@actions/core';
import { RunScanUseCase } from './src/application/use-cases/RunScanUseCase';
import { GitHubActionsInputProvider } from './src/infrastructure/github/GitHubActionsInputProvider';
import { SysdigCliScanner } from './src/infrastructure/sysdig/SysdigCliScanner';
import { SarifReportPresenter } from './src/infrastructure/github/SarifReportPresenter';
import { SummaryReportPresenter } from './src/infrastructure/github/SummaryReportPresenter';
import { IReportPresenter } from './src/application/ports/IReportPresenter';

async function run(): Promise<void> {
  try {
    const inputProvider = new GitHubActionsInputProvider();
    const config = inputProvider.getInputs();

    const scanner = new SysdigCliScanner();

    const presenters: IReportPresenter[] = [
      new SarifReportPresenter(),
    ];

    if (!config.skipSummary) {
      presenters.push(new SummaryReportPresenter());
    }

  const useCase = new RunScanUseCase(scanner, presenters, inputProvider);
  await useCase.execute();
} catch (error) {
    if (error instanceof Error) {
      core.setFailed(error.message);
    } else {
      core.setFailed(`Unknown error: ${error}`);
    }
  }
}

run();
