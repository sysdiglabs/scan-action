import * as core from '@actions/core';
import { RunScanUseCase } from './src/application/use-cases/RunScanUseCase';
import { GitHubActionsInputProvider } from './src/infrastructure/adapters/GitHubActionsInputProvider';
import { SysdigCliScanner } from './src/infrastructure/adapters/SysdigCliScanner';
import { SarifReportPresenter } from './src/infrastructure/presenters/SarifReportPresenter';
import { SummaryReportPresenter } from './src/infrastructure/presenters/SummaryReportPresenter';
import { FileSystemReportRepository } from './src/infrastructure/repositories/FileSystemReportRepository';
import { IReportPresenter } from './src/application/ports/IReportPresenter';

async function run(): Promise<void> {
  try {
    const inputProvider = new GitHubActionsInputProvider();
    const config = inputProvider.getInputs();

    const scanner = new SysdigCliScanner();
    const reportRepository = new FileSystemReportRepository();

    const presenters: IReportPresenter[] = [
      new SarifReportPresenter(),
    ];

    if (!config.skipSummary) {
      presenters.push(new SummaryReportPresenter(
        config.imageTag,
        config.overridePullString,
        config.standalone
      ));
    }

    const useCase = new RunScanUseCase(
      inputProvider,
      scanner,
      presenters,
      reportRepository
    );

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
