import * as core from '@actions/core';
import { RunScanUseCase } from './src/application/use-cases/RunScanUseCase';
import { GitHubActionsInputProvider } from './src/infrastructure/github/GitHubActionsInputProvider';
import { SysdigCliScanner } from './src/infrastructure/sysdig/SysdigCliScanner';
import { SarifReportPresenter } from './src/infrastructure/github/SarifReportPresenter';
import { SummaryReportPresenter } from './src/infrastructure/github/SummaryReportPresenter';
import { IReportPresenter } from './src/application/ports/IReportPresenter';
import {
  SysdigCliScannerDownloader,
  withSha256Sum,
  SysdigCliScannerDownloaderOption
} from './src/infrastructure/sysdig/SysdigCliScannerDownloader';

async function run(): Promise<void> {
  try {
    const inputProvider = new GitHubActionsInputProvider();
    const config = inputProvider.getInputs();

    const downloaderOptions: SysdigCliScannerDownloaderOption[] = [];
    if (config.cliScannerSha256sum) {
      downloaderOptions.push(withSha256Sum(config.cliScannerSha256sum));
    }

    const downloader = new SysdigCliScannerDownloader(...downloaderOptions);

    const scanner = new SysdigCliScanner(downloader);

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
