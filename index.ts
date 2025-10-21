import { RunScanUseCase } from './src/application/use-cases/RunScanUseCase';
import { GitHubActionsInputProvider } from './src/infrastructure/adapters/GitHubActionsInputProvider';
import { SysdigCliScanner } from './src/infrastructure/adapters/SysdigCliScanner';
import { SarifReportPresenter } from './src/infrastructure/presenters/SarifReportPresenter';
import { SummaryReportPresenter } from './src/infrastructure/presenters/SummaryReportPresenter';
import { IReportPresenter } from './src/application/ports/IReportPresenter';
import { FileSystemReportRepository } from './src/infrastructure/repositories/FileSystemReportRepository';

if (require.main === module) {
  const inputProvider = new GitHubActionsInputProvider();
  const scanner = new SysdigCliScanner();
  const opts = inputProvider.getInputs();
  const presenters: IReportPresenter[] = [
    new SarifReportPresenter(),
  ];
  if (!opts.skipSummary) {
    presenters.push(new SummaryReportPresenter(opts));
  }
  const reportRepository = new FileSystemReportRepository();
  const useCase = new RunScanUseCase(inputProvider, scanner, presenters, reportRepository);
  useCase.execute();
}
