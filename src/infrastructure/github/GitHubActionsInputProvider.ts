import { ActionInputs } from './ActionInputs';
import { IInputProvider } from '../../application/ports/IInputProvider';
import { ScanConfig } from '../../application/ports/ScanConfig';

export class GitHubActionsInputProvider implements IInputProvider {
  getInputs(): ScanConfig {
    const actionInputs = ActionInputs.parseActionInputs();
    return actionInputs.params;
  }
}
