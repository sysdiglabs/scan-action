import { ActionInputs } from '../../action';
import { IInputProvider } from '../../application/ports/IInputProvider';

export class GitHubActionsInputProvider implements IInputProvider {
  getInputs(): ActionInputs {
    return ActionInputs.parseActionInputs();
  }
}
