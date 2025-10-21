import { ActionInputs } from '../ActionInputs';
import { IInputProvider } from '../../application/ports/IInputProvider';

export class GitHubActionsInputProvider implements IInputProvider {
  getInputs(): ActionInputs {
    return ActionInputs.parseActionInputs();
  }
}
