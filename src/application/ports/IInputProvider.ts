import { ActionInputs } from "../../infrastructure/ActionInputs";

export interface IInputProvider {
  getInputs(): ActionInputs;
}
