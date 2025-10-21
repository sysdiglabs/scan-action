import { ActionInputs } from "../../../src/action";

export interface IInputProvider {
  getInputs(): ActionInputs;
}
