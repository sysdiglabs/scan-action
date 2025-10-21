import { ScanConfig } from "./ScanConfig";

export interface IInputProvider {
  getInputs(): ScanConfig;
}
