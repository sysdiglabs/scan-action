import { ComposeFlags, ScanExecutionResult } from "../../scanner";

export interface IScanner {
  pullScanner(url: string): Promise<number>;
  executeScan(flags: ComposeFlags): Promise<ScanExecutionResult>;
}
