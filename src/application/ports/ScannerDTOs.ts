export enum ScanMode {
  vm = "vm",
  iac = "iac",
}

export namespace ScanMode {
  export function fromString(str: string): ScanMode | undefined {
    switch (str.toLowerCase()) {
      case "vm":
        return ScanMode.vm;
      case "iac":
        return ScanMode.iac;
    }
  }
}

export interface ScanExecutionResult {
  ReturnCode: number;
  Output: string;
  Error: string;
}

export interface ComposeFlags {
  envvars: {
    [key: string]: string;
  };
  flags: string[];
}
