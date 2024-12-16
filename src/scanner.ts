import * as core from '@actions/core';
import * as exec from '@actions/exec';
import os from 'os';
import process from 'process';
const performance = require('perf_hooks').performance;

const cliScannerVersion = "1.18.0"
const cliScannerOS = getRunOS()
const cliScannerArch = getRunArch()
const cliScannerURLBase = "https://download.sysdig.com/scanning/bin/sysdig-cli-scanner";
export const cliScannerName = "sysdig-cli-scanner"
export const cliScannerResult = "scan-result.json"
export const cliScannerURL = `${cliScannerURLBase}/${cliScannerVersion}/${cliScannerOS}/${cliScannerArch}/${cliScannerName}`

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

export async function pullScanner(scannerURL: string) {
  let start = performance.now();
  core.info('Pulling cli-scanner from: ' + scannerURL);
  let cmd = `wget ${scannerURL} -O ./${cliScannerName}`;
  let retCode = await exec.exec(cmd, undefined, { silent: true });

  if (retCode == 0) {
    cmd = `chmod u+x ./${cliScannerName}`;
    await exec.exec(cmd, undefined, { silent: true });
  } else {
    core.error(`Falied to pull scanner using "${scannerURL}"`)
  }

  core.info("Scanner pull took " + Math.round(performance.now() - start) + " milliseconds.");
  return retCode;
}

export interface ScanExecutionResult {
  ReturnCode: number;
  Output: string;
  Error: string;
}


// If custom scanner version is specified
export async function executeScan(scanFlags: ComposeFlags): Promise<ScanExecutionResult> {

  let { envvars, flags } = scanFlags;
  let execOutput = '';
  let errOutput = '';


  const scanOptions: exec.ExecOptions = {
    env: {
    ...Object.fromEntries(
      Object.entries(process.env).map(([key, value]) => [key, value ?? ""])
    ),
    ...envvars,
  },
    silent: true,
    ignoreReturnCode: true,
    listeners: {
      stdout: (data: Buffer) => {
        process.stdout.write(data);
      },
      stderr: (data: Buffer) => {
        process.stderr.write(data);
      }
    }
  };

  const catOptions: exec.ExecOptions = {
    silent: true,
    ignoreReturnCode: true,
    listeners: {
      stdout: (data) => {
        execOutput += data.toString();
      },
      stderr: (data) => {
        errOutput += data.toString();
      }
    }
  }

  let start = performance.now();
  let cmd = `./${cliScannerName} ${flags}`;
  core.info("Executing: " + cmd);
  let retCode = await exec.exec(cmd, undefined, scanOptions);
  core.info("Image analysis took " + Math.round(performance.now() - start) + " milliseconds.");

  if (retCode == 0 || retCode == 1) {
    cmd = `cat ./${cliScannerResult}`;
    await exec.exec(cmd, undefined, catOptions);
  }
  return { ReturnCode: retCode, Output: execOutput, Error: errOutput };
}

export interface ComposeFlags {
  envvars: {
    [key: string]: string;
  };
  flags: string;
}

export function scannerURLForVersion(version: string): string {
  return `${cliScannerURLBase}/${version}/${cliScannerOS}/${cliScannerArch}/${cliScannerName}`;

}
export function numericPriorityForSeverity(severity: string): number | undefined {
  switch (severity.toLowerCase()) {
    case 'critical':
      return 0
    case 'high':
      return 1
    case 'medium':
      return 2
    case 'low':
      return 3
    case 'negligible':
      return 4
    case 'any':
      return 5
  }
}


function getRunArch() {
  let arch = "unknown";
  if (os.arch() == "x64") {
    arch = "amd64";
  } else if (os.arch() == "arm64") {
    arch = "arm64";
  }
  return arch;
}

function getRunOS() {
  let os_name = "unknown";
  if (os.platform() == "linux") {
    os_name = "linux";
  } else if (os.platform() == "darwin") {
    os_name = "darwin";
  }
  return os_name;
}


