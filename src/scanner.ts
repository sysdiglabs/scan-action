import * as core from '@actions/core';
import * as exec from '@actions/exec';
import os from 'os';
import process from 'process';
import { ActionInputs } from './action';
const performance = require('perf_hooks').performance;

const cliScannerVersion = "1.13.0"
const cliScannerOS = getRunOS()
const cliScannerArch = getRunArch()
const cliScannerURLBase = "https://download.sysdig.com/scanning/bin/sysdig-cli-scanner";
export const cliScannerName = "sysdig-cli-scanner"
export const cliScannerResult = "scan-result.json"
export const cliScannerURL = `${cliScannerURLBase}/${cliScannerVersion}/${cliScannerOS}/${cliScannerArch}/${cliScannerName}`

export const vmMode = "vm"
export const iacMode = "iac"

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
    env: envvars,
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

interface ComposeFlags {
  envvars: {
    [key: string]: string;
  };
  flags: string;
}
export function composeFlags(opts: ActionInputs): ComposeFlags {
  if (opts.cliScannerVersion && opts.cliScannerURL == cliScannerURL) {
    opts.cliScannerURL = `${cliScannerURLBase}/${opts.cliScannerVersion}/${cliScannerOS}/${cliScannerArch}/${cliScannerName}`
  }
  let envvars: { [key: string]: string } = {}
  envvars['SECURE_API_TOKEN'] = opts.sysdigSecureToken || "";

  let flags = ""

  if (opts.registryUser) {
    envvars['REGISTRY_USER'] = opts.registryUser;
  }

  if (opts.registryPassword) {
    envvars['REGISTRY_PASSWORD'] = opts.registryPassword;
  }

  if (opts.standalone) {
    flags += " --standalone";
  }

  if (opts.sysdigSecureURL) {
    flags += ` --apiurl ${opts.sysdigSecureURL}`;
  }

  if (opts.dbPath) {
    flags += ` --dbpath=${opts.dbPath}`;
  }

  if (opts.skipUpload) {
    flags += ' --skipupload';
  }

  if (opts.usePolicies) {
    flags += ` --policy=${opts.usePolicies}`;
  }

  if (opts.sysdigSkipTLS) {
    flags += ` --skiptlsverify`;
  }

  if (opts.overridePullString) {
    flags += ` --override-pullstring=${opts.overridePullString}`;
  }

  if (opts.extraParameters) {
    flags += ` ${opts.extraParameters}`;
  }

  if (opts.mode && opts.mode == iacMode) {
    flags += ` --iac`;
  }

  if (opts.recursive && opts.mode == iacMode) {
    flags += ` -r`;
  }

  if (opts.minimumSeverity && opts.mode == iacMode) {
    flags += ` -f=${opts.minimumSeverity}`;
  }

  if (opts.mode && opts.mode == vmMode) {
    flags += ` --json-scan-result=${cliScannerResult}`
    flags += ` ${opts.imageTag}`;
  }

  if (opts.mode && opts.mode == iacMode) {
    flags += ` ${opts.iacScanPath}`;
  }

  return {
    envvars: envvars,
    flags: flags
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


