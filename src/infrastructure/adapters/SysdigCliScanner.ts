import * as core from '@actions/core';
import * as exec from '@actions/exec';
import os from 'os';
import process from 'process';
import { IScanner } from '../../application/ports/IScanner';
import { ComposeFlags, ScanExecutionResult, cliScannerName, cliScannerResult } from '../../scanner';
const performance = require('perf_hooks').performance;

export class SysdigCliScanner implements IScanner {
  async pullScanner(scannerURL: string): Promise<number> {
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

  async executeScan(scanFlags: ComposeFlags): Promise<ScanExecutionResult> {
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
    const command = `./${cliScannerName}`;
    const loggableFlags = flags.map(flag => flag.includes(' ') ? `"${flag}"` : flag);
    core.info("Executing: " + command + " " + loggableFlags.join(' '));
    let retCode = await exec.exec(command, flags, scanOptions);
    core.info("Image analysis took " + Math.round(performance.now() - start) + " milliseconds.");

    if (retCode == 0 || retCode == 1) {
      await exec.exec(`cat ./${cliScannerResult}`, undefined, catOptions);
    }
    return { ReturnCode: retCode, Output: execOutput, Error: errOutput };
  }
}
