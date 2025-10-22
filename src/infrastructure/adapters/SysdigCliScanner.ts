import * as core from '@actions/core';
import * as exec from '@actions/exec';
import os from 'os';
import process from 'process';
import { IScanner } from '../../application/ports/IScanner';
import { ComposeFlags, ScanMode } from '../../application/ports/ScannerDTOs';
import { cliScannerName, cliScannerResult, cliScannerURL, scannerURLForVersion } from './SysdigCliScannerConstants';
import { ScanConfig } from '../../application/ports/ScanConfig';
import { Report } from '../../domain/entities/report';
import { ReportParsingError } from '../../application/errors/ReportParsingError';
const performance = require('perf_hooks').performance;

export class SysdigCliScanner implements IScanner {

  async executeScan(config: ScanConfig): Promise<Report> {
    await this.pullScanner(cliScannerURL, 'latest');

    const scanFlags = this.composeFlags(config);
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

    try {
      return JSON.parse(execOutput) as Report;
    } catch (e) {
      throw new ReportParsingError(execOutput);
    }
  }

  private async pullScanner(scannerURL: string, version: string): Promise<number> {
    let url = scannerURL;
    if (version && url === cliScannerURL) { // cliScannerURL is the default
      url = scannerURLForVersion(version);
    }

    let start = performance.now();
    core.info('Pulling cli-scanner from: ' + url);
    let cmd = `wget ${url} -O ./${cliScannerName}`;
    let retCode = await exec.exec(cmd, undefined, { silent: true });

    if (retCode == 0) {
      cmd = `chmod u+x ./${cliScannerName}`;
      await exec.exec(cmd, undefined, { silent: true });
    } else {
      core.error(`Falied to pull scanner using "${url}"`)
    }

    core.info("Scanner pull took " + Math.round(performance.now() - start) + " milliseconds.");
    return retCode;
  }

  private composeFlags(config: ScanConfig): ComposeFlags {
    let envvars: { [key: string]: string } = {}
    envvars['SECURE_API_TOKEN'] = config.sysdigSecureToken || "";

    let flags: string[] = [];

    if (config.registryUser) {
      envvars['REGISTRY_USER'] = config.registryUser;
    }

    if (config.registryPassword) {
      envvars['REGISTRY_PASSWORD'] = config.registryPassword;
    }

    if (config.standalone) {
      flags.push("--standalone");
    }

    if (config.sysdigSecureURL) {
      flags.push('--apiurl', config.sysdigSecureURL);
    }

    if (config.dbPath) {
      flags.push(`--dbpath=${config.dbPath}`);
    }

    if (config.skipUpload) {
      flags.push('--skipupload');
    }

    if (config.usePolicies) {
      const policies = config.usePolicies.split(',').map(p => p.trim());
      for (const policy of policies) {
        flags.push('--policy', policy.replace(/"/g, ''));
      }
    }

    if (config.sysdigSkipTLS) {
      flags.push(`--skiptlsverify`);
    }

    if (config.overridePullString) {
      flags.push(`--override-pullstring=${config.overridePullString}`);
    }

    if (config.extraParameters) {
      flags.push(...config.extraParameters.split(' '));
    }

    if (config.mode == ScanMode.iac) {
      flags.push(`--iac`);

      if (config.recursive) {
        flags.push(`-r`);
      }
      if (config.minimumSeverity) {
        flags.push(`-f=${config.minimumSeverity}`);
      }

      flags.push(config.iacScanPath);
    }

    if (config.mode == ScanMode.vm) {
      flags.push(`--output=json-file=${cliScannerResult}`)
      flags.push(config.imageTag);
    }

    return {
      envvars: envvars,
      flags: flags
    }
  }
}
