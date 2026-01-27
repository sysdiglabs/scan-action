import * as core from '@actions/core';
import * as exec from '@actions/exec';
import process from 'process';
import { IScanner } from '../../application/ports/IScanner';
import { ComposeFlags, ScanMode } from '../../application/ports/ScannerDTOs';
import { cliScannerName, cliScannerResult, cliScannerURL, scannerURLForVersion } from './SysdigCliScannerConstants';
import { ScanConfig } from '../../application/ports/ScanConfig';
import { JsonScanResultV1 } from './JsonScanResultV1';
import { ReportParsingError } from '../../application/errors/ReportParsingError';
import { Architecture, EvaluationResult, Family, OperatingSystem, ScanResult, ScanType } from '../../domain/scanresult';
import { JsonScanResultV1ToScanResultAdapter } from './JsonScanResultV1ToScanResultAdapter';
const performance = require('perf_hooks').performance;

import { SysdigCliScannerDownloader } from './SysdigCliScannerDownloader';

export class SysdigCliScanner implements IScanner {
  private readonly downloader: SysdigCliScannerDownloader;

  constructor(downloader: SysdigCliScannerDownloader) {
    this.downloader = downloader;
  }

  async executeScan(config: ScanConfig): Promise<ScanResult> {
    const scannerPath = await this.downloader.download(config.cliScannerVersion, config.cliScannerURL);

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
    const command = scannerPath;
    const loggableFlags = flags.map(flag => flag.includes(' ') ? `"${flag}"` : flag);
    core.info("Executing: " + command + " " + loggableFlags.join(' '));
    let retCode = await exec.exec(command, flags, scanOptions);
    core.info("Image analysis took " + Math.round(performance.now() - start) + " milliseconds.");

    // IaC mode: No JSON output file - derive result from exit code
    if (config.mode === ScanMode.iac) {
      return this.createIacResult(retCode);
    }

    // VM mode: Parse JSON output
    if (retCode == 0 || retCode == 1) {
      await exec.exec(`cat ./${cliScannerResult}`, undefined, catOptions);
    }

    try {
      const jsonScanResult = JSON.parse(execOutput) as JsonScanResultV1;
      return new JsonScanResultV1ToScanResultAdapter().toScanResult(jsonScanResult);
    } catch (e) {
      throw new ReportParsingError(execOutput);
    }
  }

  private createIacResult(exitCode: number): ScanResult {
    const evaluationResult = exitCode === 0
      ? EvaluationResult.Passed
      : EvaluationResult.Failed;

    return new ScanResult(
      ScanType.Docker,
      'iac-scan',
      'iac-scan',
      null,
      new OperatingSystem(Family.Unknown, 'N/A'),
      BigInt(0),
      Architecture.Unknown,
      {},
      new Date(),
      evaluationResult
    );
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
