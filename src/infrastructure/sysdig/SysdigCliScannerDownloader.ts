import * as core from '@actions/core';
import * as exec from '@actions/exec';
import * as crypto from 'crypto';
import * as fs from 'fs';
import { ChecksumVerificationError } from '../../application/errors/ChecksumVerificationError';
import { cliScannerName, cliScannerURL, scannerURLForVersion } from './SysdigCliScannerConstants';

interface DownloaderConfig {
  sha256sum?: string;
}

export type SysdigCliScannerDownloaderOption = (config: DownloaderConfig) => void;

export function withSha256Sum(sha256sum: string): SysdigCliScannerDownloaderOption {
  return (config: DownloaderConfig) => {
    config.sha256sum = sha256sum;
  };
}

export class SysdigCliScannerDownloader {
  private readonly sha256sum?: string;

  constructor(...options: SysdigCliScannerDownloaderOption[]) {
    const config: DownloaderConfig = {};
    options.forEach(option => option(config));

    this.sha256sum = config.sha256sum;
  }

  public async download(version?: string, customURL?: string): Promise<string> {
    let url = customURL;
    if (!url) {
      url = cliScannerURL;
    }

    if (version && url === cliScannerURL) { // cliScannerURL is the default
      url = scannerURLForVersion(version);
    }
    if (!url) {
      throw Error("download url is empty")
    }

    const destination = `./${cliScannerName}`;

    core.info(`Pulling cli-scanner from: ${url}`);
    await exec.exec(`curl -sL ${url} -o ${destination}`, undefined, { silent: true });

    let expectedSum = await this.expectedSumFor(url)
    if (!expectedSum) {
      throw Error("unable to verify the sum of the scanner, the expected sum is empty");
    }

    await this.verifyChecksum(destination, expectedSum);

    return destination;
  }

  private async expectedSumFor(url: string): Promise<string | undefined> {
    let expectedSum = this.sha256sum;
    if (expectedSum) {
      core.info(`Manually provided checksum: ${expectedSum}`);
      return expectedSum;
    }

    const checksumUrl = `${url}.sha256`;
    core.info(`Downloading checksum from: ${checksumUrl}`);
    let checksumOutput = '';
    await exec.exec(`curl -sL ${checksumUrl}`, undefined, {
      silent: true,
      listeners: {
        stdout: (data: Buffer) => {
          checksumOutput += data.toString();
        },
      },
    });

    expectedSum = checksumOutput.split(' ')[0].trim();
    core.info(`Checksum downloaded: ${expectedSum}`);
    return expectedSum;
  }

  private async verifyChecksum(filePath: string, expectedSha256sum: string): Promise<void> {
    core.info(`Verifying checksum for ${filePath}`);

    const fileBuffer = fs.readFileSync(filePath);
    const hash = crypto.createHash('sha256');
    hash.update(fileBuffer);
    const calculatedSum = hash.digest('hex');

    if (calculatedSum !== expectedSha256sum) {
      throw new ChecksumVerificationError(
        `Checksum verification failed. Expected ${expectedSha256sum} but got ${calculatedSum}`
      );
    }

    core.info('Checksum verified successfully.');
    await exec.exec(`chmod u+x ${filePath}`, undefined, { silent: true });
  }
}
