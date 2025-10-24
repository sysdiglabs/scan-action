import { SysdigCliScannerDownloader, withSha256Sum } from '../../../src/infrastructure/sysdig/SysdigCliScannerDownloader';
import { cliScannerName } from '../../../src/infrastructure/sysdig/SysdigCliScannerConstants';
import * as fs from 'fs';
import * as path from 'path';

describe('SysdigCliScannerDownloader - Integration Test', () => {
  const scannerVersion = '1.22.6';
  // This is the hardcoded, known-good SHA256 checksum for version 1.22.6 of the scanner.
  // Using a hardcoded value makes the test more stable and deterministic.
  const correctSha256sum = '68ec2fc48c6ad61eba60a2469c5548153700fedab40ac79e34b7baa5f2e86e42';
  const downloadedFilePath = path.resolve(process.cwd(), cliScannerName);

  // Cleanup the downloaded scanner binary after each test
  afterEach(() => {
    if (fs.existsSync(downloadedFilePath)) {
      fs.unlinkSync(downloadedFilePath);
    }
  });

  it('should succeed when a correct, user-provided checksum is used', async () => {
    jest.setTimeout(30000);
    const downloader = new SysdigCliScannerDownloader(withSha256Sum(correctSha256sum));
    const scannerPath = await downloader.download(scannerVersion);

    expect(scannerPath).toBe(`./${cliScannerName}`);
    expect(fs.existsSync(downloadedFilePath)).toBe(true);
    const stats = fs.statSync(downloadedFilePath);
    expect((stats.mode & fs.constants.S_IXUSR) !== 0).toBe(true);
  }, 30000);

  it('should fail when an incorrect, user-provided checksum is used', async () => {
    jest.setTimeout(30000);
    const incorrectChecksum = 'a'.repeat(64);
    const downloader = new SysdigCliScannerDownloader(withSha256Sum(incorrectChecksum));

    await expect(downloader.download(scannerVersion)).rejects.toThrow(
      `Checksum verification failed. Expected ${incorrectChecksum} but got ${correctSha256sum}`
    );
  }, 30000);

  it('should succeed when no checksum is provided (auto-fetch mechanism)', async () => {
    jest.setTimeout(30000);
    const downloader = new SysdigCliScannerDownloader();
    const scannerPath = await downloader.download(scannerVersion);

    expect(scannerPath).toBe(`./${cliScannerName}`);
    expect(fs.existsSync(downloadedFilePath)).toBe(true);
    const stats = fs.statSync(downloadedFilePath);
    expect((stats.mode & fs.constants.S_IXUSR) !== 0).toBe(true);
  }, 30000);
});
