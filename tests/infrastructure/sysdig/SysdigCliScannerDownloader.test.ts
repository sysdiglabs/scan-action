import { SysdigCliScannerDownloader, withSha256Sum } from '../../../src/infrastructure/sysdig/SysdigCliScannerDownloader';
import { cliScannerName, getRunOS, getRunArch } from '../../../src/infrastructure/sysdig/SysdigCliScannerConstants';
import * as fs from 'fs';
import * as path from 'path';

describe('SysdigCliScannerDownloader - Integration Test', () => {
  const scannerVersion = '1.24.1';
  // This is the hardcoded, known-good SHA256 checksum for version 1.22.6 of the scanner.
  // Using a hardcoded value makes the test more stable and deterministic.
  const correctSha256sum: Record<string, string> = {
    "linux/amd64": 'aaca2b5d029cef6e0647da304fa25b969b2711d0e23e884ae2848f15044f6bed',
    "darwin/arm64": '726fb81d735ddc30e18cc0ca702326141537d64fa9fb03cb50290f4c74c70361'
  }
  const downloadedFilePath = path.resolve(process.cwd(), cliScannerName);

  // Cleanup the downloaded scanner binary after each test
  afterEach(() => {
    if (fs.existsSync(downloadedFilePath)) {
      fs.unlinkSync(downloadedFilePath);
    }
  });

  it('should succeed when a correct, user-provided checksum is used', async () => {
    jest.setTimeout(30000);
    const archOsString = getRunOS() + '/' + getRunArch();

    const downloader = new SysdigCliScannerDownloader(withSha256Sum(correctSha256sum[archOsString]));
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
    const archOsString = getRunOS() + '/' + getRunArch();

    await expect(downloader.download(scannerVersion)).rejects.toThrow(
      `Checksum verification failed. Expected ${incorrectChecksum} but got ${correctSha256sum[archOsString]}`
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
