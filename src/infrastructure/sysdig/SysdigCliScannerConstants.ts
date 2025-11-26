import os from 'os';

const cliScannerVersion = "1.22.6"
const cliScannerOS = getRunOS()
const cliScannerArch = getRunArch()
const cliScannerURLBase = "https://download.sysdig.com/scanning/bin/sysdig-cli-scanner";
export const cliScannerName = "sysdig-cli-scanner"
export const cliScannerResult = "scan-result.json"
export const cliScannerURL = `${cliScannerURLBase}/${cliScannerVersion}/${cliScannerOS}/${cliScannerArch}/${cliScannerName}`

export function scannerURLForVersion(version: string): string {
  return `${cliScannerURLBase}/${version}/${cliScannerOS}/${cliScannerArch}/${cliScannerName}`;
}

export function getRunArch() {
  let arch = "unknown";
  if (os.arch() == "x64") {
    arch = "amd64";
  } else if (os.arch() == "arm64") {
    arch = "arm64";
  }
  return arch;
}

export function getRunOS() {
  let os_name = "unknown";
  if (os.platform() == "linux") {
    os_name = "linux";
  } else if (os.platform() == "darwin") {
    os_name = "darwin";
  }
  return os_name;
}
