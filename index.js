const core = require('@actions/core');
const exec = require('@actions/exec');
const fs = require('fs');
const performance = require('perf_hooks').performance;
const process = require('process');
const { version } = require('./package.json');
const os = require('os');

const toolVersion = `${version}`;
const dottedQuadToolVersion = `${version}.0`;
const vmMode = "vm"
const iacMode = "iac"

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

const cliScannerVersion = "1.8.1"
const cliScannerName = "sysdig-cli-scanner"
const cliScannerOS = getRunOS()
const cliScannerArch = getRunArch()
const cliScannerURLBase = "https://download.sysdig.com/scanning/bin/sysdig-cli-scanner";
const cliScannerURL = `${cliScannerURLBase}/${cliScannerVersion}/${cliScannerOS}/${cliScannerArch}/${cliScannerName}`
const cliScannerResult = "scan-result.json"

const defaultSecureEndpoint = "https://secure.sysdig.com/"

// Sysdig to SARIF severity convertion
const LEVELS = {
  "error": ["High","Critical"],
  "warning": ["Medium"],
  "note": ["Negligible","Low"]
}

const PRIORITY = {
  "critical": 0,
  "high": 1,
  "medium": 2,
  "low": 3,
  "negligible": 4
}

const EVALUATION = {
  "failed": "❌",
  "passed": "✅" 
}

class ExecutionError extends Error {
  constructor(stdout, stderr) {
    super("execution error\n\nstdout: " + stdout + "\n\nstderr: " + stderr);
    this.stdout = stdout;
    this.stderr = stderr;
  }
}


function parseActionInputs() {
  return {
    cliScannerURL: core.getInput('cli-scanner-url') || cliScannerURL,
    cliScannerVersion: core.getInput('cli-scanner-version'),
    registryUser: core.getInput('registry-user'),
    registryPassword: core.getInput('registry-password'),
    stopOnFailedPolicyEval: core.getInput('stop-on-failed-policy-eval') == 'true',
    stopOnProcessingError: core.getInput('stop-on-processing-error') == 'true',
    standalone: core.getInput('standalone') == 'true',
    dbPath: core.getInput('db-path'),
    skipUpload: core.getInput('skip-upload') == 'true',
    skipSummary: core.getInput('skip-summary') == 'true',
    usePolicies: core.getInput('use-policies'),
    overridePullString: core.getInput('override-pullstring'),
    imageTag: core.getInput('image-tag'),
    sysdigSecureToken: core.getInput('sysdig-secure-token'),
    sysdigSecureURL: core.getInput('sysdig-secure-url') || defaultSecureEndpoint,
    sysdigSkipTLS: core.getInput('sysdig-skip-tls') == 'true',
    severityAtLeast: core.getInput('severity-at-least') || 'any',
    groupByPackage: core.getInput('group-by-package') == 'true',
    extraParameters: core.getInput('extra-parameters'),
    mode: core.getInput('mode') || vmMode,
    recursive: core.getInput('recursive') == 'true',
    minimumSeverity: core.getInput('minimum-severity'),
    iacScanPath: core.getInput('iac-scan-path') || './'
  }
}


function printOptions(opts) {
  if (opts.standalone) {
    core.info(`[!] Running in Standalone Mode.`);
  }

  if (opts.sysdigSecureURL) {
    core.info('Sysdig Secure URL: ' + opts.sysdigSecureURL);
  }

  if (opts.registryUser && opts.registryPassword) {
    core.info(`Using specified Registry credentials.`);
  }

  core.info(`Stop on Failed Policy Evaluation: ${opts.stopOnFailedPolicyEval}`);

  core.info(`Stop on Processing Error: ${opts.stopOnProcessingError}`);

  if (opts.skipUpload) {
    core.info(`Skipping scan results upload to Sysdig Secure...`);
  }

  if (opts.dbPath) {
    core.info(`DB Path: ${opts.dbPath}`);
  }

  core.info(`Sysdig skip TLS: ${opts.sysdigSkipTLS}`);

  if (opts.severityAtLeast != 'any') {
    core.info(`Severity level: ${opts.severityAtLeast}`);
  }

  core.info('Analyzing image: ' + opts.imageTag);

  if (opts.overridePullString) {
    core.info(` * Image PullString will be overwritten as ${opts.overridePullString}`);
  }

  if (opts.skipSummary) {
    core.info("This run will NOT generate a SUMMARY.");
  }
}

function composeFlags(opts) {
  let envvars = {}
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

function writeReport(reportData) {
  fs.writeFileSync("./report.json", reportData);
  core.setOutput("scanReport", "./report.json");
}

function validateInput(opts) {
  if (!opts.standalone && !opts.sysdigSecureToken) {
    core.setFailed("Sysdig Secure Token is required for standard execution, please set your token or remove the standalone input.");
    throw new Error("Sysdig Secure Token is required for standard execution, please set your token or remove the standalone input.");
  }

  if (opts.mode && opts.mode == vmMode && !opts.imageTag) {
    core.setFailed("image-tag is required for VM mode.");
    throw new Error("image-tag is required for VM mode.");
  }

  if (opts.mode && opts.mode == iacMode && opts.iacScanPath == "") {
    core.setFailed("iac-scan-path can't be empty, please specify the path you want to scan your manifest resources.");
    throw new Error("iac-scan-path can't be empty, please specify the path you want to scan your manifest resources.");
  }
}

async function run() {

  try {
    let opts = parseActionInputs();
    validateInput(opts)
    printOptions(opts);
    let scanFlags = composeFlags(opts);

    // If custom scanner version is specified
    if (opts.cliScannerVersion && opts.cliScannerURL == cliScannerURL) {
      opts.cliScannerURL = `${cliScannerURLBase}/${opts.cliScannerVersion}/${cliScannerOS}/${cliScannerArch}/${cliScannerName}`
    }

    let scanResult;
    // Download CLI Scanner from 'cliScannerURL'
    let retCode = await pullScanner(opts.cliScannerURL);
    if (retCode == 0) {
      // Execute Scanner
      scanResult = await executeScan(scanFlags.envvars, scanFlags.flags);

      retCode = scanResult.ReturnCode;
      if (retCode == 0 || retCode == 1) {
        // Transform Scan Results to other formats such as SARIF
        if (opts.mode && opts.mode == vmMode) {
          await processScanResult(scanResult, opts);
        }
      } else {
        core.error("Terminating scan. Scanner couldn't be executed.")
      }
    } else {
      core.error("Terminating scan. Scanner couldn't be pulled.")
    }

    if (opts.stopOnFailedPolicyEval && retCode == 1) {
      core.setFailed(`Stopping because Policy Evaluation was FAILED.`);
    } else if (opts.standalone && retCode == 0) {
      core.info("Policy Evaluation was OMITTED.");
    } else if (retCode == 0) {
      core.info("Policy Evaluation was PASSED.");
    } else if (opts.stopOnProcessingError && retCode > 1) {
      core.setFailed(`Stopping because the scanner terminated with an error.`);
    } // else: Don't stop regardless the outcome.

  } catch (error) {
    if (core.getInput('stop-on-processing-error') == 'true') {
      core.setFailed("Unexpected error");
    }
    core.error(error);
  }
}

function filterResult(report, severity) {
  let filter_num = PRIORITY[severity.toLowerCase()];

  report.result.packages.forEach(pkg => {
    if (pkg.vulns) pkg.vulns = pkg.vulns.filter((vuln) => PRIORITY[vuln.severity.value.toLowerCase()] <= filter_num);
  });
  return report;
}

async function processScanResult(result, opts) {
  writeReport(result.Output);

  let report;
  try {
    report = JSON.parse(result.Output);
  } catch (error) {
    core.error("Error parsing analysis JSON report: " + error + ". Output was: " + result.output);
    throw new ExecutionError(result.Output, result.Error);
  }

  if (report) {
    if (opts.severityAtLeast && opts.severityAtLeast != 'any') {
      report = filterResult(report, opts.severityAtLeast);
    }

    generateSARIFReport(report, opts.groupByPackage);

    if (!opts.skipSummary) {
      core.info("Generating Summary...")

      await generateSummary(opts, report);

    } else {
      core.info("Skipping Summary...")
    }
  }
}

async function pullScanner(scannerURL) {
  let start = performance.now();
  core.info('Pulling cli-scanner from: ' + scannerURL);
  let cmd = `wget ${scannerURL} -O ./${cliScannerName}`;
  let retCode = await exec.exec(cmd, null, {silent: true});

  if (retCode == 0) {
    cmd = `chmod u+x ./${cliScannerName}`;
    await exec.exec(cmd, null, {silent: true});
  } else {
    core.error(`Falied to pull scanner using "${scannerURL}"`)
  }
  
  core.info("Scanner pull took " + Math.round(performance.now() - start) + " milliseconds.");
  return retCode;
}

async function executeScan(envvars, flags) {

  let execOutput = '';
  let errOutput = '';


  const scanOptions = {
    env: envvars,
    silent: true,
    ignoreReturnCode: true,
    listeners: {
      stdout: (data) => {
        process.stdout.write(data);
      },
      stderr: (data) => {
        process.stderr.write(data);
      }
    }
  };

  const catOptions = {
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
  let retCode = await exec.exec(cmd, null, scanOptions);
  core.info("Image analysis took " + Math.round(performance.now() - start) + " milliseconds.");

  if (retCode == 0 || retCode == 1) {
    cmd = `cat ./${cliScannerResult}`;
    await exec.exec(cmd, null, catOptions);
  }
  return { ReturnCode: retCode, Output: execOutput, Error: errOutput };
}

function vulnerabilities2SARIF(data, groupByPackage) {
  let rules = [];
  let results = [];

  if (groupByPackage) {
    [rules, results] = vulnerabilities2SARIFResByPackage(data)
  } else {
    [rules, results] = vulnerabilities2SARIFRes(data)
  }

  if (!rules.length || !results.length) {
    return {};
  }

  const runs = [{
    tool: {
      driver: {
        name: "sysdig-cli-scanner",
        fullName: "Sysdig Vulnerability CLI Scanner",
        informationUri: "https://docs.sysdig.com/en/docs/installation/sysdig-secure/install-vulnerability-cli-scanner",
        version: toolVersion,
        semanticVersion: toolVersion,
        dottedQuadFileVersion: dottedQuadToolVersion,
        rules: rules 
      }
    },
    logicalLocations: [
      {
        name: "container-image",
        fullyQualifiedName: "container-image",
        kind: "namespace"
      }
    ],
    results: results,
    columnKind: "utf16CodeUnits",
    properties: {
      pullString: data.result.metadata.pullString,
      digest: data.result.metadata.digest,
      imageId: data.result.metadata.imageId,
      architecture: data.result.metadata.architecture,
      baseOs: data.result.metadata.baseOs,
      os: data.result.metadata.os,
      size: data.result.metadata.size,
      layersCount: data.result.metadata.layersCount,
      resultUrl: data.info.resultUrl || "",
      resultId: data.info.resultId || "",
  }
  }];


  const sarifOutput = {
    "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
    version: "2.1.0",
    runs: runs
  };

  return (sarifOutput);
}

function check_level(sev_value) {
  let level = "note";

  for (let key in LEVELS) {
    if (sev_value in LEVELS[key]) {
      level = key
    }
  }

  return level
}


function vulnerabilities2SARIFResByPackage(data) {
  let results = [];
  let rules = [];
  let resultUrl = "";
  let baseUrl = null;
  
  if (data.info && data.result) {
    if (data.info.resultUrl) {
      resultUrl = data.info.resultUrl;
      baseUrl = resultUrl.slice(0,resultUrl.lastIndexOf('/'));
    }
  
    data.result.packages.forEach(pkg => {
      if (!pkg.vulns) {
        return
      }

      let helpUri = "";
      let fullDescription = "";
      let severity_level = "";
      let severity_num = 5;
      let score = 0.0;
      pkg.vulns.forEach(vuln => {
        fullDescription += `${getSARIFVulnFullDescription(pkg, vuln)}\n\n\n`;

        if (PRIORITY[vuln.severity.value.toLowerCase()] < severity_num) {
          severity_level = vuln.severity.value.toLowerCase();
          severity_num = PRIORITY[severity_level];
        }

        if (vuln.cvssScore.value.score > score) {
          score = vuln.cvssScore.value.score;
        }
      });
      if (baseUrl) helpUri = `${baseUrl}/content?filter=freeText+in+("${pkg.name}")`;


      let rule = {
        id: pkg.name,
        name: pkg.name,
        shortDescription: {
          text: `Vulnerable package: ${pkg.name}`
        },
        fullDescription: {
          text: fullDescription
        },
        helpUri: helpUri,
        help: getSARIFPkgHelp(pkg),
        properties: {
          precision: "very-high",
          'security-severity': `${score}`,
          tags: [
              'vulnerability',
              'security',
              severity_level
          ]
        }
      }
      rules.push(rule);
      
      let result = {
        ruleId: pkg.name,
        level: check_level(severity_level),
        message: {
          text: getSARIFReportMessageByPackage(data, pkg, baseUrl)
        },
        locations: [
          {
              physicalLocation: {
                  artifactLocation: {
                      uri: `file:///${data.result.metadata.pullString}`,
                      uriBaseId: "ROOTPATH"
                  }
              },
              message: {
                  text: `${data.result.metadata.pullString} - ${pkg.name}@${pkg.version}`
              }
          }
        ]
      }
      results.push(result)
    });
  }
  
  return [rules, results];
}

function vulnerabilities2SARIFRes(data) {
  let results = [];
  let rules = [];
  let ruleIds = [];
  let resultUrl = "";
  let baseUrl = null;
  
  if (data.info && data.result) {
    if (data.info.resultUrl) {
      resultUrl = data.info.resultUrl;
      baseUrl = resultUrl.slice(0,resultUrl.lastIndexOf('/'));
    }
  
    data.result.packages.forEach(pkg => {
      if (!pkg.vulns) {
        return
      }

      pkg.vulns.forEach(vuln =>{
        if (!(vuln.name in ruleIds)){
          ruleIds.push(vuln.name)
          let rule = {
            id: vuln.name,
            name: pkg.type,
            shortDescription: {
              text: getSARIFVulnShortDescription(pkg, vuln)
            },
            fullDescription: {
              text: getSARIFVulnFullDescription(pkg, vuln)
            },
            helpUri: `https://nvd.nist.gov/vuln/detail/${vuln.name}`,
            help: getSARIFVulnHelp(pkg, vuln),
            properties: {
              precision: "very-high",
              'security-severity': `${vuln.cvssScore.value.score}`,
              tags: [
                  'vulnerability',
                  'security',
                  vuln.severity.value
              ]
            }
          }
          rules.push(rule)
        }
  
        let result = {
          ruleId: vuln.name,
          level: check_level(vuln.severity.value),
          message: {
            text: getSARIFReportMessage(data, vuln, pkg, baseUrl)
          },
          locations: [
            {
                physicalLocation: {
                    artifactLocation: {
                        uri: data.result.metadata.pullString,
                        uriBaseId: "ROOTPATH"
                    }
                },
                message: {
                    text: `${data.result.metadata.pullString} - ${pkg.name}@${pkg.version}`
                }
            }
          ]
        }
        results.push(result)
      });
    });
  }
  
  return [rules, results];
}

function getSARIFVulnShortDescription(pkg, vuln) {
  return `${vuln.name} Severity: ${vuln.severity.value} Package: ${pkg.name}`;
}

function getSARIFVulnFullDescription(pkg, vuln) {
  return `${vuln.name}
Severity: ${vuln.severity.value}
Package: ${pkg.name}
Type: ${pkg.type}
Fix: ${pkg.suggestedFix || "No fix available"}
URL: https://nvd.nist.gov/vuln/detail/${vuln.name}`;
}

function getSARIFPkgHelp(pkg) {
  let text = "";
  pkg.vulns.forEach(vuln => {text +=`Vulnerability ${vuln.name}
  Severity: ${vuln.severity.value}
  Package: ${pkg.name}
  CVSS Score: ${vuln.cvssScore.value.score}
  CVSS Version: ${vuln.cvssScore.value.version}
  CVSS Vector: ${vuln.cvssScore.value.vector}
  Version: ${pkg.version}
  Fix Version: ${pkg.suggestedFix || "No fix available"}
  Exploitable: ${vuln.exploitable}
  Type: ${pkg.type}
  Location: ${pkg.path}
  URL: https://nvd.nist.gov/vuln/detail/${vuln.name}\n\n\n`
  });

  let markdown = `| Vulnerability | Severity | CVSS Score | CVSS Version | CVSS Vector | Exploitable |
  | -------- | ------- | ---------- | ------------ | -----------  | ----------- |\n`;

  pkg.vulns.forEach(vuln => {markdown += `| ${vuln.name} | ${vuln.severity.value} | ${vuln.cvssScore.value.score} | ${vuln.cvssScore.value.version} | ${vuln.cvssScore.value.vector} | ${vuln.exploitable} |\n` });
  
  return {
    text: text,
    markdown: markdown
  };
}

function getSARIFVulnHelp(pkg, vuln) {
  return {
    text: `Vulnerability ${vuln.name}
Severity: ${vuln.severity.value}
Package: ${pkg.name}
CVSS Score: ${vuln.cvssScore.value.score}
CVSS Version: ${vuln.cvssScore.value.version}
CVSS Vector: ${vuln.cvssScore.value.vector}
Version: ${pkg.version}
Fix Version: ${pkg.suggestedFix || "No fix available"}
Exploitable: ${vuln.exploitable}
Type: ${pkg.type}
Location: ${pkg.path}
URL: https://nvd.nist.gov/vuln/detail/${vuln.name}`,
    markdown: `
**Vulnerability [${vuln.name}](https://nvd.nist.gov/vuln/detail/${vuln.name})**
| Severity | Package | CVSS Score | CVSS Version | CVSS Vector | Fixed Version | Exploitable |
| -------- | ------- | ---------- | ------------ | ----------- | ------------- | ----------- |
| ${vuln.severity.value} | ${pkg.name} | ${vuln.cvssScore.value.score} | ${vuln.cvssScore.value.version} | ${vuln.cvssScore.value.vector} | ${pkg.suggestedFix || "None"} | ${vuln.exploitable} |`
  }
}

function getSARIFReportMessageByPackage(data, pkg, baseUrl) {
  let message = `Full image scan results in Sysdig UI: [${data.result.metadata.pullString} scan result](${data.info.resultUrl})\n`;

  if (baseUrl) {
    message += `Package: [${pkg.name}](${baseUrl}/content?filter=freeText+in+("${pkg.name}"))\n`;
  } else {
    message += `Package: ${pkg.name}\n`;
  }
  
  message += `Package type: ${pkg.type}
  Installed Version: ${pkg.version}
  Package path: ${pkg.path}\n`;

  pkg.vulns.forEach(vuln => {
    message += `.\n`;

    if (baseUrl) {
      message += `Vulnerability: [${vuln.name}](${baseUrl}/vulnerabilities?filter=freeText+in+("${vuln.name}"))\n`;
    } else {
      message += `Vulnerability: ${vuln.name}\n`;
    }
    
    message += `Severity: ${vuln.severity.value}
    CVSS Score: ${vuln.cvssScore.value.score}
    CVSS Version: ${vuln.cvssScore.value.version}
    CVSS Vector: ${vuln.cvssScore.value.vector}
    Fixed Version: ${(vuln.fixedInVersion || 'No fix available')}
    Exploitable: ${vuln.exploitable}
    Link to NVD: [${vuln.name}](https://nvd.nist.gov/vuln/detail/${vuln.name})\n`;
  });

  
  return message;
}

function getSARIFReportMessage(data, vuln, pkg, baseUrl) {
  let message = `Full image scan results in Sysdig UI: [${data.result.metadata.pullString} scan result](${data.info.resultUrl})\n`;

  if (baseUrl) {
    message += `Package: [${pkg.name}](${baseUrl}/content?filter=freeText+in+("${pkg.name}"))\n`;
  } else {
    message += `Package: ${pkg.name}\n`;
  }
  
  message += `Package type: ${pkg.type}
  Installed Version: ${pkg.version}
  Package path: ${pkg.path}\n`;

  if (baseUrl) {
    message += `Vulnerability: [${vuln.name}](${baseUrl}/vulnerabilities?filter=freeText+in+("${vuln.name}"))\n`;
  } else {
    message += `Vulnerability: ${vuln.name}\n`;
  }
  message += `Severity: ${vuln.severity.value}
  CVSS Score: ${vuln.cvssScore.value.score}
  CVSS Version: ${vuln.cvssScore.value.version}
  CVSS Vector: ${vuln.cvssScore.value.vector}
  Fixed Version: ${(vuln.fixedInVersion || 'No fix available')}
  Exploitable: ${vuln.exploitable}
  Link to NVD: [${vuln.name}](https://nvd.nist.gov/vuln/detail/${vuln.name})`;
  
  return message;
}

function generateSARIFReport(data, groupByPackage) {
  let sarifOutput = vulnerabilities2SARIF(data, groupByPackage);
  core.setOutput("sarifReport", "./sarif.json");
  fs.writeFileSync("./sarif.json", JSON.stringify(sarifOutput, null, 2));
}

async function generateSummary(opts, data) {

  core.summary.emptyBuffer().clear();
  core.summary.addHeading(`Scan Results for ${opts.overridePullString || opts.imageTag}`);
  
  addVulnTableToSummary(data);

  if (!opts.standalone) {
    core.summary.addBreak()
        .addRaw(`Policies evaluation: ${data.result.policyEvaluationsResult} ${EVALUATION[data.result.policyEvaluationsResult]}`);
    
    addReportToSummary(data);
  }
  
  await core.summary.write({overwrite: true});
}

function getRulePkgMessage(rule, packages) {
  let table = [[ 
    {data: 'Severity', header: true},
    {data: 'Package', header: true},
    {data: 'CVSS Score', header: true},
    {data: 'CVSS Version', header: true},
    {data: 'CVSS Vector', header: true},
    {data: 'Fixed Version', header: true},
    {data: 'Exploitable', header: true}]];

  rule.failures.forEach(failure => {
    let pkgIndex = failure.pkgIndex;
    let vulnInPkgIndex = failure.vulnInPkgIndex;

    let pkg = packages[pkgIndex];
    let vuln = pkg.vulns[vulnInPkgIndex];

    if (vuln) {
      table.push([`${vuln.severity.value}`,
      `${pkg.name}`,
      `${vuln.cvssScore.value.score}`,
      `${vuln.cvssScore.value.version}`,
      `${vuln.cvssScore.value.vector}`,
      `${pkg.suggestedFix || "No fix available"}`,
      `${vuln.exploitable}`
      ]);
    }
  });

  core.summary.addTable(table);
}

function getRuleImageMessage(rule) {
  let message = [];

  rule.failures.forEach(failure => {
    message.push(`${failure.remediation}`)
  });

  core.summary.addList(message);
}

function addVulnTableToSummary(data) {
  let totalVuln = data.result.vulnTotalBySeverity;
  let fixableVuln = data.result.fixableVulnTotalBySeverity;

  core.summary.addBreak;
  core.summary.addTable([
    [{data: '', header: true}, {data: '🟣 Critical', header: true}, {data: '🔴 High', header: true}, {data: '🟠 Medium', header: true}, {data: '🟡 Low', header: true}, {data: '⚪ Negligible', header: true}],
    [{data: '⚠️ Total Vulnerabilities', header: true}, `${totalVuln.critical}`, `${totalVuln.high}`, `${totalVuln.medium}`, `${totalVuln.low}`, `${totalVuln.negligible}`],
    [{data: '🔧 Fixable Vulnerabilities', header: true}, `${fixableVuln.critical}`, `${fixableVuln.high}`, `${fixableVuln.medium}`, `${fixableVuln.low}`, `${fixableVuln.negligible}`],
  ]);
}

function addReportToSummary(data) {
  let policyEvaluations = data.result.policyEvaluations;
  let packages = data.result.packages;

  policyEvaluations.forEach(policy => {
    core.summary.addHeading(`${EVALUATION[policy.evaluationResult]} Policy: ${policy.name}`,2)

    if (policy.evaluationResult != "passed") {
      policy.bundles.forEach(bundle => {
        core.summary.addHeading(`Rule Bundle: ${bundle.name}`,3)

        bundle.rules.forEach(rule => {
          core.summary.addHeading(`${EVALUATION[rule.evaluationResult]} Rule: ${rule.description}`,5)

          if (rule.evaluationResult != "passed") {
            if (rule.failureType == "pkgVulnFailure") {
              getRulePkgMessage(rule, packages)
            } else {
              getRuleImageMessage(rule)
            }
          }
          core.summary.addBreak()
        });
      });
    }
  });

}

module.exports = {
  ExecutionError,
  parseActionInputs,
  composeFlags,
  pullScanner,
  executeScan,
  processScanResult,
  run,
  validateInput,
  cliScannerName,
  cliScannerResult,
  cliScannerVersion,
  cliScannerArch,
  cliScannerOS,
  cliScannerURLBase,
  cliScannerURL,
  defaultSecureEndpoint
};

if (require.main === module) {
  run();
}
