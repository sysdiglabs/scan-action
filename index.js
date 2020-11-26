const core = require('@actions/core');
const exec = require('@actions/exec');
const fs = require('fs')
const github = require('@actions/github')
const path = require('path');
const performance = require('perf_hooks').performance;
const process = require('process');
const Tail = require('tail').Tail;

const toolVersion = "3.0.0";
const dottedQuadToolVersion = "3.0.0.0";
const secureInlineScanImage = "airadier/secure-inline-scan:ci";


function parseActionInputs() {
  return {
    imageTag: core.getInput('image-tag', {required: true}),
    sysdigSecureToken: core.getInput('sysdig-secure-token', {required: true}),
    sysdigSecureURL: core.getInput('sysdig-secure-url'),
    sysdigSkipTLS: core.getInput('sysdig-skip-tls') == 'true',
    dockerfilePath: core.getInput('dockerfile-path'),
    ignoreFailedScan: core.getInput('ignore-failed-scan') == 'true',
    inputType: core.getInput('input-type'),
    inputPath: core.getInput('input-path'),
    runAsUser: core.getInput('run-as-user'),
    extraParameters: core.getInput('extra-parameters'),
    extraDockerParameters: core.getInput('extra-docker-parameters')
    }
}


function printOptions(opts) {
  if (opts.sysdigSecureURL) {
    core.info('Sysdig Secure URL: ' + opts.sysdigSecureURL);
  }

  if (opts.inputType == "pull") {
    core.info('Input type: pull from registry');
  } else {
    core.info(`Input type: ${opts.inputType}`);
  }

  if (opts.inputPath) {
    core.info(`Input path: ${opts.inputPath}`);
  }

  if (opts.dockerfilePath) {
    core.info(`Dockerfile Path: ${opts.dockerfilePath}`);
  }

  if (opts.runAsUser) {
    core.info(`Running as user: ${opts.runAsUser}`);
  }

  if (opts.sysdigSkipTLS) {
    core.info(`Sysdig skip TLS: true`);
  }
}

function composeFlags(opts) {
  let dockerFlags = `--rm -v ${process.cwd()}/scan-output:/tmp/sysdig-inline-scan`;
  let runFlags = `--sysdig-token=${opts.sysdigSecureToken || ""} --format=JSON`;

  if (opts.sysdigSecureURL) {
    runFlags += ` --sysdig-url ${opts.sysdigSecureURL}`;
  }

  if (opts.inputType != "pull") {
    runFlags += ` --storage-type=${opts.inputType}`;

    if (opts.inputType == "docker-daemon") {
      let dockerSocketPath = opts.inputPath || "/var/run/docker.sock";
      dockerFlags += ` -v ${dockerSocketPath}:/var/run/docker.sock`;
    } else if (opts.inputPath) {
        let filename = path.basename(opts.inputPath);
        dockerFlags += ` -v ${path.resolve(opts.inputPath)}:/tmp/${filename}`;
        runFlags += ` --storage-path=/tmp/${filename}`;
    }  
  }

  if (opts.dockerfilePath) {
    dockerFlags += ` -v ${path.resolve(opts.dockerfilePath)}:/tmp/Dockerfile`;
    runFlags += ` --dockerfile=/tmp/Dockerfile`;
  }

  if (opts.runAsUser) {
    dockerFlags += ` -u ${opts.runAsUser}`;
  }

  if (opts.sysdigSkipTLS) {
    runFlags += ` --sysdig-skip-tls`;
  }

  if (opts.extraParameters) {
    runFlags += ` ${opts.extraParameters}`;
  }

  if (opts.extraDockerParameters) {
    dockerFlags += ` ${opts.extraDockerParameters}`;
  }

  runFlags += ` ${opts.imageTag || ""}`;

  return {
    dockerFlags: dockerFlags,
    runFlags: runFlags
  }
}

function writeReport(reportData) {
  fs.writeFileSync("./report.json", reportData);
  core.setOutput("scanReport", "./report.json");
}

async function run() {
  
  try {

    let opts = parseActionInputs();
    printOptions(opts);
    let flags = composeFlags(opts);

    try {
      await pullScanImage(secureInlineScanImage);

      core.info('Analyzing image: ' + opts.imageTag);
      let result = await executeInlineScan(secureInlineScanImage, flags.dockerFlags, flags.runFlags);

      writeReport(result.Output);
      
      let scanResult = "unknown";
      if (result.ReturnCode == 0) {
        scanResult = "Success";
        core.info(`Scan was SUCCESS.`);
      } else if (result.ReturnCode == 1) {
        scanResult = "Failed";
        if (opts.ignoreFailedScan) {
          core.info(`Scan was FAILED.`);
        } else {
          core.setFailed(`Scan was FAILED.`);
        }
      } else {
        core.setFailed(`
        or:\n${result.Output}`);
      }

      let report = JSON.parse(result.Output);

      let vulnerabilities = [];
      if (report.vulnsReport) {
        vulnerabilities = report.vulnsReport.vulnerabilities;
      }

      let checkGensPromise = generateChecks(scanResult, vulnerabilities);
      generateSARIFReport(vulnerabilities);

      await checkGensPromise

    } catch (error) {
      core.setFailed(error.message);
    }
  } catch (error) {
    core.setFailed(error.message);
  }
}

async function pullScanImage(scanImage) {
  let start = performance.now();
  core.info('Pulling inline-scanner image: ' + scanImage);
  let cmd = `docker pull ${scanImage}`;
  await exec.exec(cmd, null);
  core.info("Image pull took " + Math.round(performance.now() - start) + " milliseconds.");
}

async function executeInlineScan(scanImage, dockerFlags, runFlags) {

  let execOutput = '';

  fs.mkdirSync("./scan-output", {recursive: true});
  fs.chmodSync("./scan-output", 0o777);
  fs.closeSync(fs.openSync("./scan-output/info.log", 'w'));
  fs.chmodSync("./scan-output/info.log", 0o666);
  let tail = new Tail("./scan-output/info.log", {fromBeginning: true, follow: true});
  tail.on("line", function(data) {
    console.log(data);
  });

  const options = {
    silent: true,
    ignoreReturnCode: true,
    listeners:  {
      stdout: (data) => {
        execOutput += data.toString();
      }
    }
  };
  
  let start = performance.now();
  let cmd = `docker run ${dockerFlags} ${scanImage} ${runFlags}`;
  let retCode = await exec.exec(cmd, null, options);
  core.info("Image analysis took " + Math.round(performance.now() - start) + " milliseconds.");
  tail.unwatch();

  return { ReturnCode: retCode, Output: execOutput };
}

function vulnerabilities2SARIF(vulnerabilities) {

  const sarifOutput = {
  "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
  version: "2.1.0",
  runs: [{
          tool: {
              driver: {
                name: "Sysdig Inline Scanner V2",
                fullName: "Sysdig Inline Scanner V2",
                version: toolVersion,
                semanticVersion: toolVersion,
                dottedQuadFileVersion: dottedQuadToolVersion,
                rules: vulnerabilities2SARIFRules(vulnerabilities)
              }
          },
          logicalLocations: [
              {
                name: "container-image",
                fullyQualifiedName: "container-image",
                kind: "namespace"
              }
          ],
          results: vulnerabilities2SARIFResults(vulnerabilities),
          columnKind: "utf16CodeUnits"
      }]
  };

  return(sarifOutput);
}

function vulnerabilities2SARIFRules(vulnerabilities) {
  var ret = {};
  if (vulnerabilities) {
    ret = vulnerabilities.map(v => {
        return {
          id: getRuleId(v),
          shortDescription: {
              text: getSARIFVulnShortDescription(v),
          },
          fullDescription: {
              text: getSARIFVulnFullDescription(v),
          },
          help: getSARIFVulnHelp(v)
        }
      }
    );
  }
  return(ret);
}

function vulnerabilities2SARIFResults(vulnerabilities) {
  var ret = {};

  if (vulnerabilities) {
    ret = vulnerabilities.map((v) => {
      return {
        ruleId: getRuleId(v),
        ruleIndex: 0,
        level: "error",
        message: {
          text: getSARIFVulnShortDescription(v),
          id: "default",
        },
        analysisTarget: {
          uri: "Container image",
          index: 0,
        },
        locations: [
          {
            physicalLocation: {
              artifactLocation: {
                uri: "Container image",
              },
              region: {
                startLine: 1,
                startColumn: 1,
                endLine: 1,
                endColumn: 1,
                byteOffset: 1,
                byteLength: 1,
              },
            },
            logicalLocations: [
              {
                fullyQualifiedName: "container-image",
              },
            ],
          },
        ],
        suppressions: [
          {
            kind: "external",
          },
        ],
        baselineState: "unchanged",
      };
    });
  }
  return ret;
}


function getSARIFVulnShortDescription(v) {
  return `${v.vuln} Severity: ${v.severity} Package: ${v.package}`;
}

function getSARIFVulnFullDescription(v) {
  return `${v.vuln}
Severity: ${v.severity}
Package: ${v.package}
Type: ${v.package_type}
Fix: ${v.fix}
URL: ${v.url}`;
}

function getSARIFVulnHelp(v) {
  return {
    text: `Vulnerability ${v.vuln}
Severity: ${v.severity}
Package: ${v.package_name}
Version: ${v.package_version}
Fix Version: ${v.fix}
Type: ${v.package_type}
Location: ${v.package_path}
Data Namespace: ${v.feed}, ${v.feed_group}
URL: ${v.url}`,
    markdown: `
**Vulnerability [${v.vuln}](${v.url})**
| Severity | Package | Version | Fix Version | Type | Location | Data Namespace |
| --- | --- | --- | --- | --- | --- | --- | --- |
|${v.severity}|${v.package_name}|${v.package_version$}|${v.fix}|${v.package_type}|${v.package_path}|${v.feed_group}|`
  }
}

function getRuleId(v) {
  return "VULN_" + v.vuln + "_" + v.package_type + "_" + v.package;
}

function generateSARIFReport(vulnerabilities) {

  let sarifOutput = vulnerabilities2SARIF(vulnerabilities);
  fs.writeFileSync("./sarif.json", JSON.stringify(sarifOutput, null, 2));
  core.setOutput("sarifReport", "./sarif.json");
}

async function generateChecks(scanResult, vulnerabilities) {
  const githubToken = core.getInput('github-token');
  if (!githubToken) {
    core.warning("No github-token provided. Skipping creation of check run");
  }

  try {
    const octokit = github.getOctokit(githubToken);

    await octokit.checks.create({
      owner: github.context.repo.owner,
      repo: github.context.repo.repo,
      name: "Scan results",
      head_sha: github.context.sha,
      output: {
        title: "Inline scan results",
        summary: "Scan result is " + scanResult,
        annotations: getReportAnnotations(vulnerabilities)
      }
    });
  } catch (error) {
    core.warning("Error creating check run: " + error);
  }
}

function getReportAnnotations(vulnerabilities) {
  return vulnerabilities.map(v =>
    {
      return {
        path: "Dockerfile",
        start_line: 1,
        end_line: 1,
        annotation_level: "warning", //Convert v.severity to notice, warning, or failure?
        message: v.vuln + " Severity=" + v.severity + " Package=" + v.package + " Type=" + v.package_type + " Fix=" + v.fix + " Url=" + v.url,
        title: v.vuln
      }
    }
  );
}

module.exports = {parseActionInputs, composeFlags, pullScanImage, executeInlineScan};

if (require.main === module) {
  run();
}
