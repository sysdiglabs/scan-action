const core = require('@actions/core');
const exec = require('@actions/exec');
const fs = require('fs')
const github = require('@actions/github')
const path = require('path');
const performance = require('perf_hooks').performance;
const process = require('process');

const toolVersion = "3.0.0";
const dottedQuadToolVersion = "3.0.0.0";
const secureInlineScanImage = "quay.io/sysdig/secure-inline-scan:2";

class ExecutionError extends Error {
  constructor(stdout, stderr) {
    super("execution error\n\nstdout: " + stdout + "\n\nstderr: " + stderr);
    this.stdout = stdout;
    this.stderr = stderr;
  }
}

function parseActionInputs() {
  return {
    imageTag: core.getInput('image-tag', { required: true }),
    sysdigSecureToken: core.getInput('sysdig-secure-token', { required: true }),
    sysdigSecureURL: core.getInput('sysdig-secure-url'),
    sysdigSkipTLS: core.getInput('sysdig-skip-tls') == 'true',
    dockerfilePath: core.getInput('dockerfile-path'),
    ignoreFailedScan: core.getInput('ignore-failed-scan') == 'true',
    inputType: core.getInput('input-type'),
    inputPath: core.getInput('input-path'),
    runAsUser: core.getInput('run-as-user'),
    extraParameters: core.getInput('extra-parameters'),

    extraDockerParameters: core.getInput('extra-docker-parameters'),
    inlineScanImage: core.getInput('inline-scan-image'),
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

  if (opts.severity) {
    core.info(`Severity level: ${opts.severity}`);
  }

  core.info('Analyzing image: ' + opts.imageTag);
}

function composeFlags(opts) {
  let dockerFlags = `--rm -e SYSDIG_API_TOKEN=${opts.sysdigSecureToken || ""}`;
  let runFlags = `--format=JSON`;

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
  } else {
    dockerFlags += ` -u ${process.getuid()}`
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

    let inlineScanImage = secureInlineScanImage;
    if (opts.inlineScanImage) {
      inlineScanImage = opts.inlineScanImage;
    }
    await pullScanImage(inlineScanImage);
    let scanResult = await executeInlineScan(inlineScanImage, flags.dockerFlags, flags.runFlags);
    let success = await processScanResult(scanResult);
    if (!(success || opts.ignoreFailedScan)) {
      core.setFailed(`Scan was FAILED.`)
    }

  } catch (error) {
    core.setFailed("Unexpected error");
    core.error(error);
  }
}

async function processScanResult(result) {
  let scanResult;
  if (result.ReturnCode == 0) {
    scanResult = "Success";
    core.info(`Scan was SUCCESS.`);
  } else if (result.ReturnCode == 1) {
    scanResult = "Failed";
    core.info(`Scan was FAILED.`);
  } else {
    core.setFailed("Execution error");
    throw new ExecutionError(result.Output, result.Error);
  }

  writeReport(result.Output);

  let report;
  try {
    report = JSON.parse(result.Output);
  } catch (error) {
    core.error("Error parsing analysis JSON report: " + error + ". Output was: " + result.output);
    throw new ExecutionError(result.Output, result.Error);
  }

  if (report) {

    let vulnerabilities = [];
    if (report.vulnsReport) {
      vulnerabilities = report.vulnsReport.vulnerabilities;
    }

    let evaluationResults;
    if (report.scanReport) {
      try {
        let digest = Object.keys(report.scanReport[0])[0];
        let tag = Object.keys(report.scanReport[0][digest])[0];
        let imageId = report.scanReport[0][digest][tag][0].detail.result.image_id;
        evaluationResults = report.scanReport[0][digest][tag][0].detail.result.result[imageId].result;
      } catch (error) {
        core.error("Error parsing results report: " + error);
      }
    }

    generateSARIFReport(report.tag, vulnerabilities);
    await generateChecks(report.tag, scanResult, evaluationResults, vulnerabilities);
  }

  return result.ReturnCode == 0;
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
  let errOutput = '';

  const tailOptions = {
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

  }

  const scanOptions = {
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
  };


  let retCode = await exec.exec(`docker run -d --entrypoint /bin/cat -ti ${dockerFlags} ${scanImage}`, null, scanOptions);
  if (retCode != 0) {
    return { ReturnCode: -1, Output: execOutput, Error: errOutput };
  }

  let containerId = execOutput.trim();
  await exec.exec(`docker exec ${containerId} mkdir -p /tmp/sysdig-inline-scan/logs/`, null, {silent: true, ignoreReturnCode: true});
  await exec.exec(`docker exec ${containerId} touch /tmp/sysdig-inline-scan/logs/info.log`, null, {silent: true, ignoreReturnCode: true});
  let tailExec = exec.exec(`docker exec ${containerId} tail -f /tmp/sysdig-inline-scan/logs/info.log`, null, tailOptions);

  execOutput = '';
  let start = performance.now();
  let cmd = `docker exec ${containerId} /sysdig-inline-scan.sh ${runFlags}`;
  core.debug("Executing: " + cmd);
  retCode = await exec.exec(cmd, null, scanOptions);
  core.info("Image analysis took " + Math.round(performance.now() - start) + " milliseconds.");

  await function () {
    return new Promise((resolve) => {
      setTimeout(resolve, 1000);
    });
  }();

  try {
    await exec.exec(`docker stop ${containerId} -t 0`, null, {silent: true, ignoreReturnCode: true});
    await exec.exec(`docker rm ${containerId}`, null, {silent: true, ignoreReturnCode: true});
    await tailExec;
  } catch (error) {
    core.info("Error stopping container: " + error);
  }

  return { ReturnCode: retCode, Output: execOutput, Error: errOutput };
}

function vulnerabilities2SARIF(tag, vulnerabilities) {

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
      results: vulnerabilities2SARIFResults(tag, vulnerabilities),
      columnKind: "utf16CodeUnits"
    }]
  };

  return (sarifOutput);
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
  return (ret);
}

function vulnerabilities2SARIFResults(tag, vulnerabilities) {
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
          uri: `Container image ${tag}`,
          index: 0,
        },
        locations: [
          {
            physicalLocation: {
              artifactLocation: {
                uri: `Container image ${tag}`,
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
                fullyQualifiedName: `Container image ${tag}`,
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
| --- | --- | --- | --- | --- | --- | --- |
| ${v.severity} | ${v.package_name} | ${v.package_version} | ${v.fix} | ${v.package_type} | ${v.package_path} | ${v.feed}, ${v.feed_group} |`
  }
}

function getRuleId(v) {
  return "VULN_" + v.vuln + "_" + v.package_type + "_" + v.package;
}

function generateSARIFReport(tag, vulnerabilities) {
  let sarifOutput = vulnerabilities2SARIF(tag, vulnerabilities);
  core.setOutput("sarifReport", "./sarif.json");
  fs.writeFileSync("./sarif.json", JSON.stringify(sarifOutput, null, 2));
}

async function generateChecks(tag, scanResult, evaluationResults, vulnerabilities) {
  const githubToken = core.getInput('github-token');
  if (!githubToken) {
    core.warning("No github-token provided. Skipping creation of check run");
  }

  let octokit;
  let annotations;
  let check_run;

  try {
    octokit = github.getOctokit(githubToken);
    annotations = getReportAnnotations(evaluationResults, vulnerabilities)
  } catch (error) {
    core.warning("Error creating octokit: " + error);
    return;
  }

  let conclusion = "success";
  if (scanResult != "Success") {
    conclusion = "failure";
  }

  try {
    check_run = await octokit.rest.checks.create({
      owner: github.context.repo.owner,
      repo: github.context.repo.repo,
      name: `Scan results for ${tag}`,
      head_sha: github.context.sha,
      status: "completed",
      conclusion:  conclusion,
      output: {
        title: `Inline scan results for ${tag}`,
        summary: "Scan result is " + scanResult,
        annotations: annotations.slice(0,50)
      }
    });
  } catch (error) {
    core.warning("Error creating check run: " + error);
  }

  try {
    for (let i = 50; i < annotations.length; i+=50) {
      await octokit.rest.checks.update({
        owner: github.context.repo.owner,
        repo: github.context.repo.repo,
        check_run_id: check_run.data.id,
        output: {
          title: "Inline scan results",
          summary: "Scan result is " + scanResult,
          annotations: annotations.slice(i, i+50)
        }
      });
    }
  } catch (error) {
    core.warning("Error updating check run: " + error);
  }
}

function getReportAnnotations(evaluationResults, vulnerabilities) {
  let actionCol = evaluationResults.header.indexOf("Gate_Action");
  let gateCol = evaluationResults.header.indexOf("Gate");
  let triggerCol = evaluationResults.header.indexOf("Trigger");
  let outputCol = evaluationResults.header.indexOf("Check_Output");
  let gates = evaluationResults.rows.map(g => {
    let action = g[actionCol];
    let level = "notice"
    if (action == "warn") {
      level = "warning";
    } else if (action == "stop") {
      level = "failure";
    }
    return {
      path: "Dockerfile",
      start_line: 1,
      end_line: 1,
      annotation_level: level,
      message: `${g[actionCol]} ${g[gateCol]}:${g[triggerCol]}\n${g[outputCol]}`,
      title: `${g[actionCol]} ${g[gateCol]}`
    }
  });
  let severities = {"critical":0,"high":1, "medium":2, "low":3, "negligible":4,"unknown":5}
  let severity =  core.getInput('severity') || "unknown";
  let uniqueReportByPackage = core.getInput('unique-report-by-package') === 'true' || false;
  let _vulns = vulnerabilities;
  if(uniqueReportByPackage) {
    const key = 'package'; // Show only one issue by package, avoiding flood of annotations
    _vulns = [...new Map(vulnerabilities.map(item => [item[key], item])).values()];
  }
  let vulns = _vulns.filter(v => severities[v.severity.toLowerCase()] <=  severities[severity.toLowerCase()]).map(v => {
    return {
      path: "Dockerfile",
      start_line: 1,
      end_line: 1,
      annotation_level: "warning", //Convert v.severity to notice, warning, or failure?
      message: `${v.vuln} Severity=${v.severity} Package=${v.package} Type=${v.package_type} Fix=${v.fix} Url=${v.url}`,
      title: `Vulnerability found: ${v.vuln}`
    }
  });
  return gates.concat(vulns);
}

module.exports = {
  ExecutionError,
  parseActionInputs,
  composeFlags,
  pullScanImage,
  executeInlineScan,
  processScanResult,
  run
};

if (require.main === module) {
  run();
}
