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

async function run() {
  
  try {

    const imageTag = core.getInput('image-tag', {required: true});
    const sysdigSecureToken = core.getInput('sysdig-secure-token', {required: true});
    const sysdigSecureURL = core.getInput('sysdig-secure-url');
    const sysdigSkipTLS = core.getInput('sysdig-skip-tls') == 'true';
    const dockerfilePath = core.getInput('dockerfile-path');
    const pullFromRegistry = core.getInput('pull-from-registry') == 'true';
    const ignoreFailedScan = core.getInput('ignore-failed-scan') == 'true';
    const inputType = core.getInput('input-type');
    const inputPath = core.getInput('input-path');
    const runAsUser = core.getInput('run-as-user');
    const extraParameters = core.getInput('extra-parameters');
    const extraDockerParameters = core.getInput('extra-docker-parameters');
    
    let dockerFlags = `--rm -v ${process.cwd()}/scan-output:/tmp/sysdig-inline-scan`;
    let runFlags = `--sysdig-token ${sysdigSecureToken} --format=JSON`;

    if (sysdigSecureURL) {
      core.info('Sysdig Secure URL: ' + sysdigSecureURL);
      runFlags += ` --sysdig-url ${sysdigSecureURL}`;
    }

    let storageType = inputType
    if (pullFromRegistry) {
      core.info('Input type: pull from registry');
    } else {
      core.info(`Input type: ${inputType}`);
      storageType = storageType || "docker-daemon";
      runFlags += ` --storage-type=${storageType}`;
    }

    if (inputPath) {
      core.info(`Input path: ${inputPath}`);
      let filename = path.basename(inputPath);
      dockerFlags += ` -v ${path.resolve(inputPath)}:/tmp/${filename}`;
      runFlags += ` --storage-path=/tmp/${filename}`;
    }

    if (storageType == "docker-daemon") {
      let dockerSocketPath = inputPath || "/var/run/docker.sock";
      dockerFlags += ` -v ${dockerSocketPath}:/var/run/docker.sock`;
    }

    if (dockerfilePath) {
      core.info(`Dockerfile Path: ${dockerfilePath}`);
      dockerFlags += ` -v ${path.resolve(dockerfilePath)}:/tmp/Dockerfile`;
      runFlags += ` --dockerfile /tmp/Dockerfile`;
    }

    if (runAsUser) {
      core.info(`Running as user: ${runAsUser}`);
      dockerFlags += ` -u ${runAsUser}`;
    }

    if (sysdigSkipTLS) {
      core.info(`Sysdig skip TLS: true`);
      runFlags += `--sysdig-skip-tls`;
    }

    if (extraParameters) {
      runFlags += ` ${extraParameters}`;
    }

    if (extraDockerParameters) {
      dockerFlags += ` ${extraDockerParameters}`;
    }

    runFlags += ` ${imageTag}`;

    try {
      await pullScanImage();

      let result = await executeInlineScan(imageTag, dockerFlags, runFlags);
      
      let scanResult = "unknown";
      if (result.ReturnCode == 0) {
        scanResult = "Success";
        core.info(`Scan was SUCCESS.`);
      } else if (result.ReturnCode == 1) {
        scanResult = "Failed";
        if (ignoreFailedScan) {
          core.info(`Scan was FAILED.`);
        } else {
          core.setFailed(`Scan was FAILED.`);
        }
      } else {
        core.setFailed(`Execution error`);
      }

      fs.writeFileSync("./report.json", result.Output);
      core.setOutput("scanReport", "./report.json");

      let reportData = fs.readFileSync("./report.json");
      let report = JSON.parse(reportData);

      let vulnerabilities = [];
      if (report.vulnsReport) {
        vulnerabilities = report.vulnsReport.vulnerabilities;
      }

      let checkGens = generateChecks(scanResult, vulnerabilities);
      generateSARIFReport(vulnerabilities);

      await checkGens

    } catch (error) {
      core.setFailed(error.message);
    }
  } catch (error) {
    core.setFailed(error.message);
  }
}

async function pullScanImage() {
  let start = performance.now();
  core.info('Pulling inline-scanner image: ' + secureInlineScanImage);
  let cmd = `docker pull ${secureInlineScanImage}`;
  await exec.exec(cmd, null);
  core.info("Image pull took " + Math.round(performance.now() - start) + " milliseconds.");
}

async function executeInlineScan(image_tag, docker_flags, run_flags) {
  core.info('Analyzing image: ' + image_tag);

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
  let cmd = `docker run ${docker_flags} ${secureInlineScanImage} ${run_flags}`;
  let retCode = await exec.exec(cmd, null, options);
  core.info("Image analysis took " + Math.round(performance.now() - start) + " milliseconds.");
  tail.unwatch();

  return { ReturnCode: retCode, Output: execOutput };
}

function vulnerabilities2SARIF(vulnerabilities) {

  const sarifOutput = {
  "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
  "version": "2.1.0",
  "runs": [
          {
      "tool": {
          "driver": {
          "name": "Sysdig Inline Scanner V2",
          "fullName": "Sysdig Inline Scanner V2",
          "version": toolVersion,
          "semanticVersion": toolVersion,
          "dottedQuadFileVersion": dottedQuadToolVersion,
          "rules": renderRules(vulnerabilities)
          }
      },
      "logicalLocations": [
                  {
          "name": "container-image",
          "fullyQualifiedName": "container-image",
          "kind": "namespace"
                  }
      ],
      "results": renderResults(vulnerabilities),
      "columnKind": "utf16CodeUnits"
          }
  ]
  };

  return(sarifOutput);
}

function renderRules(vulnerabilities) {
  var ret = {};
  if (vulnerabilities) {
    ret = vulnerabilities.map(v =>
      {
        return {
        "id": "ANCHOREVULN_"+v.vuln+"_"+v.package_type+"_"+v.package,
        "shortDescription": {
            "text": v.vuln + " Severity=" + v.severity + " Package=" + v.package + " Type=" + v.package_type + " Fix=" + v.fix + " Url=" + v.url,
        },
        "fullDescription": {
            "text": v.vuln + " Severity=" + v.severity + " Package=" + v.package + " Type=" + v.package_type + " Fix=" + v.fix + " Url=" + v.url,
        },
        "help": {
            "text": "Vulnerability "+v.vuln+"\n"+
            "Severity: "+v.severity+"\n"+
            "Package: "+v.package_name+"\n"+
            "Version: "+v.package_version+"\n"+
            "Fix Version: "+v.fix+"\n"+
            "Type: "+v.package_type+"\n"+
            "Location: "+v.package_path+"\n"+
            "Data Namespace: "+v.feed + ", "+v.feed_group+"\n"+
            "Link: ["+v.vuln+"]("+v.url+")",
            "markdown": "**Vulnerability "+v.vuln+"**\n"+
            "| Severity | Package | Version | Fix Version | Type | Location | Data Namespace | Link |\n"+
            "| --- | --- | --- | --- | --- | --- | --- | --- |\n"+
            "|"+v.severity+"|"+v.package_name+"|"+v.package_version+"|"+v.fix+"|"+v.package_type+"|"+v.package_path+"|"+v.feed_group+"|["+v.vuln+"]("+v.url+")|\n"
        }

        }
      }
    );
  }
  return(ret);
}

// function convertSeverityToSARIF(input_severity) {
//   var ret = "error";
//   const severityLevels = {
//     Unknown: 0,
//     Negligible: 1,
//     Low: 2,
//     Medium: 3,
//     High: 4,
//     Critical: 5,
//   };

//   return ret;
// }

function renderResults(vulnerabilities) {
  var ret = {};

  if (vulnerabilities) {
    ret = vulnerabilities.map((v) => {
      return {
        ruleId:
          "ANCHOREVULN_" + v.vuln + "_" + v.package_type + "_" + v.package,
        ruleIndex: 0,
        level: "error",
        message: {
          text: v.vuln + " Severity=" + v.severity + "Package=" + v.package + " Type=" + v.package_type + " Fix=" + v.fix + " Url=" + v.url,
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

if (require.main === module) {
  run();
}
