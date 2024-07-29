import * as core from '@actions/core';
import fs from 'fs';
import { Package, Report, Vuln } from './report';

import { version } from '../package.json';
import { numericPriorityForSeverity } from './scanner';
const toolVersion = `${version}`;
const dottedQuadToolVersion = `${version}.0`;

interface SARIFResult {
  ruleId: string;
  level: string;
  message: {
    text: string;
  };
  locations: {
    physicalLocation: {
      artifactLocation: {
        uri: string;
        uriBaseId: string;
      };
    };
    message: {
      text: string;
    };
  }[];
}

interface SARIFRule {
  id: string;
  name: string;
  shortDescription: {
    text: string;
  };
  fullDescription: {
    text: string;
  };
  helpUri: string;
  help: {
    text: string;
    markdown: string;
  };
  properties: {
    precision: string;
    'security-severity': string;
    tags: string[];
  };
}

export function generateSARIFReport(data: Report, groupByPackage: boolean) {
  let sarifOutput = vulnerabilities2SARIF(data, groupByPackage);
  core.setOutput("sarifReport", "./sarif.json");
  fs.writeFileSync("./sarif.json", JSON.stringify(sarifOutput, null, 2));
}

function vulnerabilities2SARIF(data: Report, groupByPackage: boolean) {
  let rules: SARIFRule[] = [];
  let results: SARIFResult[] = [];

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


function vulnerabilities2SARIFResByPackage(data: Report): [SARIFRule[], SARIFResult[]] {
  let rules: SARIFRule[] = [];
  let results: SARIFResult[] = [];
  let resultUrl = "";
  let baseUrl: string | undefined;

  if (data.info && data.result) {
    if (data.info.resultUrl) {
      resultUrl = data.info.resultUrl;
      baseUrl = resultUrl.slice(0, resultUrl.lastIndexOf('/'));
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

        if (numericPriorityForSeverity(vuln.severity.value) ?? 5 < severity_num) {
          severity_level = vuln.severity.value.toLowerCase();
          severity_num = numericPriorityForSeverity(vuln.severity.value) ?? 5;
        }

        if (vuln.cvssScore.value.score > score) {
          score = vuln.cvssScore.value.score;
        }
      });
      if (baseUrl) helpUri = `${baseUrl}/content?filter=freeText+in+("${pkg.name}")`;


      let rule: SARIFRule = {
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

      let result: SARIFResult = {
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


function vulnerabilities2SARIFRes(data: Report): [SARIFRule[], SARIFResult[]] {
  let results: SARIFResult[] = [];
  let rules: SARIFRule[] = [];
  let ruleIds: string[] = [];
  let resultUrl = "";
  let baseUrl: string | undefined;

  if (data.info && data.result) {
    if (data.info.resultUrl) {
      resultUrl = data.info.resultUrl;
      baseUrl = resultUrl.slice(0, resultUrl.lastIndexOf('/'));
    }

    data.result.packages.forEach(pkg => {
      if (!pkg.vulns) {
        return
      }

      pkg.vulns.forEach(vuln => {
        if (!(vuln.name in ruleIds)) {
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
function getSARIFVulnShortDescription(pkg: Package, vuln: Vuln) {
  return `${vuln.name} Severity: ${vuln.severity.value} Package: ${pkg.name}`;
}

function getSARIFVulnFullDescription(pkg: Package, vuln: Vuln) {
  return `${vuln.name}
Severity: ${vuln.severity.value}
Package: ${pkg.name}
Type: ${pkg.type}
Fix: ${pkg.suggestedFix || "No fix available"}
URL: https://nvd.nist.gov/vuln/detail/${vuln.name}`;
}

function getSARIFPkgHelp(pkg: Package) {
  let text = "";
  pkg.vulns?.forEach(vuln => {
    text += `Vulnerability ${vuln.name}
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

  pkg.vulns?.forEach(vuln => { markdown += `| ${vuln.name} | ${vuln.severity.value} | ${vuln.cvssScore.value.score} | ${vuln.cvssScore.value.version} | ${vuln.cvssScore.value.vector} | ${vuln.exploitable} |\n` });

  return {
    text: text,
    markdown: markdown
  };
}

function getSARIFVulnHelp(pkg: Package, vuln: Vuln) {
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
function getSARIFReportMessageByPackage(data: Report, pkg: Package, baseUrl?: string) {
  let message = `Full image scan results in Sysdig UI: [${data.result.metadata.pullString} scan result](${data.info.resultUrl})\n`;

  if (baseUrl) {
    message += `Package: [${pkg.name}](${baseUrl}/content?filter=freeText+in+("${pkg.name}"))\n`;
  } else {
    message += `Package: ${pkg.name}\n`;
  }

  message += `Package type: ${pkg.type}
  Installed Version: ${pkg.version}
  Package path: ${pkg.path}\n`;

  pkg.vulns?.forEach(vuln => {
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

function getSARIFReportMessage(data: Report, vuln: Vuln, pkg: Package, baseUrl: string | undefined) {
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

// Sysdig to SARIF severity convertion
const LEVELS: any = {
  "error": ["High", "Critical"],
  "warning": ["Medium"],
  "note": ["Negligible", "Low"]
}

function check_level(sev_value: string) {
  let level = "note";

  for (let key in LEVELS) {
    if (sev_value in LEVELS[key]) {
      level = key
    }
  }

  return level
}
