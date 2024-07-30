import fs from 'fs';
import process from 'process';
import tmp from 'tmp';
import * as index from "..";
import * as core from "@actions/core";
import * as report_test from "./fixtures/report-test.json";

import { exec } from "@actions/exec";
import { ActionInputs } from '../src/action';
jest.mock("@actions/exec");
const mockExec = jest.mocked(exec);

interface TempDir {
  tmpDir: string;
  cwd: string;
}

function prepareTemporaryDir(): TempDir {
  let tmpDir = tmp.dirSync().name;
  let cwd = process.cwd();
  process.chdir(tmpDir);
  return { tmpDir: tmpDir, cwd: cwd }
}

function cleanupTemporaryDir(tmpDir: TempDir) {
  fs.rmdirSync(tmpDir.tmpDir, { recursive: true });
  process.chdir(tmpDir.cwd);
}

const exampleReport = JSON.stringify(report_test);

describe("input parsing", () => {
  let oldEnv: NodeJS.ProcessEnv;

  beforeAll(async () => {
    oldEnv = process.env;
    await createReportFileIfNotExists();
  });

  beforeEach(() => {
    jest.resetModules(); // most important - it clears the cache
    process.env = { ...oldEnv }; // make a copy
  });

  afterEach(() => {
    process.env = oldEnv; // restore old env
  });

  it("raises error if no image tag provided", () => {
    process.env['INPUT_SYSDIG-SECURE-TOKEN'] = "token";
    expect(() => ActionInputs.parseActionInputs()).toThrow("image-tag is required for VM mode.");
  });

  it("sets default for inputs", () => {
    process.env['INPUT_SYSDIG-SECURE-TOKEN'] = "token";
    process.env['INPUT_IMAGE-TAG'] = "image:tag";
    let opts = ActionInputs.parseActionInputs();

    expect(opts.params).toEqual({
      cliScannerURL: index.cliScannerURL,
      cliScannerVersion: "",
      registryUser: "",
      registryPassword: "",
      stopOnFailedPolicyEval: false,
      stopOnProcessingError: false,
      standalone: false,
      dbPath: "",
      skipUpload: false,
      skipSummary: false,
      usePolicies: "",
      overridePullString: "",
      imageTag: "image:tag",
      sysdigSecureToken: "token",
      sysdigSecureURL: index.defaultSecureEndpoint,
      sysdigSkipTLS: false,
      severityAtLeast: undefined,
      groupByPackage: false,
      extraParameters: "",
      iacScanPath: "./",
      recursive: false,
      minimumSeverity: "",
      mode: "vm"
    });
  });

  it("parses all inputs", () => {
    process.env['INPUT_CLI-SCANNER-URL'] = "https://foo";
    process.env['INPUT_CLI-SCANNER-VERSION'] = "1.0.0";
    process.env['INPUT_REGISTRY-USER'] = "user";
    process.env['INPUT_REGISTRY-PASSWORD'] = "pass";
    process.env['INPUT_STOP-ON-FAILED-POLICY-EVAL'] = "true";
    process.env['INPUT_STOP-ON-PROCESSING-ERROR'] = "true";
    process.env['INPUT_STANDALONE'] = "true";
    process.env['INPUT_DB-PATH'] = "/dbpath";
    process.env['INPUT_SKIP-UPLOAD'] = "true";
    process.env['INPUT_SKIP-SUMMARY'] = "true";
    process.env['INPUT_USE-POLICIES'] = "abcxyz";
    process.env['INPUT_OVERRIDE-PULLSTRING'] = "my-image";
    process.env['INPUT_IMAGE-TAG'] = "image:tag";
    process.env['INPUT_SYSDIG-SECURE-TOKEN'] = "token";
    process.env['INPUT_SYSDIG-SECURE-URL'] = "https://foo";
    process.env['INPUT_SYSDIG-SKIP-TLS'] = "true";
    process.env['INPUT_SEVERITY-AT-LEAST'] = "medium";
    process.env['INPUT_GROUP-BY-PACKAGE'] = 'true';
    process.env['INPUT_EXTRA-PARAMETERS'] = "--extra-param";
    process.env['INPUT_IAC-SCAN-PATH'] = "./";
    process.env['INPUT_RECURSIVE'] = "true";
    process.env['INPUT_MINIMUM-SEVERITY'] = "high";
    process.env['INPUT_MODE'] = "vm";
    let opts = ActionInputs.parseActionInputs();

    expect(opts.params).toEqual({
      "cliScannerURL": "https://foo",
      "cliScannerVersion": "1.0.0",
      "registryUser": "user",
      "registryPassword": "pass",
      "stopOnFailedPolicyEval": true,
      "stopOnProcessingError": true,
      "standalone": true,
      "dbPath": "/dbpath",
      "skipUpload": true,
      "skipSummary": true,
      "usePolicies": "abcxyz",
      "overridePullString": "my-image",
      "imageTag": "image:tag",
      "sysdigSecureToken": "token",
      "sysdigSecureURL": "https://foo",
      "sysdigSkipTLS": true,
      "severityAtLeast": "medium",
      "groupByPackage": true,
      "extraParameters": "--extra-param",
      "iacScanPath": "./",
      "recursive": true,
      "minimumSeverity": "high",
      "mode": "vm"
    });
  });
});


describe("execution flags", () => {

  it("uses default flags for VM mode", () => {
    let flags = ActionInputs.overridingParsedActionInputs({ sysdigSecureToken: "foo-token", imageTag: "image:tag", mode: "vm" }).composeFlags();
    expect(flags.envvars.SECURE_API_TOKEN).toMatch("foo-token");
    expect(flags.flags).toMatch(/(^| )image:tag($| )/);
  });

  it("uses default flags for IaC mode", () => {
    let flags = ActionInputs.overridingParsedActionInputs({ sysdigSecureToken: "foo-token", imageTag: "image:tag", mode: "iac", iacScanPath: "/my-special-path" }).composeFlags();
    expect(flags.envvars.SECURE_API_TOKEN).toMatch("foo-token");
    expect(flags.flags).toMatch(/(^| )--iac \/my-special-path($| )/);
  });

  it("adds secure URL flag", () => {
    let flags = ActionInputs.overridingParsedActionInputs({ sysdigSecureToken: "foo-token", imageTag: "image:tag", sysdigSecureURL: "https://foo" }).composeFlags();
    expect(flags.flags).toMatch(/(^| )--apiurl[ =]https:\/\/foo($| )/);
  });

  it("uses standalone mode", () => {
    let flags = ActionInputs.overridingParsedActionInputs({ sysdigSecureToken: "foo-token", imageTag: "image:tag", standalone: true }).composeFlags();
    expect(flags.flags).toMatch(/(^| )--standalone($| )/);
  });

  it("uses registry credentials", () => {
    let flags = ActionInputs.overridingParsedActionInputs({ sysdigSecureToken: "foo-token", imageTag: "image:tag", registryUser: "user", registryPassword: "pass" }).composeFlags();
    expect(flags.envvars.REGISTRY_USER).toMatch('user');
    expect(flags.envvars.REGISTRY_PASSWORD).toMatch('pass');
  });

  it("uses custom db path", () => {
    let flags = ActionInputs.overridingParsedActionInputs({ sysdigSecureToken: "foo-token", imageTag: "image:tag", dbPath: "/mypath", }).composeFlags();
    expect(flags.flags).toMatch(new RegExp(/(^| )--dbpath[ =]\/mypath($| )/));
  });

  it("uses skip upload flag", () => {
    let flags = ActionInputs.overridingParsedActionInputs({ sysdigSecureToken: "foo-token", imageTag: "image:tag", skipUpload: true, }).composeFlags();
    expect(flags.flags).toMatch(new RegExp(/(^| )--skipupload($| )/));
  });

  it("uses custom policies flag", () => {
    let flags = ActionInputs.overridingParsedActionInputs({ sysdigSecureToken: "foo-token", imageTag: "image:tag", usePolicies: "abcxyz", }).composeFlags();
    expect(flags.flags).toMatch(new RegExp(/(^| )--policy[ =]abcxyz($| )/));
  });

  it("uses --skip-tls flag", () => {
    let flags = ActionInputs.overridingParsedActionInputs({ sysdigSecureToken: "foo-token", imageTag: "image:tag", sysdigSkipTLS: true, }).composeFlags();
    expect(flags.flags).toMatch(new RegExp(/(^| )--skiptlsverify($| )/));
  });

  it("uses override pullstring flag", () => {
    let flags = ActionInputs.overridingParsedActionInputs({ sysdigSecureToken: "foo-token", imageTag: "image:tag", overridePullString: "my-image", }).composeFlags();
    expect(flags.flags).toMatch(new RegExp(/(^| )--override-pullstring[ =]my-image($| )/));
  });
});

describe("scanner pulling", () => {
  beforeEach(() => {
    jest.resetAllMocks();
    jest.mock("@actions/exec");
  });

  afterEach(() => {
    jest.resetModules();
  });

  it("pulls the configured scanner", async () => {
    mockExec.mockImplementation(jest.fn());

    await index.pullScanner("https://foo");
    expect(mockExec).toHaveBeenCalledTimes(1);
    expect(mockExec.mock.calls[0][0]).toMatch(`wget https://foo -O ./${index.cliScannerName}`);
  });
});

describe("scanner execution", () => {
  let tmpDir: TempDir;
  beforeEach(() => {
    jest.resetAllMocks();

    tmpDir = prepareTemporaryDir();

    mockExec.mockImplementation(jest.fn());

    jest.resetModules(); // most important - it clears the cache
    // Re-import to ensure fresh module
    delete require.cache[require.resolve("..")];
  });

  afterEach(() => {
    cleanupTemporaryDir(tmpDir);

    jest.resetModules(); // most important - it clears the cache
    // Re-import to ensure fresh module
    delete require.cache[require.resolve("..")];
  });

  it("invokes the container with the corresponding flags", async () => {
    mockExec.mockImplementationOnce((cmdline, args, options) => {
      if (options?.listeners) {
        options?.listeners?.stdout?.(Buffer.from("foo-id"));
      }
      return Promise.resolve(0);
    });

    const result = await index.executeScan({ envvars: { SECURE_API_TOKEN: "token" }, flags: "--run1 --run2 image-to-scan" });

    expect(mockExec).toHaveBeenCalledTimes(2);
    expect(mockExec.mock.calls[0][0]).toMatch(`${index.cliScannerName} --run1 --run2 image-to-scan`);
    expect(mockExec.mock.calls[1][0]).toMatch(`cat ./${index.cliScannerResult}`);
  });

  it("returns the execution return code", async () => {
    mockExec.mockResolvedValueOnce(123);
    const result = await index.executeScan({ envvars: { SECURE_API_TOKEN: "token" }, flags: "image-to-scan" });
    expect(result.ReturnCode).toBe(123);
  });

  it("returns the output", async () => {
    mockExec.mockImplementation((cmd, args, options) => {
      if (options?.listeners) {
        options?.listeners?.stdout?.(Buffer.from("foo-output"));
      }
      return Promise.resolve(0);
    });

    const result = await index.executeScan({ envvars: { SECURE_API_TOKEN: "token" }, flags: "image-to-scan" });
    expect(result.Output).toBe("foo-output");
  });
});

describe("process scan results", () => {
  let fs: typeof import("fs");
  let mockCore: jest.Mocked<typeof core>;

  beforeEach(() => {
    jest.resetAllMocks();
    jest.mock("@actions/core");
    mockCore = jest.mocked(core);
    mockCore.error = jest.fn();

    fs = require("fs");
  });

  afterEach(() => {
    jest.resetModules(); // most important - it clears the cache
  });

  it("handles error on invalid JSON", async () => {
    let scanResult = {
      ReturnCode: 0,
      Output: 'invalid JSON',
      Error: ""
    };

    let opts = ActionInputs.overridingParsedActionInputs({ sysdigSecureToken: "foo-token", imageTag: "image:tag", skipSummary: true, standalone: false, overridePullString: "none" });
    await expect(index.processScanResult(scanResult, opts)).rejects.toThrow(new index.ExecutionError('invalid JSON', ''));
    expect(mockCore.error).toHaveBeenCalledTimes(1);
    expect(mockCore.error).toHaveBeenCalledWith(expect.stringContaining("Error parsing analysis JSON report"))
  });

  it("generates a report JSON", async () => {
    let realWriteFileSync = fs.writeFileSync;
    fs.writeFileSync = jest.fn();

    let reportData = '{"foo": "bar"}';
    let scanResult = {
      ReturnCode: 0,
      Output: reportData,
      Error: ""
    };

    let opts = ActionInputs.overridingParsedActionInputs({ sysdigSecureToken: "foo-token", imageTag: "image:tag", skipSummary: true, standalone: false, overridePullString: "none" });
    await index.processScanResult(scanResult, opts);
    expect(fs.writeFileSync).toHaveBeenCalledWith("./report.json", reportData);
    fs.writeFileSync = realWriteFileSync;
  });
});

describe("run the full action", () => {
  let tmpDir: TempDir;
  let oldEnv: NodeJS.ProcessEnv;
  let mockCore: jest.Mocked<typeof core>;

  beforeEach(() => {
    oldEnv = process.env;
    jest.resetAllMocks();

    jest.mock("@actions/core");
    mockCore = jest.mocked(core);
    mockCore.error = jest.fn();
    mockCore.setFailed = jest.fn();


    process.env['INPUT_IMAGE-TAG'] = "image:tag";
    process.env['INPUT_SYSDIG-SECURE-TOKEN'] = "footoken";

    tmpDir = prepareTemporaryDir();

  });

  function setupExecMocks() {
    mockExec.mockImplementationOnce((cmdline, args, options) => {
      return Promise.resolve(0);
    });

    mockExec.mockImplementationOnce((cmdline, args, options) => {
      return Promise.resolve(0);
    });
  }

  afterEach(() => {
    cleanupTemporaryDir(tmpDir);

    jest.resetModules(); // most important - it clears the cache

    process.env = oldEnv;
  });

  it("ends ok with scan pass", async () => {
    setupExecMocks();
    mockExec.mockImplementationOnce((_cmdline, _args, options) => {
      return Promise.resolve(0);
    });

    mockExec.mockImplementationOnce((cmdline, args, options) => {
      options?.listeners?.stdout?.(Buffer.from(exampleReport));
      return Promise.resolve(0);
    });

    await index.run();

    expect(core.setFailed).not.toHaveBeenCalled();
    expect(core.error).not.toHaveBeenCalled();
  });

  it("fails if scan fails", async () => {
    process.env['INPUT_STOP-ON-FAILED-POLICY-EVAL'] = "true";

    setupExecMocks();

    mockExec.mockImplementationOnce((_cmdline, _args, options) => {
      return Promise.resolve(1);
    });

    mockExec.mockImplementationOnce((cmdline, args, options) => {
      options?.listeners?.stdout?.(Buffer.from(exampleReport));
      return Promise.resolve(0);
    });

    await index.run();

    expect(core.setFailed).toHaveBeenCalled();
  });

  it("ends ok if scan fails but stopOnFailedPolicyEval is false", async () => {
    process.env['INPUT_STOP-ON-FAILED-POLICY-EVAL'] = "false";

    setupExecMocks();

    mockExec.mockImplementationOnce((_cmdline, _args, options) => {
      return Promise.resolve(1);
    });

    mockExec.mockImplementationOnce((cmdline, args, options) => {
      options?.listeners?.stdout?.(Buffer.from(exampleReport));
      return Promise.resolve(0);
    });

    await index.run();

    expect(core.setFailed).not.toHaveBeenCalled();
  });

  it("fails if scanner has wrong parameters and stopOnProcessingError is true", async () => {
    process.env['INPUT_STOP-ON-PROCESSING-ERROR'] = "true";

    mockExec.mockImplementationOnce((cmdline, args, options) => {
      return Promise.resolve(2);
    });

    await index.run();

    expect(core.setFailed).toHaveBeenCalled();
  });

  it("fails on unexpected error and stopOnProcessingError is true", async () => {
    process.env['INPUT_STOP-ON-PROCESSING-ERROR'] = "true";

    setupExecMocks();

    mockExec.mockImplementationOnce((cmdline, args, options) => {
      options?.listeners?.stdout?.(Buffer.from(exampleReport));
      return Promise.resolve(123);
    });

    await index.run();

    expect(core.setFailed).toHaveBeenCalled();
  });

  it("ends ok if scan fails but stopOnProcessingError is false", async () => {
    process.env['INPUT_STOP-ON-PROCESSING-ERROR'] = "false";

    setupExecMocks();

    mockExec.mockImplementationOnce((_cmdline, _args, options) => {
      return Promise.resolve(123);
    });

    mockExec.mockImplementationOnce((cmdline, args, options) => {
      options?.listeners?.stdout?.(Buffer.from(exampleReport));
      return Promise.resolve(0);
    });

    await index.run();

    expect(core.setFailed).not.toHaveBeenCalled();
  });

  it("allows override of inline-scan image", async () => {
    process.env['INPUT_OVERRIDE-PULLSTRING'] = "my-custom-image:latest";

    mockExec.mockImplementation(jest.fn(() => {
      return Promise.resolve(0);
    }));

    await index.run();
    expect(mockExec).toHaveBeenCalledTimes(4);
    expect(mockExec.mock.calls[2][0]).toMatch(`${index.cliScannerName}  --apiurl https://secure.sysdig.com/ --override-pullstring=my-custom-image:latest --json-scan-result=scan-result.json image:tag`);
  });
});


async function createReportFileIfNotExists() {
  const summary_file = process.env.GITHUB_STEP_SUMMARY || "/tmp/github_summary.html";
  const promise = new Promise((resolve, reject) => {
    if (fs.existsSync(summary_file)) {
      return resolve(undefined);
    }
    fs.writeFile(summary_file, "", (err) => {
      if (err == null) {
        return resolve(undefined);
      }
      return reject(err);
    });
  });

  return promise;
}
