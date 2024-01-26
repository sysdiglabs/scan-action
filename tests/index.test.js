const fs = require('fs');
const process = require('process');
const tmp = require('tmp');
let index = require("..");


function prepareTemporaryDir() {
    let tmpDir = tmp.dirSync().name;
    let cwd = process.cwd();
    process.chdir(tmpDir);
    return { tmpDir: tmpDir, cwd: cwd }
}

function cleanupTemporaryDir(tmpDir) {
    fs.rmdirSync(tmpDir.tmpDir, { recursive: true });
    process.chdir(tmpDir.cwd);
}

const exampleReport = JSON.stringify(require("./fixtures/report-test.json"));
const exampleSarif = JSON.stringify(require("./fixtures/sarif-test.json"),null,2);

describe("input parsing", () => {
    let oldEnv;

    beforeAll(() => {
        oldEnv = process.env;
    })

    beforeEach(() => {
        jest.resetModules() // most important - it clears the cache
        process.env = { ...oldEnv }; // make a copy
    });

    afterEach(() => {
        process.env = oldEnv; // restore old env
    });


    it("raises error if no image tag provided", () => {
        process.env['INPUT_SYSDIG-SECURE-TOKEN'] = "token";
        expect(() => index.parseActionInputs()).toThrow("Input required and not supplied: image-tag");
    })

    it("sets default for inputs", () => {
        process.env['INPUT_SYSDIG-SECURE-TOKEN'] = "token";
        process.env['INPUT_IMAGE-TAG'] = "image:tag";
        let opts = index.parseActionInputs()

        expect(opts).toEqual({
            "cliScannerURL": `${index.cliScannerURL}`,
            "cliScannerVersion": "",
            "registryUser": "",
            "registryPassword": "",
            "stopOnFailedPolicyEval": false,
            "stopOnProcessingError": false,
            "standalone": false,
            "dbPath": "",
            "skipUpload": false,
            "skipSummary": false,
            "usePolicies": "",
            "overridePullString": "",
            "imageTag": "image:tag",
            "sysdigSecureToken": "token",
            "sysdigSecureURL": `${index.defaultSecureEndpoint}`,
            "sysdigSkipTLS": false,
            "extraParameters": ""
        })
    })

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
        process.env['INPUT_EXTRA-PARAMETERS'] = "--extra-param";
        let opts = index.parseActionInputs()

        expect(opts).toEqual({
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
            "extraParameters": "--extra-param"
        })
    })

})

describe("execution flags", () => {

    it("uses default flags", () => {
        let flags = index.composeFlags({ sysdigSecureToken: "foo-token", imageTag: "image:tag" });
        expect(flags.envvars.SECURE_API_TOKEN).toMatch("foo-token");
        expect(flags.flags).toMatch(/(^| )image:tag($| )/);
    })

    it("adds secure URL flag", () => {
        let flags = index.composeFlags({
            sysdigSecureToken: "foo-token",
            sysdigSecureURL: "https://foo"
        });
        expect(flags.flags).toMatch(/(^| )--apiurl[ =]https:\/\/foo($| )/)
    })

    it("uses standalone mode", () => {
        let flags = index.composeFlags({
            sysdigSecureToken: "foo-token",
            standalone: true,
        });
        expect(flags.flags).toMatch(/(^| )--standalone($| )/)
    })

    it("uses registry credentials", () => {
        let flags = index.composeFlags({
            sysdigSecureToken: "foo-token",
            registryUser: "user",
            registryPassword: "pass"
        });
        expect(flags.envvars.REGISTRY_USER).toMatch('user')
        expect(flags.envvars.REGISTRY_PASSWORD).toMatch('pass')
    })

    it("uses custom db path", () => {
        let flags = index.composeFlags({
            dbPath: "/mypath",
        });
        expect(flags.flags).toMatch(new RegExp(/(^| )--dbpath[ =]\/mypath($| )/));
    })

    it("uses skip upload flag", () => {
        let flags = index.composeFlags({
            skipUpload: true,
        });
        expect(flags.flags).toMatch(new RegExp(/(^| )--skipupload($| )/));
    })

    it("uses custom policies flag", () => {
        let flags = index.composeFlags({
            usePolicies: "abcxyz",
        });
        expect(flags.flags).toMatch(new RegExp(/(^| )--policy[ =]abcxyz($| )/));
    })

    it("uses --skip-tls flag", () => {
        let flags = index.composeFlags({
            sysdigSkipTLS: true,
        });
        expect(flags.flags).toMatch(new RegExp(/(^| )--skiptlsverify($| )/));
    })

    it("uses override pullstring flag", () => {
        let flags = index.composeFlags({
            overridePullString: "my-image",
        });
        expect(flags.flags).toMatch(new RegExp(/(^| )--override-pullstring[ =]my-image($| )/));
    })
})

describe("scanner pulling", () => {
    let exec;

    beforeEach(() => {
        jest.resetAllMocks()
        exec = require("@actions/exec");
        index = require("..");
    })

    afterEach(() => {
        jest.resetModules();
        index = require("..");
    })

    it("pulls the configured scanner", async () => {
        exec.exec = jest.fn();
        await index.pullScanner("https://foo");
        expect(exec.exec).toBeCalledTimes(1);
        expect(exec.exec.mock.calls[0][0]).toMatch(`wget https://foo -O ./${index.cliScannerName}`, null);
    })
})

describe("scanner execution", () => {
    let tmpDir;
    let exec;

    beforeEach(() => {
        jest.resetAllMocks()

        tmpDir = prepareTemporaryDir();

        exec = require("@actions/exec");
        exec.exec = jest.fn();
        index = require("..");
    })

    afterEach(() => {
        cleanupTemporaryDir(tmpDir);

        jest.resetModules() // most important - it clears the cache
        index = require("..");
    })

    it("invokes the container with the corresponding flags", async () => {
        exec.exec.mockImplementationOnce((cmdline, args, options) => {
            if (options && options.listeners) { options.listeners.stdout("foo-id"); }
            return Promise.resolve(0);
        });

        await index.executeScan({SECURE_API_TOKEN: "token"}, "--run1 --run2 image-to-scan");

        expect(exec.exec).toBeCalledTimes(2);
        expect(exec.exec.mock.calls[0][0]).toMatch(`${index.cliScannerName} --run1 --run2 image-to-scan`);
        expect(exec.exec.mock.calls[1][0]).toMatch(`cat ./${index.cliScannerResult}`);
    })

    it("returns the execution return code", async () => {
        exec.exec.mockResolvedValueOnce(123);
        let result = await index.executeScan({SECURE_API_TOKEN: "token"}, "image-to-scan");
        expect(result.ReturnCode).toBe(123);
    })

    it("returns the output", async () => {

        exec.exec = jest.fn((cmd, args, options) => {
            if (options && options.listeners) { options.listeners.stdout("foo-output"); }
            return Promise.resolve(0);
        });

        let result = await index.executeScan({SECURE_API_TOKEN: "token"}, "image-to-scan");
        expect(result.Output).toBe("foo-output");
    })
})

describe("process scan results", () => {
    let fs;
    let core;

    beforeEach(() => {
        jest.resetAllMocks()

        core = require("@actions/core");
        fs = require("fs");
        index = require("..");
    })

    afterEach(() => {
        jest.resetModules() // most important - it clears the cache
        index = require("..");
    })

    it("handles error on invalid JSON", async () => {
        core.error = jest.fn();

        let scanResult = {
            ReturnCode: 0,
            Output: 'invalid JSON',
            Error: ""
        };

        let opts = {
            skipSummary: true,
            standalone: false,
            overridePullString: null
        }
        await expect(index.processScanResult(scanResult, opts)).rejects.toThrow(new index.ExecutionError('invalid JSON', ''));
        expect(core.error).toBeCalledTimes(1);
        expect(core.error.mock.calls[0][0]).toMatch(/Error parsing analysis JSON report/)
    })

    it("generates a report JSON", async () => {
        let realWriteFileSync = fs.writeFileSync;
        fs.writeFileSync = jest.fn();

        let reportData = '{"foo": "bar"}';
        let scanResult = {
            ReturnCode: 0,
            Output: reportData,
            Error: ""
        };

        let opts = {
            skipSummary: true,
            standalone: false,
            overridePullString: null
        }

        await index.processScanResult(scanResult, opts);
        expect(fs.writeFileSync).toBeCalledWith("./report.json", reportData);
        fs.writeFileSync = realWriteFileSync;
    })

    it("generates SARIF report with vulnerabilities", async () => {
        let realWriteFileSync = fs.writeFileSync;
        fs.writeFileSync = jest.fn();

        let scanResult = {
            ReturnCode: 0,
            Output: exampleReport,
            Error: ""
        };

        let opts = {
            skipSummary: true,
            standalone: false,
            overridePullString: null
        }
        await index.processScanResult(scanResult, opts);
        expect(fs.writeFileSync).toBeCalledWith("./sarif.json", exampleSarif);
        fs.writeFileSync = realWriteFileSync;
    })
})

describe("run the full action", () => {
    let tmpDir;
    let oldEnv;
    let exec;
    let core;

    beforeEach(() => {
        oldEnv = process.env;

        process.env['INPUT_IMAGE-TAG'] = "image:tag";
        process.env['INPUT_SYSDIG-SECURE-TOKEN'] = "footoken";

        tmpDir = prepareTemporaryDir();

        exec = require("@actions/exec");
        core = require("@actions/core");
        index = require("..");

        exec.exec = jest.fn();
    })

    function setupExecMocks() {
        /* eslint-disable no-unused-vars */
        exec.exec.mockImplementationOnce((cmdline, args, options) => {
            return Promise.resolve(0);
        });

        exec.exec.mockImplementationOnce((cmdline, args, options) => {
            return Promise.resolve(0);
        });

        /* eslint-enable no-unused-vars */
    }

    afterEach(() => {
        cleanupTemporaryDir(tmpDir);

        jest.resetModules() // most important - it clears the cache
        index = require("..");

        process.env = oldEnv;
    })

    it("ends ok with scan pass", async () => {
        core.setFailed = jest.fn();
        core.error = jest.fn();

        setupExecMocks();
        /* eslint-disable no-unused-vars */
        exec.exec.mockImplementationOnce((_cmdline, _args, options) => {
            return Promise.resolve(0);
        });

        exec.exec.mockImplementationOnce((cmdline, args, options) => {
            options.listeners.stdout(exampleReport);
            return Promise.resolve(0);
        });

        await index.run();

        expect(core.setFailed).not.toBeCalled();
        expect(core.error).not.toBeCalled();
    })

    it("writes scan report on pass", async () => {
        core.setOutput = jest.fn();

        setupExecMocks();
        /* eslint-disable no-unused-vars */
        exec.exec.mockImplementationOnce((_cmdline, _args, options) => {
            return Promise.resolve(0);
        });

        exec.exec.mockImplementationOnce((cmdline, args, options) => {
            options.listeners.stdout(exampleReport);
            return Promise.resolve(0);
        });
        /* eslint-enable no-unused-vars */

        await index.run();

        expect(core.setOutput).toBeCalledWith("scanReport", "./report.json");
        let report = JSON.parse(fs.readFileSync("./report.json"));
        expect(report.result).not.toBeUndefined();
    })

    it("writes scan report on fail", async () => {
        core.setOutput = jest.fn();


        setupExecMocks();
        /* eslint-disable no-unused-vars */
        exec.exec.mockImplementationOnce((_cmdline, _args, options) => {
            return Promise.resolve(1);
        });

        exec.exec.mockImplementationOnce((cmdline, args, options) => {
            options.listeners.stdout(exampleReport);
            return Promise.resolve(0);
        });
        /* eslint-enable no-unused-vars */

        await index.run();

        expect(core.setOutput).toBeCalledWith("scanReport", "./report.json");
        let report = JSON.parse(fs.readFileSync("./report.json"));
        expect(report.result).not.toBeUndefined();
    })

    it("writes sarif report on pass", async () => {
        core.setOutput = jest.fn();

        setupExecMocks();
        /* eslint-disable no-unused-vars */
        exec.exec.mockImplementationOnce((_cmdline, _args, options) => {
            return Promise.resolve(0);
        });

        exec.exec.mockImplementationOnce((cmdline, args, options) => {
            options.listeners.stdout(exampleReport);
            return Promise.resolve(0);
        });
        /* eslint-enable no-unused-vars */

        await index.run();

        expect(core.setOutput).toBeCalledWith("sarifReport", "./sarif.json");
        let sarif = JSON.parse(fs.readFileSync("./sarif.json"));
        expect(sarif.version).toBe("2.1.0");
        expect(sarif.runs[0].tool.driver.rules[0].id).toBe("CVE-2023-30861");
        expect(sarif.runs[0].results[0].ruleId).toBe("CVE-2023-30861");
    })

    it("writes scan report on fail", async () => {
        core.setOutput = jest.fn();
        core.error = jest.fn();

        setupExecMocks();
        /* eslint-disable no-unused-vars */
        exec.exec.mockImplementationOnce((_cmdline, _args, options) => {
            return Promise.resolve(1);
        });

        exec.exec.mockImplementationOnce((cmdline, args, options) => {
            options.listeners.stdout(exampleReport);
            return Promise.resolve(0);
        });
        /* eslint-enable no-unused-vars */

        await index.run();
        expect(core.error).not.toBeCalled();
        expect(core.setOutput).toBeCalledWith("scanReport", "./report.json");
        expect(core.setOutput).toBeCalledWith("sarifReport", "./sarif.json");

        JSON.parse(fs.readFileSync("./report.json"));
        JSON.parse(fs.readFileSync("./sarif.json"));
    })

    it("fails if scan fails", async () => {
        process.env['INPUT_STOP-ON-FAILED-POLICY-EVAL'] = "true";

        core.setFailed = jest.fn();

        setupExecMocks();

        /* eslint-disable no-unused-vars */
        exec.exec.mockImplementationOnce((_cmdline, _args, options) => {
            return Promise.resolve(1);
        });

        exec.exec.mockImplementationOnce((cmdline, args, options) => {
            options.listeners.stdout(exampleReport);
            return Promise.resolve(0);
        });
        /* eslint-enable no-unused-vars */

        await index.run();

        expect(core.setFailed).toBeCalled();
    })

    it("ends ok if scan fails but stopOnFailedPolicyEval is false", async () => {
        process.env['INPUT_STOP-ON-FAILED-POLICY-EVAL'] = "false";

        core.setFailed = jest.fn();

        setupExecMocks();

        /* eslint-disable no-unused-vars */
        exec.exec.mockImplementationOnce((_cmdline, _args, options) => {
            return Promise.resolve(1);
        });

        exec.exec.mockImplementationOnce((cmdline, args, options) => {
            options.listeners.stdout(exampleReport);
            return Promise.resolve(0);
        });
        /* eslint-enable no-unused-vars */

        await index.run();

        expect(core.setFailed).not.toBeCalled();
    })

    it("fails if scanner has wrong parameters and stopOnProcessingError is true", async () => {
        process.env['INPUT_STOP-ON-PROCESSING-ERROR'] = "true";

        core.setFailed = jest.fn();

        /* eslint-disable no-unused-vars */
        exec.exec.mockImplementationOnce((cmdline, args, options) => {
            return Promise.resolve(2);
        });
        /* eslint-enable no-unused-vars */

        await index.run();

        expect(core.setFailed).toBeCalled();
    })

    it("fails on unexpected error  and stopOnProcessingError is true", async () => {
        process.env['INPUT_STOP-ON-PROCESSING-ERROR'] = "true";

        core.setFailed = jest.fn();
        setupExecMocks();

        /* eslint-disable no-unused-vars */
        exec.exec.mockImplementationOnce((cmdline, args, options) => {
            options.listeners.stdout(exampleReport);
            return Promise.resolve(123);
        });
        /* eslint-enable no-unused-vars */

        await index.run();

        expect(core.setFailed).toBeCalled();
    })


    it("ends ok if scan fails but stopOnProcessingError is false", async () => {
        process.env['INPUT_STOP-ON-PROCESSING-ERROR'] = "false";

        core.setFailed = jest.fn();

        setupExecMocks();

        /* eslint-disable no-unused-vars */
        exec.exec.mockImplementationOnce((_cmdline, _args, options) => {
            return Promise.resolve(123);
        });

        exec.exec.mockImplementationOnce((cmdline, args, options) => {
            options.listeners.stdout(exampleReport);
            return Promise.resolve(0);
        });
        /* eslint-enable no-unused-vars */

        await index.run();

        expect(core.setFailed).not.toBeCalled();
    })

    it("allows override of inline-scan image", async () => {
        process.env['INPUT_OVERRIDE-PULLSTRING'] = "my-custom-image:latest";

        exec.exec = jest.fn(() => {
            return Promise.resolve(0);
        });

        await index.run();
        expect(exec.exec).toBeCalledTimes(4);
        expect(exec.exec.mock.calls[2][0]).toMatch(`${index.cliScannerName}  --json-scan-result=scan-result.json --apiurl https://secure.sysdig.com/ --override-pullstring=my-custom-image:latest image:tag`);
    })

})