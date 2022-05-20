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

const exampleReport = JSON.stringify(require("./fixtures/report.json"));
const exampleLongReport = JSON.stringify(require("./fixtures/longreport.json"));

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

    it("raises error if no token provided", () => {
        process.env['INPUT_IMAGE-TAG'] = "image:tag";
        expect(() => index.parseActionInputs()).toThrow("Input required and not supplied: sysdig-secure-token");
    })

    it("raises error if no image tag provided", () => {
        process.env['INPUT_SYSDIG-SECURE-TOKEN'] = "token";
        expect(() => index.parseActionInputs()).toThrow("Input required and not supplied: image-tag");
    })

    it("sets default for inputs", () => {
        process.env['INPUT_SYSDIG-SECURE-TOKEN'] = "token";
        process.env['INPUT_IMAGE-TAG'] = "image:tag";
        let opts = index.parseActionInputs()

        expect(opts).toEqual({
            "imageTag": "image:tag",
            "sysdigSecureToken": "token",
            "dockerfilePath": "",
            "extraDockerParameters": "",
            "extraParameters": "",
            "ignoreFailedScan": false,
            "inputPath": "",
            "inputType": "",
            "runAsUser": "",
            "sysdigSecureURL": "",
            "sysdigSkipTLS": false,
            "inlineScanImage": "",
        })
    })

    it("parses all inputs", () => {
        process.env['INPUT_SYSDIG-SECURE-TOKEN'] = 'token';
        process.env['INPUT_IMAGE-TAG'] = 'image:tag';
        process.env['INPUT_DOCKERFILE-PATH'] = '/Dockerfile';
        process.env['INPUT_EXTRA-DOCKER-PARAMETERS'] = '-docker -params';
        process.env['INPUT_EXTRA-PARAMETERS'] = '-extra -params';
        process.env['INPUT_IGNORE-FAILED-SCAN'] = "true";
        process.env['INPUT_INPUT-PATH'] = "/input-path";
        process.env['INPUT_INPUT-TYPE'] = "foo-type";
        process.env['INPUT_RUN-AS-USER'] = "user";
        process.env['INPUT_SYSDIG-SECURE-URL'] = "https://foo";
        process.env['INPUT_SYSDIG-SKIP-TLS'] = "true";
        process.env['INPUT_INLINE-SCAN-IMAGE'] = "my-custom-image:latest";
        let opts = index.parseActionInputs()

        expect(opts).toEqual({
            "imageTag": "image:tag",
            "sysdigSecureToken": "token",
            "dockerfilePath": "/Dockerfile",
            "extraDockerParameters": "-docker -params",
            "extraParameters": "-extra -params",
            "ignoreFailedScan": true,
            "inputPath": "/input-path",
            "inputType": "foo-type",
            "runAsUser": "user",
            "sysdigSecureURL": "https://foo",
            "sysdigSkipTLS": true,
            "inlineScanImage": "my-custom-image:latest",
        })
    })

})

describe("docker flags", () => {

    it("uses default docker flags", () => {
        let flags = index.composeFlags({});
        expect(flags.dockerFlags).toMatch(/(^| )--rm($| )/)
        expect(flags.dockerFlags).toMatch(new RegExp(`(^| )-u ${process.getuid()}($| )`));
    })

    it("mounts the input file", () => {
        let flags = index.composeFlags({
            inputPath: "/myfolder/myfile.tar",
            inputType: "docker-archive"
        });
        expect(flags.dockerFlags).toMatch(new RegExp(`(^| )-v /myfolder/myfile.tar:/tmp/myfile.tar($| )`));
    })

    it("mounts the docker socket", () => {
        let flags = index.composeFlags({
            inputType: "docker-daemon",
            inputPath: "/var/lib/run/docker/docker.sock",
        });
        expect(flags.dockerFlags).toMatch(new RegExp(`(^| )-v /var/lib/run/docker/docker.sock:/var/run/docker.sock($| )`));
    })

    it("mounts the Dockerfile", () => {
        let flags = index.composeFlags({
            dockerfilePath: "/my/Dockerfile",
        });
        expect(flags.dockerFlags).toMatch(new RegExp(`(^| )-v /my/Dockerfile:/tmp/Dockerfile($| )`));
    })

    it("runs as specified user", () => {
        let flags = index.composeFlags({
            runAsUser: "foo",
        });
        expect(flags.dockerFlags).toMatch(/(^| )-u foo($| )/);
    })

    it("adds extra docker flags", () => {
        let flags = index.composeFlags({
            extraDockerParameters: "--extra-param"
        });
        expect(flags.dockerFlags).toMatch(/(^| )--extra-param($| )/);
    })

    it("adds the token as environment", () => {
        let flags = index.composeFlags({
            sysdigSecureToken: "foo-token",
        });
        expect(flags.dockerFlags).toMatch(/(^| )-e SYSDIG_API_TOKEN[ =]foo-token($| )/)

    })
})

describe("execution flags", () => {

    it("uses default flags", () => {
        let flags = index.composeFlags({ sysdigSecureToken: "foo-token", imageTag: "image:tag" });
        expect(flags.runFlags).toMatch(/(^| )--format[ =]JSON($| )/);
        expect(flags.runFlags).toMatch(/(^| )image:tag($| )/);
    })

    it("adds secure URL flag", () => {
        let flags = index.composeFlags({
            sysdigSecureToken: "foo-token",
            sysdigSecureURL: "https://foo"
        });
        expect(flags.runFlags).toMatch(/(^| )--sysdig-url[ =]https:\/\/foo($| )/)
    })

    it("uses storage-type flags", () => {
        let flags = index.composeFlags({
            sysdigSecureToken: "foo-token",
            inputType: "foo-input",
        });
        expect(flags.runFlags).toMatch(/(^| )--storage-type[ =]foo-input($| )/)
    })

    it("uses storage-path flags", () => {
        let flags = index.composeFlags({
            sysdigSecureToken: "foo-token",
            inputType: "foo-input",
            inputPath: "/myPath"
        });
        expect(flags.runFlags).toMatch(/(^| )--storage-path[ =]\/tmp\/myPath($| )/)
    })

    it("uses dockerfile flag", () => {
        let flags = index.composeFlags({
            dockerfilePath: "/my/Dockerfile",
        });
        expect(flags.runFlags).toMatch(new RegExp(/(^| )--dockerfile[ =]\/tmp\/Dockerfile($| )/));
    })

    it("uses --skip-tls flag", () => {
        let flags = index.composeFlags({
            sysdigSkipTLS: true,
        });
        expect(flags.runFlags).toMatch(new RegExp(/(^| )--sysdig-skip-tls($| )/));
    })
})

describe("image pulling", () => {
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

    it("pulls the configured scan image", async () => {
        exec.exec = jest.fn();
        await index.pullScanImage("dummy-image:tag");
        expect(exec.exec).toBeCalledTimes(1);
        expect(exec.exec).toBeCalledWith("docker pull dummy-image:tag", null);
    })
})

describe("inline-scan execution", () => {
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

        await index.executeInlineScan("inline-scan:tag", "--docker1 --docker2", "--run1 --run2 image-to-scan");

        expect(exec.exec).toBeCalledTimes(7);
        expect(exec.exec.mock.calls[0][0]).toMatch(/docker run -d --entrypoint \/bin\/cat -ti --docker1 --docker2 inline-scan:tag/);
        expect(exec.exec.mock.calls[4][0]).toMatch(/docker exec foo-id \/sysdig-inline-scan.sh --run1 --run2 image-to-scan/);
    })

    it("returns the execution return code", async () => {
        exec.exec.mockResolvedValueOnce(0);
        exec.exec.mockResolvedValueOnce(0);
        exec.exec.mockResolvedValueOnce(0);
        exec.exec.mockResolvedValueOnce(0);
        exec.exec.mockResolvedValueOnce(123);
        let result = await index.executeInlineScan("inline-scan:tag");
        expect(result.ReturnCode).toBe(123);
    })

    it("returns the output", async () => {

        exec.exec = jest.fn((cmd, args, options) => {
            if (options && options.listeners) { options.listeners.stdout("foo-output"); }
            return Promise.resolve(0);
        });

        let result = await index.executeInlineScan("inline-scan:tag");
        expect(result.Output).toBe("foo-output");
    })
})

describe("process scan results", () => {
    let fs;
    let core;
    let github;

    beforeEach(() => {
        jest.resetAllMocks()

        core = require("@actions/core");
        fs = require("fs");
        github = require("@actions/github");
        index = require("..");
    })

    afterEach(() => {
        jest.resetModules() // most important - it clears the cache
        index = require("..");
    })

    it("returns true if success", async () => {
        let scanResult = {
            ReturnCode: 0,
            Output: "{}",
            Error: ""
        };
        let success = await index.processScanResult(scanResult);
        expect(success).toBe(true);
    })

    it("returns false if not success", async () => {
        let scanResult = {
            ReturnCode: 1,
            Output: "{}",
            Error: ""
        };
        let success = await index.processScanResult(scanResult);
        expect(success).toBe(false);
    })

    it("throws an error on failed execution", async () => {
        let scanResult = {
            ReturnCode: 3,
            Output: "Some output",
            Error: "Some error"
        };
        return expect(index.processScanResult(scanResult)).rejects.toThrow(new index.ExecutionError('Some output', 'Some error'));
    })

    it("handles error on invalid JSON", async () => {
        core.error = jest.fn();

        let scanResult = {
            ReturnCode: 0,
            Output: 'invalid JSON',
            Error: ""
        };

        await expect(index.processScanResult(scanResult)).rejects.toThrow(new index.ExecutionError('invalid JSON', ''));
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

        await index.processScanResult(scanResult);
        expect(fs.writeFileSync).toBeCalledWith("./report.json", reportData);
        fs.writeFileSync = realWriteFileSync;
    })

    it("generates a check run with vulnerability annotations", async () => {
        let data;
        github.context = { repo: { repo: "foo-repo", owner: "foo-owner" } };

        core.getInput = jest.fn();
        core.getInput.mockReturnValueOnce("foo");

        github.getOctokit = jest.fn(() => {
            return {
                rest: {
                    checks: {
                        create: async function (receivedData) {
                            data = receivedData;
                        }
                    }
                }
            }
        });

        let scanResult = {
            ReturnCode: 0,
            Output: exampleReport,
            Error: ""
        };
        await index.processScanResult(scanResult);
        expect(github.getOctokit).toBeCalledWith("foo");
        expect(data).not.toBeUndefined();
        expect(data.name).toBe("Scan results for myimage:mytag");
        expect(data.output.annotations).toContainEqual({ "annotation_level": "warning", "end_line": 1, "message": "CVE-2019-14697 Severity=High Package=musl-1.1.18-r3 Type=APKG Fix=1.1.18-r4 Url=https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-14697", "path": "Dockerfile", "start_line": 1, "title": "Vulnerability found: CVE-2019-14697" });
        expect(data.output.annotations).toContainEqual({"path": "Dockerfile", "start_line": 1, "end_line": 1, "annotation_level": "warning", "message": "CVE-2011-3374 Severity=Negligible Package=apt-1.0 Type=APKG Fix=null Url=https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2011-3374", "title": "Vulnerability found: CVE-2011-3374"});
    })

    it("generates a check run with vulnerability annotations, at least medium severity", async () => {
        let data;
        github.context = { repo: { repo: "foo-repo", owner: "foo-owner" } };

        core.getInput = jest.fn();
        core.getInput.mockReturnValueOnce("foo");

        github.getOctokit = jest.fn(() => {
            return {
                rest: {
                    checks: {
                        create: async function (receivedData) {
                            data = receivedData;
                        }
                    }
                }
            }
        });

        let scanResult = {
            ReturnCode: 0,
            Output: exampleReport,
            Error: ""
        };
        core.getInput.mockReturnValueOnce("medium")

        await index.processScanResult(scanResult);
        expect(github.getOctokit).toBeCalledWith("foo");
        expect(data).not.toBeUndefined();
        expect(data.name).toBe("Scan results for myimage:mytag");
        expect(data.output.annotations).toContainEqual({ "annotation_level": "warning", "end_line": 1, "message": "CVE-2019-14697 Severity=High Package=musl-1.1.18-r3 Type=APKG Fix=1.1.18-r4 Url=https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-14697", "path": "Dockerfile", "start_line": 1, "title": "Vulnerability found: CVE-2019-14697" });
        expect(data.output.annotations).not.toContainEqual({"path": "Dockerfile", "start_line": 1, "end_line": 1, "annotation_level": "warning", "message": "CVE-2011-3374 Severity=Negligible Package=apt-1.0 Type=APKG Fix=null Url=https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2011-3374", "title": "Vulnerability found: CVE-2011-3374"});
        expect(data.output.annotations).toContainEqual({"path": "Dockerfile", "start_line": 1, "end_line": 1, "annotation_level": "warning", "message": "CVE-2019-14697 Severity=High Package=musl-utils-1.1.18-r3 Type=APKG Fix=1.1.18-r4 Url=https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-14697", "title": "Vulnerability found: CVE-2019-14697"});
        expect(data.output.annotations).toContainEqual({"path": "Dockerfile", "start_line": 1, "end_line": 1, "annotation_level": "warning", "message": "CVE-2019-14698 Severity=Medium Package=musl-utils-1.1.18-r3 Type=APKG Fix=1.1.18-r4 Url=https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-14698", "title": "Vulnerability found: CVE-2019-14698"});
    })

    it("generates a check run with unique vulnerability annotations", async () => {
        let data;
        github.context = { repo: { repo: "foo-repo", owner: "foo-owner" } };

        core.getInput = jest.fn();
        core.getInput.mockReturnValueOnce("foo");


        github.getOctokit = jest.fn(() => {
            return {
                rest: {
                    checks: {
                        create: async function (receivedData) {
                            data = receivedData;
                        }
                    }
                }
            }
        });

        let scanResult = {
            ReturnCode: 0,
            Output: exampleReport,
            Error: ""
        };
        core.getInput.mockReturnValueOnce("medium")
        core.getInput.mockReturnValueOnce("true")

        await index.processScanResult(scanResult);
        expect(github.getOctokit).toBeCalledWith("foo");
        expect(data).not.toBeUndefined();
        expect(data.name).toBe("Scan results for myimage:mytag");
        //Should display the vulnerability with the highest severity
        expect(data.output.annotations).toContainEqual({"path": "Dockerfile", "start_line": 1, "end_line": 1, "annotation_level": "warning", "message": "CVE-2019-14697 Severity=High Package=musl-utils-1.1.18-r3 Type=APKG Fix=1.1.18-r4 Url=https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-14697", "title": "Vulnerability found: CVE-2019-14697"});
        expect(data.output.annotations).not.toContainEqual({"path": "Dockerfile", "start_line": 1, "end_line": 1, "annotation_level": "warning", "message": "CVE-2019-14698 Severity=Medium Package=musl-utils-1.1.18-r3 Type=APKG Fix=1.1.18-r4 Url=https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-14698", "title": "Vulnerability found: CVE-2019-14698"});

    })

    it("generates a check run with gate annotations", async () => {
        let data;
        github.context = { repo: { repo: "foo-repo", owner: "foo-owner" } };

        core.getInput = jest.fn();
        core.getInput.mockReturnValueOnce("foo");

        github.getOctokit = jest.fn(() => {
            return {
                rest: {
                        checks: {
                        create: async function (receivedData) {
                            data = receivedData;
                        }
                    }
                }
            }
        });

        let scanResult = {
            ReturnCode: 0,
            Output: exampleReport,
            Error: ""
        };

        await index.processScanResult(scanResult);
        expect(github.getOctokit).toBeCalledWith("foo");
        expect(data).not.toBeUndefined();
        expect(data.name).toBe("Scan results for myimage:mytag");
        expect(data.output.annotations).toContainEqual({ "annotation_level": "warning", "end_line": 1, "message": "warn dockerfile:instruction\nDockerfile directive 'HEALTHCHECK' not found, matching condition 'not_exists' check", "path": "Dockerfile", "start_line": 1, "title": "warn dockerfile" });
        expect(data.output.annotations).toContainEqual({ "annotation_level": "failure", "end_line": 1, "message": "stop dockerfile:instruction\nDockerfile directive 'USER' not found, matching condition 'not_exists' check", "path": "Dockerfile", "start_line": 1, "title": "stop dockerfile" });
    })

    it("generates a check run and then updates it if more than 50 entries", async () => {
        let createData;
        let updateData
        github.context = { repo: { repo: "foo-repo", owner: "foo-owner" } };

        core.getInput = jest.fn();
        core.getInput.mockReturnValueOnce("foo");

        github.getOctokit = jest.fn(() => {
            return {
                rest: {
                    checks: {
                        create: async function (receivedData) {
                            createData = receivedData;
                            return { data: {id: 1 } };
                        },
                        update: async function (receivedData) {
                            updateData = receivedData;
                        }
                    }
                }
            }
        });

        let scanResult = {
            ReturnCode: 0,
            Output: exampleLongReport,
            Error: ""
        };

        await index.processScanResult(scanResult);
        expect(createData.output.annotations).not.toContainEqual({ "annotation_level": "failure", "end_line": 1, "message": "stop dockerfile:instruction\nDockerfile directive 'USER' not found, matching condition 'not_exists' check", "path": "Dockerfile", "start_line": 1, "title": "stop dockerfile" });
        expect(updateData.output.annotations).toContainEqual({ "annotation_level": "failure", "end_line": 1, "message": "stop dockerfile:instruction\nDockerfile directive 'USER' not found, matching condition 'not_exists' check", "path": "Dockerfile", "start_line": 1, "title": "stop dockerfile" });
    })

    it("generates SARIF report with vulnerabilities", async () => {
        let realWriteFileSync = fs.writeFileSync;
        fs.writeFileSync = jest.fn();

        let scanResult = {
            ReturnCode: 0,
            Output: exampleReport,
            Error: ""
        };
        await index.processScanResult(scanResult);
        expect(fs.writeFileSync).toBeCalledWith("./sarif.json", expect.stringMatching(/"version": "2.1.0"/));
        expect(fs.writeFileSync).toBeCalledWith("./sarif.json", expect.stringMatching(/"id": "VULN_CVE-2019-14697_APKG_musl-1.1.18-r3/));
        expect(fs.writeFileSync).toBeCalledWith("./sarif.json", expect.stringMatching(/"ruleId": "VULN_CVE-2019-14697_APKG_musl-1.1.18-r3/));
        fs.writeFileSync = realWriteFileSync;
    })

    xit("generates SARIF report with gates", async () => {
        //TODO: Gates are not included in SARIF report
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
        process.env['INPUT_INPUT-TYPE'] = "pull";

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

        exec.exec.mockImplementationOnce((cmdline, args, options) => {
            return Promise.resolve(0);
        });

        exec.exec.mockImplementationOnce((cmdline, args, options) => {
            return Promise.resolve(0);
        });

        exec.exec.mockImplementationOnce((_cmdline, _args, options) => {
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
        exec.exec.mockImplementationOnce((cmdline, args, options) => {
            options.listeners.stdout(exampleReport);
            return Promise.resolve(0);
        });
        /* eslint-enable no-unused-vars */

        await index.run();

        expect(core.setOutput).toBeCalledWith("scanReport", "./report.json");
        let report = JSON.parse(fs.readFileSync("./report.json"));
        expect(report.status).not.toBeUndefined();
    })

    it("writes scan report on fail", async () => {
        core.setOutput = jest.fn();


        setupExecMocks();
        /* eslint-disable no-unused-vars */
        exec.exec.mockImplementationOnce((cmdline, args, options) => {
            options.listeners.stdout(exampleReport);
            return Promise.resolve(1);
        });
        /* eslint-enable no-unused-vars */

        await index.run();

        expect(core.setOutput).toBeCalledWith("scanReport", "./report.json");
        let report = JSON.parse(fs.readFileSync("./report.json"));
        expect(report.status).not.toBeUndefined();
    })

    it("writes sarif report on pass", async () => {
        core.setOutput = jest.fn();

        setupExecMocks();
        /* eslint-disable no-unused-vars */
        exec.exec.mockImplementationOnce((cmdline, args, options) => {
            options.listeners.stdout(exampleReport);
            return Promise.resolve(0);
        });
        /* eslint-enable no-unused-vars */

        await index.run();

        expect(core.setOutput).toBeCalledWith("sarifReport", "./sarif.json");
        let sarif = JSON.parse(fs.readFileSync("./sarif.json"));
        expect(sarif.version).toBe("2.1.0");
        expect(sarif.runs[0].tool.driver.rules[0].id).toBe("VULN_CVE-2019-14697_APKG_musl-1.1.18-r3");
        expect(sarif.runs[0].results[0].ruleId).toBe("VULN_CVE-2019-14697_APKG_musl-1.1.18-r3");
    })

    it("writes scan report on fail", async () => {
        core.setOutput = jest.fn();
        core.error = jest.fn();

        setupExecMocks();
        /* eslint-disable no-unused-vars */
        exec.exec.mockImplementationOnce((cmdline, args, options) => {
            options.listeners.stdout(exampleReport);
            return Promise.resolve(1);
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
        core.setFailed = jest.fn();

        setupExecMocks();

        /* eslint-disable no-unused-vars */
        exec.exec.mockImplementationOnce((cmdline, args, options) => {
            options.listeners.stdout(exampleReport);
            return Promise.resolve(1);
        });
        /* eslint-enable no-unused-vars */

        await index.run();

        expect(core.setFailed).toBeCalled();
    })

    it("ends ok if scan fails but ignoreFailedScan is true", async () => {
        process.env['INPUT_IGNORE-FAILED-SCAN'] = "true";

        core.setFailed = jest.fn();

        setupExecMocks();

        exec.exec.mockImplementationOnce((cmdline, args, options) => {
            options.listeners.stdout(exampleReport);
            return Promise.resolve(1);
        });

        await index.run();

        expect(core.setFailed).not.toBeCalled();
    })

    it("fails if container creation fails", async () => {
        process.env['INPUT_IGNORE-FAILED-SCAN'] = "true";

        core.setFailed = jest.fn();

        /* eslint-disable no-unused-vars */
        exec.exec.mockImplementationOnce((cmdline, args, options) => {
            return Promise.resolve(0);
        });

        exec.exec.mockImplementationOnce((cmdline, args, options) => {
            options.listeners.stderr("some-error");
            return Promise.resolve(1);
        });
        /* eslint-enable no-unused-vars */

        await index.run();

        expect(core.setFailed).toBeCalled();
    })

    it("fails on unexpected error", async () => {
        process.env['INPUT_IGNORE-FAILED-SCAN'] = "true";

        core.setFailed = jest.fn();
        setupExecMocks();

        exec.exec.mockImplementationOnce((cmdline, args, options) => {
            options.listeners.stdout(exampleReport);
            return Promise.resolve(2);
        });

        await index.run();

        expect(core.setFailed).toBeCalled();
    })


    it("allows override of inline-scan image", async () => {
        process.env['INPUT_INLINE-SCAN-IMAGE'] = "my-custom-image:latest";

        exec.exec = jest.fn(() => {
            return Promise.resolve(0);
        });

        await index.run();
        expect(exec.exec).toBeCalledTimes(8);
        expect(exec.exec).toBeCalledWith("docker pull my-custom-image:latest", null);
        expect(exec.exec).toBeCalledWith(expect.stringMatching(/docker run .* my-custom-image:latest/), null, expect.anything());
    })

})