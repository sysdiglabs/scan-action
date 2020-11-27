let core = require("@actions/core");
let exec = require("@actions/exec");
let github = require('@actions/github')
let fs = require('fs');
const process = require('process');
const tmp = require('tmp');
let index = require("..");

describe("input parsing", () => {
    const OLD_ENV = process.env;

    beforeEach(() => {
      jest.resetModules() // most important - it clears the cache
      process.env = { ...OLD_ENV }; // make a copy
    });

    afterEach(() => {
        process.env = OLD_ENV; // restore old env
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
        })
    })    

})

describe("docker flags", () => {
    it("uses default docker flags", () => {
        let flags = index.composeFlags({});
        expect(flags.dockerFlags).toMatch(/(^| )--rm($| )/)
        expect(flags.dockerFlags).toMatch(new RegExp(`(^| )-v ${process.cwd()}/scan-output:/tmp/sysdig-inline-scan($| )`));
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
})

describe("execution flags", () => {
    it("uses default flags", () => {
        let flags = index.composeFlags({sysdigSecureToken: "foo-token", imageTag: "image:tag"});
        expect(flags.runFlags).toMatch(/(^| )--sysdig-token[ =]foo-token($| )/)
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

    beforeAll(() => {
        jest.mock("@actions/exec");
        exec = require("@actions/exec");
        index = require("..");
    })

    afterAll(()=> {
        jest.resetModules() // most important - it clears the cache
    })

    it("pulls the configured scan image", async () => {
        await index.pullScanImage("dummy-image:tag");
        expect(exec.exec).toBeCalledTimes(1);
        expect(exec.exec).toBeCalledWith("docker pull dummy-image:tag", null);
    })
})

describe("inline-scan execution", () => {
    let tmpDir;
    let cwd;

    beforeAll(() => {
        jest.mock("@actions/exec");
        exec = require("@actions/exec");
        index = require("..");
    })

    afterAll(()=> {
        jest.resetModules() // most important - it clears the cache
    })

    beforeEach(() => {
        jest.resetAllMocks()
        tmpDir = tmp.dirSync().name;
        cwd = process.cwd();
        process.chdir(tmpDir);
    })

    afterEach(() => {
        fs.rmdirSync(tmpDir, {recursive: true});
        process.chdir(cwd);
    })

    it("invokes the container with the corresponding flags", async () => {
        await index.executeInlineScan("inline-scan:tag", "--docker1 --docker2", "--run1 --run2 image-to-scan");
        expect(exec.exec).toBeCalledTimes(1);
        expect(exec.exec.mock.calls[0][0]).toMatch(/docker run --docker1 --docker2 inline-scan:tag --run1 --run2 image-to-scan/)
    })

    it("returns the execution return code", async () => {
        exec.exec.mockResolvedValueOnce(123);
        let result = await index.executeInlineScan("inline-scan:tag");
        expect(result.ReturnCode).toBe(123);
    })

    it("returns the output", async () => {
        exec.exec.mockImplementationOnce((cmdline, args, options) => {
            options.listeners.stdout("foo-output");
            return Promise.resolve(0);
        });
        let result = await index.executeInlineScan("inline-scan:tag");
        expect(result.Output).toBe("foo-output");
    })
})

describe("process scan results", () => {

    const exampleReport = JSON.stringify(require("./fixtures/report.json"));

    beforeAll(() => {
        jest.mock("@actions/core");
        jest.mock("@actions/github");
        jest.mock("fs");
        fs = require("fs")
        core = require("@actions/core");
        github = require('@actions/github')
        index = require("..");
    })

    afterAll(()=> {
        jest.resetModules() // most important - it clears the cache
    })

    beforeEach(() => {
        jest.resetAllMocks()
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
        return expect(index.processScanResult(scanResult)).rejects.toThrow(new index.ExecutionError('Some output', "Some error"));
    })

    it("handles error on invalid JSON", async () => {
        core.error.mockReturnValueOnce(123);
        let scanResult = {
            ReturnCode: 0,
            Output: 'invalid JSON',
            Error: ""
        };

        let success = await index.processScanResult(scanResult);
        expect(success).toBe(true);
        expect(core.error).toBeCalledTimes(1);
        expect(core.error.mock.calls[0][0]).toMatch(/Error parsing analysis JSON report/)
    })

   it("generates a report JSON", async () => {
        let reportData = '{"foo": "bar"}';
        let scanResult = {
            ReturnCode: 0,
            Output: reportData,
            Error: ""
        };

        await index.processScanResult(scanResult);
        expect(fs.writeFileSync).toBeCalledWith("./report.json", reportData)
    })
    
    it("generates a check run with vulnerability annotations", async () => {
        var data;
        core.getInput.mockReturnValueOnce("foo");
        github.context.repo = { repo: "foo-repo", owner: "foo-owner"};
        github.getOctokit.mockReturnValueOnce({
            checks: {
                create: async function (receivedData) {
                    data = receivedData;
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
        expect(data.name).toBe("Scan results");
        expect(data.output.annotations).toContainEqual({"annotation_level": "warning", "end_line": 1, "message": "CVE-2019-14697 Severity=High Package=musl-1.1.18-r3 Type=APKG Fix=1.1.18-r4 Url=https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-14697", "path": "Dockerfile", "start_line": 1, "title": "CVE-2019-14697"});
    })

    it("generates a check run with gate annotations", async () => {

    })

    it("generates SARIF report with vulnerabilities", async () => {
        let scanResult = {
            ReturnCode: 0,
            Output: exampleReport,
            Error: ""
        };
        await index.processScanResult(scanResult);
        expect(fs.writeFileSync).toBeCalledWith("./sarif.json", expect.stringMatching(/"version": "2.1.0"/));
        expect(fs.writeFileSync).toBeCalledWith("./sarif.json", expect.stringMatching(/"id": "VULN_CVE-2019-14697_APKG_musl-1.1.18-r3/));
        expect(fs.writeFileSync).toBeCalledWith("./sarif.json", expect.stringMatching(/"ruleId": "VULN_CVE-2019-14697_APKG_musl-1.1.18-r3/));
    })

    it("generates SARIF report with gates", async () => {

    })
})

describe("run the full action", () => {
    it("ends ok with scan pass", () => {

    })

    it("fails if scan fails", () => {

    })

    it("ends ok if scan fails but ignoreScanFailed is true", () => {

    })

    it("fails on unexpected error", () => {

    })
})