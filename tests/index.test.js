//const { TestScheduler } = require('jest')
var index = require('..');
const fs = require('fs');
const process = require('process');
const tmp = require('tmp');

describe("input parsing", () => {
    const OLD_ENV = process.env;

    beforeEach(() => {
      jest.resetModules() // most important - it clears the cache
      process.env = { ...OLD_ENV }; // make a copy
    });

    afterAll(() => {
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

describe("Compose docker flags", () => {
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

describe("Compose execution flags", () => {
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

describe("Image pulling", () => {
    let exec;

    beforeEach(() => {
        jest.mock("@actions/exec");
        exec = require("@actions/exec");
        index = require("..");
    })

    afterEach(() => {
        exec.exec.mockRestore();
    })

    it("should pull the configured scan image", async () => {
        await index.pullScanImage("dummy-image:tag");
        expect(exec.exec).toHaveBeenCalledTimes(1);
        expect(exec.exec).toHaveBeenCalledWith("docker pull dummy-image:tag", null);
    })
})

describe("Container execution", () => {
    let exec;
    let tmpDir;

    beforeEach(() => {
        jest.mock("@actions/exec");
        exec = require("@actions/exec");
        index = require("..");

        tmpDir = tmp.dirSync().name;
        process.chdir(tmpDir);
    })

    afterEach(() => {
        jest.clearAllMocks()
        exec.exec.mockRestore();

        fs.rmdirSync(tmpDir, {recursive: true});
    })

    it("should execute the container with the corresponding flags", async () => {
        await index.executeInlineScan("inline-scan:tag", "--docker1 --docker2", "--run1 --run2 image-to-scan");
        expect(exec.exec).toHaveBeenCalledTimes(1);
        expect(exec.exec.mock.calls[0][0]).toMatch(/docker run --docker1 --docker2 inline-scan:tag --run1 --run2 image-to-scan/)
    })

    it("should return the return code", async () => {
        exec.exec.mockResolvedValueOnce(123);
        let result = await index.executeInlineScan("inline-scan:tag");
        expect(result.ReturnCode).toBe(123);
    })

    it("should return the output", async () => {
        exec.exec.mockImplementationOnce((cmdline, args, options) => {
            options.listeners.stdout("foo-output");
            return Promise.resolve(0);
        });
        let result = await index.executeInlineScan("inline-scan:tag");
        expect(result.Output).toBe("foo-output");
    })
})

describe("Report generation tests", () => {

})

describe("Check run generation tests", () => {

})