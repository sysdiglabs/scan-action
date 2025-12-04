import { SummaryReportPresenter } from "../../../src/infrastructure/github/SummaryReportPresenter";
import { JsonScanResultV1ToScanResultAdapter } from "../../../src/infrastructure/sysdig/JsonScanResultV1ToScanResultAdapter";
import * as fs from "fs";
import * as core from "@actions/core";
import { Severity, ScanResult, ScanType, OperatingSystem, Family, Architecture, EvaluationResult, PackageType, AcceptedRiskReason } from "../../../src/domain/scanresult";

describe("SummaryReportPresenter", () => {
    afterEach(() => {
        jest.clearAllMocks();
    });

    it("should generate a summary report and sort packages by severity correctly", async () => {
        const fileContent = fs.readFileSync("tests/fixtures/vm/report-test-v1.json", "utf-8");
        const json = JSON.parse(fileContent);
        const scanResult = new JsonScanResultV1ToScanResultAdapter().toScanResult(json);

        // Clear existing summary buffer, as generateReport no longer does this.
        core.summary.emptyBuffer().clear();

        const presenter: SummaryReportPresenter = new SummaryReportPresenter(core.summary);
        await presenter.generateReport(scanResult, false, { minSeverity: Severity.Low });

        const generatedHtml = core.summary.stringify();

        // Validate the output for Layer 2 which contains the vulnerable packages
        // We look for the "Package vulnerabilities per layer" section
        // And then the table following Layer 2

        // Find the index of Layer 2 header
        const layer2HeaderIndex = generatedHtml.indexOf("LAYER 2 - RUN /bin/sh -c apk add");
        expect(layer2HeaderIndex).toBeGreaterThan(-1);

        // Extract the part of HTML after Layer 2 header
        const htmlAfterLayer2 = generatedHtml.substring(layer2HeaderIndex);

        // Find the first table start
        const tableStartIndex = htmlAfterLayer2.indexOf("<table>");
        expect(tableStartIndex).toBeGreaterThan(-1);

        // Find the table end
        const tableEndIndex = htmlAfterLayer2.indexOf("</table>");
        expect(tableEndIndex).toBeGreaterThan(tableStartIndex);

        const layer2Table = htmlAfterLayer2.substring(tableStartIndex, tableEndIndex + 8);

        // Extract package names from the first column of the table rows
        // Regex to match <tr><td>PACKAGE_NAME</td>...
        // Note: The table header is in the first row with <th>, data rows use <td>

        const packageNames: string[] = [];
        // Match rows that start with <tr> and capture the content of the first <td>
        const rowRegex = /<tr>\s*<td>(.*?)<\/td>/g;

        let match;
        while ((match = rowRegex.exec(layer2Table)) !== null) {
            packageNames.push(match[1]);
        }

        // We check the relative order of these known packages
        const expectedOrder = [
            "libexpat",
            "curl",
            "libcurl",
            "gnutls",
            "git",
            "openssh-client-common",
            "openssh-keygen"
        ];

        // Filter extracted names to only include those in our expected list for stable comparison
        const actualOrder = packageNames.filter(name => expectedOrder.includes(name));

        expect(actualOrder).toEqual(expectedOrder);
    });

    describe("Filtering", () => {
        it("should filter packages by included package types", async () => {
            const fileContent = fs.readFileSync("tests/fixtures/vm/report-test-v1.json", "utf-8");
            const json = JSON.parse(fileContent);
            const scanResult = new JsonScanResultV1ToScanResultAdapter().toScanResult(json);

            core.summary.emptyBuffer().clear();

            const presenter: SummaryReportPresenter = new SummaryReportPresenter(core.summary);
            // Only include "os" packages
            await presenter.generateReport(scanResult, false, {
                minSeverity: Severity.Unknown,
                packageTypes: ["os"]
            });

            const generatedHtml = core.summary.stringify();

            // Check that an OS package is present in the report
            expect(generatedHtml).toContain("libcurl");

            // Check that a Java package is NOT present in the layer details
            // "commons-fileupload" is a Java package. It fails a policy, so it WILL appear in Policy Failures.
            // But it should NOT appear in "Package vulnerabilities per layer".

            const layerDetailsStartIndex = generatedHtml.indexOf("<h2>Package vulnerabilities per layer</h2>");
            const policySummaryStartIndex = generatedHtml.indexOf("<h2>Policy evaluation summary</h2>");

            const layerDetails = generatedHtml.substring(layerDetailsStartIndex, policySummaryStartIndex);

            expect(layerDetails).not.toContain("commons-fileupload");
        });

        it("should filter packages by excluded package types", async () => {
            const fileContent = fs.readFileSync("tests/fixtures/vm/report-test-v1.json", "utf-8");
            const json = JSON.parse(fileContent);
            const scanResult = new JsonScanResultV1ToScanResultAdapter().toScanResult(json);

            core.summary.emptyBuffer().clear();

            const presenter: SummaryReportPresenter = new SummaryReportPresenter(core.summary);
            // Exclude "os" packages
            await presenter.generateReport(scanResult, false, {
                minSeverity: Severity.Unknown,
                notPackageTypes: ["os"]
            });

            const generatedHtml = core.summary.stringify();

            // Check that an OS package is NOT present in the layer details
            // "libcurl" is an OS package. It fails a policy, so it WILL appear in Policy Failures.

            const layerDetailsStartIndex = generatedHtml.indexOf("<h2>Package vulnerabilities per layer</h2>");
            const policySummaryStartIndex = generatedHtml.indexOf("<h2>Policy evaluation summary</h2>");

            const layerDetails = generatedHtml.substring(layerDetailsStartIndex, policySummaryStartIndex);

            expect(layerDetails).not.toContain("libcurl");

            // Check that a Java package is present
            expect(generatedHtml).toContain("commons-fileupload");
        });

        it("should filter vulnerabilities counts in summary table", async () => {
            const fileContent = fs.readFileSync("tests/fixtures/vm/report-test-v1.json", "utf-8");
            const json = JSON.parse(fileContent);
            const scanResult = new JsonScanResultV1ToScanResultAdapter().toScanResult(json);

            core.summary.emptyBuffer().clear();

            const presenter: SummaryReportPresenter = new SummaryReportPresenter(core.summary);

            // Filter to only "os" packages.
            // In report-test-v1.json:
            // "os" packages like libcurl, busybox, etc. have vulnerabilities.
            // "java" packages like jenkins-core also have vulnerabilities.
            // We expect the total count to be LESS than the total unfiltered count.

            // Unfiltered counts (approximate based on fixture):
            // Total: 132 (Critical: 16, High: 41, Medium: 68, Low: 7)

            await presenter.generateReport(scanResult, false, {
                minSeverity: Severity.Unknown,
                packageTypes: ["os"]
            });

            const generatedHtml = core.summary.stringify();

            // Check the table row for "Total Vulnerabilities"
            // We need to parse or regex the HTML to find the counts.
            // Structure: <tr><th>⚠️ Total Vulnerabilities</th><td>Crit</td><td>High</td><td>Med</td><td>Low</td><td>Neg</td></tr>

            // Let's count vulnerabilities for OS packages only to set expectation.
            // We rely on the fact that if filtering works, the numbers should be different from the global totals.
            // Global totals as seen in previous test output: Critical 16, High 41.

            // If we only keep OS packages, many Java vulns (jenkins-core etc) should disappear.
            // So Critical count should be < 16.

            // Finding the Critical count cell in the Total row
            // <tr><th>⚠️ Total Vulnerabilities</th><td>16</td>... implies it found 16 criticals.

            // We expect it NOT to contain "<td>16</td>" after "Total Vulnerabilities" if filtering works,
            // because we know there are non-OS critical vulnerabilities (e.g. spring-web, jenkins-core, snakeyaml).
            // Actually, let's be more precise.

            // From previous test failure output:
            // <tr><th>⚠️ Total Vulnerabilities</th><td>16</td><td>41</td><td>68</td><td>7</td><td>0</td></tr>

            // If we filter to "os", we drop Java packages.
            // Java packages with Criticals in fixture (from failure output):
            // org.springframework:spring-web (4 criticals)
            // org.jenkins-ci.main:jenkins-core (1 critical)
            // org.springframework.security:spring-security-core (1 critical)
            // ... and others ...

            // So the count MUST be significantly lower than 16.

            const totalRowMatch = generatedHtml.match(/⚠️ Total Vulnerabilities<\/th><td>(\d+)<\/td><td>(\d+)<\/td>/);
            expect(totalRowMatch).not.toBeNull();

            if (totalRowMatch) {
                const criticalCount = parseInt(totalRowMatch[1]);
                const highCount = parseInt(totalRowMatch[2]);

                // Expected criticals for OS only < 16
                expect(criticalCount).toBeLessThan(16);

                // Expected highs for OS only < 41
                expect(highCount).toBeLessThan(41);
            }
        });

        it("should filter packages by minSeverity", async () => {
            const fileContent = fs.readFileSync("tests/fixtures/vm/report-test-v1.json", "utf-8");
            const json = JSON.parse(fileContent);
            const scanResult = new JsonScanResultV1ToScanResultAdapter().toScanResult(json);

            core.summary.emptyBuffer().clear();

            const presenter: SummaryReportPresenter = new SummaryReportPresenter(core.summary);
            // Filter to only Critical severity.
            // In report-test-v1.json, many packages have High or Medium but no Critical.
            // For example, "libssl3" has High but no Critical (from previous test output: 0 Critical, 5 High).
            // "musl" has 1 Critical.
            await presenter.generateReport(scanResult, false, {
                minSeverity: Severity.Critical
            });

            const generatedHtml = core.summary.stringify();

            const layerDetailsStartIndex = generatedHtml.indexOf("<h2>Package vulnerabilities per layer</h2>");
            const policySummaryStartIndex = generatedHtml.indexOf("<h2>Policy evaluation summary</h2>");
            const layerDetails = generatedHtml.substring(layerDetailsStartIndex, policySummaryStartIndex);

            // Check that a package with ONLY High severity (no Critical) is NOT present in the layer details
            // "libssl3" fits this description based on previous test logs
            expect(layerDetails).not.toContain("libssl3");

            // Check that a package with Critical severity IS present
            // "musl" has 1 Critical
            expect(layerDetails).toContain("musl");

            // Verify counts in summary table
            // Only Critical column should be shown (and potentially Total/Fixable)
            // But specifically, we shouldn't see counts for High/Medium/Low if they are filtered out from the columns to display logic
            // The logic is: colsToDisplay = severities.filter(s => s.sev.isMoreSevereThanOrEqualTo(minSeverity));

            // If minSeverity is Critical, colsToDisplay only contains Critical.
            // So we expect "🟣 Critical" header
            expect(generatedHtml).toContain("🟣 Critical");
            // And we expect "🔴 High" header to be ABSENT from the table
            expect(generatedHtml).not.toContain("🔴 High");
        });

        describe("Accepted Risks", () => {
            let presenter: SummaryReportPresenter;

            beforeEach(() => {
                core.summary.emptyBuffer().clear();
                presenter = new SummaryReportPresenter(core.summary);
            });

            it("should filter out packages with accepted risks when excludeAccepted is true", async () => {
                const scanResult = createScanResultWithAcceptedRisk();

                await presenter.generateReport(scanResult, false, { excludeAccepted: true });

                const html = core.summary.stringify();

                // The package "vulnerable-pkg" has an accepted risk, so it should be filtered out
                expect(html).not.toContain("vulnerable-pkg");

                // Counts should be 0
                expect(html).toContain("<td>0</td>"); // For total vulnerabilities
            });

            it("should NOT filter out packages with accepted risks when excludeAccepted is false", async () => {
                const scanResult = createScanResultWithAcceptedRisk();

                await presenter.generateReport(scanResult, false, { excludeAccepted: false });

                const html = core.summary.stringify();

                // The package should be present
                expect(html).toContain("vulnerable-pkg");

                // Counts should be > 0 (1 critical)
                // Table row for Critical
                expect(html).toContain("<td>1</td>");
            });

            function createScanResultWithAcceptedRisk(): ScanResult {
                const result = new ScanResult(
                    ScanType.Docker,
                    "my-image:latest",
                    "sha256:12345",
                    "sha256:digest",
                    new OperatingSystem(Family.Unknown, "Linux"),
                    BigInt(1000),
                    Architecture.Amd64,
                    {},
                    new Date(),
                    EvaluationResult.Passed
                );

                const layer = result.addLayer("sha256:layer1", 0, BigInt(100), "RUN something");

                const pkg = result.addPackage(
                    "pkg-1",
                    PackageType.Os,
                    "vulnerable-pkg",
                    "1.0.0",
                    "/usr/bin/pkg",
                    layer
                );

                const vuln = result.addVulnerability(
                    "CVE-2023-9999",
                    Severity.Critical,
                    9.8,
                    new Date(),
                    null,
                    true,
                    "1.0.1"
                );

                const risk = result.addAcceptedRisk(
                    "risk-1",
                    AcceptedRiskReason.RiskOwned,
                    "Accepting this risk",
                    null,
                    true,
                    new Date(),
                    new Date()
                );

                // Link them
                pkg.addVulnerability(vuln);
                vuln.addAcceptedRisk(risk);
                pkg.addAcceptedRisk(risk); // Assuming this is done by the adapter, we do it manually here

                return result;
            }
        });
    });

    it("should count the same vulnerability multiple times if it appears in multiple packages", async () => {
        core.summary.emptyBuffer().clear();

        // 1. Create ScanResult
        const result = new ScanResult(
            ScanType.Docker,
            "my-image:latest",
            "sha256:12345",
            "sha256:digest",
            new OperatingSystem(Family.Unknown, "Linux"),
            BigInt(1000),
            Architecture.Amd64,
            {},
            new Date(),
            EvaluationResult.Passed
        );

        const layer = result.addLayer("sha256:layer1", 0, BigInt(100), "RUN something");

        // 2. Add Package 1
        const pkg1 = result.addPackage(
            "pkg-1",
            PackageType.Os,
            "vulnerable-pkg-1",
            "1.0.0",
            "/usr/bin/pkg1",
            layer
        );

        // 3. Add Package 2
        const pkg2 = result.addPackage(
            "pkg-2",
            PackageType.Os,
            "vulnerable-pkg-2",
            "1.0.0",
            "/usr/bin/pkg2",
            layer
        );

        // 4. Create ONE vulnerability (same CVE)
        const cveId = "CVE-2023-12345";

        const vuln1 = result.addVulnerability(
            cveId,
            Severity.Critical,
            9.8,
            new Date(),
            null,
            true,
            "1.0.1"
        );
        pkg1.addVulnerability(vuln1);

        const vuln2 = result.addVulnerability(
            cveId,
            Severity.Critical,
            9.8,
            new Date(),
            null,
            true,
            "1.0.1"
        );
        pkg2.addVulnerability(vuln2);

        // 5. Generate Report
        const presenter = new SummaryReportPresenter(core.summary);
        await presenter.generateReport(result, false, { minSeverity: Severity.Low });

        const html = core.summary.stringify();

        // 6. Assertions
        const totalRowMatch = html.match(/⚠️ Total Vulnerabilities<\/th><td>(\d+)<\/td>/);
        expect(totalRowMatch).not.toBeNull();

        if (totalRowMatch) {
            const criticalCount = parseInt(totalRowMatch[1]);
            expect(criticalCount).toBe(2);
        }
    });
});
