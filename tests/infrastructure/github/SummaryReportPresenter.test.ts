import { SummaryReportPresenter } from "../../../src/infrastructure/github/SummaryReportPresenter";
import { JsonScanResultV1ToScanResultAdapter } from "../../../src/infrastructure/sysdig/JsonScanResultV1ToScanResultAdapter";
import * as fs from "fs";
import * as core from "@actions/core";
import { Severity } from "../../../src/domain/scanresult/Severity";

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
});
