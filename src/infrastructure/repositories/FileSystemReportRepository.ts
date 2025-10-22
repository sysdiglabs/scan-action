import * as core from '@actions/core';
import fs from 'fs';
import { Report } from '../entities/JsonScanResultV1';
import { IReportRepository } from '../../application/ports/IReportRepository';

export class FileSystemReportRepository implements IReportRepository {
  writeReport(report: Report): void {
    const reportData = JSON.stringify(report, null, 2);
    fs.writeFileSync("./report.json", reportData);
    core.setOutput("scanReport", "./report.json");
  }
}
