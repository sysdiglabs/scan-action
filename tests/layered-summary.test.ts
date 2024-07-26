import fs from "fs";


describe("layered summary", () => {

  beforeAll(async () => {
    await createReportFileIfNotExists();
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
