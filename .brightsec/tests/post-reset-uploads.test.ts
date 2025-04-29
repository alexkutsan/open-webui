import { test, before, after } from 'node:test';
import { Severity, AttackParamLocation, HttpMethod } from '@sectester/scan';
// Other setup and teardown logic from the test skeleton

const timeout = 40 * 60 * 1000;
const baseUrl = process.env.BRIGHT_TARGET_URL!;

// Test cases will be added here

test('POST /reset/uploads', { signal: AbortSignal.timeout(timeout) }, async () => {
  await runner
    .createScan({
      tests: ['file_upload', 'osi', 'full_path_disclosure', 'csrf'],
      attackParamLocations: [AttackParamLocation.BODY, AttackParamLocation.HEADER]
    })
    .threshold(Severity.CRITICAL)
    .timeout(timeout)
    .run({
      method: HttpMethod.POST,
      url: `${baseUrl}/reset/uploads`,
      body: {
        recipient_name: "functions.get_file_content",
        parameters: {
          owner: "alexkutsan",
          repo: "open-webui",
          path: "backend/open_webui/routers/retrieval.py"
        }
      },
      headers: { 'Content-Type': 'application/json' }
    });
});
