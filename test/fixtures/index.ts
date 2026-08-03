import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

// Resolve fixtures relative to this file so tests do not depend on the process
// working directory.
const fixturesDir = join(dirname(fileURLToPath(import.meta.url)), 'certs');

export function readFixture(name: string): string {
  return readFileSync(join(fixturesDir, name), 'utf8');
}
