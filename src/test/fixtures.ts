import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';

const here = dirname(fileURLToPath(import.meta.url));
const projectRoot = resolve(here, '..', '..');

export function loadFixture(name: string): string {
  return readFileSync(resolve(projectRoot, 'test', 'fixtures', name), 'utf8');
}
