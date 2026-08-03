import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { parsePEM } from '../src/utils/asn1';

const fixturesDir = join(dirname(fileURLToPath(import.meta.url)), 'fixtures');

export function loadFixture(name: string): string {
  return readFileSync(join(fixturesDir, name), 'utf8');
}

export function loadFixtureDER(name: string): Uint8Array {
  const pem = loadFixture(name);
  const blocks = parsePEM(pem);
  if (blocks.length === 0) throw new Error(`No PEM block found in ${name}`);
  return blocks[0].der;
}
