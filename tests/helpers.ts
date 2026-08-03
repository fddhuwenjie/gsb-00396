import { readFileSync } from 'node:fs';
import { parsePEM } from '../src/utils/asn1';

export function loadFixtureDer(name: string): Uint8Array {
  const url = new URL(`./fixtures/${name}`, import.meta.url);
  const pem = readFileSync(url, 'utf8');
  const blocks = parsePEM(pem);
  if (blocks.length === 0) throw new Error(`No PEM block found in fixture: ${name}`);
  return blocks[0].der;
}
