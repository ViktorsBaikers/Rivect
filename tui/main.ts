import { lstatSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { runClient } from './modes';
import { installNativeGuard } from './native-guard';

declare const RIVECT_NATIVE_SHA256: string;
declare const RIVECT_NATIVE_BYTES: number;

installNativeGuard();

if (!process.stdin.isTTY || !process.stdout.isTTY) {
  process.stderr.write('interactive client requires a terminal\n');
  process.exitCode = 2;
} else if (typeof RIVECT_NATIVE_SHA256 !== 'undefined') {
  const ext = process.platform === 'darwin' ? '.dylib' : '.so';
  const library = join(dirname(process.execPath), 'libopentui' + ext);
  async function validLibrary() {
    const stat = lstatSync(library, {throwIfNoEntry: false});
    if (!stat?.isFile() || stat.size !== RIVECT_NATIVE_BYTES) return false;
    const bytes = await Bun.file(library).arrayBuffer();
    return new Bun.CryptoHasher('sha256').update(bytes).digest('hex') === RIVECT_NATIVE_SHA256;
  }
  if (await validLibrary()) {
    process.env.OPENTUI_LIB_PATH = library;
    await runClient(process.argv.slice(2));
  } else {
    process.stderr.write('installed renderer unavailable or invalid\n');
    process.exitCode = 1;
  }
} else {
  const {packageManager} = await Bun.file(join(import.meta.dir, 'package.json')).json();
  if (packageManager !== 'bun@' + Bun.version) throw new Error('development client requires ' + packageManager);
  await runClient(process.argv.slice(2));
}
export {};
