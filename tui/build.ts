import solid from '@opentui/solid/bun-plugin';
import { createHash } from 'node:crypto';
import { createReadStream } from 'node:fs';
import { dirname, join } from 'node:path';

const {packageManager} = await Bun.file('package.json').json();
if (packageManager !== 'bun@' + Bun.version) throw new Error('build requires ' + packageManager);

const ext = process.platform === 'darwin' ? 'dylib' : 'so';
const pkg = '@opentui/core-' + process.platform + '-' + process.arch;
const native = Bun.file(join(dirname(require.resolve(pkg)), 'libopentui.' + ext));
const digest = new Bun.CryptoHasher('sha256').update(await native.arrayBuffer()).digest('hex');
const result = await Bun.build({
  entrypoints: ['./main.ts'], target: 'bun', plugins: [solid], metafile: true,
  external: ['@opentui/core-darwin-*', '@opentui/core-linux-*', '@opentui/core-win32-*'],
  define: { RIVECT_NATIVE_SHA256: JSON.stringify(digest), RIVECT_NATIVE_BYTES: String(native.size) },
  compile: { outfile: 'build/rivect-tui', autoloadBunfig: false, autoloadDotenv: false },
});
if (!result.success) throw new AggregateError(result.logs, 'client build failed');
await Bun.write('build/libopentui.' + ext, native);
if (!result.metafile) throw new Error('missing compiler inventory');
const roots = new Set([dirname(require.resolve(pkg))]);
for (const output of Object.values(result.metafile.outputs)) {
  for (const input of Object.keys(output.inputs)) {
    const root = /^(.*\bnode_modules\/(?:@[^/]+\/)?[^/]+)\//u.exec(input)?.[1];
    if (root) roots.add(root);
  }
}
const packages = [];
for (const root of roots) {
  const {name, version, license} = await Bun.file(join(root, 'package.json')).json();
  packages.push({name, version, license});
}
const sha = createHash('sha256');
for await (const chunk of createReadStream('build/rivect-tui')) sha.update(chunk);
await Bun.write('build/ui-inventory.json', JSON.stringify({
  ui: sha.digest('hex'), library: digest, bun: Bun.version, packages,
}));
