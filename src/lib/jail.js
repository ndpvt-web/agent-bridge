'use strict';
// Filesystem jail: resolves a requested path to a real path guaranteed to be
// inside one of the allowed roots. Symlinks are resolved before the prefix
// check, so a symlink inside a root cannot point outside it.
const fs = require('fs');
const os = require('os');
const path = require('path');

class JailError extends Error {
  constructor(msg) { super(msg); this.code = 'EJAIL'; }
}

function realpathOrSelf(p) {
  try { return fs.realpathSync.native(p); } catch { return p; }
}

// Resolve `target` against `roots` (array of absolute real paths).
// Relative paths resolve against `anchor` (the workspace root), never the
// process cwd. Returns { real, root } or throws JailError.
function resolveInRoots(target, roots, anchor) {
  if (typeof target !== 'string' || target.length === 0) throw new JailError('empty path');
  if (target.includes('\0')) throw new JailError('NUL in path');
  const expanded = target.replace(/^~(?=$|\/)/, os.homedir());
  const abs = path.isAbsolute(expanded) ? path.resolve(expanded) : path.resolve(anchor || roots[0], expanded);

  // Walk up to the deepest existing ancestor; resolve it for real, then
  // re-append the non-existing tail lexically. Guards writes to new files.
  let cur = abs;
  const tail = [];
  while (!fs.existsSync(cur)) {
    const parent = path.dirname(cur);
    if (parent === cur) break; // reached filesystem root without existing
    tail.unshift(path.basename(cur));
    cur = parent;
  }
  const realAncestor = realpathOrSelf(cur);
  const real = path.join(realAncestor, ...tail);

  for (const root of roots) {
    const realRoot = realpathOrSelf(root);
    if (real === realRoot || real.startsWith(realRoot + path.sep)) {
      return { real, root: realRoot };
    }
  }
  throw new JailError('path outside allowed roots: ' + target);
}

function assertRegularFileOrDir(real) {
  const st = fs.lstatSync(real);
  if (st.isSymbolicLink()) throw new JailError('symlink not allowed at final component');
  if (!st.isFile() && !st.isDirectory()) throw new JailError('not a regular file or directory');
  return st;
}

module.exports = { JailError, resolveInRoots, assertRegularFileOrDir, realpathOrSelf };
