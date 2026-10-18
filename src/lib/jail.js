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

// APFS is case-insensitive by default and realpath does not reliably return
// canonical case, so on macOS the prefix compare folds case. Over-strict on
// a case-sensitive volume (a look-alike sibling is denied too): safe side.
const CASE_FOLD = process.platform === 'darwin';
function insideRoot(real, realRoot) {
  let a = real, b = realRoot;
  if (CASE_FOLD) { a = a.toLowerCase(); b = b.toLowerCase(); }
  const prefix = b === path.parse(b).root ? b : b + path.sep;
  return a === b || a.startsWith(prefix);
}

// Resolve `target` against `roots` (array of absolute real paths).
// Relative paths resolve against `anchor` (the workspace root), never the
// process cwd. opts.installDir + opts.workspaceRoot: anything inside the
// bridge's own install dir that is NOT the workspace is always denied, so a
// read root of $HOME can never expose secrets/, approvals/, or logs/.
// Returns { real, root } or throws JailError.
function resolveInRoots(target, roots, anchor, opts = {}) {
  if (typeof target !== 'string' || target.length === 0) throw new JailError('empty path');
  if (target.includes('\0')) throw new JailError('NUL in path');
  const expanded = target.replace(/^~(?=$|\/)/, os.homedir());
  const abs = path.isAbsolute(expanded) ? path.resolve(expanded) : path.resolve(anchor || roots[0], expanded);

  // Walk up to the deepest existing ancestor (lstat, so a dangling symlink
  // counts as existing); resolve it for real, then re-append the
  // non-existing tail lexically. Guards writes to new files.
  let cur = abs;
  const tail = [];
  for (;;) {
    try { fs.lstatSync(cur); break; } catch {}
    const parent = path.dirname(cur);
    if (parent === cur) break; // reached filesystem root without existing
    tail.unshift(path.basename(cur));
    cur = parent;
  }
  const realAncestor = realpathOrSelf(cur);
  const real = path.join(realAncestor, ...tail);

  for (const root of roots) {
    const realRoot = realpathOrSelf(root);
    if (insideRoot(real, realRoot)) {
      if (opts.installDir && opts.workspaceRoot) {
        const inst = realpathOrSelf(opts.installDir);
        const ws = realpathOrSelf(opts.workspaceRoot);
        if (insideRoot(real, inst) && !insideRoot(real, ws)) {
          throw new JailError('bridge state is not agent-visible: ' + target);
        }
      }
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

// Open with symlink-race hardening: lstat the path, open with O_NOFOLLOW,
// then verify the opened fd is the same inode the lstat saw. Narrows the
// check-to-open window to "must swap twice, timed to the nanosecond".
function safeOpen(real, flags, mode) {
  const NOFOLLOW = fs.constants.O_NOFOLLOW || 0;
  let before = null;
  try { before = fs.lstatSync(real); } catch (e) { if (e.code !== 'ENOENT') throw e; }
  const fd = fs.openSync(real, flags | NOFOLLOW, mode);
  try {
    const after = fs.fstatSync(fd);
    if (before && (before.dev !== after.dev || before.ino !== after.ino)) {
      throw new JailError('path changed during open (race) - refusing');
    }
    if (after.nlink > 1 && (flags & (fs.constants.O_WRONLY | fs.constants.O_RDWR))) {
      throw new JailError('hardlinked file - refusing to write through it');
    }
    return fd;
  } catch (e) { fs.closeSync(fd); throw e; }
}

module.exports = { JailError, resolveInRoots, assertRegularFileOrDir, realpathOrSelf, safeOpen, insideRoot };
