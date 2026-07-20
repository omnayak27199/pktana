/**
 * electron-builder afterPack hook.
 *
 * 1) Always copy the native pktana binary into the packaged app.
 *    (extraResources alone is not enough — electron-builder respects
 *    .gitignore, and resources/bin/pktana(.exe) is gitignored.)
 * 2) On macOS, ad-hoc codesign the .app + nested binary.
 */
const { execFileSync } = require('child_process');
const fs = require('fs');
const path = require('path');

function ensureDir(dir) {
  fs.mkdirSync(dir, { recursive: true });
}

function packagedResourcesDir(context) {
  if (context.electronPlatformName === 'darwin') {
    const appName = context.packager.appInfo.productFilename;
    return path.join(context.appOutDir, `${appName}.app`, 'Contents', 'Resources');
  }
  // win-unpacked / linux unpacked
  return path.join(context.appOutDir, 'resources');
}

function nativeBinaryName(platform) {
  return platform === 'win32' || platform === 'win' ? 'pktana.exe' : 'pktana';
}

exports.default = async function afterPack(context) {
  const projectDir = context.packager.projectDir;
  const platform = context.electronPlatformName; // 'darwin' | 'win32' | 'linux'
  const binName = nativeBinaryName(platform === 'win32' ? 'win32' : platform);
  const srcCandidates = [
    path.join(projectDir, 'resources', 'bin', binName),
    path.join(projectDir, 'resources', 'bin', 'pktana.exe'),
    path.join(projectDir, 'resources', 'bin', 'pktana'),
    path.join(projectDir, '..', 'target', 'release', binName),
    path.join(projectDir, '..', 'target', 'release', 'pktana.exe'),
    path.join(projectDir, '..', 'target', 'release', 'pktana'),
  ];

  const src = srcCandidates.find((p) => fs.existsSync(p));
  if (!src) {
    throw new Error(
      'Native pktana binary not found for packaging.\n' +
        'Build it first:\n' +
        '  cargo build --release --features pcap,tui -p pktana-cli\n' +
        '  copy into pktana-desktop/resources/bin/\n' +
        'Looked in:\n  - ' +
        srcCandidates.join('\n  - ')
    );
  }

  const destDir = path.join(packagedResourcesDir(context), 'bin');
  ensureDir(destDir);
  const dest = path.join(destDir, binName);
  fs.copyFileSync(src, dest);
  try {
    fs.chmodSync(dest, 0o755);
  } catch {
    /* windows may ignore chmod */
  }
  console.log(`Packaged native binary: ${src} -> ${dest}`);

  if (context.electronPlatformName !== 'darwin') {
    return;
  }

  const appName = context.packager.appInfo.productFilename;
  const appPath = path.join(context.appOutDir, `${appName}.app`);
  if (!fs.existsSync(appPath)) {
    console.warn('afterPack: app not found at', appPath);
    return;
  }

  console.log('Ad-hoc codesigning', appPath);
  execFileSync('codesign', ['--force', '--deep', '--sign', '-', appPath], {
    stdio: 'inherit',
  });

  if (fs.existsSync(dest)) {
    console.log('Ad-hoc codesigning nested binary', dest);
    execFileSync('codesign', ['--force', '--sign', '-', dest], {
      stdio: 'inherit',
    });
    execFileSync('codesign', ['--force', '--deep', '--sign', '-', appPath], {
      stdio: 'inherit',
    });
  }
};
