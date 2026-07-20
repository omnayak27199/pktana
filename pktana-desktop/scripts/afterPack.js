/**
 * electron-builder afterPack hook.
 * Ad-hoc codesign the .app so macOS is less likely to report it as "damaged"
 * when opened from a downloaded DMG/ZIP (Gatekeeper quarantine still needs
 * `xattr -cr` for fully unsigned builds without Apple notarization).
 */
const { execFileSync } = require('child_process');
const fs = require('fs');
const path = require('path');

exports.default = async function afterPack(context) {
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

  const nestedBin = path.join(appPath, 'Contents', 'Resources', 'bin', 'pktana');
  if (fs.existsSync(nestedBin)) {
    console.log('Ad-hoc codesigning nested binary', nestedBin);
    execFileSync('codesign', ['--force', '--sign', '-', nestedBin], {
      stdio: 'inherit',
    });
    execFileSync('codesign', ['--force', '--deep', '--sign', '-', appPath], {
      stdio: 'inherit',
    });
  }
};
