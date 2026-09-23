/*
 * msrf :: root-bypass
 * Defeats common Android root-detection strategies for authorised testing.
 */
Java.perform(function () {
    function log(msg) { send({ tag: 'root-bypass', msg: msg }); }

    var ROOT_FILES = ['/system/bin/su', '/system/xbin/su', '/sbin/su',
        '/system/app/Superuser.apk', '/system/bin/magisk', '/data/adb/magisk'];
    var ROOT_PACKAGES = ['com.topjohnwu.magisk', 'eu.chainfire.supersu',
        'com.noshufou.android.su'];

    // File existence checks.
    try {
        var File = Java.use('java.io.File');
        File.exists.implementation = function () {
            var path = this.getAbsolutePath();
            if (ROOT_FILES.indexOf(path) !== -1) {
                log('File.exists("' + path + '") -> false');
                return false;
            }
            return this.exists();
        };
    } catch (e) { log('File hook skipped: ' + e); }

    // Runtime.exec("su" / "which su") -> throw as if not found.
    try {
        var Runtime = Java.use('java.lang.Runtime');
        Runtime.exec.overload('java.lang.String').implementation = function (cmd) {
            if (cmd && (cmd.indexOf('su') !== -1 || cmd.indexOf('which') !== -1)) {
                log('Runtime.exec("' + cmd + '") blocked');
                return this.exec('echo');
            }
            return this.exec(cmd);
        };
    } catch (e) { /* ignore */ }

    // Installed root packages via PackageManager.
    try {
        var ApplicationPackageManager = Java.use('android.app.ApplicationPackageManager');
        ApplicationPackageManager.getPackageInfo.overload('java.lang.String', 'int')
            .implementation = function (pkg, flags) {
                if (ROOT_PACKAGES.indexOf(pkg) !== -1) {
                    log('Hiding root package ' + pkg);
                    throw Java.use('android.content.pm.PackageManager$NameNotFoundException').$new(pkg);
                }
                return this.getPackageInfo(pkg, flags);
            };
    } catch (e) { /* ignore */ }

    log('Root detection bypass installed');
});
