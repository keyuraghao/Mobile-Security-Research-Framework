/*
 * mobiot :: anti-frida-bypass
 * Hides common Frida/debugger detection signals for authorised testing.
 */
Java.perform(function () {
    function log(m) { send({ tag: 'anti-frida-bypass', msg: m }); }
    try {
        var Debug = Java.use('android.os.Debug');
        Debug.isDebuggerConnected.implementation = function () {
            log('Debug.isDebuggerConnected -> false'); return false;
        };
    } catch (e) {}
    try {
        var File = Java.use('java.io.File');
        File.exists.implementation = function () {
            var p = this.getAbsolutePath();
            if (p.indexOf('frida') !== -1 || p.indexOf('/proc/') !== -1) {
                log('File.exists("' + p + '") -> false'); return false;
            }
            return this.exists();
        };
    } catch (e) {}
    try {
        var Runtime = Java.use('java.lang.Runtime');
        Runtime.exec.overload('java.lang.String').implementation = function (c) {
            if (c && (c.indexOf('frida') !== -1 || c.indexOf('ps') !== -1)) {
                log('Runtime.exec("' + c + '") blocked'); return this.exec('echo');
            }
            return this.exec(c);
        };
    } catch (e) {}
    log('Anti-Frida/debugger bypass installed');
});
