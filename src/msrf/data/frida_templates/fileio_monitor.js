/*
 * msrf :: fileio-monitor
 * Logs file opens for read/write (insecure local storage discovery).
 */
Java.perform(function () {
    function log(m) { send({ tag: 'fileio-monitor', msg: m }); }
    try {
        var FOS = Java.use('java.io.FileOutputStream');
        FOS.$init.overload('java.io.File').implementation = function (f) {
            log('write open: ' + f.getAbsolutePath()); return this.$init(f);
        };
        var FIS = Java.use('java.io.FileInputStream');
        FIS.$init.overload('java.io.File').implementation = function (f) {
            log('read open: ' + f.getAbsolutePath()); return this.$init(f);
        };
    } catch (e) { log('hook skipped: ' + e); }
    log('File I/O monitor installed');
});
