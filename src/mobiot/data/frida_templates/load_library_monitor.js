/*
 * mobiot :: load-library-monitor
 * Logs native library loads (System.loadLibrary / System.load).
 */
Java.perform(function () {
    function log(m) { send({ tag: 'load-library-monitor', msg: m }); }
    try {
        var System = Java.use('java.lang.System');
        System.loadLibrary.implementation = function (name) {
            log('System.loadLibrary("' + name + '")'); return this.loadLibrary(name);
        };
        System.load.implementation = function (path) {
            log('System.load("' + path + '")'); return this.load(path);
        };
    } catch (e) { log('hook skipped: ' + e); }
    log('Native library load monitor installed');
});
