/*
 * mobiot :: logcat-monitor
 * Logs android.util.Log calls (apps often log secrets).
 */
Java.perform(function () {
    function log(m) { send({ tag: 'logcat-monitor', msg: m }); }
    try {
        var Log = Java.use('android.util.Log');
        ['d', 'e', 'i', 'v', 'w'].forEach(function (lvl) {
            Log[lvl].overload('java.lang.String', 'java.lang.String').implementation = function (tag, msg) {
                log(lvl.toUpperCase() + '/' + tag + ': ' + msg); return this[lvl](tag, msg);
            };
        });
    } catch (e) { log('hook skipped: ' + e); }
    log('Logcat monitor installed');
});
