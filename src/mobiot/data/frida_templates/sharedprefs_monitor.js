/*
 * mobiot :: sharedprefs-monitor
 * Logs SharedPreferences reads/writes (a common insecure-storage sink).
 */
Java.perform(function () {
    function log(m) { send({ tag: 'sharedprefs-monitor', msg: m }); }
    try {
        var Editor = Java.use('android.app.SharedPreferencesImpl$EditorImpl');
        ['putString', 'putInt', 'putBoolean', 'putLong', 'putFloat'].forEach(function (mth) {
            if (Editor[mth]) {
                Editor[mth].overloads.forEach(function (ov) {
                    ov.implementation = function (k, v) {
                        log('write ' + mth + '(' + k + ' = ' + v + ')');
                        return ov.call(this, k, v);
                    };
                });
            }
        });
        var Impl = Java.use('android.app.SharedPreferencesImpl');
        Impl.getString.implementation = function (k, d) {
            var v = this.getString(k, d); log('read getString(' + k + ') = ' + v); return v;
        };
    } catch (e) { log('hook skipped: ' + e); }
    log('SharedPreferences monitor installed');
});
