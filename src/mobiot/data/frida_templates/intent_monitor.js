/*
 * mobiot :: intent-monitor
 * Logs Intent creation and component navigation (IPC surface).
 */
Java.perform(function () {
    function log(m) { send({ tag: 'intent-monitor', msg: m }); }
    try {
        var Activity = Java.use('android.app.Activity');
        Activity.startActivity.overload('android.content.Intent').implementation = function (i) {
            log('startActivity: ' + i.toString()); return this.startActivity(i);
        };
    } catch (e) {}
    try {
        var Intent = Java.use('android.content.Intent');
        Intent.putExtra.overload('java.lang.String', 'java.lang.String').implementation = function (k, v) {
            log('Intent.putExtra(' + k + ' = ' + v + ')'); return this.putExtra(k, v);
        };
    } catch (e) {}
    log('Intent monitor installed');
});
