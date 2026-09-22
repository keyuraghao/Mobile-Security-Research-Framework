/*
 * mobiot :: clipboard-monitor
 * Logs clipboard writes (sensitive-data leakage vector).
 */
Java.perform(function () {
    function log(m) { send({ tag: 'clipboard-monitor', msg: m }); }
    try {
        var CM = Java.use('android.content.ClipboardManager');
        CM.setPrimaryClip.implementation = function (clip) {
            log('setPrimaryClip: ' + clip.toString()); return this.setPrimaryClip(clip);
        };
    } catch (e) { log('hook skipped: ' + e); }
    log('Clipboard monitor installed');
});
