/*
 * mobiot :: base64-monitor
 * Logs android.util.Base64 encode/decode (often wraps secrets).
 */
Java.perform(function () {
    function log(m) { send({ tag: 'base64-monitor', msg: m }); }
    try {
        var B64 = Java.use('android.util.Base64');
        B64.encodeToString.overload('[B', 'int').implementation = function (data, flags) {
            var out = this.encodeToString(data, flags); log('encodeToString -> ' + out); return out;
        };
        B64.decode.overload('java.lang.String', 'int').implementation = function (s, flags) {
            log('decode("' + s + '")'); return this.decode(s, flags);
        };
    } catch (e) { log('hook skipped: ' + e); }
    log('Base64 monitor installed');
});
