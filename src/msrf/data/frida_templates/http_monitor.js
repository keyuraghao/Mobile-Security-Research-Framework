/*
 * msrf :: http-monitor
 * Logs outbound HTTP(S) requests (HttpURLConnection + OkHttp).
 */
Java.perform(function () {
    function log(m) { send({ tag: 'http-monitor', msg: m }); }
    try {
        var URL = Java.use('java.net.URL');
        URL.openConnection.overload().implementation = function () {
            log('openConnection: ' + this.toString()); return this.openConnection();
        };
    } catch (e) {}
    try {
        var Builder = Java.use('okhttp3.Request$Builder');
        Builder.url.overload('java.lang.String').implementation = function (u) {
            log('OkHttp request: ' + u); return this.url(u);
        };
    } catch (e) {}
    log('HTTP monitor installed');
});
