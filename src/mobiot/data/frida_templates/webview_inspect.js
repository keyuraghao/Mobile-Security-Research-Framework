/*
 * mobiot :: webview-inspect
 * Logs Android WebView navigation and JS evaluation calls.
 */
Java.perform(function () {
    function log(msg) { send({ tag: 'webview-inspect', msg: msg }); }

    try {
        var WebView = Java.use('android.webkit.WebView');

        WebView.loadUrl.overload('java.lang.String').implementation = function (url) {
            log('loadUrl: ' + url);
            return this.loadUrl(url);
        };
        WebView.loadData.overload('java.lang.String', 'java.lang.String', 'java.lang.String')
            .implementation = function (data, mime, enc) {
                log('loadData (' + mime + '): ' + data);
                return this.loadData(data, mime, enc);
            };
        WebView.evaluateJavascript.implementation = function (script, cb) {
            log('evaluateJavascript: ' + script);
            return this.evaluateJavascript(script, cb);
        };
        WebView.addJavascriptInterface.implementation = function (obj, name) {
            log('addJavascriptInterface: ' + name + ' (' + obj.getClass().getName() + ')');
            return this.addJavascriptInterface(obj, name);
        };
        log('WebView inspection installed');
    } catch (e) {
        log('WebView hook skipped: ' + e);
    }
});
