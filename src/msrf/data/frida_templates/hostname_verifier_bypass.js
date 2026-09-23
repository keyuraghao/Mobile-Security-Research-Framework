/*
 * msrf :: hostname-verifier-bypass
 * Forces HostnameVerifier to accept all hosts (TLS testing).
 */
Java.perform(function () {
    function log(m) { send({ tag: 'hostname-verifier-bypass', msg: m }); }
    try {
        var HttpsURLConnection = Java.use('javax.net.ssl.HttpsURLConnection');
        var Verifier = Java.registerClass({
            name: 'org.msrf.AllowAllHostnames',
            implements: [Java.use('javax.net.ssl.HostnameVerifier')],
            methods: { verify: function () { return true; } }
        });
        HttpsURLConnection.setDefaultHostnameVerifier(Verifier.$new());
        log('Default HostnameVerifier -> accept all');
    } catch (e) { log('hook skipped: ' + e); }
    log('Hostname verifier bypass installed');
});
