/*
 * mobiot :: ssl-pinning-bypass
 * Neutralises common Android SSL/TLS certificate pinning implementations.
 * For AUTHORISED testing of apps you own or are permitted to assess only.
 */
Java.perform(function () {
    function log(msg) { send({ tag: 'ssl-pinning-bypass', msg: msg }); }

    // 1. Custom TrustManager (X509TrustManager) -> accept everything.
    try {
        var X509TrustManager = Java.use('javax.net.ssl.X509TrustManager');
        var SSLContext = Java.use('javax.net.ssl.SSLContext');
        var TrustManager = Java.registerClass({
            name: 'org.mobiot.TrustAll',
            implements: [X509TrustManager],
            methods: {
                checkClientTrusted: function () {},
                checkServerTrusted: function () {},
                getAcceptedIssuers: function () { return []; }
            }
        });
        var tms = [TrustManager.$new()];
        var init = SSLContext.init.overload(
            '[Ljavax.net.ssl.KeyManager;',
            '[Ljavax.net.ssl.TrustManager;',
            'java.security.SecureRandom');
        init.implementation = function (km, tm, sr) {
            log('SSLContext.init hooked -> trusting all certificates');
            init.call(this, km, tms, sr);
        };
    } catch (e) { log('TrustManager hook skipped: ' + e); }

    // 2. OkHttp CertificatePinner.check -> no-op.
    try {
        var CertificatePinner = Java.use('okhttp3.CertificatePinner');
        CertificatePinner.check.overload('java.lang.String', 'java.util.List')
            .implementation = function (host, peerCerts) {
                log('OkHttp CertificatePinner.check bypassed for ' + host);
                return;
            };
    } catch (e) { /* okhttp not present */ }

    // 3. TrustManagerImpl.verifyChain (Android N+) -> return the chain untouched.
    try {
        var TMImpl = Java.use('com.android.org.conscrypt.TrustManagerImpl');
        TMImpl.verifyChain.implementation = function (untrusted, trustAnchors, host, clientAuth, ocsp, tlsSct) {
            log('TrustManagerImpl.verifyChain bypassed for ' + host);
            return untrusted;
        };
    } catch (e) { /* not present */ }

    log('SSL pinning bypass installed');
});
