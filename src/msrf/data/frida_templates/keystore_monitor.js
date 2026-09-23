/*
 * msrf :: keystore-monitor
 * Logs Android KeyStore access (aliases, key operations).
 */
Java.perform(function () {
    function log(m) { send({ tag: 'keystore-monitor', msg: m }); }
    try {
        var KS = Java.use('java.security.KeyStore');
        KS.getKey.implementation = function (alias, pw) {
            log('KeyStore.getKey(alias=' + alias + ')'); return this.getKey(alias, pw);
        };
        KS.getCertificate.implementation = function (alias) {
            log('KeyStore.getCertificate(alias=' + alias + ')'); return this.getCertificate(alias);
        };
    } catch (e) { log('hook skipped: ' + e); }
    log('KeyStore monitor installed');
});
