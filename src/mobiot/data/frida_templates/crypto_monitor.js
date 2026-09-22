/*
 * mobiot :: crypto-monitor
 * Logs javax.crypto.Cipher operations: transformation, key and data.
 */
Java.perform(function () {
    function log(msg) { send({ tag: 'crypto-monitor', msg: msg }); }

    function bytesToHex(bytes) {
        if (bytes === null) { return 'null'; }
        var hex = '';
        for (var i = 0; i < bytes.length && i < 64; i++) {
            var b = (bytes[i] & 0xff).toString(16);
            hex += (b.length === 1 ? '0' : '') + b;
        }
        return hex + (bytes.length > 64 ? '...' : '');
    }

    try {
        var Cipher = Java.use('javax.crypto.Cipher');
        Cipher.getInstance.overload('java.lang.String').implementation = function (t) {
            log('Cipher.getInstance("' + t + '")');
            return this.getInstance(t);
        };
        Cipher.doFinal.overload('[B').implementation = function (data) {
            log('Cipher.doFinal input=' + bytesToHex(data));
            var out = this.doFinal(data);
            log('Cipher.doFinal output=' + bytesToHex(out));
            return out;
        };
    } catch (e) { log('Cipher hook skipped: ' + e); }

    try {
        var SecretKeySpec = Java.use('javax.crypto.spec.SecretKeySpec');
        SecretKeySpec.$init.overload('[B', 'java.lang.String').implementation = function (key, algo) {
            log('SecretKeySpec key=' + bytesToHex(key) + ' algo=' + algo);
            return this.$init(key, algo);
        };
    } catch (e) { /* ignore */ }

    log('Crypto monitor installed');
});
