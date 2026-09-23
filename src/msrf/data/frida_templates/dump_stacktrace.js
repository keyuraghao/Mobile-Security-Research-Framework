/*
 * msrf :: dump-stacktrace
 * On calling a method, prints the Java call stack (understand call flow).
 */
Java.perform(function () {
    var TARGET = '{{CLASS}}';
    var METHOD = '{{METHOD}}';
    function log(m) { send({ tag: 'dump-stacktrace', msg: m }); }
    try {
        var clazz = Java.use(TARGET);
        clazz[METHOD].overloads.forEach(function (ov) {
            ov.implementation = function () {
                var ex = Java.use('java.lang.Exception').$new();
                var trace = Java.use('android.util.Log').getStackTraceString(ex);
                log('stack for ' + TARGET + '.' + METHOD + ':\n' + trace);
                return ov.apply(this, arguments);
            };
        });
        log('Stacktrace dumper armed on ' + TARGET + '.' + METHOD);
    } catch (e) { log('failed: ' + e); }
});
