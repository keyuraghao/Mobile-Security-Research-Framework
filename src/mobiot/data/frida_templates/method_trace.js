/*
 * mobiot :: method-trace
 * Traces every overload of every method on {{CLASS}}, logging args + return.
 */
Java.perform(function () {
    var TARGET = '{{CLASS}}';
    function log(msg) { send({ tag: 'method-trace', msg: msg }); }

    try {
        var clazz = Java.use(TARGET);
        var methods = clazz.class.getDeclaredMethods();
        var hooked = 0;
        methods.forEach(function (m) {
            var name = m.getName();
            var overloads = clazz[name].overloads;
            overloads.forEach(function (ov) {
                ov.implementation = function () {
                    var args = [];
                    for (var i = 0; i < arguments.length; i++) {
                        args.push(String(arguments[i]));
                    }
                    var ret = ov.apply(this, arguments);
                    log(TARGET + '.' + name + '(' + args.join(', ') + ') = ' + ret);
                    return ret;
                };
                hooked++;
            });
        });
        log('Traced ' + hooked + ' method overloads on ' + TARGET);
    } catch (e) {
        log('Failed to trace ' + TARGET + ': ' + e);
    }
});
