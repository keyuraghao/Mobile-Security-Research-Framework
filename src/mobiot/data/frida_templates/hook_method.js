/*
 * mobiot :: hook-method
 * Hooks all overloads of {{CLASS}}.{{METHOD}}, logging arguments and return.
 */
Java.perform(function () {
    var TARGET = '{{CLASS}}';
    var METHOD = '{{METHOD}}';
    function log(msg) { send({ tag: 'hook-method', msg: msg }); }

    try {
        var clazz = Java.use(TARGET);
        var overloads = clazz[METHOD].overloads;
        overloads.forEach(function (ov) {
            ov.implementation = function () {
                var args = [];
                for (var i = 0; i < arguments.length; i++) {
                    args.push(String(arguments[i]));
                }
                log('CALL ' + TARGET + '.' + METHOD + '(' + args.join(', ') + ')');
                var ret = ov.apply(this, arguments);
                log('RET  ' + TARGET + '.' + METHOD + ' -> ' + ret);
                return ret;
            };
        });
        log('Hooked ' + overloads.length + ' overload(s) of ' + TARGET + '.' + METHOD);
    } catch (e) {
        log('Failed to hook ' + TARGET + '.' + METHOD + ': ' + e);
    }
});
