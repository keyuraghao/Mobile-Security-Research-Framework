/*
 * mobiot :: list-classes
 * Enumerates loaded Java classes whose name contains "{{FILTER}}".
 */
Java.perform(function () {
    var FILTER = '{{FILTER}}'.toLowerCase();
    function log(msg) { send({ tag: 'list-classes', msg: msg }); }

    var count = 0;
    Java.enumerateLoadedClasses({
        onMatch: function (name) {
            if (FILTER === '' || name.toLowerCase().indexOf(FILTER) !== -1) {
                log(name);
                count++;
            }
        },
        onComplete: function () {
            log('Enumeration complete: ' + count + ' matching class(es)');
        }
    });
});
