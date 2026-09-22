/*
 * mobiot :: sqlite-monitor
 * Logs SQLite queries/execSQL (data access + SQLi surface).
 */
Java.perform(function () {
    function log(m) { send({ tag: 'sqlite-monitor', msg: m }); }
    try {
        var DB = Java.use('android.database.sqlite.SQLiteDatabase');
        DB.execSQL.overload('java.lang.String').implementation = function (sql) {
            log('execSQL: ' + sql); return this.execSQL(sql);
        };
        DB.rawQuery.overload('java.lang.String', '[Ljava.lang.String;').implementation = function (sql, args) {
            log('rawQuery: ' + sql); return this.rawQuery(sql, args);
        };
    } catch (e) { log('hook skipped: ' + e); }
    log('SQLite monitor installed');
});
