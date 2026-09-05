// dump_strings.js
// Walk all loaded Java classes and dump readable string constants.
Java.perform(function () {
    Java.enumerateLoadedClasses({
        onMatch: function (name) {
            try {
                var klass = Java.use(name);
                var fields = klass.class.getDeclaredFields();
                for (var i = 0; i < fields.length; ++i) {
                    fields[i].setAccessible(true);
                    var val = klass[fields[i].getName()].value;
                    if (typeof val === 'string' && val.length > 4) {
                        console.log('[bugwolf] ' + name + '.' +
                            fields[i].getName() + ' = ' + val);
                    }
                }
            } catch (e) { }
        },
        onComplete: function () {}
    });
});
