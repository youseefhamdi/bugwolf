// enumerate_classes.js
// Enumerate loaded classes that match a pattern.
Java.perform(function () {
    Java.enumerateLoadedClasses({
        onMatch: function (name) {
            if (name.indexOf('com.target') !== -1 ||
                name.indexOf('crypto') !== -1) {
                console.log('[bugwolf] ' + name);
            }
        },
        onComplete: function () {}
    });
});
