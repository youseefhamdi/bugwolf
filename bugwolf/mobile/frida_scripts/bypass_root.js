// bypass_root.js
// Bypass common root-detection heuristics.
Java.perform(function () {
    var RootBeer = Java.use('com.scottyab.rootbeer.RootBeer');
    if (RootBeer) {
        RootBeer.isRooted.implementation = function () { return false; };
        RootBeer.detectRootCloakingApps.implementation = function () { return false; };
    }

    // Native: hook libc fopen to lie about /system/xbin/su
    var fopen = new NativeFunction(
        Module.findExportByName('libc.so', 'fopen'),
        'pointer', ['pointer', 'pointer']
    );
    Interceptor.replace(fopen, new NativeCallback(function (pathPtr, modePtr) {
        var path = pathPtr.readCString();
        if (path && path.indexOf('/su') !== -1) {
            return ptr(0);
        }
        return fopen(pathPtr, modePtr);
    }, 'pointer', ['pointer', 'pointer']));

    console.log('[bugwolf] root detection bypass installed');
});
