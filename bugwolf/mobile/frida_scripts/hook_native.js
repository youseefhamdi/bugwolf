// hook_native.js
// Hook native library calls via dlsym / dlopen tracking.
Interceptor.attach(Module.findExportByName('libc.so', 'open'), {
    onEnter: function (args) {
        var path = args[0].readCString();
        if (path && path.indexOf('secret') !== -1) {
            console.log('[bugwolf] native open(' + path + ')');
        }
    }
});
