// dump_keychain.js
// Enumerate iOS keychain entries via SecItemCopyMatching.
if (ObjC.available) {
    var SecItemCopyMatching = new NativeFunction(
        Module.findExportByName('Security', 'SecItemCopyMatching'),
        'int', ['pointer', 'pointer']
    );
    var SecItemCopyMatchingRec = new NativeCallback(function (query, result) {
        var status = SecItemCopyMatching(query, result);
        if (status === 0 && !result.isNull()) {
            console.log('[bugwolf] keychain hit status=' + status);
        }
        return status;
    }, 'int', ['pointer', 'pointer']);
    Interceptor.replace(SecItemCopyMatching, SecItemCopyMatchingRec);
}
