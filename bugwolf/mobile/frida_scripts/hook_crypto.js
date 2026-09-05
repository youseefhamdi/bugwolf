// hook_crypto.js
// Hook javax.crypto.Cipher and SecretKeySpec.
Java.perform(function () {
    var Cipher = Java.use('javax.crypto.Cipher');
    Cipher.doFinal.overload('[B').implementation = function (data) {
        console.log('[bugwolf] Cipher.doFinal() input=' +
            Java.array('byte', data).toString());
        return this.doFinal(data);
    };
    Cipher.doFinal.overload('[B', 'int', 'int').implementation = function (data, off, len) {
        console.log('[bugwolf] Cipher.doFinal() in=' +
            Java.array('byte', data).slice(off, off + len));
        return this.doFinal(data, off, len);
    };

    var SecretKeySpec = Java.use('javax.crypto.spec.SecretKeySpec');
    SecretKeySpec.$init.overload('[B', 'java.lang.String').implementation = function (key, algo) {
        console.log('[bugwolf] SecretKeySpec algo=' + algo +
            ' key=' + Java.array('byte', key));
        return this.$init(key, algo);
    };
});
