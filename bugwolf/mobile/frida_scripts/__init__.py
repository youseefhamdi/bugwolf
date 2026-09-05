"""Frida script catalog marker."""

from bugwolf.mobile import SCHEMA as _PARENT

__all__ = ["_PARENT"]


# Embed scripts as string constants so they can be inspected and
# asserted against in tests without executing them.

BYPASS_SSL_JS = r"""// bypass_ssl.js
// Universal SSL pinning bypass using the trust manager hook.
// Load with: frida -U -f com.target.app -l bypass_ssl.js --no-pause
Java.perform(function () {
    var X509TrustManager = Java.use('javax.net.ssl.X509TrustManager');
    var SSLContext = Java.use('javax.net.ssl.SSLContext');

    // 1. Build a permissive trust manager that accepts every cert.
    var TrustManager = Java.registerClass({
        name: 'com.bugwolf.TrustAllManager',
        implements: [X509TrustManager],
        methods: {
            checkClientTrusted: function (chain, authType) { },
            checkServerTrusted: function (chain, authType) { },
            getAcceptedIssuers: function () { return []; }
        }
    });

    // 2. Override the default TrustManagerFactory.
    var TrustManagerFactory = Java.use('javax.net.ssl.TrustManagerFactory');
    TrustManagerFactory.getInstance.implementation = function (type) {
        var tmf = this.getInstance(type);
        var init = tmf.init.overload('java.security.KeyStore');
        init.implementation = function (ks) {
            // deliberately empty; we'll inject via init call below.
        };
        return tmf;
    };

    // 3. Force OkHttp to use the permissive trust manager.
    var OkHttpBuilder = Java.use('okhttp3.OkHttpClient$Builder');
    OkHttpBuilder.sslSocketFactory.overload(
        'javax.net.ssl.SSLSocketFactory', 'javax.net.ssl.X509TrustManager'
    ).implementation = function (factory, trustManager) {
        return this.sslSocketFactory(factory, TrustManager.$new());
    };

    console.log('[bugwolf] SSL pinning bypass installed');
});
"""

BYPASS_ROOT_JS = r"""// bypass_root.js
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
"""

HOOK_CRYPTO_JS = r"""// hook_crypto.js
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
"""

ENUMERATE_CLASSES_JS = r"""// enumerate_classes.js
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
"""

DUMP_STRINGS_JS = r"""// dump_strings.js
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
"""

INTERCEPT_NETWORK_JS = r"""// intercept_network.js
// Intercept OkHttp calls and log URLs / bodies.
Java.perform(function () {
    var RealInterceptorChain = Java.use('okhttp3.internal.http.RealInterceptorChain');
    if (RealInterceptorChain) {
        RealInterceptorChain.proceed.overload(
            'okhttp3.Request'
        ).implementation = function (req) {
            console.log('[bugwolf] OkHttp: ' + req.url().toString());
            return this.proceed(req);
        };
    }
});
"""

BYPASS_BIOMETRIC_JS = r"""// bypass_biometric.js
// Force BiometricPrompt to succeed.
Java.perform(function () {
    var BiometricPrompt = Java.use('androidx.biometric.BiometricPrompt$PromptInfo$Builder');
    if (BiometricPrompt) {
        BiometricPrompt.setNegativeButtonText.overload(
            'java.lang.CharSequence'
        ).implementation = function (text) {
            return this.setNegativeButtonText('Cancel');
        };
    }

    // Hook BiometricManager and force authentication success.
    var AuthCallback = Java.use('androidx.biometric.BiometricPrompt$AuthenticationCallback');
    AuthCallback.onAuthenticationSucceeded.overload(
        'androidx.biometric.BiometricPrompt$AuthenticationResult'
    ).implementation = function (result) {
        console.log('[bugwolf] biometric success injected');
        // Re-emit the callback.
        this.onAuthenticationSucceeded(result);
    };
});
"""

BYPASS_JAILBREAK_JS = r"""// bypass_jailbreak.js
// Bypass iOS jailbreak detection.
if (ObjC.available) {
    // 1. Hook canOpenURL to lie about Cydia.
    var canOpenURL = ObjC.classes.UIApplication['- canOpenURL:'];
    Interceptor.attach(canOpenURL.implementation, {
        onEnter: function (args) {
            var url = ObjC.Object(args[2]).toString();
            if (url.indexOf('cydia') !== -1 ||
                url.indexOf('sileo') !== -1) {
                args[2] = Memory.allocUtf8String('about:blank');
            }
        },
        onLeave: function (retval) {
            retval.replace(ptr(0));
        }
    });

    // 2. Hook NSFileManager.fileExistsAtPath for /Applications.
    var NSFileManager = ObjC.classes.NSFileManager;
    Interceptor.attach(NSFileManager['- fileExistsAtPath:'].implementation, {
        onEnter: function (args) {
            this.path = ObjC.Object(args[2]).toString();
        },
        onLeave: function (retval) {
            if (this.path.indexOf('/Applications') !== -1 ||
                this.path.indexOf('/private/var/lib/apt') !== -1) {
                retval.replace(ptr(0));
            }
        }
    });
}
"""

DUMP_KEYCHAIN_JS = r"""// dump_keychain.js
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
"""

HOOK_NATIVE_JS = r"""// hook_native.js
// Hook native library calls via dlsym / dlopen tracking.
Interceptor.attach(Module.findExportByName('libc.so', 'open'), {
    onEnter: function (args) {
        var path = args[0].readCString();
        if (path && path.indexOf('secret') !== -1) {
            console.log('[bugwolf] native open(' + path + ')');
        }
    }
});
"""