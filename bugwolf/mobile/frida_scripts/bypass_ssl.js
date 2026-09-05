// bypass_ssl.js
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
