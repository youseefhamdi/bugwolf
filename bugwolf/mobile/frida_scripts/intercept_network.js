// intercept_network.js
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
