// bypass_jailbreak.js
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
