/*
    Frida Script for Android Application Instrumentation
	------------ One Rule to Rule Them All -------------

    Description:
    This script dynamically instruments Android applications using Frida to bypass security checks,
    root detection, debugger detection, and alter network information.

    Functionalities:
    1. Bypasses security checks by returning fake values for settings providers.
    2. Masks root detection mechanisms in PackageManager and file existence checks.
    3. Prevents debugger detection by always returning false.
    4. Masks system properties related to root detection.
    5. Filters command execution to bypass root detection or return fake results.
    6. Modifies file read operations to replace test-keys with release-keys.
    7. Intercepts native functions like fopen and system to bypass root checks.
    8. Alters network information retrieval to simulate a connected LTE mobile network.
    9. Overrides network capabilities check to always indicate availability of mobile network.
	10. Bypass all ssl certificate

    Usage:
    - Run this script within a Frida environment targeting the Android application to be instrumented.
    - Adjust code as needed based on the specific context or changes in the target application.
	
	frida --codeshare h4rithd/onerule-by-h4rithd -f YOUR_BINARY
	frida -U -l onerule.js -f YOUR_BINARY

    Author: Harith Dilshan | h4rithd.com
    Date: 22-March-2024
*/

Java.perform(function() {
    var tries = 0;
    var maxTries = 5;
    var errDict = {};
    var timeout = 1000;
    var KeyInfo = null;
    var useKeyInfo = false;
    var RootPropertiesKeys = [];
    var useProcessManager = false;
    var TLSValidationDisabled = false;
    var flutterLibraryFound = false;
    var Debug = Java.use('android.os.Debug');
    var NativeFile = Java.use('java.io.File');
    var String = Java.use('java.lang.String');
    var Runtime = Java.use('java.lang.Runtime');
    var exec1 = Runtime.exec.overload('java.lang.String');
    var loaded_classes = Java.enumerateLoadedClassesSync();
    var BufferedReader = Java.use('java.io.BufferedReader');
    var exec = Runtime.exec.overload('[Ljava.lang.String;');
    var classa = Java.use("android.net.ConnectivityManager");
    var classb = Java.use("android.net.NetworkCapabilities");
    var ProcessBuilder = Java.use('java.lang.ProcessBuilder');
    var SystemProperties = Java.use('android.os.SystemProperties');
    var settingSecure = Java.use('android.provider.Settings$Secure');
    var settingGlobal = Java.use('android.provider.Settings$Global');
    var PackageManager = Java.use("android.app.ApplicationPackageManager");
    var exec2 = Runtime.exec.overload('java.lang.String', '[Ljava.lang.String;');
    var exec3 = Runtime.exec.overload('[Ljava.lang.String;', '[Ljava.lang.String;');
    var exec5 = Runtime.exec.overload('java.lang.String', '[Ljava.lang.String;', 'java.io.File');
    var exec4 = Runtime.exec.overload('[Ljava.lang.String;', '[Ljava.lang.String;', 'java.io.File');
    var RootBinaries = ["su", "busybox", "supersu", "Superuser.apk", "KingoUser.apk", "SuperSu.apk", "magisk"];
    var RootPackages = ["com.noshufou.android.su", "com.noshufou.android.su.elite", "eu.chainfire.supersu", "com.koushikdutta.superuser", "com.thirdparty.superuser", "com.yellowes.su", "com.koushikdutta.rommanager", "com.koushikdutta.rommanager.license", "com.dimonvideo.luckypatcher", "com.chelpus.lackypatch", "com.ramdroid.appquarantine", "com.ramdroid.appquarantinepro", "com.devadvance.rootcloak", "com.devadvance.rootcloakplus", "de.robv.android.xposed.installer", "com.saurik.substrate", "com.zachspong.temprootremovejb", "com.amphoras.hidemyroot", "com.amphoras.hidemyrootadfree", "com.formyhm.hiderootPremium", "com.formyhm.hideroot", "me.phh.superuser", "eu.chainfire.supersu.pro", "com.kingouser.com", "com.topjohnwu.magisk"];
    var RootProperties = {
        "ro.build.selinux": "1",
        "ro.debuggable": "0",
        "service.adb.root": "0",
        "ro.secure": "1"
    };

    var config = {
        "ios": {
            "modulename": "Flutter",
            "patterns": {
                "arm64": [
                    "FF 83 01 D1 FA 67 01 A9 F8 5F 02 A9 F6 57 03 A9 F4 4F 04 A9 FD 7B 05 A9 FD 43 01 91 F? 03 00 AA ?? 0? 40 F9 ?8 1? 40 F9 15 ?? 4? F9 B5 00 00 B4",
                    "FF 43 01 D1 F8 5F 01 A9 F6 57 02 A9 F4 4F 03 A9 FD 7B 04 A9 FD 03 01 91 F3 03 00 AA 14 00 40 F9 88 1A 40 F9 15 E9 40 F9 B5 00 00 B4 B6 46 40 F9"
                ],
            },
        },
        "android": {
            "modulename": "libflutter.so",
            "patterns": {
                "arm64": [
                    "F? 0F 1C F8 F? 5? 01 A9 F? 5? 02 A9 F? ?? 03 A9 ?? ?? ?? ?? 68 1A 40 F9",
                    "F? 43 01 D1 FE 67 01 A9 F8 5F 02 A9 F6 57 03 A9 F4 4F 04 A9 13 00 40 F9 F4 03 00 AA 68 1A 40 F9",
                    "FF 43 01 D1 FE 67 01 A9 ?? ?? 06 94 ?? 7? 06 94 68 1A 40 F9 15 15 41 F9 B5 00 00 B4 B6 4A 40 F9",
                ],
                "arm": [
                    "2D E9 F? 4? D0 F8 00 80 81 46 D8 F8 18 00 D0 F8 ??",
                ],
                "x64": [
                    "55 41 57 41 56 41 55 41 54 53 50 49 89 f? 4c 8b 37 49 8b 46 30 4c 8b a? ?? 0? 00 00 4d 85 e? 74 1? 4d 8b",
                    "55 41 57 41 56 41 55 41 54 53 48 83 EC 18 49 89 FF 48 8B 1F 48 8B 43 30 4C 8B A0 28 02 00 00 4D 85 E4 74",
                    "55 41 57 41 56 41 55 41 54 53 48 83 EC 38 C6 02 50 48 8B AF A? 00 00 00 48 85 ED 74 7? 48 83 7D 00 00 74"
                ]
            }
        }
    };

    function logError(err, targetClass, targetFunc) {
        console.log('Error intercepted:');
        console.log('Target class:', targetClass);
        console.log('Target function:', targetFunc);
        console.log('Error:', err);
    }

    function bypassPinning(targetClass, targetFunc, returnType) {
        try {
            var clazz = Java.use(targetClass);
            var func = clazz[targetFunc];
            var overloads = func.overloads;
            for (var i = 0; i < overloads.length; i++) {
                overloads[i].implementation = function() {
                    console.log('Bypassing pinning for:', targetClass + '.' + targetFunc);
                    if (returnType === 'boolean') {
                        return true;
                    } else {
                        return null;
                    }
                };
            }
        } catch (err) {
            errDict[err] = [targetClass, targetFunc];
            logError(err, targetClass, targetFunc);
        }
    }

    function bypassUnverifiedException() {
        var UnverifiedCertError = Java.use('javax.net.ssl.SSLPeerUnverifiedException');
        UnverifiedCertError.$init.implementation = function(reason) {
            try {
                var stackTrace = Java.use('java.lang.Thread').currentThread().getStackTrace();
                var exceptionStackIndex = stackTrace.findIndex(stack =>
                    stack.getClassName() === "javax.net.ssl.SSLPeerUnverifiedException"
                );
                var callingFunctionStack = stackTrace[exceptionStackIndex + 1];
                var className = callingFunctionStack.getClassName();
                var methodName = callingFunctionStack.getMethodName();
                var callingClass = Java.use(className);
                var callingMethod = callingClass[methodName];
                if (className == 'com.android.org.conscrypt.ActiveSession' || className == 'com.google.android.gms.org.conscrypt.ActiveSession') {
                    throw 'Reason: skipped SSLPeerUnverifiedException bypass since the exception was raised from a (usually) non-blocking method on the Android app';
                } else {
                    var retTypeName = callingMethod.returnType.type;
                    if (!(callingMethod.implementation)) {
                        callingMethod.implementation = function() {
                            if (retTypeName === 'boolean') {
                                return true;
                            } else {
                                return null;
                            }
                        }
                    }
                }
            } catch (err2) {
                if (String(err2).includes('.overload')) {
                    logError(err2, className, methodName);
                } else {
                    if (!String(err2).includes('SSLPeerUnverifiedException')) {
                        console.error(err2);
                    }
                }
            }
            return this.$init(reason);
        };
    }

    settingSecure.getInt.overload('android.content.ContentResolver', 'java.lang.String', 'int').implementation = function(cr, name, flag) {
        return 0;
    }
    settingSecure.getInt.overload('android.content.ContentResolver', 'java.lang.String').implementation = function(cr, name) {
        return 0;
    }
    settingGlobal.getInt.overload('android.content.ContentResolver', 'java.lang.String', 'int').implementation = function(cr, name, flag) {
        return 0;
    }
    settingGlobal.getInt.overload('android.content.ContentResolver', 'java.lang.String').implementation = function(cr, name) {
        return 0;
    }
    try {
        var Activity = Java.use("com.learnium.RNDeviceInfo.RNDeviceModule");
        Activity.isEmulator.implementation = function() {
            Promise.resolve(false)
        }
    } catch (error) {}
    Debug.isDebuggerConnected.implementation = function() {
        return false;
    }
    for (var k in RootProperties) RootPropertiesKeys.push(k);
    send("Loaded " + loaded_classes.length + " classes!");
    send("loaded: " + loaded_classes.indexOf('java.lang.ProcessManager'));
    if (loaded_classes.indexOf('java.lang.ProcessManager') != -1) {
        try {} catch (err) {
            send("ProcessManager Hook failed: " + err);
        }
    } else {
        send("ProcessManager hook not loaded");
    }
    if (loaded_classes.indexOf('android.security.keystore.KeyInfo') != -1) {
        try {} catch (err) {
            send("KeyInfo Hook failed: " + err);
        }
    } else {
        send("KeyInfo hook not loaded");
    }
    PackageManager.getPackageInfo.overload('java.lang.String', 'int').implementation = function(pname, flags) {
        var shouldFakePackage = (RootPackages.indexOf(pname) > -1);
        if (shouldFakePackage) {
            send("Bypass root check for package: " + pname);
            pname = "set.package.name.to.a.fake.one.so.we.can.bypass.it";
        }
        return this.getPackageInfo.overload('java.lang.String', 'int').call(this, pname, flags);
    };
    NativeFile.exists.implementation = function() {
        var name = NativeFile.getName.call(this);
        var shouldFakeReturn = (RootBinaries.indexOf(name) > -1);
        if (shouldFakeReturn) {
            send("Bypass return value for binary: " + name);
            return false;
        } else {
            return this.exists.call(this);
        }
    };
    exec5.implementation = function(cmd, env, dir) {
        if (cmd.indexOf("getprop") != -1 || cmd == "mount" || cmd.indexOf("build.prop") != -1 || cmd == "id" || cmd == "sh") {
            var fakeCmd = "grep";
            send("Bypass " + cmd + " command");
            return exec1.call(this, fakeCmd);
        }
        if (cmd == "su") {
            var fakeCmd = "h4rithd.com is here";
            send("Bypass " + cmd + " command");
            return exec1.call(this, fakeCmd);
        }
        return exec5.call(this, cmd, env, dir);
    };
    exec4.implementation = function(cmdarr, env, file) {
        for (var i = 0; i < cmdarr.length; i = i + 1) {
            var tmp_cmd = cmdarr[i];
            if (tmp_cmd.indexOf("getprop") != -1 || tmp_cmd == "mount" || tmp_cmd.indexOf("build.prop") != -1 || tmp_cmd == "id" || tmp_cmd == "sh") {
                var fakeCmd = "grep";
                send("Bypass " + cmdarr + " command");
                return exec1.call(this, fakeCmd);
            }
            if (tmp_cmd == "su") {
                var fakeCmd = "h4rithd.com is here";
                send("Bypass " + cmdarr + " command");
                return exec1.call(this, fakeCmd);
            }
        }
        return exec4.call(this, cmdarr, env, file);
    };
    exec3.implementation = function(cmdarr, envp) {
        for (var i = 0; i < cmdarr.length; i = i + 1) {
            var tmp_cmd = cmdarr[i];
            if (tmp_cmd.indexOf("getprop") != -1 || tmp_cmd == "mount" || tmp_cmd.indexOf("build.prop") != -1 || tmp_cmd == "id" || tmp_cmd == "sh") {
                var fakeCmd = "grep";
                send("Bypass " + cmdarr + " command");
                return exec1.call(this, fakeCmd);
            }
            if (tmp_cmd == "su") {
                var fakeCmd = "h4rithd.com is here";
                send("Bypass " + cmdarr + " command");
                return exec1.call(this, fakeCmd);
            }
        }
        return exec3.call(this, cmdarr, envp);
    };
    exec2.implementation = function(cmd, env) {
        if (cmd.indexOf("getprop") != -1 || cmd == "mount" || cmd.indexOf("build.prop") != -1 || cmd == "id" || cmd == "sh") {
            var fakeCmd = "grep";
            send("Bypass " + cmd + " command");
            return exec1.call(this, fakeCmd);
        }
        if (cmd == "su") {
            var fakeCmd = "h4rithd.com is here";
            send("Bypass " + cmd + " command");
            return exec1.call(this, fakeCmd);
        }
        return exec2.call(this, cmd, env);
    };
    exec.implementation = function(cmd) {
        for (var i = 0; i < cmd.length; i = i + 1) {
            var tmp_cmd = cmd[i];
            if (tmp_cmd.indexOf("getprop") != -1 || tmp_cmd == "mount" || tmp_cmd.indexOf("build.prop") != -1 || tmp_cmd == "id" || tmp_cmd == "sh") {
                var fakeCmd = "grep";
                send("Bypass " + cmd + " command");
                return exec1.call(this, fakeCmd);
            }
            if (tmp_cmd == "su") {
                var fakeCmd = "h4rithd.com is here";
                send("Bypass " + cmd + " command");
                return exec1.call(this, fakeCmd);
            }
        }
        return exec.call(this, cmd);
    };
    exec1.implementation = function(cmd) {
        if (cmd.indexOf("getprop") != -1 || cmd == "mount" || cmd.indexOf("build.prop") != -1 || cmd == "id" || cmd == "sh") {
            var fakeCmd = "grep";
            send("Bypass " + cmd + " command");
            return exec1.call(this, fakeCmd);
        }
        if (cmd == "su") {
            var fakeCmd = "h4rithd.com is here";
            send("Bypass " + cmd + " command");
            return exec1.call(this, fakeCmd);
        }
        return exec1.call(this, cmd);
    };
    String.contains.implementation = function(name) {
        if (name == "test-keys") {
            send("Bypass test-keys check");
            return false;
        }
        return this.contains.call(this, name);
    };

    var get = SystemProperties.get.overload('java.lang.String');
    get.implementation = function(name) {
        if (RootPropertiesKeys.indexOf(name) != -1) {
            send("Bypass " + name);
            return RootProperties[name];
        }
        return this.get.call(this, name);
    };
    Interceptor.attach(Module.findExportByName("libc.so", "fopen"), {
        onEnter: function(args) {
            var path = Memory.readCString(args[0]);
            path = path.split("/");
            var executable = path[path.length - 1];
            var shouldFakeReturn = (RootBinaries.indexOf(executable) > -1)
            if (shouldFakeReturn) {
                Memory.writeUtf8String(args[0], "/notexists");
                send("Bypass native fopen");
            }
        },
        onLeave: function(retval) {}
    });
    Interceptor.attach(Module.findExportByName("libc.so", "system"), {
        onEnter: function(args) {
            var cmd = Memory.readCString(args[0]);
            send("SYSTEM CMD: " + cmd);
            if (cmd.indexOf("getprop") != -1 || cmd == "mount" || cmd.indexOf("build.prop") != -1 || cmd == "id") {
                send("Bypass native system: " + cmd);
                Memory.writeUtf8String(args[0], "grep");
            }
            if (cmd == "su") {
                send("Bypass native system: " + cmd);
                Memory.writeUtf8String(args[0], "h4rithd.com is here");
            }
        },
        onLeave: function(retval) {}
    });
    BufferedReader.readLine.overload('boolean').implementation = function() {
        var text = this.readLine.overload('boolean').call(this);
        if (text === null) {} else {
            var shouldFakeRead = (text.indexOf("ro.build.tags=test-keys") > -1);
            if (shouldFakeRead) {
                send("Bypass build.prop file read");
                text = text.replace("ro.build.tags=test-keys", "ro.build.tags=release-keys");
            }
        }
        return text;
    };
    ProcessBuilder.start.implementation = function() {
        var cmd = this.command.call(this);
        var shouldModifyCommand = false;
        for (var i = 0; i < cmd.size(); i = i + 1) {
            var tmp_cmd = cmd.get(i).toString();
            if (tmp_cmd.indexOf("getprop") != -1 || tmp_cmd.indexOf("mount") != -1 || tmp_cmd.indexOf("build.prop") != -1 || tmp_cmd.indexOf("id") != -1) {
                shouldModifyCommand = true;
            }
        }
        if (shouldModifyCommand) {
            send("Bypass ProcessBuilder " + cmd);
            this.command.call(this, ["grep"]);
            return this.start.call(this);
        }
        if (cmd.indexOf("su") != -1) {
            send("Bypass ProcessBuilder " + cmd);
            this.command.call(this, ["h4rithd.com is here"]);
            return this.start.call(this);
        }
        return this.start.call(this);
    };
    if (useProcessManager) {
        var ProcManExec = ProcessManager.exec.overload('[Ljava.lang.String;', '[Ljava.lang.String;', 'java.io.File', 'boolean');
        var ProcManExecVariant = ProcessManager.exec.overload('[Ljava.lang.String;', '[Ljava.lang.String;', 'java.lang.String', 'java.io.FileDescriptor', 'java.io.FileDescriptor', 'java.io.FileDescriptor', 'boolean');
        ProcManExec.implementation = function(cmd, env, workdir, redirectstderr) {
            var fake_cmd = cmd;
            for (var i = 0; i < cmd.length; i = i + 1) {
                var tmp_cmd = cmd[i];
                if (tmp_cmd.indexOf("getprop") != -1 || tmp_cmd == "mount" || tmp_cmd.indexOf("build.prop") != -1 || tmp_cmd == "id") {
                    var fake_cmd = ["grep"];
                    send("Bypass " + cmdarr + " command");
                }
                if (tmp_cmd == "su") {
                    var fake_cmd = ["h4rithd.com is here"];
                    send("Bypass " + cmdarr + " command");
                }
            }
            return ProcManExec.call(this, fake_cmd, env, workdir, redirectstderr);
        };
        ProcManExecVariant.implementation = function(cmd, env, directory, stdin, stdout, stderr, redirect) {
            var fake_cmd = cmd;
            for (var i = 0; i < cmd.length; i = i + 1) {
                var tmp_cmd = cmd[i];
                if (tmp_cmd.indexOf("getprop") != -1 || tmp_cmd == "mount" || tmp_cmd.indexOf("build.prop") != -1 || tmp_cmd == "id") {
                    var fake_cmd = ["grep"];
                    send("Bypass " + cmdarr + " command");
                }
                if (tmp_cmd == "su") {
                    var fake_cmd = ["h4rithd.com is here"];
                    send("Bypass " + cmdarr + " command");
                }
            }
            return ProcManExecVariant.call(this, fake_cmd, env, directory, stdin, stdout, stderr, redirect);
        };
    };
    if (useKeyInfo) {
        KeyInfo.isInsideSecureHardware.implementation = function() {
            send("Bypass isInsideSecureHardware");
            return true;
        }
    };
    var networkInfo = classa.getActiveNetworkInfo;
    networkInfo.implementation = function(args) {
        var netInfo = networkInfo.call(this);
        var networkInfo_class = Java.use("android.net.NetworkInfo");
        var networkInfo2 = networkInfo_class.$new(0, 0, "MOBILE", "LTE");
        var netDetailedState = Java.use("android.net.NetworkInfo$DetailedState");
        networkInfo2.mIsAvailable.value = true;
        networkInfo2.setDetailedState(netDetailedState.CONNECTED.value, null, null);
        return networkInfo2;
    };

    var hasTransport = classb.hasTransport;
    hasTransport.implementation = function(args) {
        var oldResult = hasTransport.call(this, args);
        if (args == 0) {
            var newResult = true;
            return newResult;
        } else {
            return false;
        }
        return false;
    };

    function disableTLSValidation() {

        if (TLSValidationDisabled) return;

        tries++;
        if (tries > maxTries) {
            console.log('[!] Max attempts reached, stopping');
            return;
        }

        console.log(`[+] Attempting to find and hook ssl_verify_peer_cert (${tries}/${maxTries})`)

        var platformConfig = config[Java.available ? "android" : "ios"];
        var m = Process.findModuleByName(platformConfig["modulename"]);

        if (m === null) {
            console.log('[!] Flutter library not found');
            setTimeout(disableTLSValidation, timeout);
            return;
        } else {
            if (flutterLibraryFound == false) {
                flutterLibraryFound = true;
                tries = 1;
            }
        }

        if (Process.arch in platformConfig["patterns"]) {
            var ranges;
            if (Java.available) {
                ranges = Process.enumerateRanges({
                    protection: 'r-x'
                }).filter(isFlutterRange)

            } else {
                ranges = m.enumerateRanges('r-x')
            }

            findAndPatch(ranges, platformConfig["patterns"][Process.arch], Java.available && Process.arch == "arm" ? 1 : 0);
        } else {
            console.log('[!] Processor architecture not supported: ', Process.arch);
        }

        if (!TLSValidationDisabled) {
            if (tries < maxTries) {
                console.log(`[!] Flutter library found, but ssl_verify_peer_cert could not be found.`)
            } else {
                console.log('[!] ssl_verify_peer_cert not found.');
            }
        }
    }

    function findAndPatch(ranges, patterns, thumb) {

        ranges.forEach(range => {
            patterns.forEach(pattern => {
                var matches = Memory.scanSync(range.base, range.size, pattern);
                matches.forEach(match => {
                    var info = DebugSymbol.fromAddress(match.address)
                    console.log(`[+] ssl_verify_peer_cert found at offset: ${info.name}`);
                    TLSValidationDisabled = true;
                    hook_ssl_verify_peer_cert(match.address.add(thumb));
                    console.log('[+] ssl_verify_peer_cert has been patched')

                });
                if (matches.length > 1) {
                    console.log('[!] Multiple matches detected.')
                }
            });

        });

        setTimeout(disableTLSValidation, timeout);
    }

    function isFlutterRange(range) {
        var address = range.base
        var info = DebugSymbol.fromAddress(address)
        if (info.moduleName != null) {
            if (info.moduleName.toLowerCase().includes("flutter")) {
                return true;
            }
        }
        return false;
    }

    function hook_ssl_verify_peer_cert(address) {
        Interceptor.replace(address, new NativeCallback((pathPtr, flags) => {
            return 0;
        }, 'int', ['pointer', 'int']));
    }

    bypassPinning('javax.net.ssl.X509TrustManager', 'checkClientTrusted');
    bypassPinning('javax.net.ssl.X509TrustManager', 'checkServerTrusted');
    bypassPinning('okhttp3.CertificatePinner', 'check', 'void');
    bypassPinning('okhttp3.CertificatePinner', 'check', 'void');
    bypassPinning('okhttp3.CertificatePinner', 'check', 'void');

    disableTLSValidation();

    bypassUnverifiedException();

    for (var key in errDict) {
        var err = key;
        var targetClass = errDict[key][0];
        var targetFunc = errDict[key][1];
        logError(err, targetClass, targetFunc);
    }
});
Java.perform(() => {
    try {
        const PinActivity = Java.use("m.client.library.plugin.thirdparty.pin.activity.PinActivity");
        const BaseActivity = Java.use("android.app.Activity");

        function safeSuperCall(method, instance, ...args) {
            try {
                if (instance) {
                    method.apply(instance, args);
                    console.log(`[*] ${method.name} 호출 완료 in PinActivity`);
                } else {
                    console.log("[-] 인스턴스가 존재하지 않아 ${method.name} 호출 불가");
                }
            } catch (e) {
                console.error("[-] ${method.name} 호출 중 오류 발생:", e.message);
            }
        }

        // onCreate 후킹
        PinActivity.onCreate.implementation = function (savedInstanceState) {
            console.log("[*] PinActivity의 onCreate 메서드가 호출되었습니다.");
            safeSuperCall(BaseActivity.onCreate, this, savedInstanceState);

            console.log("[*] onCreate 완료: 현재 인증 상태");
            if (this.isAuthenticated !== undefined) console.log("  - isAuthenticated:", this.isAuthenticated.value);
            if (this.isVerified !== undefined) console.log("  - isVerified:", this.isVerified.value);
            if (this.isTransitionReady !== undefined) console.log("  - isTransitionReady:", this.isTransitionReady.value);
        };

        // onResume 후킹
        PinActivity.onResume.implementation = function () {
            console.log("[*] PinActivity의 onResume 메서드가 호출되었습니다.");
            safeSuperCall(BaseActivity.onResume, this);

            if (this.isAuthenticated !== undefined) {
                this.isAuthenticated.value = true;
                console.log("  - isAuthenticated 플래그 설정 완료:", this.isAuthenticated.value);
            }
            if (this.isVerified !== undefined) {
                this.isVerified.value = true;
                console.log("  - isVerified 플래그 설정 완료:", this.isVerified.value);
            }
            if (this.isTransitionReady !== undefined) {
                this.isTransitionReady.value = true;
                console.log("  - isTransitionReady 플래그 설정 완료:", this.isTransitionReady.value);
            }
            console.log("[*] onResume 완료: 인증 플래그 설정 후 상태");
        };

        console.log("[*] PinActivity의 onCreate 및 onResume 후킹 완료.");

        // mPinLockListener 후킹
        if (PinActivity.mPinLockListener && PinActivity.mPinLockListener.value) {
            const mPinLockListener = PinActivity.mPinLockListener.value;
            mPinLockListener.onComplete.implementation = function (inputPin) {
                console.log("[*] 핀 입력 감지됨:", inputPin);

                const Intent = Java.use("android.content.Intent");
                const resultIntent = Intent.$new();
                resultIntent.putExtra("KEY_RESULT", "SUCCESS");
                resultIntent.putExtra("Define.KEY_PIN", inputPin);

                this.setResult(PinActivity.REQUEST_AUTH.value, resultIntent);
                this.finish();
                console.log("[*] PIN 인증 우회 완료: SUCCESS 설정");
            };
            console.log("[*] mPinLockListener.onComplete 후킹 완료.");
        } else {
            console.log("[-] mPinLockListener가 초기화되지 않았습니다. 초기화를 시도합니다.");
            PinActivity.mPinLockListener.value = Java.registerClass({
                name: 'm.client.library.plugin.thirdparty.pin.activity.PinActivity$1',
                implements: [Java.use("com.andrognito.pinlockview.pin.PinLockListener")],
                methods: {
                    onComplete: function (inputPin) {
                        console.log("[*] mPinLockListener 초기화 후 PIN 입력 감지됨:", inputPin);
                    },
                    onEmpty: function () { },
                    onPinChange: function (pinLength, intermediatePin) { }
                }
            });
        }

    } catch (error) {
        console.error("[-] 후킹 오류:", error.message);
    }
});

// 네이티브 라이브러리 후킹
const nativeLibrary = Process.findModuleByName("libnative-lib.so");
if (nativeLibrary) {
    nativeLibrary.enumerateExports().forEach(symbol => {
        if (symbol.name.includes("authentication") || symbol.name.includes("verify")) {
            Interceptor.attach(symbol.address, {
                onEnter: function(args) {
                    console.log("[*] 네이티브 검증 함수 호출됨:", symbol.name);
                },
                onLeave: function(retval) {
                    console.log("[*] 검증 결과 반환 전 변경:", symbol.name);
                    retval.replace(1); // 성공으로 강제 설정
                }
            });
        }
    });
} else {
    console.log("[-] 네이티브 라이브러리 'libnative-lib.so'를 찾을 수 없습니다.");
}

// OkHttpClient 후킹
Java.perform(function() {
    const OkHttpClient = Java.use('okhttp3.OkHttpClient');
    const Response = Java.use('okhttp3.Response');
    const ResponseBody = Java.use('okhttp3.ResponseBody');

    OkHttpClient.newCall.overload('okhttp3.Request').implementation = function(request) {
        const response = this.newCall(request);

        response.enqueue.implementation = function(callback) {
            console.log("[*] 서버 요청 감지됨:", request.url().toString());

            const originalCallback = callback;

            const newCallback = Java.registerClass({
                name: 'com.example.MyCustomCallback',
                implements: [originalCallback.getClass().getInterfaces()[0]],
                methods: {
                    onResponse: function(call, response) {
                        const responseBody = response.body().string();
                        console.log("[*] 원래 서버 응답:", responseBody);

                        if (request.url().toString().includes("auth") || request.url().toString().includes("pin")) {
                            const modifiedResponseBody = "{ \"status\": \"success\" }";
                            const modifiedBody = ResponseBody.create(response.body().contentType(), modifiedResponseBody);
                            response = response.newBuilder().body(modifiedBody).build();
                            console.log("[*] 수정된 서버 응답:", modifiedResponseBody);
                        }

                        originalCallback.onResponse(call, response);
                    },
                    onFailure: function(call, e) {
                        originalCallback.onFailure(call, e);
                    }
                }
            });

            response.enqueue(newCallback.$new());
        };

        return response;
    };
});

Java.perform(() => {
    const PinActivity = Java.use("m.client.library.plugin.thirdparty.pin.activity.PinActivity");

    // onCreate 메서드가 호출되었을 때 인스턴스가 유효한지 확인
    PinActivity.onCreate.implementation = function (savedInstanceState) {
        console.log("[*] PinActivity의 onCreate 메서드가 호출되었습니다.");

        // onCreate 이후에 필드 접근 수행
        if (this && this.isAuthenticated !== undefined) {
            this.isAuthenticated.value = true;
            console.log("[*] isAuthenticated 필드 설정 완료:", this.isAuthenticated.value);
        } else {
            console.log("[-] 인스턴스 또는 필드가 유효하지 않음.");
        }
        this.onCreate(savedInstanceState);
    };
});


Java.perform(function () {
    const WNInterfaceThirdPartyPin = Java.use("m.client.library.plugin.thirdparty.pin.basic.WNInterfaceThirdPartyPin");

    WNInterfaceThirdPartyPin.onPluginActivityResult.overload('int', 'int', 'android.content.Intent').implementation = function (requestCode, resultCode, data) {
        console.log("[*] onPluginActivityResult 호출됨");

        // 강제로 인증 성공 상태로 설정
        if (data !== null) {
            data.putExtra("KEY_RESULT", "SUCCESS"); // 결과를 성공으로 설정
            console.log("[*] KEY_RESULT 값을 'SUCCESS'로 설정했습니다.");
        }
        
        // 원래의 메서드 호출
        this.onPluginActivityResult(requestCode, resultCode, data);
    };

    console.log("[*] WNInterfaceThirdPartyPin의 onPluginActivityResult 후킹 완료");
});

