const commonPaths = [
    "/data/local/bin/su",
    "/data/local/su",
    "/data/local/xbin/su",
    "/dev/com.koushikdutta.superuser.daemon/",
    "/sbin/su",
    "/system/app/Superuser.apk",
    "/system/bin/failsafe/su",
    "/system/bin/su",
    "/su/bin/su",
    "/system/etc/init.d/99SuperSUDaemon",
    "/system/sd/xbin/su",
    "/system/xbin/busybox",
    "/system/xbin/daemonsu",
    "/system/xbin/su",
    "/system/sbin/su",
    "/vendor/bin/su",
    "/cache/su",
    "/data/su",
    "/dev/su",
    "/system/bin/.ext/su",
    "/system/usr/we-need-root/su",
    "/system/app/Kinguser.apk",
    "/data/adb/magisk",
    "/sbin/.magisk",
    "/cache/.disable_magisk",
    "/dev/.magisk.unblock",
    "/cache/magisk.log",
    "/data/adb/magisk.img",
    "/data/adb/magisk.db",
    "/data/adb/magisk_simple",
    "/init.magisk.rc",
    "/system/xbin/ku.sud",
    "/data/adb/ksu",
    "/data/adb/ksud"
];

const ROOTmanagementApp = [
    "com.noshufou.android.su",
    "com.noshufou.android.su.elite",
    "eu.chainfire.supersu",
    "com.koushikdutta.superuser",
    "com.thirdparty.superuser",
    "com.yellowes.su",
    "com.koushikdutta.rommanager",
    "com.koushikdutta.rommanager.license",
    "com.dimonvideo.luckypatcher",
    "com.chelpus.lackypatch",
    "com.ramdroid.appquarantine",
    "com.ramdroid.appquarantinepro",
    "com.topjohnwu.magisk",
    "me.weishu.kernelsu"
];



function stackTraceHere(isLog){
    var Exception = Java.use('java.lang.Exception');
    var Log = Java.use('android.util.Log');
    var stackinfo = Log.getStackTraceString(Exception.$new())
    if (isLog) {
        console.log(stackinfo)
    } else {
        return stackinfo
    }
}

function stackTraceNativeHere(isLog){
    var backtrace = Thread.backtrace(this.context, Backtracer.ACCURATE)
        .map(DebugSymbol.fromAddress)
        .join("\n\t");
    console.log(backtrace)
}

function bypassJavaFileCheck(){
    var UnixFileSystem = Java.use("java.io.UnixFileSystem")
    UnixFileSystem.checkAccess.implementation = function(file, access){

        var stack = stackTraceHere(false)

        const filename = file.getAbsolutePath();

        if (filename.indexOf("magisk") >= 0) {
            console.log("루팅 탐지 차단 - 파일 확인 : " + filename)
            return false;
        }

        if (commonPaths.indexOf(filename) >= 0) {
            console.log("루팅 탐지 차단 - 파일 확인 : " + filename)
            return false;
        }

        return this.checkAccess(file, access)
    }
}

function bypassNativeFileCheck(){
    var fopen = Module.findExportByName("libc.so", "fopen")
    Interceptor.attach(fopen, {
        onEnter: function(args){
            this.inputPath = args[0].readUtf8String()
        },
        onLeave: function(retval){
            if (retval.toInt32() != 0) {
                if (commonPaths.indexOf(this.inputPath) >= 0) {
                    console.log("루팅 탐지 차단 - fopen : " + this.inputPath)
                    retval.replace(ptr(0x0))
                }
            }
        }
    })

    var access = Module.findExportByName("libc.so", "access")
    Interceptor.attach(access, {
        onEnter: function(args){
            this.inputPath = args[0].readUtf8String()
        },
        onLeave: function(retval){
            if (retval.toInt32() == 0) {
                if (commonPaths.indexOf(this.inputPath) >= 0) {
                    console.log("루팅 탐지 차단 - access : " + this.inputPath)
                    retval.replace(ptr(-1))
                }
            }
        }
    })
}


function setProp(){
    var Build = Java.use("android.os.Build")
    var TAGS = Build.class.getDeclaredField("TAGS")
    TAGS.setAccessible(true)
    TAGS.set(null, "release-keys")

    var FINGERPRINT = Build.class.getDeclaredField("FINGERPRINT")
    FINGERPRINT.setAccessible(true)
    FINGERPRINT.set(null, "google/crosshatch/crosshatch:10/QQ3A.200805.001/6578210:user/release-keys")

    // Build.deriveFingerprint.inplementation = function(){
    //     var ret = this.deriveFingerprint() //이 함수는 리플렉션을 통해 호출할 수 없습니다
    //     console.log(ret)
    //     return ret
    // }

    var system_property_get = Module.findExportByName("libc.so", "__system_property_get")
    Interceptor.attach(system_property_get, {
        onEnter(args) {
            this.key = args[0].readCString()
            this.ret = args[1]
        },
        onLeave(ret) {
            if (this.key == "ro.build.fingerprint") {
                var tmp = "google/crosshatch/crosshatch:10/QQ3A.200805.001/6578210:user/release-keys"
                var p = Memory.allocUtf8String(tmp)
                Memory.copy(this.ret, p, tmp.length + 1)
            }
        }
    })
}

//android.app.PackageManager
function bypassRootAppCheck(){
    var ApplicationPackageManager = Java.use("android.app.ApplicationPackageManager")
    ApplicationPackageManager.getPackageInfo.overload('java.lang.String', 'int').implementation = function(str, i){
        // console.log(str)
        if (ROOTmanagementApp.indexOf(str) >= 0) {
            console.log("루팅 탐지 차단 - 패키지 확인 : " + str)
            str = "ashen.one.ye.not.found" // 존재하지 않는 패키지로 설정
        }
        return this.getPackageInfo(str, i)
    }

    // shell pm 확인
}


function bypassShellCheck(){
    var String = Java.use('java.lang.String')

    var ProcessImpl = Java.use("java.lang.ProcessImpl")
    ProcessImpl.start.implementation = function(cmdarray, env, dir, redirects, redirectErrorStream){

        if (cmdarray[0] == "mount") {
            console.log("루팅 탐지 차단 - 쉘 명령어 : " + cmdarray.toString())
            arguments[0] = Java.array('java.lang.String', [String.$new("")])
            return ProcessImpl.start.apply(this, arguments)
        }

        if (cmdarray[0] == "getprop") {
            console.log("루팅 탐지 차단 - 쉘 명령어 : " + cmdarray.toString())
            const prop = [
                "ro.secure",
                "ro.debuggable"
            ];
            if (prop.indexOf(cmdarray[1]) >= 0) {
                arguments[0] = Java.array('java.lang.String', [String.$new("")])
                return ProcessImpl.start.apply(this, arguments)
            }
        }

        if (cmdarray[0].indexOf("which") >= 0) {
            const prop = [
                "su"
            ];
            if (prop.indexOf(cmdarray[1]) >= 0) {
                console.log("루팅 탐지 차단 - 쉘 명령어 : " + cmdarray.toString())
                arguments[0] = Java.array('java.lang.String', [String.$new("")])
                return ProcessImpl.start.apply(this, arguments)
            }
        }

        return ProcessImpl.start.apply(this, arguments)
    }
}


console.log("Attach")
bypassNativeFileCheck()
bypassJavaFileCheck()
setProp()
bypassRootAppCheck()
bypassShellCheck()
Java.perform(function () {
    try {
        // `s.a.C0081a` 클래스에서 `invoke` 메서드를 후킹
        var AntiTamperClass = Java.use('ba.s$a$C0081a');
        AntiTamperClass.invoke.implementation = function(z10) {
            console.log("[*] 무결성 검사 invoke 호출 인터셉트.");
            // 항상 true로 설정하여 안전한 상태로 처리
            return this.invoke(true);
        };
        console.log("[+] 무결성 검사 invoke 메서드 후킹 성공.");

        // `s.a.b` 클래스에서 `m4invoke` 메서드를 후킹
        var RootCheckClass = Java.use('ba.s$a$b');
        RootCheckClass.m4invoke.implementation = function() {
            console.log("[*] 루팅 검사 invoke 호출 인터셉트.");
            // 루팅 체크를 무시하도록 설정
        };
        console.log("[+] 루팅 검사 invoke 메서드 후킹 성공.");

    } catch (error) {
        console.log("[-] 메서드 후킹 오류: " + error);
    }
});

Java.perform(function () {
    try {
        var sClass = Java.use('ca.s');

        sClass.D.implementation = function (sVar, view) {
            console.log("[*] 메서드 D 호출 인터셉트.");

            // `sVar`이 올바른 인스턴스인지 확인
            if (sVar) {
                console.log("[*] 유효한 인스턴스 발견, h() 호출 시도.");

                // h() 메서드 호출
                var hInstance = sVar.h();
                if (hInstance) {
                    console.log("[*] h 인스턴스 발견, dismiss 실행 중...");
                    hInstance.dismiss();
                } else {
                    console.log("[-] h 인스턴스 발견되지 않음, dismiss 호출되지 않음.");
                }
            } else {
                console.log("[-] sVar 인스턴스가 유효하지 않습니다.");
            }
        };

        console.log("[+] 클래스 s의 메서드 D 후킹 성공.");
    } catch (error) {
        console.log("[-] 메서드 D 후킹 오류: " + error);
    }
});

Java.perform(function () {
    Java.enumerateLoadedClasses({
        onMatch: function (className) {
            if (className.includes("ba.s$a$C0081a")) {
                console.log("[+] 클래스 발견: ", className);
            }
        },
        onComplete: function () {
            console.log("[*] 클래스 열거 완료.");
        }
    });
});
