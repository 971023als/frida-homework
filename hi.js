Java.perform(function () {
    console.log("고급 안티탬퍼링 모니터링 초기화 중...");

    // 지연 함수
    function randomDelay(min = 10, max = 50) {
        const delay = Math.floor(Math.random() * (max - min + 1)) + min;
        const start = Date.now();
        while (Date.now() - start < delay) {}
    }

    // 후킹 캐시 설정
    const interceptorCache = {};
    function attachInterceptor(libName, funcName, onEnterCallback) {
        const key = `${libName}:${funcName}`;
        if (interceptorCache[key]) return;

        const funcAddress = Module.findExportByName(libName, funcName);
        if (funcAddress) {
            Interceptor.attach(funcAddress, {
                onEnter: function (args) {
                    randomDelay();
                    try {
                        onEnterCallback.call(this, args);
                    } catch (e) {
                        console.log(`[오류] ${funcName} 함수 호출 중 접근 위반 오류 발생: ${e.message}`);
                    }
                }
            });
            interceptorCache[key] = true;
        } else {
            console.log(`[오류] ${libName}에서 ${funcName} 함수를 찾을 수 없습니다.`);
        }
    }

    // 메모리 보호 후킹 설정
    function setupMemoryProtectionHooks() {
        console.log("메모리 보호 후킹 설정 중...");
        attachInterceptor("libc.so", "mmap", function (args) {
            const size = args[1].toInt32();
            const prot = args[2].toInt32();
            if (size < 1024000 && (prot === 3 || prot === 7)) {
                console.log(`mmap 호출됨 - 크기: ${size}, 보호: ${prot}`);
            }
        });

        attachInterceptor("libc.so", "mprotect", function (args) {
            const addr = args[0];
            const prot = args[2].toInt32();
            console.log(`mprotect 호출됨 - 주소: ${addr}, 보호: ${prot}`);
        });
        console.log("메모리 보호 후킹 설정 완료.");
    }

    // 파일 접근 리디렉션 설정
    function setupFileAccessRedirection() {
        console.log("파일 접근 리디렉션 설정 중...");
        attachInterceptor("libc.so", "open", function (args) {
            const fileName = args[0].isNull() ? "" : Memory.readCString(args[0]);
            if (fileName.includes("/proc/self/maps")) {
                console.log("/proc/self/maps 접근을 가짜 콘텐츠로 리디렉션 중.");
                this.isMaps = true;
            }
        });

        attachInterceptor("libc.so", "read", function (args) {
            if (this.isMaps) {
                console.log("가짜 /proc/self/maps 콘텐츠 반환 중.");
                const fakeContent = "00400000-00452000 r-xp 00000000 fd:01 123456 /system/bin/app_process32\n";
                Memory.writeUtf8String(args[1], fakeContent);
                args[2] = ptr(fakeContent.length);
            }
        });
        console.log("파일 접근 리디렉션 설정 완료.");
    }

    // 기기 속성 스푸핑
    function spoofDeviceProperties() {
        console.log("기기 속성 스푸핑 설정 중...");
        const Build = Java.use("android.os.Build");
        Build.MODEL.value = "SM-G977N";
        Build.MANUFACTURER.value = "Samsung";
        Build.BRAND.value = "samsung";
        console.log("삼성 기기처럼 보이도록 Build 속성 수정 완료");
    }

    // 루팅 및 프로세스 종료 방지 후킹
    function setupAntiTamperingHooks() {
        console.log("루팅 및 프로세스 종료 방지 후킹 설정 중...");

        try {
            const SystemClass = Java.use('java.lang.System');
            SystemClass.exit.implementation = function (code) {
                console.log("System.exit(" + code + ") 호출 차단됨");
            };
        } catch (e) {
            console.log("[경고] 'java.lang.System.exit' 메서드를 찾을 수 없습니다.");
        }

        try {
            const ProcessClass = Java.use('android.os.Process');
            ProcessClass.killProcess.implementation = function (pid) {
                console.log("Process.killProcess(" + pid + ") 호출 차단됨");
            };
        } catch (e) {
            console.log("[경고] 'android.os.Process.killProcess' 메서드를 찾을 수 없습니다.");
        }

        try {
            const V3MobilePlusCtlClass = Java.use('com.ahnlab.v3mobileplus.V3MobilePlusCtl');
            V3MobilePlusCtlClass.startRootcheck.implementation = function (arg) {
                console.log("루팅 검사 호출 무력화됨");
                return 0;
            };
        } catch (e) {
            console.log("[경고] 'com.ahnlab.v3mobileplus.V3MobilePlusCtl' 클래스가 존재하지 않거나 로드되지 않았습니다.");
        }

        try {
            const V3MobilePlusResultListenerClass = Java.use('com.ahnlab.v3mobileplus.interfaces.V3MobilePlusResultListener');
            V3MobilePlusResultListenerClass.OnV3MobilePlusStatus.implementation = function (status, message) {
                console.log(`OnV3MobilePlusStatus 호출됨: 상태 = ${status}, 메시지 = ${message}`);
                if (status !== 0) {
                    console.log("루팅 감지 무력화 처리");
                    return;
                }
                this.OnV3MobilePlusStatus(status, message);
            };
        } catch (e) {
            console.log("[경고] 'com.ahnlab.v3mobileplus.interfaces.V3MobilePlusResultListener' 클래스가 존재하지 않거나 로드되지 않았습니다.");
        }

        console.log("루팅 및 종료 방지 후킹 설정 완료.");
    }
});




