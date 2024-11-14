Java.perform(function () {
    console.log("🛡️ 고급 보안 모니터링 및 디버깅 방지 설정 시작...");

    const DEBUG = false;
    const MAX_RETRY = 3;
    const RETRY_DELAY = 3000;

    const interceptorCache = {};
    const callCounts = {
        mmap성공: 0,
        mmap실패: 0,
        mprotect성공: 0,
        mprotect실패: 0,
        종료차단: 0,
        네이티브오류탐지: 0,
        후킹실패: 0
    };

    function attachInterceptor(libName, funcName, onEnterCallback) {
        const key = `${libName}:${funcName}`;
        if (interceptorCache[key]) return;

        const tryAttach = (retryCount) => {
            const funcAddress = Module.findExportByName(libName, funcName);
            if (funcAddress) {
                Interceptor.attach(funcAddress, {
                    onEnter(args) {
                        try {
                            onEnterCallback.call(this, args);
                        } catch (e) {
                            if (DEBUG) console.log(`⚠️ ${funcName} 예외 발생: ${e.message}`);
                        }
                    }
                });
                interceptorCache[key] = true;
                console.log(`✅ ${funcName} 후킹 성공.`);
            } else {
                if (DEBUG) console.log(`🚫 ${funcName} 후킹 실패 - 재시도 중 (${retryCount})`);
                callCounts.후킹실패++;
                if (retryCount < MAX_RETRY) {
                    setTimeout(() => tryAttach(retryCount + 1), RETRY_DELAY);
                }
            }
        };
        tryAttach(0);
    }

    function setupMemoryProtectionHooks() {
        console.log("🛡️ 메모리 보호 후킹 설정 중...");
        attachInterceptor("libc.so", "mmap", function (args) {
            const size = args[1].toInt32();
            const prot = args[2].toInt32();
            (size < 1024000 && (prot === 3 || prot === 7)) ? callCounts.mmap성공++ : callCounts.mmap실패++;
        });
        attachInterceptor("libc.so", "mprotect", function (args) {
            const prot = args[2].toInt32();
            (prot === 3 || prot === 7) ? callCounts.mprotect성공++ : callCounts.mprotect실패++;
        });
        console.log("🛡️ 메모리 보호 후킹 설정 완료.");
    }

    function preventProcessTermination() {
        console.log("🛡️ 프로세스 종료 방지 후킹 설정 중...");
        const funcNames = ["System.exit", "Process.killProcess", "Process.exit"];
        funcNames.forEach(funcName => {
            try {
                const [clazz, method] = funcName.split('.');
                const JavaClass = Java.use(`java.lang.${clazz}`);

                if (JavaClass[method]) {
                    JavaClass[method].implementation = function (code) {
                        console.log(`⛔️ ${funcName} 호출 차단. 종료 코드: ${code}`);
                        callCounts.종료차단++;
                    };
                    console.log(`✅ ${funcName} 후킹 성공`);
                } else {
                    if (DEBUG) console.log(`🚫 ${funcName} 메서드가 존재하지 않음`);
                }
            } catch (e) {
                if (DEBUG) console.log(`⚠️ ${funcName} 후킹 실패: ${e.message}`);
                callCounts.후킹실패++;
            }
        });
        
        // Activity.finish() 오버로드 후킹
        const Activity = Java.use("android.app.Activity");
        try {
            Activity.finish.overload().implementation = function () {
                console.log("⛔️ Activity.finish() 호출 차단");
                callCounts.종료차단++;
            };
            console.log("✅ Activity.finish() 후킹 성공");
        } catch (e) {
            if (DEBUG) console.log(`⚠️ Activity.finish() 후킹 실패: ${e.message}`);
        }

        try {
            Activity.finish.overload('int').implementation = function (code) {
                console.log(`⛔️ Activity.finish(int) 호출 차단. 종료 코드: ${code}`);
                callCounts.종료차단++;
            };
            console.log("✅ Activity.finish(int) 후킹 성공");
        } catch (e) {
            if (DEBUG) console.log(`⚠️ Activity.finish(int) 후킹 실패: ${e.message}`);
        }

        // 네이티브 종료 함수 후킹 추가
        console.log("🛡️ 네이티브 종료 함수 후킹 설정 중...");
        attachInterceptor("libc.so", "kill", function (args) {
            console.log(`⛔️ kill 호출 차단. PID: ${args[0]}, Signal: ${args[1]}`);
            callCounts.종료차단++;
            args[1] = 0;  // 신호를 0으로 변경하여 무력화
        });
        attachInterceptor("libc.so", "exit", function (args) {
            console.log("⛔️ exit 호출 차단");
            callCounts.종료차단++;
        });
        attachInterceptor("libc.so", "abort", function (args) {
            console.log("⛔️ abort 호출 차단");
            callCounts.종료차단++;
        });
        attachInterceptor("libc.so", "exitGroup", function (args) {
            console.log("⛔️ exitGroup 호출 차단");
            callCounts.종료차단++;
        });
        console.log("🛡️ 네이티브 종료 함수 후킹 설정 완료.");
        
        console.log("🛡️ 프로세스 종료 방지 후킹 설정 완료.");
    }

    // Anti-debugging, ptrace 무력화
    function disableAntiDebug() {
        try {
            attachInterceptor("libc.so", "ptrace", function (args) {
                console.log("⛔️ ptrace 호출 차단");
                callCounts.종료차단++;
                args[0] = 0;  // 무력화
            });
            console.log("🛡️ ptrace 후킹 성공");
        } catch (e) {
            if (DEBUG) console.log(`⚠️ ptrace 후킹 실패: ${e.message}`);
        }
    }

    function detectNativeLinkError() {
        try {
            const AuthManager = Java.use("com.ahnlab.v3mobileplus.interfaces.AuthManager");
            AuthManager.initAuth.overload("java.lang.String").implementation = function (param) {
                console.log("AuthManager.initAuth 호출 탐지, 무력화합니다.");
                callCounts.네이티브오류탐지++;
                return -1;
            };
            console.log("✅ 네이티브 오류 탐지 후킹 완료");
        } catch (e) {
            if (DEBUG) console.log("❌ 네이티브 오류 탐지 실패: " + e.message);
            callCounts.후킹실패++;
        }
    }

    // 메인 보안 우회 설정
    setupMemoryProtectionHooks();
    preventProcessTermination();
    disableAntiDebug();
    detectNativeLinkError();

    console.log("=== 모든 보안 우회 후킹 및 보호 패턴 적용 완료 ===");
});
