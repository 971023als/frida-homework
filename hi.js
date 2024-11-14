Java.perform(function () {
    console.log("🛡️ 고급 보안 모니터링 및 디버깅 방지 설정 시작...");

    const interceptorCache = {};
    const callCounts = {
        mmap성공: 0,
        mmap실패: 0,
        mprotect성공: 0,
        mprotect실패: 0,
        종료차단: 0,
        재시도횟수: 0,
        네이티브오류탐지: 0
    };

    function attachInterceptor(libName, funcName, onEnterCallback, onLeaveCallback = null) {
        try {
            const key = `${libName}:${funcName}`;
            if (interceptorCache[key]) return;

            const funcAddress = Module.findExportByName(libName, funcName);
            if (funcAddress) {
                Interceptor.attach(funcAddress, {
                    onEnter: function (args) {
                        try {
                            onEnterCallback.call(this, args);
                        } catch (e) {
                            console.log(`⚠️ 함수 호출 예외 발생 - ${funcName}: ${e.message}`);
                        }
                    },
                    onLeave: onLeaveCallback
                });
                interceptorCache[key] = true;
                console.log(`✅ ${funcName}에 대한 후킹이 성공적으로 설정되었습니다.`);
            } else {
                console.log(`🚫 ${libName}에서 ${funcName} 위치를 찾을 수 없습니다.`);
            }
        } catch (err) {
            console.log(`🚫 Interceptor 초기화 실패 - ${funcName}: ${err.message}`);
        }
    }

    function enhancedRetryHandler(funcName, retryFunc, retryCount = 0, maxRetries = 3) {
        if (retryCount < maxRetries) {
            setTimeout(() => {
                console.log(`⚠️ ${funcName} 후킹 재시도: ${retryCount + 1}/${maxRetries}`);
                retryFunc();
                enhancedRetryHandler(funcName, retryFunc, retryCount + 1, maxRetries);
            }, 2000);
        } else {
            console.log(`❌ ${funcName} 후킹 실패 - 최대 재시도 한도 도달`);
        }
    }

    function setupMemoryProtectionHooks() {
        console.log("🛡️ 메모리 보호 후킹 설정 중...");
        attachInterceptor("libc.so", "mmap", function (args) {
            const size = args[1].toInt32();
            const prot = args[2].toInt32();
            if (size < 1024000 && (prot === 3 || prot === 7)) {
                callCounts.mmap성공++;
            } else {
                callCounts.mmap실패++;
            }
        });

        attachInterceptor("libc.so", "mprotect", function (args) {
            const prot = args[2].toInt32();
            if (prot === 3 || prot === 7) {
                callCounts.mprotect성공++;
            } else {
                callCounts.mprotect실패++;
            }
        }, function () {
            console.log("🛡️ mprotect 호출 후 종료 상태를 감시 중...");
        });
        console.log("🛡️ 메모리 보호 후킹 설정 완료.");
    }

    function spoofDeviceProperties() {
        console.log("📱 기기 속성 스푸핑 설정 중...");
        const Build = Java.use("android.os.Build");
        Build.MODEL.value = "SM-G977N";
        Build.MANUFACTURER.value = "Samsung";
        Build.BRAND.value = "samsung";
        console.log("✅ 기기 속성이 스푸핑되었습니다.");
    }

    function preventProcessTermination() {
        console.log("🛡️ 프로세스 종료 방지 후킹 설정 중...");

        try {
            const System = Java.use("java.lang.System");
            System.exit.implementation = function (code) {
                console.log(`⛔️ System.exit 호출 차단. 종료 코드: ${code}`);
                callCounts.종료차단++;
            };
            console.log("✅ System.exit 후킹 성공");
        } catch (e) {
            enhancedRetryHandler("System.exit", preventProcessTermination);
        }

        try {
            const Process = Java.use("android.os.Process");
            Process.killProcess.implementation = function (pid) {
                console.log(`⛔️ Process.killProcess 호출 차단. 프로세스 ID: ${pid}`);
                callCounts.종료차단++;
            };
            Process.exit.implementation = function (code) {
                console.log(`⛔️ Process.exit 호출 차단. 종료 코드: ${code}`);
                callCounts.종료차단++;
            };
            console.log("✅ Process.killProcess 및 Process.exit 후킹 성공");
        } catch (e) {
            enhancedRetryHandler("Process.killProcess 및 Process.exit", preventProcessTermination);
        }

        ["exit", "_exit", "abort"].forEach(function (funcName) {
            attachInterceptor("libc.so", funcName, function () {
                console.log(`⛔️ Native ${funcName} 호출 차단. 호출 시간: ${new Date().toISOString()}`);
                callCounts.종료차단++;
            });
        });

        console.log("🛡️ 프로세스 종료 방지 후킹 설정 완료.");
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
            console.log("❌ 네이티브 오류 탐지 실패: " + e.message);
        }
    }

    function monitorHookStatus() {
        setInterval(function () {
            console.log("🔄 후킹 상태 모니터링 중...");
            if (!interceptorCache["libc.so:exit"]) {
                attachInterceptor("libc.so", "exit", function () {
                    console.log("⛔️ Native exit 재후킹 성공");
                });
            }
        }, 3000);
    }

    function logSummary() {
        console.log("=== 후킹 요약 ===");
        console.log(`🔹 mmap 성공: ${callCounts.mmap성공}`);
        console.log(`🔸 mmap 실패: ${callCounts.mmap실패}`);
        console.log(`🔹 mprotect 성공: ${callCounts.mprotect성공}`);
        console.log(`🔸 mprotect 실패: ${callCounts.mprotect실패}`);
        console.log(`⛔️ 프로세스 종료 차단: ${callCounts.종료차단}`);
        console.log(`🔄 종료 방지 재시도: ${callCounts.재시도횟수}`);
        console.log(`🛑 네이티브 오류 탐지: ${callCounts.네이티브오류탐지}`);
    }

    setupMemoryProtectionHooks();
    spoofDeviceProperties();
    preventProcessTermination();
    detectNativeLinkError();
    monitorHookStatus();

    logSummary();
    setInterval(logSummary, 5000);
    console.log("=== 모든 보안 우회 후킹 및 보호 패턴 적용 완료 ===");
});


