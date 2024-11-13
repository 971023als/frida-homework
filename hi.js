Java.perform(function () {
    console.log("고급 안티탬퍼링 모니터링 초기화 중...");

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

    function attachInterceptor(libName, funcName, onEnterCallback) {
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
                            console.log(`⚠️ 함수 호출 중 예외 발생 - ${funcName}: ${e.message}`);
                        }
                    }
                });
                interceptorCache[key] = true;
                console.log(`✅ ${funcName}에 대한 후킹이 성공적으로 완료되었습니다.`);
            } else {
                console.log(`🚫 ${libName} 라이브러리에서 ${funcName} 함수 위치를 찾을 수 없습니다.`);
            }
        } catch (err) {
            console.log(`🚫 Interceptor 초기화 실패 - ${funcName}: ${err.message}`);
        }
    }

    function setupMemoryProtectionHooks() {
        console.log("메모리 보호 후킹 설정 중...");
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
        });
        console.log("메모리 보호 후킹 설정 완료.");
    }

    function spoofDeviceProperties() {
        console.log("기기 속성 스푸핑 설정 중...");
        const Build = Java.use("android.os.Build");

        Build.MODEL.value = "SM-G977N";
        Build.MANUFACTURER.value = "Samsung";
        Build.BRAND.value = "samsung";

        console.log("✅ 기기 속성이 스푸핑되었습니다.");
    }

    function preventProcessTermination(retryLimit = 3) {
        console.log("프로세스 강제 종료 방지 후킹 설정 중...");

        try {
            const System = Java.use("java.lang.System");
            System.exit.implementation = function (code) {
                console.log(`⛔️ System.exit 호출이 무력화되었습니다. 종료 코드: ${code}`);
                callCounts.종료차단++;
            };
            console.log("✅ System.exit 후킹 성공");
        } catch (e) {
            handleRetry("System.exit", preventProcessTermination, retryLimit);
        }

        try {
            const Process = Java.use("android.os.Process");
            Process.killProcess.implementation = function (pid) {
                console.log(`⛔️ Process.killProcess 호출이 무력화되었습니다. 프로세스 ID: ${pid}`);
                callCounts.종료차단++;
            };
            Process.exit.implementation = function (code) {
                console.log(`⛔️ Process.exit 호출이 무력화되었습니다. 종료 코드: ${code}`);
                callCounts.종료차단++;
            };
            console.log("✅ Process.killProcess 및 Process.exit 후킹 성공");
        } catch (e) {
            handleRetry("Process.killProcess 및 Process.exit", preventProcessTermination, retryLimit);
        }

        ["exit", "_exit", "abort"].forEach(function (funcName) {
            attachInterceptor("libc.so", funcName, function (args) {
                console.log(`⛔️ Native ${funcName} 호출이 무력화되었습니다. 호출 시각: ${new Date().toISOString()}`);
                callCounts.종료차단++;
            });
        });

        console.log("프로세스 강제 종료 방지 후킹 설정 완료.");
    }

    function handleRetry(funcName, retryFunc, retryLimit) {
        callCounts.재시도횟수++;
        if (callCounts.재시도횟수 < retryLimit) {
            console.log(`⚠️ ${funcName} 후킹 실패: 재시도 중... (재시도 횟수: ${callCounts.재시도횟수}/${retryLimit})`);
            setTimeout(retryFunc, 2000);
        } else {
            console.log(`❌ ${funcName} 후킹 재시도 한도 초과 - 중단`);
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
            console.log("❌ 네이티브 오류 탐지 실패: " + e.message);
        }
    }

    function additionalHooks() {
        console.log("[*] 추가 후킹을 시작합니다.");

        try {
            const System = Java.use("java.lang.System");
            System.exit.implementation = function (code) {
                console.log("[*] System.exit() 호출을 무력화하였습니다!");
            };
            console.log("✅ System.exit 후킹 추가 완료");
        } catch (e) {
            console.log(`⚠️ System.exit 후킹 실패: ${e.message}`);
        }

        try {
            const TargetClass = Java.use("sg.vantagepoint.uncrackable1.a");
            TargetClass.a.implementation = function () {
                console.log("[*] 리턴 값을 true로 변경하였습니다.");
                return true;
            };
            console.log("✅ TargetClass.a 후킹 추가 완료");
        } catch (e) {
            console.log(`⚠️ TargetClass.a 후킹 실패: 클래스 'sg.vantagepoint.uncrackable1.a'를 찾을 수 없습니다.`);
        }
    }

    function logSummary() {
        console.log("=== 후킹 요약 ===");
        console.log(`🔹 mmap 호출 성공 횟수: ${callCounts.mmap성공}`);
        console.log(`🔸 mmap 호출 조건 불일치 횟수: ${callCounts.mmap실패}`);
        console.log(`🔹 mprotect 호출 성공 횟수: ${callCounts.mprotect성공}`);
        console.log(`🔸 mprotect 호출 조건 불일치 횟수: ${callCounts.mprotect실패}`);
        console.log(`⛔️ 프로세스 종료 차단 횟수: ${callCounts.종료차단}`);
        console.log(`🔄 종료 방지 재시도 횟수: ${callCounts.재시도횟수}`);
        console.log(`🛑 네이티브 오류 탐지 횟수: ${callCounts.네이티브오류탐지}`);
    }

    function saveLogToCSV() {
        const csvContent = `mmap성공, mmap실패, mprotect성공, mprotect실패, 종료차단, 재시도횟수, 네이티브오류탐지
${callCounts.mmap성공}, ${callCounts.mmap실패}, ${callCounts.mprotect성공}, ${callCounts.mprotect실패}, ${callCounts.종료차단}, ${callCounts.재시도횟수}, ${callCounts.네이티브오류탐지}`;

        const fs = require("fs");
        const csvFile = "/sdcard/hook_log.csv";

        try {
            fs.writeFileSync(csvFile, csvContent, { encoding: "utf-8" });
            console.log(`🔖 후킹 요약이 CSV 파일(${csvFile})로 저장되었습니다.`);
        } catch (e) {
            console.log(`⚠️ CSV 저장 실패: ${e.message}`);
        }
    }

    setupMemoryProtectionHooks();
    spoofDeviceProperties();
    preventProcessTermination();
    detectNativeLinkError();
    additionalHooks();
    console.log("고급 안티탬퍼링 모니터링이 성공적으로 초기화되었습니다.");

    console.log("EmulatorDetectionActivity 후킹 시작");
    try {
        const EmulatorDetectionActivity = Java.use("owasp.sat.agoat.EmulatorDetectionActivity");
        EmulatorDetectionActivity.isEmulator.implementation = function () {
            console.log("에뮬레이터 감지가 무력화되었습니다!");
            return true;
        };
        console.log("✅ EmulatorDetectionActivity 후킹 성공");
    } catch (e) {
        console.log(`⚠️ EmulatorDetectionActivity 클래스 로드 실패: ${e.message}`);
    }

    setInterval(logSummary, 5000);
    setInterval(saveLogToCSV, 30000);
});
