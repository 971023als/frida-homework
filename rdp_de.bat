@echo off
setlocal enabledelayedexpansion

REM 설정
set logDirectory=C:\ForensicLogs
set logFilePath=%logDirectory%\ForensicAnalysisLog.txt
set analysisResultsCsv=%logDirectory%\AnalysisResults.csv

REM 디렉토리 생성
if not exist "%logDirectory%" (
    mkdir "%logDirectory%"
)

REM 로그 작성 함수
:WriteLog
set timestamp=%date% %time:~0,8%
echo [%timestamp%] - %1 >> "%logFilePath%"
goto :EOF

REM 로그 시작
call :WriteLog "==== 침해사고 분석 시작 ===="

REM 1. 휘발성 데이터 수집
call :WriteLog "실행 중인 프로세스 목록 수집 중..."
powershell -Command "tasklist | Out-File -Append -FilePath '%logFilePath%'"

call :WriteLog "네트워크 연결 상태 수집 중..."
powershell -Command "netstat -an | Out-File -Append -FilePath '%logFilePath%'"

call :WriteLog "현재 사용자의 권한 정보 수집 중..."
powershell -Command "whoami /priv | Out-File -Append -FilePath '%logFilePath%'"

REM 2. 이벤트 로그 분석
call :WriteLog "이벤트 로그 분석 중..."
powershell -Command "Get-WinEvent -FilterHashtable @{ LogName = 'Security'; ID = @(4624, 4625, 4688, 4720, 4726) } | Format-Table -Wrap | Out-File -Append -FilePath '%logFilePath%'"

REM 3. 레지스트리 키 분석
call :WriteLog "레지스트리 키 분석 중..."
for %%K in (
    "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    "HKCU\Software\Microsoft\Windows\CurrentVersion\Run"
) do (
    powershell -Command "if (Test-Path '%%K') { 'Registry Key Exists: %%K' | Out-File -Append -FilePath '%logFilePath%' } else { 'Registry Key Missing: %%K' | Out-File -Append -FilePath '%logFilePath%' }"
)

REM 4. 숨김 파일 분석
call :WriteLog "숨김 파일 분석 중..."
powershell -Command "Get-ChildItem -Path C:\ -Recurse -ErrorAction SilentlyContinue | Where-Object { $_.Attributes -match 'Hidden' } | Out-File -Append -FilePath '%logFilePath%'"

REM 5. 네트워크 로그 분석
set firewallLogPath=C:\Windows\System32\LogFiles\Firewall\pfirewall.log
if exist "%firewallLogPath%" (
    call :WriteLog "방화벽 로그 확인됨: %firewallLogPath%"
) else (
    call :WriteLog "방화벽 로그를 찾을 수 없음: %firewallLogPath%"
)

REM 6. 사용자 계정 분석
call :WriteLog "사용자 계정 분석 중..."
powershell -Command "Get-LocalUser | Out-File -Append -FilePath '%logFilePath%'"

REM 로그 종료
call :WriteLog "==== 침해사고 분석 종료 ===="
echo 분석이 완료되었습니다. 로그 파일: %logFilePath%
echo 결과 CSV 파일: %analysisResultsCsv%
