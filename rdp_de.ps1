# 설정
$logDirectory = "C:\ForensicLogs"
$logFilePath = Join-Path $logDirectory "ForensicAnalysisLog.txt"
$analysisResultsCsv = Join-Path $logDirectory "AnalysisResults.csv"
$analysisResults = @()

# 로그 작성 함수
function Write-Log {
    param([string]$message)
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Add-Content -Path $logFilePath -Value "$timestamp - $message"
}

# 분석 결과 추가 함수
function Add-Result {
    param([string]$category, [string]$detail, [string]$value, [string]$description)
    $analysisResults += [PSCustomObject]@{
        Category    = $category
        Detail      = $detail
        Value       = $value
        Description = $description
    }
}

# 디렉토리 생성 함수
function Ensure-Directory {
    param([string]$path)
    if (-not (Test-Path $path)) {
        New-Item -ItemType Directory -Path $path | Out-Null
    }
}

# 데이터 수집 함수
function Collect-Data {
    param([string]$command, [string]$category, [string]$description])
    try {
        $result = Invoke-Expression $command
        Add-Result -category $category -detail $description -value ($result | Out-String) -description $description
        Write-Log "$description 데이터 수집 완료"
    } catch {
        Write-Log "$description 데이터 수집 실패: $_"
    }
}

# 경로 또는 키 분석 함수
function Analyze-PathOrKey {
    param(
        [string]$category,
        [array]$paths,
        [string]$description
    )
    foreach ($path in $paths) {
        if (Test-Path $path) {
            Add-Result -category $category -detail $description -value $path -description "$description 파일/키 확인: $path"
            Write-Log "$description 확인: $path"
        } else {
            Write-Log "$description 파일/키를 찾을 수 없음: $path"
        }
    }
}

# 초기 디렉토리 생성
Ensure-Directory -path $logDirectory

# 로그 시작
Write-Log "==== 침해사고 분석 시작 ===="

# 1. 휘발성 데이터 수집
Collect-Data -command "tasklist" -category "Volatile Data" -description "실행 중인 프로세스 목록"
Collect-Data -command "netstat -an" -category "Volatile Data" -description "네트워크 연결 상태"
Collect-Data -command "whoami /priv" -category "Volatile Data" -description "현재 사용자의 권한 정보"

# 2. 이벤트 로그 분석
$eventIDs = @(4624, 4625, 4688, 4720, 4726)
try {
    $eventLogs = Get-WinEvent -FilterHashtable @{ LogName = 'Security'; ID = $eventIDs }
    foreach ($log in $eventLogs) {
        Add-Result -category "Event Log" -detail "Event ID: $($log.Id)" -value $log.Message -description "보안 이벤트 로그"
    }
    Write-Log "이벤트 로그 분석 완료"
} catch {
    Write-Log "이벤트 로그 분석 실패: $_"
}

# 3. 레지스트리 키 분석
$registryKeys = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
)
Analyze-PathOrKey -category "Registry Analysis" -paths $registryKeys -description "자동 실행 프로그램"

# 4. 숨김 및 삭제 파일 분석
try {
    $hiddenFiles = Get-ChildItem -Path "C:\" -Recurse -ErrorAction SilentlyContinue | Where-Object { $_.Attributes -match 'Hidden' }
    Add-Result -category "File Analysis" -detail "Hidden Files" -value ($hiddenFiles | Out-String) -description "숨김 파일 분석"
    Write-Log "숨김 파일 분석 완료"
} catch {
    Write-Log "숨김 파일 분석 실패: $_"
}

# 5. 네트워크 로그 분석
$firewallLogPath = "C:\Windows\System32\LogFiles\Firewall\pfirewall.log"
Analyze-PathOrKey -category "Network Logs" -paths @($firewallLogPath) -description "방화벽 로그"

# 6. 사용자 계정 분석
try {
    $localUsers = Get-LocalUser
    Add-Result -category "User Analysis" -detail "Local Users" -value ($localUsers | Out-String) -description "로컬 사용자 계정 분석"
    Write-Log "사용자 계정 분석 완료"
} catch {
    Write-Log "사용자 계정 분석 실패: $_"
}

# 분석 결과 저장
try {
    $analysisResults | Export-Csv -Path $analysisResultsCsv -NoTypeInformation -Encoding UTF8
    Write-Log "분석 결과가 CSV로 저장되었습니다: $analysisResultsCsv"
} catch {
    Write-Log "CSV 저장 실패: $_"
}

# 로그 종료
Write-Log "==== 침해사고 분석 종료 ===="
Write-Host "분석이 완료되었습니다. 로그 파일: $logFilePath"
Write-Host "결과 CSV 파일: $analysisResultsCsv"
