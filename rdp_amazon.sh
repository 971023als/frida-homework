#!/bin/bash

# 설정
logDirectory="/var/log/ForensicLogs"
logFilePath="$logDirectory/ForensicAnalysisLog.txt"
analysisResultsCsv="$logDirectory/AnalysisResults.csv"

# 디렉토리 생성
if [ ! -d "$logDirectory" ]; then
    mkdir -p "$logDirectory"
fi

# 로그 작성 함수
WriteLog() {
    local timestamp
    timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo "[$timestamp] - $1" >> "$logFilePath"
}

# 로그 시작
WriteLog "==== 침해사고 분석 시작 ===="

# 1. 휘발성 데이터 수집
WriteLog "실행 중인 프로세스 목록 수집 중..."
ps aux >> "$logFilePath"

WriteLog "네트워크 연결 상태 수집 중..."
ss -tuln >> "$logFilePath"

WriteLog "현재 사용자의 권한 정보 수집 중..."
id -a >> "$logFilePath"

# 2. 이벤트 로그 분석
WriteLog "이벤트 로그 분석 중..."
journalctl -p err >> "$logFilePath"

# 3. 자동 시작 프로그램 분석
WriteLog "시작 프로그램 목록 분석 중..."
if [ -d "/etc/xdg/autostart" ]; then
    ls -l /etc/xdg/autostart >> "$logFilePath"
else
    WriteLog "/etc/xdg/autostart 디렉토리를 찾을 수 없음."
fi

if [ -d "$HOME/.config/autostart" ]; then
    ls -l "$HOME/.config/autostart" >> "$logFilePath"
else
    WriteLog "$HOME/.config/autostart 디렉토리를 찾을 수 없음."
fi

# 4. 숨김 파일 분석
WriteLog "숨김 파일 분석 중..."
find / -type f -name ".*" 2>/dev/null >> "$logFilePath"

# 5. 네트워크 로그 분석
iptablesLogPath="/var/log/messages"
if grep -q "iptables" "$iptablesLogPath"; then
    WriteLog "iptables 로그 확인됨: $iptablesLogPath"
    grep "iptables" "$iptablesLogPath" >> "$logFilePath"
else
    WriteLog "iptables 로그를 찾을 수 없음: $iptablesLogPath"
fi

# 6. 사용자 계정 분석
WriteLog "사용자 계정 분석 중..."
cat /etc/passwd >> "$logFilePath"

# 7. 시스템 정보 수집
WriteLog "시스템 정보 수집 중..."
uname -a >> "$logFilePath"
df -h >> "$logFilePath"
uptime >> "$logFilePath"

# 8. AppArmor 상태 확인
WriteLog "AppArmor 상태 확인 중..."
if command -v aa-status &> /dev/null; then
    aa-status >> "$logFilePath"
else
    WriteLog "AppArmor가 활성화되어 있지 않음."
fi

# 9. 크론 작업 분석
WriteLog "크론 작업 목록 분석 중..."
for cron_file in /etc/cron* /var/spool/cron/*; do
    if [ -e "$cron_file" ]; then
        echo "Cron File: $cron_file" >> "$logFilePath"
        cat "$cron_file" >> "$logFilePath"
    fi
