
# 1단계: 목표 정의 및 범위 설정 (Define Goal & Scope)
가장 먼저 프로젝트의 구체적인 목표와 범위를 명확히 해야 합니다.

- 대상 프로그래밍 언어: Java  
- 대상 취약점 유형: Vul4J 데이터(실제 CVE)기반 취약점을 탐지할 계획  
- 입력 : 단일 .java 소스코드
- 결과물 : 탐지된 취약점 유형, 취약점 위치(filename, vulnerable_line_range), 제안된 패치 내용(patch_line : 패치 라인, operation : {코드 삽입(Insert), 코드 삭제(Delete), 코드 업데이트(Update)}, 테스트 결과(성공/실패 로그), 수리 소요 시간
- 자동화 수준 : 전체 프로세스를 완전 자동화  

# 2단계: 핵심 에이전트 역할 정의 (Define Core Agent Roles)
AVR 워크플로우를 기반으로 각 단계를 책임질 전문 에이전트들을 설계합니다. 각 에이전트는 명확한 역할과 책임(Responsibility)을 가져야 합니다.
AVR 워크플로우의 각 단계를 책임질 전문 에이전트들의 역할과 책임을 다음과 같이 세분화하고 구체화합니다.

1. (Orchestrator) AVR_Manager_Agent  
핵심 역할: 전체 AVR 프로세스를 지휘하고 에이전트 간의 협업을 조율하는 총괄 관리자.
주요 책임 (세분화):
사용자로부터 소스코드(프로젝트 디렉토리)를 입력받아 전체 프로세스를 시작.  
Scanner_Agent에게 취약점 분석을 지시하고, 결과 보고서의 우선순위에 따라 Code_Analyzer_Agent에게 순차적으로 작업을 할당.  
전체 워크플로우의 상태(e.g., ANALYZING, PATCHING, TESTING)를 추적하고 관리.  
에이전트 간 메시지와 결과물을 전달하는 허브 역할 수행.  
최종 수리가 성공하거나, 지정된 횟수 이상 실패했을 때 프로세스를 종료하고 수리 보고서를 생성.  

2. (Scanner) Scanner_Agent
핵심 역할: 다양한 정적 분석 도구를 사용하여 소스 코드와 의존성의 취약점을 식별하고 통합된 리포트를 생성.
주요 책임 (세분화):  
지정된 SAST/SCA 도구(Semgrep, Snyk, CodeQL 등)의 CLI를 실행하여 스캔 수행.  
각 도구에서 생성된 결과(JSON, XML 등)를 표준화된 형식으로 파싱.  
여러 도구에서 나온 중복된 취약점 결과를 식별하고 병합(De-duplication).  
각 취약점에 CVSS 점수와 같은 심각도 정보를 결합하여 처리 우선순위를 결정.  
우선순위가 매겨진 최종 취약점 목록을 AVR_Manager_Agent에게 보고.  
필요 도구/기술 예시: subprocess (CLI 실행), JSON/XML 파서.  
- 역할: 코드 컨텍스트 이해, 버그 원인 분석, 수정 필요 지점 특정.  
예시: "SQL 쿼리가 user_input을 필터링 없이 사용하여 db_query.py의 53번째 줄에서 SQL 인젝션이 발생 가능함" 과 같은 분석 결과를 생성합니다.  
(Developer) Patch_Generator_Agent: Code_Analyzer_Agent의 분석 내용을 바탕으로 실제 수정 코드를 생성합니다.

- 역할: 취약점을 해결하기 위한 코드 패치 생성.
예시: 파라미터화된 쿼리(Parameterized Query)를 사용하거나 입력 값 검증(Input Validation) 로직을 추가하는 코드 조각을 생성합니다.
(QA) Test_Validator_Agent: Patch_Generator_Agent가 생성한 패치를 적용한 후, 해당 패치가 실제로 취약점을 해결했는지, 그리고 기존 기능에 다른 문제를 일으키지 않는지(회귀 테스트) 검증합니다.

- 역할: 단위 테스트 실행, 빌드 검증
예시: pytest나 unittest를 실행하고, Java 프로젝트를 빌드해 검증을 수행합니다.
(Human) Human_in_the_Loop_Agent: AutoGen의 UserProxyAgent를 활용하여 구현합니다. 자동화된 프로세스가 불확실한 결정을 내려야 하거나, 생성된 패치가 복잡하여 사람의 검토가 필요할 때 개입을 요청하는 창구 역할을 합니다.

# 3단계: 에이전트 간 상호작용 및 워크플로우 설계 (Design Agent Interaction & Workflow)
정의된 에이전트들이 어떤 순서와 방식으로 소통하며 작업을 진행할지 구체적인 시나리오를 설계합니다.

3단계: 에이전트 간 상호작용 및 워크플로우 설계 (구현을 위한 상세 수정안)
AVR 시스템의 전체 프로세스를 여러 상태(State)로 정의하고, 각 상태는 명확한 책임과 전환 조건을 가집니다. AVR_Manager_Agent는 이 상태를 관리하며 전체 오케스트레이션을 담당합니다.

- 워크플로우 상태(State) 정의
- IDLE: 대기 상태
- SCANNING: 취약점 스캔 중
- ANALYZING: 단일 취약점 분석 중
- PATCHING: 패치 생성 중 (피드백을 통한 개선 포함)
- BUILDING: 패치 적용 후 프로젝트 빌드 중
- TESTING_VULNERABILITY: 취약점 수정 여부 검증 (PoC 테스트)
- TESTING_REGRESSION: 회귀 오류 여부 검증 (단위 테스트)
- AWAITING_APPROVAL: 검증된 패치에 대한 사람의 최종 승인 대기
- SUCCESS: 프로세스 성공적으로 완료
- FAILED: 프로세스 실패

상태 전환 다이어그램
```
graph TD
    A[사용자 요청] --> B(SCANNING);
    B -- 취약점 발견 --> C(ANALYZING);
    B -- 취약점 없음 --> I(SUCCESS);
    B -- 스캔 실패 --> J(FAILED);
    C -- 분석 성공 --> D(PATCHING);
    C -- 분석 실패 --> J(FAILED);
    D -- 패치 생성 --> E(BUILDING);
    D -- 패치 생성 반복 실패 --> J(FAILED);
    E -- 빌드 성공 --> F(TESTING_VULNERABILITY);
    E -- "빌드 실패 (<b>컴파일 에러 로그</b> 피드백)" --> D;
    F -- 취약점 해결 --> G(TESTING_REGRESSION);
    F -- "취약점 미해결 (<b>PoC 테스트 실패 로그</b> 피드백)" --> D;
    G -- 모든 테스트 통과 --> H(AWAITING_APPROVAL);
    G -- "회귀 테스트 실패 (<b>단위 테스트 실패 로그</b> 피드백)" --> D;
    H -- 사람 승인 --> I;
    H -- 사람 거절 --> J;
```
LLM에게 지시할 에이전트 간 상세 상호작용 시나리오
[상태: IDLE → SCANNING]

AVR_Manager_Agent는 사용자로부터 프로젝트 경로를 받아 작업을 시작하고, 상태를 SCANNING으로 변경합니다.
지시: Scanner_Agent에게 "지정된 경로의 Java 프로젝트에 대해 CodeQL, Snyk 스캔을 실행하고, 결과를 통합하여 우선순위가 매겨진 JSON 형식의 취약점 보고서를 제출해."
[상태: SCANNING → ANALYZING]

Scanner_Agent가 결과를 보고하면, AVR_Manager는 보고서에서 우선순위가 가장 높은 취약점 하나를 선택하고 상태를 ANALYZING으로 변경합니다.
지시: Code_Analyzer_Agent에게 "이 CVE 정보와 관련 소스 코드를 바탕으로, 근본 원인과 수정 필요 지점을 AST와 데이터 흐름 분석을 통해 상세히 분석하고 JSON 형식으로 보고해."
[상태: ANALYZING → PATCHING]

분석이 완료되면, AVR_Manager는 상태를 PATCHING으로 변경합니다.
지시: Patch_Generator_Agent에게 "이 상세 분석 보고서를 바탕으로, diff 형식의 코드 패치를 생성해줘."
[상태: PATCHING → BUILDING]

패치가 생성되면, AVR_Manager는 상태를 BUILDING으로 변경합니다.
지시: Test_Validator_Agent에게 "격리된 워크스페이스에 패치를 적용하고 mvn clean install로 프로젝트를 빌드해줘."
[상태: BUILDING → PATCHING (실패 피드백 루프)]

만약 빌드 실패 시, Test_Validator_Agent는 컴파일 에러 로그를 AVR_Manager에게 보고합니다.
AVR_Manager는 상태를 다시 PATCHING으로 변경하고, Patch_Generator_Agent에게 "패치 적용 후 빌드에 실패했어. 다음 컴파일 에러를 참고하여 패치를 수정해줘: [컴파일 에러 로그 내용]" 이라고 구체적인 실패 원인을 전달합니다.
[상태: BUILDING → TESTING_VULNERABILITY]

빌드가 성공하면, AVR_Manager는 상태를 TESTING_VULNERABILITY로 변경합니다.
지시: Test_Validator_Agent에게 "이 취약점에 대한 PoC(Proof-of-Concept) 테스트를 실행하고 결과를 보고해줘."
[상태: TESTING_VULNERABILITY → PATCHING (실패 피드백 루프)]

만약 PoC 테스트 실패 시, Test_Validator_Agent는 실패한 테스트의 로그를 보고합니다.
AVR_Manager는 상태를 다시 PATCHING으로 변경하고, Patch_Generator_Agent에게 "취약점이 해결되지 않았어. 다음 테스트 실패 로그를 참고하여 패치를 수정해줘: [PoC 테스트 실패 로그]" 라고 피드백합니다.
[상태: TESTING_VULNERABILITY → TESTING_REGRESSION]

PoC 테스트를 통과하면, AVR_Manager는 상태를 TESTING_REGRESSION으로 변경합니다.
지시: Test_Validator_Agent에게 "이제 전체 단위 테스트를 실행해서 다른 기능이 망가지지 않았는지 확인해줘."
[상태: TESTING_REGRESSION → PATCHING (실패 피드백 루프)]

만약 회귀 테스트 실패 시, Test_Validator_Agent는 실패한 단위 테스트 로그를 보고합니다.
AVR_Manager는 상태를 PATCHING으로 변경하고, Patch_Generator_Agent에게 "패치 때문에 다른 기능이 고장났어. 다음 실패 로그를 참고해서 패치를 수정해줘: [단위 테스트 실패 로그]" 라고 피드백합니다.
[상태: TESTING_REGRESSION → AWAITING_APPROVAL]

모든 테스트를 통과하면, AVR_Manager는 상태를 AWAITING_APPROVAL로 변경합니다.
지시: Human_in_the_Loop_Agent에게 "패치가 성공적으로 검증되었어. 최종 수리 보고서를 확인하고 적용하려면 'approve'를 입력해줘."
[상태: AWAITING_APPROVAL → SUCCESS / FAILED]

사용자의 결정에 따라 최종 상태를 변경하고, 모든 과정을 요약한 최종 수리 보고서를 생성하며 프로세스를 종료합니다.

# 4단계: 각 에이전트의 도구(Tools) 및 지식(Knowledge) 정의
각 에이전트가 자신의 역할을 수행하기 위해 어떤 도구(함수)와 지식(프롬프트)이 필요한지 구체적으로 정의해야 합니다.

1. Scanner_Agent
- 지식 (Knowledge): 시스템 프롬프트 : "당신은 여러 보안 스캔 도구를 다루는 자동화된 보안 감사 전문가입니다. 당신의 임무는 주어진 프로젝트 경로에 대해 지정된 모든 SAST 및 SCA 도구를 실행하고, 그 결과를 취합하여 중복을 제거한 후, 심각도(CVSS 점수) 순으로 정렬된 단일 JSON 보고서를 생성하는 것입니다. 추측하지 말고, 오직 도구의 결과에만 의존하여 보고서를 작성하세요."

도구 (Tools): 함수 정의
```python
def run_codeql_scan(path: str) -> str:
    """
    주어진 경로에 대해 CodeQL 스캔을 실행하고 결과를 JSON 문자열로 반환합니다.
    - path (str): 스캔할 프로젝트의 경로.
    - 반환 (str): CodeQL 스캔 결과가 담긴 JSON 문자열.
    """
    # ... CodeQL CLI 실행 로직 ...

def run_snyk_scan(path: str) -> str:
    """
    주어진 경로에 대해 Snyk 스캔을 실행하고 결과를 JSON 문자열로 반환합니다.
    - path (str): 스캔할 프로젝트의 경로.
    - 반환 (str): Snyk 스캔 결과가 담긴 JSON 문자열.
    """
    # ... Snyk CLI 실행 로직 ...
```

Code_Analyzer_Agent
지식 (Knowledge): 시스템 프롬프트
"당신은 코드의 근본 원인을 분석하는 데 특화된 최고 수준의 보안 분석가입니다. 당신은 Scanner_Agent로부터 단일 취약점 보고서를 입력받습니다. 당신의 목표는 보고서에 명시된 라인뿐만 아니라, 주변 코드와 데이터 흐름을 분석하여 취약점의 근본 원인을 찾아내는 것입니다. 최종적으로 분석 결과를 JSON 형식으로 출력해야 하며, 이 JSON에는 'file_path', 'line_number', 'vulnerable_code_snippet', 'root_cause_analysis', 'suggested_fix_strategy' 키가 반드시 포함되어야 합니다."

도구 (Tools): 함수 정의
```python
def read_file_content(file_path: str) -> str:
    """
    지정된 파일 경로의 전체 내용을 문자열로 읽어 반환합니다.
    - file_path (str): 읽을 파일의 경로.
    - 반환 (str): 파일의 전체 내용.
    """
    # ... 파일 읽기 로직 ...

def get_code_context(file_path: str, line_number: int, span: int = 10) -> str:
    """
    지정된 파일의 특정 라인 주변 코드를 지정된 줄 수(span)만큼 가져옵니다.
    - file_path (str): 대상 파일 경로.
    - line_number (int): 중심이 될 라인 번호.
    - span (int): 주변에 가져올 코드 라인 수.
    - 반환 (str): 중심 라인과 주변 코드가 포함된 문자열.
    """
    # ... 주변 코드 추출 로직 ...
```

3. Patch_Generator_Agent
지식 (Knowledge): 시스템 프롬프트

"당신은 보안 패치 작성에 능숙한 전문 Java 개발자입니다. Code_Analyzer_Agent의 상세 분석 보고서와, 이전 시도의 실패 로그(선택 사항)를 입력받습니다. 당신의 임무는 분석 내용을 바탕으로 취약점을 해결하기 위한 최소한의 코드 변경사항을 diff 형식의 패치로 생성하는 것입니다. 만약 error_log가 함께 제공된다면, 반드시 해당 에러의 원인을 분석하여 이전과 다른 방식으로 패치를 생성해야 합니다. 항상 가장 안전하고 효율적인 코드를 작성하세요."

도구 (Tools): 함수 정의

```python
def read_file_for_patch(file_path: str) -> str:
    """
    패치를 생성하기 위해 원본 파일 내용을 읽습니다.
    - file_path (str): 읽을 파일의 경로.
    - 반환 (str): 파일 내용.
    """
    # ... 파일 읽기 로직 ...

# 참고: 이 에이전트는 직접 파일을 쓰기보다는 diff 형식의 텍스트를 생성하는 데 집중합니다.
# 실제 파일 수정은 Test_Validator_Agent가 워크스페이스에서 수행합니다.
```

4. Test_Validator_Agent
지식 (Knowledge): 시스템 프롬프트

"당신은 빌드 및 테스트 자동화를 담당하는 QA 엔지니어입니다. 당신의 임무는 생성된 패치를 임시 작업 공간에 적용하고, 3단계의 검증 프로세스(빌드, 취약점 검증, 회귀 테스트)를 순차적으로 실행하는 것입니다. 각 단계를 실행하고, 성공 여부와 실패 시 상세 로그를 포함한 JSON 보고서를 생성하세요. 하나의 단계라도 실패하면 즉시 프로세스를 중단하고 결과를 보고해야 합니다."

도구 (Tools): 함수 정의
```python
def setup_test_workspace(project_path: str) -> str:
    """
    테스트를 위한 격리된 임시 작업 공간을 생성하고 원본 프로젝트를 복사합니다.
    - project_path (str): 원본 프로젝트 경로.
    - 반환 (str): 생성된 임시 워크스페이스의 경로.
    """
    # ... 임시 디렉토리 생성 및 파일 복사 로직 ...

def apply_patch(workspace_path: str, patch_content: str) -> bool:
    """
    주어진 워크스페이스에 diff 형식의 패치를 적용합니다.
    - workspace_path (str): 패치를 적용할 워크스페이스 경로.
    - patch_content (str): diff 형식의 패치 내용.
    - 반환 (bool): 패치 적용 성공 여부.
    """
    # ... 'git apply' 또는 'patch' 명령어 실행 로직 ...
def run_build(workspace_path: str) -> dict:
    """
    워크스페이스에서 'mvn clean install'을 실행하여 프로젝트를 빌드합니다.
    - workspace_path (str): 빌드를 실행할 워크스페이스 경로.
    - 반환 (dict): {"success": bool, "log": "빌드 로그 내용..."}
    """
    # ... Maven 빌드 실행 및 결과 캡처 로직 ...
def run_vulnerability_test(workspace_path: str) -> dict:
    """
    취약점 해결 여부를 검증하기 위한 특정 테스트(PoC)를 실행합니다.
    - workspace_path (str): 테스트를 실행할 워크스페이스 경로.
    - 반환 (dict): {"success": bool, "log": "PoC 테스트 로그..."}
    """
    # ... 'mvn test -Dtest=TestSpecificVulnerability' 와 같은 특정 테스트 실행 로직 ...

def run_regression_tests(workspace_path: str) -> dict:
    """
    프로젝트의 전체 단위 테스트를 실행하여 회귀 오류를 확인합니다.
    - workspace_path (str): 테스트를 실행할 워크스페이스 경로.
    - 반환 (dict): {"success": bool, "log": "전체 테스트 로그..."}
    """
    # ... 'mvn test' 실행 및 결과 캡처 로직 ...

def cleanup_workspace(workspace_path: str) -> None:
    """
    사용한 임시 워크스페이스를 삭제합니다.
    - workspace_path (str): 삭제할 워크스페이스 경로.
    """
    # ... 디렉토리 삭제 로직 ...
```