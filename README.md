# AutoGen 기반 자동 취약점 수리(AVR) 에이전트 시스템

이 프로젝트는 Microsoft의 **AutoGen 프레임워크**를 사용하여 지정된 Java 소스 코드의 취약점을 자동으로 탐지, 분석, 패치 및 검증하는 자율적인 다중 에이전트 시스템입니다.

## 프로젝트 목표

-   **대상 언어**: Java
-   **대상 취약점**: CVE (CodeQL, Snyk 등으로 스캔)
-   **입력**: Java 프로젝트 디렉토리
-   **출력**: 취약점 정보, 제안된 패치, 테스트 결과 등을 포함하는 수리 보고서
-   **자동화 수준**: 전체 프로세스 자동화 (LLM 기반의 자율적인 에이전트 협업)

## 프로젝트 구조

```
avr_agent/
├── main.py                     # 메인 실행 파일 (AutoGen 에이전트 설정 및 실행)
├── readme.md                   # 프로젝트 설명 파일
├── requirements.txt            # 필요한 Python 라이브러리 목록
├── config_list.json   # LLM 설정 템플릿 파일 (API 키 등)
│
├── tools/                      # 에이전트들이 사용하는 "도구" 모음
│   ├── avr_functions.py        # 스캔, 분석, 패치, 검증을 위한 핵심 함수들
│   ├── scanning_tools.py
│   ├── analysis_tools.py
│   ├── patching_tools.py
│   └── validation_tools.py
│
├── reports/                    # (현재 미사용) 최종 수리 보고서 저장
└── workspace/                  # 패치 적용 및 테스트를 위한 임시 작업 공간
```

## 워크플로우: AI 에이전트 팀의 협업

이 시스템은 정적인 상태 머신 대신, **LLM의 지능을 활용하여 여러 AI 에이전트들이 그룹 채팅을 통해 자율적으로 협업**하는 방식으로 동작합니다.

1.  **팀 구성**: `main.py`가 전문가 AI 에이전트 팀(Scanner, Analyzer, Patcher, Validator)과 작업을 지시하는 사용자 대리인(User Proxy)을 생성하여 그룹 채팅방에 초대합니다.
2.  **작업 시작**: `User_Proxy`가 "프로젝트를 스캔하고 취약점을 고쳐주세요"라고 첫 지시를 내립니다.
3.  **자율적 수행**:
    -   **Scanner**가 `run_scans_and_report` 도구를 사용해 취약점을 스캔하고 결과를 채팅방에 공유합니다.
    -   **Analyzer**가 스캔 결과를 보고, `analyze_vulnerability_and_report` 도구로 가장 심각한 취약점을 분석하여 보고서를 공유합니다.
    -   **Patcher**가 분석 보고서를 바탕으로 `generate_patch_and_report` 도구를 사용해 코드 패치를 생성합니다.
    -   **Validator**가 생성된 패치를 `validate_patch_and_report` 도구를 사용해 빌드 및 테스트하여 검증합니다.
4.  **지능적 피드백 루프**: 만약 검증이 실패하면, **Validator**가 실패 로그를 채팅방에 공유합니다. 그러면 **Patcher**가 이 로그를 보고 문제를 수정한 새로운 패치를 생성하여 다시 검증을 요청합니다.
5.  **최종 승인**: 검증이 성공하면, `User_Proxy`에게 최종 승인을 요청합니다. `--auto-approve` 옵션이 켜져 있으면 자동으로 승인되고 전체 프로세스가 완료됩니다.

## 실행 방법

1.  **필수 라이브러리 설치:**
    ```bash
    pip install -r requirements.txt
    ```

2.  **LLM 설정:**
    `config_list.json.template` 파일을 `config_list.json`으로 복사한 후, 파일 내에 자신의 LLM API 키 (Gemini, OpenAI 등) 또는 로컬 모델(Ollama) 설정을 입력합니다.
    ```bash
    cp config_list.json.template config_list.json
    # nano, vi 등을 이용해 config_list.json 파일 수정
    ```

3.  **시스템 실행:**
    분석할 Java 프로젝트 경로를 지정하여 시스템을 실행합니다.
    ```bash
    # /path/to/your/java/project 부분을 실제 프로젝트 경로로 변경
    python main.py --project-path /path/to/your/java/project --auto-approve
    ``` 