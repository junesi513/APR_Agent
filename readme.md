# Automated Vulnerability Repair (AVR) Agent System

이 프로젝트는 지정된 Java 소스 코드의 취약점을 자동으로 탐지, 분석, 패치 및 검증하는 다중 에이전트 시스템입니다.

## 프로젝트 목표

- **대상 언어**: Java
- **대상 취약점**: Vul4J 데이터 기반 CVE
- **입력**: Java 프로젝트 디렉토리
- **출력**: 취약점 정보, 제안된 패치, 테스트 결과 등을 포함하는 수리 보고서
- **자동화 수준**: 전체 프로세스 자동화

## 프로젝트 구조

```
avr_agent/
├── main.py                 # 메인 실행 파일
├── readme.md               # 프로젝트 설명 파일
├── agents/                 # 각 에이전트의 로직
│   ├── manager.py
│   ├── scanner.py
│   ├── code_analyzer.py
│   ├── patch_generator.py
│   └── test_validator.py
├── tools/                  # 에이전트들이 사용하는 공용 도구
│   ├── scanning_tools.py
│   ├── analysis_tools.py
│   ├── patching_tools.py
│   └── validation_tools.py
├── reports/                # 최종 수리 보고서 저장
└── workspace/              # 패치 적용 및 테스트를 위한 임시 작업 공간
```

## 워크플로우

본 시스템은 상태 머신(State Machine) 기반의 워크플로우를 따릅니다. `AVR_Manager_Agent`가 전체 상태를 관리하며 각 단계에 맞는 에이전트를 호출합니다.

1.  **SCANNING**: `Scanner_Agent`가 CodeQL, Snyk 등의 도구로 취약점을 스캔합니다.
2.  **ANALYZING**: `Code_Analyzer_Agent`가 발견된 취약점의 근본 원인을 분석합니다.
3.  **PATCHING**: `Patch_Generator_Agent`가 분석 결과를 바탕으로 코드 패치를 생성합니다.
4.  **BUILDING**: `Test_Validator_Agent`가 패치를 적용하고 프로젝트를 빌드합니다.
5.  **TESTING**: `Test_Validator_Agent`가 PoC 테스트와 회귀 테스트를 실행하여 패치를 검증합니다.
6.  **AWAITING_APPROVAL**: 모든 테스트를 통과한 패치는 사용자의 최종 승인을 기다립니다.
7.  **SUCCESS / FAILED**: 최종 결과에 따라 프로세스를 종료하고 보고서를 생성합니다.

## 실행 방법

```bash
python main.py --project-path /path/to/your/java/project
```
