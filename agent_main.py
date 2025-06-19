import argparse
import json
import logging
import os
import re # 정규표현식 모듈 추가
import time
from datetime import datetime
from functools import partial
import traceback
import inspect

# 새로운 도구 및 LLM 호출기 임포트
from tools.agent_tools import (
    list_files,
    read_file_content,
    update_file_content,
    run_semgrep_scan,
    apply_patch_to_file,
    finish_patch,
    tool_definitions,
    find_tool_by_name,
    create_report,
    save_report
)
from llm_handler import call_gemini_api, configure_gemini # configure_gemini 임포트 추가
import difflib # _save_final_report 에서 직접 사용하도록 이동
from utils.logging_utils import setup_logging, ensure_reports_dir
from utils.file_utils import get_vuln_details

# --- 1. 기본 설정 ---

def setup_logging(vuln_id):
    """ID별로 로그 파일을 설정합니다."""
    log_dir = 'log'
    if not os.path.exists(log_dir):
        os.makedirs(log_dir)
    
    # ID가 없는 경우를 대비한 기본 로그 파일 이름
    log_filename = f"{vuln_id}-{datetime.now().strftime('%Y-%m-%d')}.log" if vuln_id else f"agent_run-{datetime.now().strftime('%Y-%m-%d')}.log"
    
    # 기존 핸들러 제거
    for handler in logging.root.handlers[:]:
        logging.root.removeHandler(handler)
        
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(os.path.join(log_dir, log_filename)),
            logging.StreamHandler()
        ]
    )

def ensure_reports_dir():
    """보고서 디렉토리가 존재하는지 확인하고 없으면 생성합니다."""
    if not os.path.exists('reports'):
        os.makedirs('reports')

# --- LLM Mock ---
def call_llm_mock(agent):
    """
    실제 LLM API 호출을 모방하는 함수.
    에이전트의 상태를 기반으로 미리 정의된 시나리오에 따라 다음 행동을 결정합니다.
    """
    history = agent.history
    turn = len(history) // 2

    # 에이전트로부터 취약 파일 경로를 가져옴
    vulnerable_file_path = agent.file_path

    if turn == 0:
        action = {"tool": "list_files", "parameters": {"directory": "."}}
    elif turn == 1:
        action = {"tool": "read_file_content", "parameters": {"file_path": vulnerable_file_path}}
    elif turn == 2:
        action = {"tool": "run_semgrep_scan", "parameters": {"file_path": vulnerable_file_path}}
    elif turn == 3:
        # 이전 기록에서 원본 코드를 가져옴
        original_code = ""
        for record in reversed(agent.history):
            if record["role"] == "user" and "도구 실행 결과" in record["content"] and "SAXParserFactory" in record["content"]:
                 # '도구 실행 결과:\n' 부분을 제거하고 실제 코드를 가져옵니다.
                original_code = record["content"].split("도구 실행 결과:\n", 1)[1]
                break
        
        if not original_code:
             # 만약 위에서 코드를 못찾으면 그냥 initial_code를 사용
            original_code = agent.initial_code

        patched_code = original_code.replace(
            'return (Document) f.parse(is);',
            '        f.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);\n'
            '        f.setFeature("http://xml.org/sax/features/external-general-entities", false);\n'
            '        f.setFeature("http://xml.org/sax/features/external-parameter-entities", false);\n'
            '        return (Document) f.parse(is);'
        )
        action = {"tool": "update_file_content", "parameters": {"file_path": vulnerable_file_path, "new_content": patched_code}}
    elif turn == 4:
        action = {"tool": "apply_patch_to_file", "parameters": {}}
    elif turn == 5:
        action = {"tool": "run_vul4j_test", "parameters": {"vuln_id": agent.id}}
    elif turn == 6:
        test_output = agent.history[-1]['content']
        action = {"tool": "save_test_result", "parameters": {"vuln_id": agent.id, "test_output": test_output}}
    elif turn == 7:
        action = {"tool": "revert_project", "parameters": {"vuln_id": agent.id}}
    else:
        action = {"tool": "finish_patch", "parameters": {"reason": "모든 프로세스(패치, 테스트, 결과 저장, 복구)를 완료했습니다."}}
    
    logging.info(f"[LLM Mock] 행동 결정: {json.dumps(action, indent=2)}")
    return json.dumps(action)

# --- 2. 에이전트 클래스 정의 ---

class Agent:
    def __init__(self, project_dir, vuln_id):
        self.vuln_id = vuln_id
        self.project_dir = project_dir
        self.vuln_details = get_vuln_details(vuln_id)
        if not self.vuln_details:
            raise ValueError(f"ID {vuln_id}에 해당하는 취약점 정보를 찾을 수 없습니다.")
        
        self.max_turns = 30
        self.turn_count = 0
        self.is_running = True
        
        self.file_path = None # read_file_content 호출 시 설정됨
        self.initial_code = ""
        self.working_code = ""
        
        self.history = []
        self.full_log = []
        self.final_report = ""
        self.start_time = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        self.system_prompt = self._build_system_prompt()
        logging.info(f"에이전트 ID-{vuln_id} 초기화 완료")

    def run(self):
        """에이전트의 메인 실행 루프"""
        logging.info("에이전트 실행 시작...")
        self.history.append({"role": "user", "content": self._get_initial_user_message()})
        self.full_log.append(self.system_prompt)

        while self.is_running and self.turn_count < self.max_turns:
            self.turn_count += 1
            logging.info(f"--- [ Turn {self.turn_count}/{self.max_turns} ] ---")

            messages = self._prepare_messages()
            response_json = call_gemini_api(messages, self.system_prompt)

            if not response_json:
                logging.error("API 응답이 없습니다. 5초 후 재시도합니다.")
                time.sleep(5)
                continue
            
            self.history.append({"role": "model", "content": json.dumps(response_json)})
            
            thought = response_json.get("thought", "")
            tool_call = response_json.get("tool", {})
            tool_name = tool_call.get("name")
            parameters = tool_call.get("parameters", {})
            
            logging.info(f"LLM Thought: {thought}")
            self.full_log.append(f"🧠 Thought\n\n{thought}\n\n---\n")
            
            if not tool_name:
                logging.warning("LLM이 도구를 선택하지 않았습니다.")
                self.full_log.append("🔧 System\n\nLLM이 도구를 선택하지 않고 응답을 종료했습니다.\n\n---\n")
                self.is_running = False
                continue

            tool_result = self.dispatch_tool(tool_name, parameters)
            self.history.append({"role": "user", "content": f"Tool Execution Result:\n{tool_result}"})
            
            if tool_name == 'finish_patch':
                self.is_running = False # finish_patch가 호출되면 루프 종료
        
        logging.info("에이전트 실행 종료.")
        if not self.final_report:
             self.final_report = create_report(self, "에이전트가 최대 턴 수에 도달했거나 다른 이유로 작업을 완료하지 못했습니다.", "미완료")
             save_report(self)
             logging.warning("최종 보고서가 생성되지 않아, 미완료 보고서를 저장합니다.")
    
    def _get_initial_user_message(self):
        """에이전트가 처음 받는 사용자 메시지를 생성합니다."""
        return f"""안녕하세요. 당신은 자동 취약점 수리 전문가입니다.
**임무:** 다음 파일의 보안 취약점을 분석하고 수리하는 것입니다. '생각 -> 행동 -> 성찰'의 순환 과정을 통해 임무를 완수하세요.
**목표 파일:** `{self.vuln_details['file_path']}`
이제, 첫 번째 분석 계획을 'thought'에 담아 임무를 시작해 주십시오."""
    
    def _build_system_prompt(self):
        """CoT와 Reflection을 강조하는 시스템 프롬프트를 생성합니다."""
        return f"""당신은 체계적이고, 신중하며, 비판적인 사고를 하는 자동화된 Java 보안 분석가입니다.

**핵심 작동 원리: 생각, 행동, 성찰 (Think, Act, Reflect)**
1.  **생각 (Chain-of-Thought):** 도구를 선택하기 전에, 당신의 논리적 추론 과정을 `thought` 필드에 상세히 서술하세요.
2.  **행동 (Act):** 당신의 `thought`에 기반하여, 계획을 실행하기 위한 단 하나의 `tool`을 선택하고 필요한 `parameters`를 지정하세요.
3.  **성찰 (Reflect):** 도구 실행 결과를 보고 다음 `thought`를 시작하세요. 이것이 당신의 학습 과정입니다.

**매우 중요한 규칙:**
- **작업 흐름:** 당신은 다음의 작업 절차를 따라야 합니다.
  1. **초기 분석:** `list_files`와 `read_file_content`로 기본적인 파일 정보를 파악합니다.
  2. **정적 분석:** `run_semgrep_scan`을 실행하여 자동화된 보안 스캔을 수행합니다.
     - **Semgrep 실패 시:** 작업을 중단하지 말고, 당신의 전문 지식에 따라 코드의 논리적 결함을 직접 분석하여 **반드시 하나 이상의 `REPLACE`, `INSERT`, 또는 `DELETE` 작업을 포함하는, 비어있지 않은 `edits` 목록으로 `edit_code`를 호출해야 합니다.** 섣불리 취약점이 없다고 단정하지 마세요.
  3. **코드 수정 및 검증 루프:**
     a. 분석 결과를 바탕으로 `edit_code`를 사용하여 메모리상에서 코드를 수정합니다.
     b. **수정 직후, 반드시 `compile_and_test`를 호출하여 당신이 수정한 코드의 유효성을 즉시 검증해야 합니다.**
     c. 컴파일 결과가 **성공일 때만** 다음 단계로 넘어갈 수 있습니다. 컴파일이 실패하면, 실패 원인을 분석하여 다시 a단계(코드 수정)로 돌아가 문제를 해결하세요. 이 과정을 성공할 때까지 반복해야 합니다.
  4. **종료 및 패치 적용:** **`compile_and_test`의 성공이 확인된 후에만** `finish_patch`를 호출하여 메모리의 변경 사항을 실제 파일에 저장하고, diff 리포트를 생성하며 작업을 마무합니다.
- 당신의 모든 응답은 **반드시** `thought`와 `tool` 필드를 포함한 유효한 JSON 객체여야 합니다.
- API는 JSON 모드로 설정되어 있으므로, 다른 어떤 텍스트도 응답에 포함할 수 없습니다.

**사용 가능한 도구:**
1.  `list_files(directory: str)`: 지정된 디렉토리의 파일 목록을 확인합니다.
2.  `read_file_content(file_path: str)`: 파일의 전체 내용을 읽어 메모리에 저장합니다. `initial_code`와 `working_code`가 이 내용으로 설정됩니다.
3.  `run_semgrep_scan(file_path: str)`: Semgrep으로 코드의 정적 분석을 수행합니다.
4.  `edit_code(edits: list)`: 메모리 상의 코드를 주어진 편집 목록에 따라 수정합니다.
    - `edits` 파라미터는 편집 작업을 정의하는 딕셔너리의 리스트입니다.
    - 각 딕셔너리는 `action`, 라인 번호(`line_number` 또는 `start_line`/`end_line`), 그리고 `content`(필요시)를 포함해야 합니다.
    - 예시: `[ {{"action": "REPLACE", "start_line": 10, "end_line": 11, "content": "..."}}, {{"action": "INSERT", "line_number": 25, "content": "..."}} ]`
5.  `compile_and_test()`: 메모리에 있는 수정된 코드를 사용하여 컴파일을 시도하고 결과를 반환합니다. 이 도구는 실제 파일의 최종 내용을 변경하지 않습니다.
6.  `finish_patch(reason: str)`: 모든 분석과 수정을 마친 후, 최종 보고서를 생성하고 임무를 종료합니다. 이 함수는 메모리에 있는 최종 수정 코드를 실제 파일에 쓰고, 원본 코드와의 차이점을 담은 diff 리포트를 생성합니다.

**필수 응답 형식 (JSON만 가능):**
{{
  "thought": "여기에 당신의 상세한 추론 과정을 서술합니다.",
  "tool": {{
    "name": "<도구_이름>",
    "parameters": {{
      "<파라미터_이름>": "<파라미터_값>"
    }}
  }}
}}
"""

    def _save_final_report(self):
        """에이전트의 최종 작업 보고서를 저장합니다."""
        report_dir = "reports"
        ensure_reports_dir()
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_filename = f"report_{self.vuln_id}_{timestamp}.md"
        report_filepath = os.path.join(report_dir, report_filename)

        with open(report_filepath, 'w', encoding='utf-8') as f:
            f.write(f"# AVR Agent Report (ID: {self.vuln_id})\n\n")
            
            if self.final_patch_diff:
                f.write("## 최종 생성된 패치\n")
                f.write("```diff\n")
                f.write(self.final_patch_diff)
                f.write("\n```\n\n")
            else:
                f.write("## 최종 생성된 패치\n")
                f.write("코드 변경 사항이 없습니다.\n\n")

            f.write("## 에이전트 활동 기록\n\n")
            for record in self.history:
                role = "🤖 Agent" if record['role'] == 'assistant' else "🔧 System"
                content = record['content']
                if isinstance(content, str) and content.startswith('{"thought"'):
                    try:
                        json_content = json.loads(content)
                        thought = json_content.get("thought", "N/A")
                        tool_name = json_content.get("tool", {}).get("name", "N/A")
                        parameters = json_content.get("tool", {}).get("parameters", {})
                        f.write(f"### {role}\n\n")
                        f.write(f"**Thought:**\n{thought}\n\n")
                        f.write(f"**Tool:** `{tool_name}`\n")
                        f.write(f"**Parameters:** `{parameters}`\n\n---\n")
                    except json.JSONDecodeError:
                        f.write(f"### {role}\n\n{content}\n\n---\n")
                else:
                    f.write(f"### {role}\n\n{content}\n\n---\n")

        logging.info(f"최종 보고서 저장 완료: {report_filepath}")

    def dispatch_tool(self, tool_name, params):
        """요청된 도구를 찾아 실행하고, 그 결과를 반환하며, 전체 로그에 기록합니다."""
        tool_info = find_tool_by_name(tool_name)
        if not tool_info:
            result = f"오류: '{tool_name}'이라는 이름의 도구를 찾을 수 없습니다."
        else:
            logging.info(f"도구 실행: {tool_name} with params {params}")
            try:
                # 더 이상 **params를 사용하지 않고, 필요한 인자만 명시적으로 전달합니다.
                # 대부분의 함수는 agent 객체와 함께 params 딕셔너리의 특정 값들을 인자로 받습니다.
                func = tool_info["function"]
                
                # 도구 함수 시그니처에 따라 필요한 인자만 추출하여 호출
                # inspect 라이브러리를 사용하여 함수의 실제 파라미터 목록을 가져옵니다.
                sig = inspect.signature(func)
                
                # 'agent'는 기본으로 전달하고, 나머지 파라미터는 시그니처에 존재하는 것만 필터링합니다.
                required_params = {p: params[p] for p in sig.parameters if p != 'agent' and p in params}

                result = func(self, **required_params)

            except Exception as e:
                result = f"도구 '{tool_name}' 실행 중 오류 발생: {e}"
                logging.error(f"{result}\n{traceback.format_exc()}")

        self.full_log.append(f"🔧 System\n\n도구 실행 결과:\n{result}\n\n---\n")
        return result

    def _prepare_messages(self):
        """API 요청을 위해 시스템 프롬프트와 대화 기록을 Gemini 형식에 맞게 변환합니다."""
        # 시스템 프롬프트는 `system_instruction`으로 별도 처리되므로 메시지 목록에서는 제외
        
        gemini_messages = []
        for msg in self.history:
            role = 'model' if msg['role'] == 'assistant' else 'user'
            
            # content가 문자열인지 확인하고, 아니면 문자열로 변환 (예: JSON 덤프)
            content_str = msg.get('content')
            if not isinstance(content_str, str):
                content_str = json.dumps(content_str, ensure_ascii=False)

            gemini_messages.append({
                "role": role,
                "parts": [content_str]
            })
        return gemini_messages


# --- 3. 메인 실행 로직 ---

def main():
    """메인 실행 함수"""
    configure_gemini() # 에이전트 실행 전 API 설정 초기화

    parser = argparse.ArgumentParser(description="Java 취약점 자동 수리 에이전트")
    parser.add_argument("--id", type=int, required=True, help="분석할 취약점의 숫자 ID")
    args = parser.parse_args()

    # setup_logging을 main 함수 시작 부분으로 이동
    setup_logging(args.id)

    vuln_details = get_vuln_details(args.id)
    if not vuln_details:
        logging.error(f"ID {args.id}에 대한 취약점 정보를 가져오는 데 실패하여 프로그램을 종료합니다.")
        return

    project_dir = os.path.expanduser(f"~/vul4j_test/VUL4J-{args.id}")
    
    agent = Agent(project_dir, args.id)
    agent.run()

if __name__ == "__main__":
    main() 