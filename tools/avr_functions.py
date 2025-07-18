import json
import logging
import os
import google.generativeai as genai
import re

from tools.scanning_tools import run_semgrep_scan, run_codeql_scan, run_snyk_scan

# --- LLM 설정 로드 ---
try:
    # config_list.json에서 Gemini API 키를 직접 찾아서 설정
    with open("config_list.json") as f:
        config_data = json.load(f)
    gemini_config = next((config for config in config_data if config.get("model") and "gemini" in config["model"]), None)
    
    if gemini_config and gemini_config.get("api_key"):
        genai.configure(api_key=gemini_config["api_key"])
        MODEL = genai.GenerativeModel('gemini-1.5-pro-latest')
    else:
        logging.error("Gemini API key not found in config_list.json.")
        MODEL = None
except Exception as e:
    logging.error(f"Error loading Gemini config: {e}")
    MODEL = None

def _call_llm(prompt: str) -> str:
    """LLM 호출을 처리하는 내부 함수"""
    if not MODEL:
        return '{"error": "LLM model is not configured."}'
    try:
        response = MODEL.generate_content(prompt)
        text_response = response.text.strip()
        
        # 응답에서 JSON 객체만 추출
        start_index = text_response.find('{')
        end_index = text_response.rfind('}')
        
        if start_index != -1 and end_index != -1 and start_index < end_index:
            json_part = text_response[start_index:end_index+1]
            # 추출된 부분이 유효한 JSON인지 한번 더 확인
            try:
                json.loads(json_part)
                return json_part
            except json.JSONDecodeError:
                logging.warning("Extracted part is not a valid JSON. Returning the full response.")
                return text_response
        else:
            # JSON 객체를 찾지 못한 경우, 원래 응답 반환
            return text_response

    except Exception as e:
        logging.error(f"LLM call failed: {e}")
        return f'{{"error": "LLM call failed", "details": "{e}"}}'

# =====================================================================================
# Code Summarizer Function (New)
# =====================================================================================
def summarize_code_functionality(code_snippet: str) -> str:
    """
    LLM을 호출하여 주어진 코드의 기능적, 의미적 요약을 생성하고
    JSON 형식의 문자열로 반환합니다.
    """
    prompt = f"""
    You are an expert code analyst. Your task is to read the following code snippet and provide a clear, concise summary of its functionality.
    Focus on the overall purpose of the code, its primary inputs and outputs, and its role within a larger application.
    Do not analyze for vulnerabilities, just explain what the code *does*.

    Return the result as a JSON object with a single key "code_summary".

    **Full Source Code:**
    ```java
    {code_snippet}
    ```

    Provide the functional summary as a single JSON object.
    """
    return _call_llm(prompt)

# =====================================================================================
# Scanner Function
# =====================================================================================
def run_scans_and_report(project_path: str) -> str:
    """
    주어진 프로젝트 경로에 대해 Semgrep, CodeQL, Snyk 스캔을 실행하고,
    결과를 통합, 중복 제거, 정렬하여 최종 취약점 목록을 JSON 문자열로 반환합니다.
    """
    logging.info(f"Executing all scans for project: {project_path}")
    
    def _parse_semgrep(json_output: str) -> List[Dict[str, Any]]:
        vulns = []
        try:
            data = json.loads(json_output)
            for result in data.get("results", []):
                vulns.append({
                    "id": result.get("check_id", "N/A"),
                    "file_path": result.get("path", "N/A"),
                    "line": result.get("start", {}).get("line", 0),
                    "description": result.get("extra", {}).get("message", ""),
                    # Semgrep severity: "INFO", "WARNING", "ERROR" -> 3.0, 6.0, 9.0
                    "severity": {
                        "INFO": 3.0, "WARNING": 6.0, "ERROR": 9.0
                    }.get(result.get("extra", {}).get("severity", "INFO"), 3.0)
                })
        except json.JSONDecodeError:
            logging.error("Failed to parse Semgrep JSON")
        return vulns

    # 모든 스캔 실행
    semgrep_vulns = _parse_semgrep(run_semgrep_scan(project_path))
    codeql_vulns = [] # _parse_codeql(run_codeql_scan(project_path)) # 미구현
    snyk_vulns = [] # _parse_snyk(run_snyk_scan(project_path)) # 미구현
    
    all_vulns = semgrep_vulns + codeql_vulns + snyk_vulns

    # 중복 제거 및 심각도 순 정렬
    unique_vulns = {}
    if all_vulns:
        # file_path와 line을 기준으로 유일한 취약점만 남김 (심각도가 높은 것을 유지)
        sorted_by_severity = sorted(all_vulns, key=lambda x: x["severity"], reverse=True)
        unique_vulns = { (v["file_path"], v["line"]): v for v in reversed(sorted_by_severity) }

    sorted_vulns = sorted(list(unique_vulns.values()), key=lambda x: x["severity"], reverse=True)
    
    logging.info(f"Found {len(sorted_vulns)} unique vulnerabilities.")
    return json.dumps(sorted_vulns, indent=2)

# =====================================================================================
# Analyzer Function
# =====================================================================================
def analyze_vulnerability(code_snippet: str, file_path: str, vulnerability_json: str, semgrep_report_json: str = None, code_summary_json: str = None) -> str:
    """
    LLM을 호출하여 주어진 코드와 취약점 정보를 분석하고,
    분석 보고서를 JSON 형식의 문자열로 반환합니다.
    """
    vulnerability = json.loads(vulnerability_json)
    
    semgrep_section = ""
    if semgrep_report_json:
        try:
            # Semgrep 보고서를 예쁘게 포맷하여 프롬프트에 추가
            semgrep_data = json.loads(semgrep_report_json)
            if semgrep_data.get("results"):
                semgrep_section = f"""
    **Semgrep Scan Results for Context:**
    The following issues were found in the code, which may be related to the primary vulnerability.
    ```json
    {json.dumps(semgrep_data["results"], indent=2)}
    ```
    """
        except json.JSONDecodeError:
            semgrep_section = "\n**Semgrep Scan Results:**\n(Could not parse Semgrep report)\n"

    summary_section = ""
    if code_summary_json:
        try:
            summary_data = json.loads(code_summary_json)
            if summary_data.get("code_summary"):
                summary_section = f"""
    **Code Functionality Summary:**
    To help you understand the context, here is a high-level summary of what this code does:
    ---
    {summary_data.get("code_summary")}
    ---
    """
        except json.JSONDecodeError:
            summary_section = "\n**Code Functionality Summary:**\n(Could not parse summary report)\n"


    prompt = f"""
    You are a senior security analyst. Your task is to analyze a piece of code for a reported vulnerability.
    I will provide you with a summary of the code's functionality, the main vulnerability details, the full source code, and results from a Semgrep scan.

    Your primary goal is to perform a deep root cause analysis for the main reported vulnerability, using all the contextual information provided.
    Then, suggest a concrete fix strategy.
    Return the result in a JSON format with keys: "file_path", "line_number", "vulnerable_code_snippet", "root_cause_analysis", "suggested_fix_strategy".

    {summary_section}
    **Main Vulnerability Details:**
    - ID: {vulnerability.get('id', 'N/A')}
    - File: {file_path}
    - Line: {vulnerability.get('line', 'N/A')}
    - Description: {vulnerability.get('description', 'N/A')}
    {semgrep_section}
    **Full Source Code:**
    ```java
    {code_snippet}
    ```

    Based on all the information above, provide your final analysis as a single JSON object.
    Focus on the main vulnerability, but use the functional summary and Semgrep findings to support your analysis.
    """
    return _call_llm(prompt)

# =====================================================================================
# Patcher Function
# =====================================================================================
def generate_patch(analysis_report_json: str) -> str:
    """
    LLM을 호출하여 분석 보고서를 기반으로 코드 패치를 생성하고,
    패치 정보를 JSON 형식의 문자열로 반환합니다.
    """
    analysis_report = json.loads(analysis_report_json)
    prompt = f"""
    You are an expert software engineer specializing in code patching.
    Based on the following vulnerability analysis, generate a patch in the 'diff' format.
    The diff should only contain the changes needed to fix the vulnerability.
    Return the result as a JSON object with a single key "diff".

    **Analysis Report:**
    - File: {analysis_report.get('file_path')}
    - Line: {analysis_report.get('line_number')}
    - Vulnerable Code: 
      ```
      {analysis_report.get('vulnerable_code_snippet')}
      ```
    - Root Cause: {analysis_report.get('root_cause_analysis')}
    - Suggested Fix: {analysis_report.get('suggested_fix_strategy')}

    Generate the diff now.
    Example of a valid JSON response:
    {{
      "diff": "--- a/{analysis_report.get('file_path')}\\n+++ b/{analysis_report.get('file_path')}\\n@@ -XX,X +XX,X @@\\n- removed_line;\\n+ added_line;"
    }}
    """
    return _call_llm(prompt)

# =====================================================================================
# Diff Parser Function (Updated)
# =====================================================================================
def parse_diff_to_patch_list(diff_content: str) -> list:
    """
    diff 형식의 문자열을 파싱하여, '각 라인'의 변경 사항에 대한
    상세 정보 객체의 리스트를 반환합니다.
    """
    if not diff_content:
        return []

    patch_list = []
    normalized_content = diff_content.replace('\\n', '\n')
    
    # hunk: `@@ ... @@`로 시작하고, 다음 `@@` 또는 문자열 끝까지의 블록
    hunk_pattern = re.compile(r'@@ -(\d+)(?:,\d+)? \+(\d+)(?:,\d+)? @@([\s\S]*?)(?=\n@@|\Z)')

    for match in hunk_pattern.finditer(normalized_content):
        try:
            original_line_num = int(match.group(1))
            new_line_num = int(match.group(2))
            hunk_body = match.group(3)
            
            lines = hunk_body.strip().split('\n')

            # hunk 내부에서 라인별로 처리
            for line in lines:
                if not line: continue

                if line.startswith('+'):
                    # 삽입된 라인
                    patch_list.append({
                        "action": "Insert",
                        "line_number": new_line_num,
                        "patch_code": [line[1:].strip()]
                    })
                    new_line_num += 1
                elif line.startswith('-'):
                    # 삭제된 라인
                    patch_list.append({
                        "action": "Delete",
                        "line_number": original_line_num,
                        "patch_code": []
                    })
                    original_line_num += 1
                elif line.startswith(' '):
                    # 컨텍스트 라인 (변경 없음)
                    original_line_num += 1
                    new_line_num += 1
                # diff 헤더 등 다른 라인은 무시
        
        except (ValueError, IndexError) as e:
            logging.error(f"Failed to parse hunk: {match.group(0)} - Error: {e}")
            continue
    
    return patch_list

# =====================================================================================
# Validator Function
# =====================================================================================
def validate_patch_and_report(patch_content: str) -> str:
    """
    패치를 검증합니다. 실제 빌드 환경이 없으므로,
    패치가 유효하다고 가정하고 항상 성공을 반환합니다.
    """
    logging.info("Validating patch (simulation)...")
    if not patch_content or "--- a/" not in patch_content:
        logging.warning("Validator received an empty or invalid patch.")
        return json.dumps({"status": "VALIDATION_ERROR", "log": "Patch content is invalid."})
    
    # 시뮬레이션: 항상 성공
    logging.info("Patch is assumed to be valid. Reporting SUCCESS.")
    return json.dumps({"status": "SUCCESS", "log": "Validation successful (simulated). No build or tests were run."}) 