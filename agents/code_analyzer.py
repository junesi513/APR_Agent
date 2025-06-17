import json
import logging
import os
from tools.analysis_tools import get_code_context

class CodeAnalyzerAgent:
    def __init__(self):
        self.system_prompt = """
        You are a top-tier security analyst specialized in root cause analysis of code vulnerabilities. 
        You will receive a single vulnerability report from the Scanner_Agent. 
        Your goal is to analyze the surrounding code and data flow, not just the line specified in the report, 
        to find the root cause of the vulnerability. Finally, you must output your analysis in JSON format, 
        which must include the keys 'file_path', 'line_number', 'vulnerable_code_snippet', 
        'root_cause_analysis', and 'suggested_fix_strategy'.
        """
        logging.info("CodeAnalyzerAgent initialized.")

    def analyze_vulnerability(self, project_path: str, vulnerability: dict) -> str:
        """
        단일 취약점 보고서를 받아 근본 원인을 분석하고 JSON 형식의 보고서를 반환합니다.
        """
        logging.info(f"CodeAnalyzerAgent analyzing vulnerability: {vulnerability.get('id')}")

        file_path = vulnerability.get("file_path")
        line_number = vulnerability.get("line")
        
        # 프로젝트의 절대 경로와 파일의 상대 경로를 조합
        full_file_path = os.path.join(project_path, file_path)

        # 1. 분석에 필요한 코드 컨텍스트 가져오기
        code_context = get_code_context(full_file_path, line_number, span=15)
        
        if "Error:" in code_context:
            logging.error(f"Could not get code context for {full_file_path}. Aborting analysis.")
            return json.dumps({
                "error": "Failed to read file or get context",
                "details": code_context
            })

        # 2. LLM에 전달할 프롬프트 구성 (시뮬레이션)
        # 실제 구현에서는 이 프롬프트를 LLM API로 전달합니다.
        llm_prompt = f"""
        **Vulnerability Analysis Request**

        **Vulnerability Details:**
        - Title: {vulnerability.get('title')}
        - File: {file_path}
        - Line: {line_number}
        - Description: {vulnerability.get('description')}

        **Code Context:**
        ```java
        {code_context}
        ```

        **Task:**
        Based on the provided vulnerability details and code context, perform a root cause analysis.
        Your analysis should identify the core reason for the vulnerability and suggest a concrete strategy for fixing it.
        Respond in JSON format with the keys: 'file_path', 'line_number', 'vulnerable_code_snippet', 'root_cause_analysis', 'suggested_fix_strategy'.
        """
        logging.info("--- LLM Prompt for Analysis (Simulation) ---")
        logging.info(llm_prompt)
        logging.info("-------------------------------------------")

        # 3. LLM 응답 시뮬레이션
        # 실제 LLM 호출 대신 더미 분석 결과를 생성합니다.
        analysis_result = {
            "file_path": file_path,
            "line_number": line_number,
            "vulnerable_code_snippet": code_context,
            "root_cause_analysis": "The method at line {line_number} directly uses user-controlled input in a SQL query string without sanitization or parameterization. The input from 'request.getParameter(\"id\")' flows into the 'query' variable and is executed, making it vulnerable to SQL Injection.",
            "suggested_fix_strategy": "Use a PreparedStatement with parameter placeholders (?) to safely pass the user input to the SQL query. This prevents the input from being interpreted as SQL commands by the database engine."
        }

        logging.info(f"Analysis complete for vulnerability: {vulnerability.get('id')}")
        return json.dumps(analysis_result, indent=2)

# 에이전트 테스트용
if __name__ == '__main__':
    # 분석가 에이전트의 동작을 테스트합니다.
    analyzer = CodeAnalyzerAgent()
    
    # 테스트용 더미 프로젝트 및 파일 생성
    if not os.path.exists("./dummy_project/src/main/java/com/example"):
        os.makedirs("./dummy_project/src/main/java/com/example")
    with open("./dummy_project/src/main/java/com/example/App.java", "w") as f:
        f.write("public class App {\n" * 41)
        f.write("    String id = request.getParameter(\"id\");\n")
        f.write("    String query = \"SELECT * FROM users WHERE id = '\" + id + \"';\";\n")
        f.write("    statement.executeQuery(query);\n")
        f.write("}\n" * 10)

    # 스캐너가 생성했을 법한 더미 취약점 정보
    dummy_vuln = {
        "id": "SNYK-JAVA-SQLI-12345",
        "tool": "Snyk",
        "title": "SQL Injection",
        "description": "SQL Injection vulnerability found in user input.",
        "file_path": "src/main/java/com/example/App.java",
        "line": 42,
        "severity": 9.8
    }

    analysis_report = analyzer.analyze_vulnerability("./dummy_project", dummy_vuln)
    print("--- Generated Analysis Report ---")
    print(analysis_report)
    print("---------------------------------")
