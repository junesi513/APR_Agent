import json
import logging
import os
from tools.patching_tools import read_file_for_patch

class PatchGeneratorAgent:
    def __init__(self):
        self.system_prompt = """
        You are an expert Java developer skilled in writing security patches. 
        You will receive a detailed analysis report from the Code_Analyzer_Agent, and optionally, 
        error logs from previous attempts. Your mission is to generate a minimal code change in 'diff' format 
        to fix the vulnerability based on the analysis. If an error_log is provided, you must analyze the cause 
        of that error and generate a different patch to fix it. Always write the safest and most efficient code.
        """
        logging.info("PatchGeneratorAgent initialized.")

    def generate_patch(self, project_path: str, analysis_report: str, error_log: str = None) -> str:
        """
        분석 보고서와 선택적 에러 로그를 바탕으로 diff 형식의 패치를 생성합니다.
        """
        logging.info("PatchGeneratorAgent generating patch...")
        
        try:
            analysis = json.loads(analysis_report)
        except json.JSONDecodeError as e:
            logging.error(f"Failed to parse analysis report: {e}")
            return f"Error: Invalid analysis report format. {e}"

        file_path = analysis.get("file_path")
        full_file_path = os.path.join(project_path, file_path)

        # 1. 패치 생성을 위해 원본 파일 읽기
        original_code = read_file_for_patch(full_file_path)
        if "Error:" in original_code:
            logging.error(f"Could not read file for patch: {full_file_path}")
            return f"Error: Could not read file {full_file_path}"
            
        # 2. LLM에 전달할 프롬프트 구성 (시뮬레이션)
        error_log_prompt = f"**Previous Error Log:**\n{error_log}" if error_log else ""

        llm_prompt = f"""
        **Patch Generation Request**

        **Analysis Report:**
        - Root Cause: {analysis.get('root_cause_analysis')}
        - Suggested Fix: {analysis.get('suggested_fix_strategy')}

        **Target File:** {file_path}

        **Vulnerable Code Snippet:**
        ```java
        {analysis.get('vulnerable_code_snippet')}
        ```
        
        {error_log_prompt}

        **Task:**
        Based on the analysis and suggested fix, generate a code patch in the unified diff format.
        The patch should only contain the necessary changes to fix the vulnerability.
        If an error log is provided, make sure your new patch addresses the error.
        Start the diff with `--- a/{file_path}` and `+++ b/{file_path}`.
        """
        logging.info("--- LLM Prompt for Patch Generation (Simulation) ---")
        logging.info(llm_prompt)
        logging.info("-------------------------------------------------")
        
        # 3. LLM 응답 시뮬레이션 (diff 형식의 패치)
        # SQL 인젝션 취약점에 대한 PreparedStatement 사용 예시
        simulated_patch = f"""--- a/{file_path}
+++ b/{file_path}
@@ -40,8 +40,11 @@
 public class App {{
 // ... existing code ...
     String id = request.getParameter("id");
-    String query = "SELECT * FROM users WHERE id = '" + id + "';";
-    statement.executeQuery(query);
+    String query = "SELECT * FROM users WHERE id = ?";
+    PreparedStatement pstmt = connection.prepareStatement(query);
+    pstmt.setString(1, id);
+    ResultSet rs = pstmt.executeQuery();
 // ... existing code ...
 }}
"""
        # 만약 에러 로그가 있다면, 다른 패치를 생성하도록 시뮬레이션 할 수 있습니다.
        if error_log and "cannot find symbol" in error_log:
             simulated_patch = f"""--- a/{file_path}
+++ b/{file_path}
@@ -38,10 +38,13 @@
 import java.sql.ResultSet;
 import java.sql.SQLException;
+import java.sql.PreparedStatement;
 
 public class App {{
 // ... existing code ...
     String id = request.getParameter("id");
-    String query = "SELECT * FROM users WHERE id = '" + id + "';";
-    statement.executeQuery(query);
+    String query = "SELECT * FROM users WHERE id = ?";
+    PreparedStatement pstmt = connection.prepareStatement(query);
+    pstmt.setString(1, id);
+    ResultSet rs = pstmt.executeQuery();
 // ... existing code ...
 }}
"""

        logging.info("Patch generated successfully.")
        return simulated_patch

# 에이전트 테스트용
if __name__ == '__main__':
    generator = PatchGeneratorAgent()

    # CodeAnalyzerAgent가 생성했을 법한 더미 분석 보고서
    dummy_analysis = {
        "file_path": "src/main/java/com/example/App.java",
        "line_number": 42,
        "vulnerable_code_snippet": "   41: public class App {\\n>> 42:     String id = request.getParameter(\"id\");\\n   43:     String query = \\\"SELECT * FROM users WHERE id = '\\\" + id + \\\"';\\\";\\n   44:     statement.executeQuery(query);\\n   45: }",
        "root_cause_analysis": "The method directly uses user-controlled input in a SQL query string without sanitization.",
        "suggested_fix_strategy": "Use a PreparedStatement with parameter placeholders."
    }
    
    # 더미 프로젝트 파일 생성
    if not os.path.exists("./dummy_project/src/main/java/com/example"):
        os.makedirs("./dummy_project/src/main/java/com/example")
    with open("./dummy_project/src/main/java/com/example/App.java", "w") as f:
        f.writelines([f"Line {i+1}\n" for i in range(50)])

    patch = generator.generate_patch("./dummy_project", json.dumps(dummy_analysis))
    print("--- Generated Patch (Initial) ---")
    print(patch)
    print("---------------------------------")
    
    # 에러 로그가 있을 경우 테스트
    error_log_feedback = "Compilation error: cannot find symbol\n  symbol:   class PreparedStatement\n  location: class com.example.App"
    patch_with_feedback = generator.generate_patch("./dummy_project", json.dumps(dummy_analysis), error_log=error_log_feedback)
    print("--- Generated Patch (With Feedback) ---")
    print(patch_with_feedback)
    print("---------------------------------------")
