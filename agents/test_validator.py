import logging
import json
from tools.validation_tools import (
    setup_test_workspace,
    apply_patch,
    run_build,
    run_vulnerability_test,
    run_regression_tests,
    cleanup_workspace
)

class TestValidatorAgent:
    def __init__(self):
        self.system_prompt = """
        You are a QA engineer responsible for build and test automation. Your mission is to apply a
        generated patch to a temporary workspace and execute a three-step verification process: 
        build, vulnerability verification, and regression testing, in sequence. 
        You must generate a JSON report with the success status and detailed logs for each step. 
        If any step fails, you must stop the process immediately and report the failure.
        """
        logging.info("TestValidatorAgent initialized.")

    def validate_patch(self, project_path: str, patch_content: str) -> str:
        """
        주어진 패치를 격리된 환경에서 검증하고, 각 단계의 결과를 JSON으로 보고합니다.
        """
        logging.info(f"TestValidatorAgent starting validation for project: {project_path}")
        
        workspace_path = ""
        try:
            # 1. 테스트 작업 공간 설정
            workspace_path = setup_test_workspace(project_path)
            if not workspace_path:
                raise Exception("Failed to create test workspace.")

            # 2. 패치 적용
            if not apply_patch(workspace_path, patch_content):
                raise Exception("Failed to apply patch.")

            # 3. 빌드 실행
            build_result = run_build(workspace_path)
            if not build_result["success"]:
                return self._create_report(workspace_path, "BUILD_FAILED", build_result["log"])

            # 4. 취약점 테스트 실행 (PoC)
            # 실제로는 취약점 정보에 따라 특정 테스트 명령어를 동적으로 구성해야 합니다.
            poc_test_command = "mvn test -Dtest=TestSpecificVulnerability"
            vuln_test_result = run_vulnerability_test(workspace_path, poc_test_command)
            if not vuln_test_result["success"]:
                return self._create_report(workspace_path, "VULN_TEST_FAILED", vuln_test_result["log"])

            # 5. 회귀 테스트 실행
            reg_test_result = run_regression_tests(workspace_path)
            if not reg_test_result["success"]:
                return self._create_report(workspace_path, "REG_TEST_FAILED", reg_test_result["log"])
            
            # 모든 테스트 통과
            return self._create_report(workspace_path, "SUCCESS", "All validation steps passed.")

        except Exception as e:
            logging.error(f"An exception occurred during validation: {e}")
            return self._create_report(workspace_path, "VALIDATION_ERROR", str(e))
        finally:
            # 6. 작업 공간 정리
            if workspace_path:
                cleanup_workspace(workspace_path)
    
    def _create_report(self, workspace_path: str, status: str, log: str) -> str:
        """결과 보고서 생성을 위한 헬퍼 함수"""
        report = {
            "status": status,
            "log": log,
            "workspace_path": workspace_path
        }
        return json.dumps(report, indent=2)

# 에이전트 테스트용
if __name__ == '__main__':
    validator = TestValidatorAgent()
    
    # 더미 프로젝트 생성
    dummy_project = "./dummy_project_for_validation"
    if not os.path.exists(dummy_project):
        os.makedirs(dummy_project)
    with open(os.path.join(dummy_project, "test.txt"), "w") as f:
        f.write("This is a test file.")

    # 더미 패치 내용
    dummy_patch = "--- a/test.txt\n+++ b/test.txt\n@@ -1 +1 @@\n-This is a test file.\n+This is a patched test file."

    validation_result = validator.validate_patch(dummy_project, dummy_patch)
    print("--- Validation Result ---")
    print(validation_result)
    print("-------------------------")
    
    # 임시 작업 공간이 삭제되었는지 확인 (수동 확인)
    import os
    # The workspace path is inside the JSON result. We can parse it to check.
    try:
        result_data = json.loads(validation_result)
        workspace_parent = os.path.dirname(result_data["workspace_path"])
        print(f"Checking if workspace '{workspace_parent}' was deleted...")
        if not os.path.exists(workspace_parent):
            print("Workspace successfully cleaned up.")
        else:
            print("Workspace cleanup might have failed.")
    except (json.JSONDecodeError, KeyError, FileNotFoundError):
        print("Could not check workspace cleanup status from result.")

    import shutil
    shutil.rmtree(dummy_project)
