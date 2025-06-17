import json
import logging
import time
from enum import Enum

from agents.scanner import ScannerAgent
from agents.code_analyzer import CodeAnalyzerAgent
from agents.patch_generator import PatchGeneratorAgent
from agents.test_validator import TestValidatorAgent

class State(Enum):
    IDLE = "IDLE"
    SCANNING = "SCANNING"
    ANALYZING = "ANALYZING"
    PATCHING = "PATCHING"
    VALIDATING = "VALIDATING" # BUILDING, TESTING_VULNERABILITY, TESTING_REGRESSION을 포함
    AWAITING_APPROVAL = "AWAITING_APPROVAL"
    SUCCESS = "SUCCESS"
    FAILED = "FAILED"

class AVRManagerAgent:
    def __init__(self, project_path: str, auto_approve: bool = False):
        self.project_path = project_path
        self.auto_approve = auto_approve
        self.state = State.IDLE
        self.scanner = ScannerAgent()
        self.analyzer = CodeAnalyzerAgent()
        self.patcher = PatchGeneratorAgent()
        self.validator = TestValidatorAgent()
        self.final_report = {}
        self.start_time = None
        logging.info("AVRManagerAgent initialized.")

    def set_state(self, new_state: State):
        logging.info(f"Transitioning from {self.state.value} to {new_state.value}")
        self.state = new_state

    def run_workflow(self):
        self.start_time = time.time()
        logging.info(f"Starting AVR workflow for project: {self.project_path}")
        
        try:
            # 1. SCANNING 상태
            self.set_state(State.SCANNING)
            vulnerabilities_report = self.scanner.run_scans(self.project_path)
            vulnerabilities = json.loads(vulnerabilities_report)

            if not vulnerabilities:
                self.set_state(State.SUCCESS)
                logging.info("No vulnerabilities found.")
                return self._generate_final_report()

            # 가장 심각한 취약점 하나를 선택하여 처리
            target_vulnerability = vulnerabilities[0]
            logging.info(f"Highest priority vulnerability selected: {target_vulnerability['id']}")
            
            error_log_for_patcher = None
            patch_attempts = 0
            max_patch_attempts = 3

            while patch_attempts < max_patch_attempts:
                # 2. ANALYZING 상태 (피드백 루프에 의해 반복될 수 있음)
                self.set_state(State.ANALYZING)
                analysis_report = self.analyzer.analyze_vulnerability(self.project_path, target_vulnerability)
                if "error" in json.loads(analysis_report):
                    raise Exception(f"Analysis failed: {analysis_report}")
                
                # 3. PATCHING 상태
                self.set_state(State.PATCHING)
                patch_attempts += 1
                logging.info(f"Patch attempt {patch_attempts}/{max_patch_attempts}")
                patch_content = self.patcher.generate_patch(self.project_path, analysis_report, error_log_for_patcher)
                if "Error:" in patch_content:
                     raise Exception(f"Patch generation failed: {patch_content}")

                # 4. VALIDATING 상태
                self.set_state(State.VALIDATING)
                validation_report_str = self.validator.validate_patch(self.project_path, patch_content)
                validation_report = json.loads(validation_report_str)
                
                validation_status = validation_report["status"]
                validation_log = validation_report["log"]

                if validation_status == "SUCCESS":
                    self.set_state(State.AWAITING_APPROVAL)
                    logging.info("Patch validated successfully. Awaiting human approval.")
                    
                    # 5. AWAITING_APPROVAL 상태 (Human-in-the-loop)
                    if self.auto_approve:
                        approval = "approve"
                        logging.info("Auto-approving patch as per --auto-approve flag.")
                    else:
                        approval = input("A validated patch is ready. Apply? [approve/reject]: ")

                    if approval.lower() == "approve":
                        self.set_state(State.SUCCESS)
                        self.final_report['patch'] = patch_content
                        logging.info("Patch approved and applied.")
                        return self._generate_final_report()
                    else:
                        self.set_state(State.FAILED)
                        logging.warning("Patch was rejected by human.")
                        self.final_report['reason'] = "Patch rejected by user."
                        return self._generate_final_report()
                
                else:
                    # 유효성 검사 실패 시, 로그를 다음 패치 생성에 사용
                    logging.warning(f"Validation failed with status: {validation_status}. Retrying patch generation.")
                    error_log_for_patcher = f"Validation failed with status '{validation_status}'.\nLog:\n{validation_log}"

            # 최대 시도 횟수 도달
            self.set_state(State.FAILED)
            logging.error("Maximum patch attempts reached. Aborting.")
            self.final_report['reason'] = "Maximum patch attempts reached."

        except Exception as e:
            self.set_state(State.FAILED)
            logging.error(f"An unrecoverable error occurred in the workflow: {e}", exc_info=True)
            self.final_report['error'] = str(e)
        
        finally:
            return self._generate_final_report()

    def _generate_final_report(self):
        end_time = time.time()
        self.final_report.update({
            "project_path": self.project_path,
            "final_status": self.state.value,
            "total_time_seconds": round(end_time - self.start_time, 2)
        })
        logging.info(f"Workflow finished with state: {self.state.value}")
        report_str = json.dumps(self.final_report, indent=2)
        
        # 보고서 파일로 저장
        report_filename = f"report-{time.strftime('%Y%m%d-%H%M%S')}.json"
        with open(os.path.join("reports", report_filename), "w") as f:
            f.write(report_str)
        logging.info(f"Final report saved to reports/{report_filename}")

        return report_str

if __name__ == '__main__':
    # This is for testing the manager. It requires a dummy project setup.
    import os
    dummy_project_path = "./dummy_project_for_manager"
    if not os.path.exists(dummy_project_path):
        # Create a structure similar to what agents expect
        dummy_src_path = os.path.join(dummy_project_path, "src/main/java/com/example")
        os.makedirs(dummy_src_path)
        with open(os.path.join(dummy_src_path, "App.java"), "w") as f:
            f.write("public class App {}")
        with open(os.path.join(dummy_src_path, "Util.java"), "w") as f:
            f.write("public class Util {}")
    
    print("--- Starting AVR Manager Agent Workflow ---")
    print("This is an interactive test. You may be prompted for input.")
    # NOTE: The test will use simulated tool/LLM outputs.
    # To test failure loops, you would need to modify the mock outputs in the respective agent/tool files.
    manager = AVRManagerAgent(project_path=dummy_project_path)
    final_report = manager.run_workflow()
    
    print("\n--- Final AVR Report ---")
    print(final_report)
    print("------------------------")
    
    import shutil
    shutil.rmtree(dummy_project_path)

# Add missing import
import os
