import json
import logging
from tools.scanning_tools import run_codeql_scan, run_snyk_scan

class ScannerAgent:
    def __init__(self):
        self.system_prompt = """
        You are an automated security audit expert who handles multiple security scanning tools. 
        Your mission is to run all specified SAST and SCA tools for a given project path, 
        aggregate the results, de-duplicate them, and generate a single JSON report 
        sorted by severity (CVSS score). Do not guess; rely only on the output of the tools.
        """
        logging.info("ScannerAgent initialized.")

    def _parse_codeql_output(self, json_output: str, project_path: str) -> list:
        """CodeQL SARIF 결과를 표준 형식으로 파싱합니다."""
        standardized_vulns = []
        try:
            data = json.loads(json_output)
            for run in data.get("runs", []):
                for result in run.get("results", []):
                    rule_id = result.get("ruleId", "N/A")
                    message = result.get("message", {}).get("text", "No description")
                    location = result.get("locations", [{}])[0].get("physicalLocation", {})
                    file_path = location.get("artifactLocation", {}).get("uri", "N/A")
                    line = location.get("region", {}).get("startLine", 0)
                    severity_score = result.get("properties", {}).get("security-severity", "0.0")

                    standardized_vulns.append({
                        "id": f"CODEQL-{rule_id}-{file_path}-{line}",
                        "tool": "CodeQL",
                        "title": rule_id,
                        "description": message,
                        "file_path": file_path,
                        "line": line,
                        "severity": float(severity_score)
                    })
        except json.JSONDecodeError as e:
            logging.error(f"Failed to parse CodeQL JSON: {e}")
        return standardized_vulns

    def _parse_snyk_output(self, json_output: str, project_path: str) -> list:
        """Snyk JSON 결과를 표준 형식으로 파싱합니다."""
        standardized_vulns = []
        try:
            data = json.loads(json_output)
            for vuln in data.get("vulnerabilities", []):
                standardized_vulns.append({
                    "id": vuln.get("id", "N/A"),
                    "tool": "Snyk",
                    "title": vuln.get("title", "N/A"),
                    "description": vuln.get("description", "No description"),
                    "file_path": vuln.get("filePath", "N/A"),
                    "line": vuln.get("lineNumber", 0),
                    "severity": float(vuln.get("cvssScore", "0.0"))
                })
        except json.JSONDecodeError as e:
            logging.error(f"Failed to parse Snyk JSON: {e}")
        return standardized_vulns

    def run_scans(self, project_path: str) -> str:
        """
        지정된 프로젝트 경로에 대해 모든 스캔을 실행하고, 결과를 통합하여 정렬된 JSON 보고서를 반환합니다.
        """
        logging.info(f"ScannerAgent starting scans for project: {project_path}")
        
        # 1. 스캔 도구 실행
        codeql_raw = run_codeql_scan(project_path)
        snyk_raw = run_snyk_scan(project_path)

        # 2. 결과 파싱 및 표준화
        codeql_vulns = self._parse_codeql_output(codeql_raw, project_path)
        snyk_vulns = self._parse_snyk_output(snyk_raw, project_path)

        all_vulns = codeql_vulns + snyk_vulns
        
        # 3. 중복 제거 (file_path와 line을 기준으로)
        unique_vulns = {}
        for vuln in all_vulns:
            # 더 심각도가 높은 것을 유지
            key = (vuln["file_path"], vuln["line"])
            if key not in unique_vulns or vuln["severity"] > unique_vulns[key]["severity"]:
                unique_vulns[key] = vuln
        
        deduplicated_list = list(unique_vulns.values())

        # 4. 심각도(severity) 기준으로 내림차순 정렬
        sorted_vulns = sorted(deduplicated_list, key=lambda x: x["severity"], reverse=True)

        logging.info(f"Scans complete. Found {len(sorted_vulns)} unique vulnerabilities.")
        
        return json.dumps(sorted_vulns, indent=2)

# 에이전트 테스트용
if __name__ == '__main__':
    # 이 스크립트를 직접 실행하여 스캐너 에이전트의 동작을 테스트할 수 있습니다.
    # 테스트를 위해서는 프로젝트 경로가 필요합니다.
    # 예: python agents/scanner.py
    scanner = ScannerAgent()
    # '/path/to/dummy/project'를 실제 또는 임시 프로젝트 경로로 변경해야 합니다.
    # 여기서는 더미 경로를 사용합니다.
    report = scanner.run_scans("./dummy_project")
    print("--- Generated Vulnerability Report ---")
    print(report)
    print("------------------------------------")
