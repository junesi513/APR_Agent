import argparse
import json
import logging
import os
import time
import tempfile
import shutil

from tools.avr_functions import (
    analyze_vulnerability,
    generate_patch
)
from tools.scanning_tools import run_semgrep_scan

# 로깅 설정
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def process_vulnerability(vuln_details: dict):
    """단일 취약점을 분석, 패치, 보고하는 전체 프로세스를 처리합니다."""
    
    file_path = vuln_details.get("file_path")
    line = vuln_details.get("line")
    vuln_id = vuln_details.get("id")

    if not vuln_id:
        logging.error("Vulnerability 'id' is missing. Skipping.")
        return

    logging.info(f"--- Processing vulnerability: {vuln_id} in {file_path}:{line} ---")

    code_before = vuln_details.get("code_before")
    if not code_before:
        logging.error(f"'code_before' is missing for ID {vuln_id}. Skipping.")
        return

    # 임시 작업 공간 생성
    workspace_dir = tempfile.mkdtemp(prefix="avr_workspace_")
    logging.info(f"Created temporary workspace at: {workspace_dir}")

    semgrep_report_json = None
    try:
        # 1. Semgrep 스캔을 위한 임시 파일 생성
        if file_path:
            # 원본 파일 경로와 디렉토리 구조를 임시 작업 공간에 재현
            temp_file_path = os.path.join(workspace_dir, file_path)
            os.makedirs(os.path.dirname(temp_file_path), exist_ok=True)
            with open(temp_file_path, 'w', encoding='utf-8') as f:
                f.write(code_before)
            logging.info(f"Created temporary file for scanning at: {temp_file_path}")
        else:
            # 파일 경로가 없으면 workspace 루트에 임시 파일 생성
            with open(os.path.join(workspace_dir, "temp_code.java"), 'w', encoding='utf-8') as f:
                f.write(code_before)
            logging.info("Created temporary file for scanning at workspace root.")
        
        # 2. Semgrep 스캔 실행
        logging.info("Step 1: Running Semgrep scan on the provided code...")
        semgrep_report_json = run_semgrep_scan(workspace_dir)
        logging.info("Semgrep scan completed.")

        # 3. 취약점 분석 (Semgrep 결과와 함께)
        logging.info("Step 2: Analyzing vulnerability with Semgrep context...")
        analysis_report = analyze_vulnerability(code_before, file_path, json.dumps(vuln_details), semgrep_report_json)
        logging.info(f"Analysis Report:\n{analysis_report}")

        # 4. 패치 생성
        logging.info("Step 3: Generating patch...")
        patch_generation_report = generate_patch(analysis_report)
        logging.info(f"Patch Generation Report:\n{patch_generation_report}")

        # 5. 최종 보고서 생성
        logging.info("Step 4: Creating final report...")
        patch_data = json.loads(patch_generation_report)
        diff_patch = patch_data.get("diff")

        if diff_patch is None:
            raise ValueError("Diff key not found in patch generation report")

        final_report_data = {
            "id": vuln_id,
            "file_path": file_path,
            "line": line,
            "code_before": code_before,
            "patch": diff_patch,
            "analysis": json.loads(analysis_report),
        }
        
        report_dir = "reports"
        os.makedirs(report_dir, exist_ok=True)
        report_filepath = os.path.join(report_dir, f"{vuln_id}-report.json")
        with open(report_filepath, 'w', encoding='utf-8') as f:
            json.dump(final_report_data, f, indent=2, ensure_ascii=False)
        logging.info(f"Successfully generated and saved report to {report_filepath}")

    except (json.JSONDecodeError, ValueError) as e:
        logging.error(f"Failed during processing: {e}")
    finally:
        # 임시 작업 공간 삭제
        shutil.rmtree(workspace_dir)
        logging.info(f"Cleaned up temporary workspace: {workspace_dir}")

def main():
    start_time = time.time()
    parser = argparse.ArgumentParser(
        description="AVR System - Analyze, Patch, and Report from JSON data.",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("--json-path", required=True, help="Path to a JSON file containing vulnerability information.")
    parser.add_argument("--id", required=True, help="The ID of the vulnerability to process from the JSON file.")
    args = parser.parse_args()

    # JSON 파일에서 정보 읽기
    logging.info(f"Processing vulnerability ID '{args.id}' from '{args.json_path}'...")
    try:
        with open(args.json_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        if not isinstance(data, list): data = [data]
        target_vuln = next((item for item in data if str(item.get("id")) == args.id), None)

        if target_vuln and target_vuln.get("files"):
            file_info = target_vuln["files"][0]
            code_before = file_info.get("code_before")
            
            if not code_before:
                raise ValueError("'code_before' field not found in the JSON data for the given ID.")

            vuln_details = {
                "id": target_vuln.get("id"),
                "file_path": file_info.get("filepath_before"),
                "line": None, 
                "code_before": code_before,
                "description": target_vuln.get("cve_description", "N/A"),
            }
            process_vulnerability(vuln_details)
        else:
            logging.error(f"Vulnerability with ID '{args.id}' not found in the JSON file.")

    except (FileNotFoundError, json.JSONDecodeError, ValueError) as e:
        logging.error(f"Failed to process the request: {e}")

    total_time = time.time() - start_time
    logging.info(f"Total execution time: {total_time:.2f} seconds.")

if __name__ == "__main__":
    main()

