import argparse
import json
import logging
import os
import time
import tempfile
import shutil

from tools.avr_functions import (
    analyze_vulnerability,
    generate_patch,
    summarize_code_functionality,
    parse_diff_to_patch_list
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

    # 1. (신규) 코드 기능 분석
    logging.info("Step 1: Summarizing code functionality...")
    summary_report_json = summarize_code_functionality(code_before)
    logging.info("Code summary generated.")
    
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
        logging.info("Step 2: Running Semgrep scan on the provided code...")
        semgrep_report_json = run_semgrep_scan(workspace_dir)
        logging.info("Semgrep scan completed.")

        # 4. 취약점 분석 (기능 요약 및 Semgrep 결과와 함께)
        logging.info("Step 3: Analyzing vulnerability with summary and Semgrep context...")
        analysis_report = analyze_vulnerability(
            code_snippet=code_before, 
            file_path=file_path, 
            vulnerability_json=json.dumps(vuln_details), 
            semgrep_report_json=semgrep_report_json,
            code_summary_json=summary_report_json
        )
        logging.info(f"Analysis Report:\n{analysis_report}")

        # 5. 패치 생성
        logging.info("Step 4: Generating patch...")
        patch_generation_report = generate_patch(analysis_report)
        logging.info(f"Patch Generation Report:\n{patch_generation_report}")

        # 6. 최종 보고서 생성
        logging.info("Step 5: Creating final report...")
        patch_data = json.loads(patch_generation_report)
        diff_patch = patch_data.get("diff")

        if diff_patch is None:
            raise ValueError("Diff key not found in patch generation report")

        # (신규) diff 내용을 파싱하여 patch 객체 리스트 생성
        patch_list = parse_diff_to_patch_list(diff_patch)

        final_report_data = {
            "id": vuln_id,
            "file_path": file_path,
            "analysis": json.loads(analysis_report),
            "patch_diff": diff_patch,
            "patch": patch_list
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

        if target_vuln:
            # 1. JSON에서 파일 이름 정보 가져오기
            file_info = target_vuln.get("files", [{}])[0]
            # 'filepath_before' 대신 'filename' 필드를 읽도록 수정
            filename_from_json = file_info.get("filename")
            
            if not filename_from_json:
                raise ValueError("'filename' not found in the JSON data for the given ID.")

            # 2. VUL4J 프로젝트 경로 구성
            vuln_id = args.id
            base_dir = os.path.join("/home/ace4_sijune", "vul4j_test", f"VUL4J-{vuln_id}", "VUL4J", "vulnerable")
            full_path = os.path.join(base_dir, filename_from_json)
            logging.info(f"Attempting to read source code from: {full_path}")

            # 3. 소스 코드 파일 읽기
            try:
                with open(full_path, 'r', encoding='utf-8') as f:
                    code_before = f.read()
            except FileNotFoundError:
                logging.error(f"Source code file not found at '{full_path}'. Please check the path and VUL4J project structure.")
                return
            except Exception as e:
                logging.error(f"Failed to read source code file: {e}")
                return

            # 4. 분석을 위한 데이터 구성 및 실행
            vuln_details = {
                "id": target_vuln.get("id"),
                "file_path": filename_from_json,
                "line": None, 
                "code_before": code_before, # 파일에서 직접 읽은 코드로 교체
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

