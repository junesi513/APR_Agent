import json
import subprocess
import logging
import os

# 로깅 설정
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def run_codeql_scan(project_path: str) -> str:
    """
    (미구현) CodeQL 스캔을 실행하고 결과를 JSON으로 반환하는 더미 함수.
    """
    logging.warning("CodeQL scan is not implemented. Returning dummy data.")
    return "{}" # 빈 JSON 객체 반환

def run_snyk_scan(project_path: str) -> str:
    """
    (미구현) Snyk 스캔을 실행하고 결과를 JSON으로 반환하는 더미 함수.
    """
    logging.warning("Snyk scan is not implemented. Returning dummy data.")
    return "{}" # 빈 JSON 객체 반환

def run_semgrep_scan(project_path: str) -> str:
    """
    지정된 프로젝트 경로에 대해 Semgrep 스캔을 실행하고,
    결과를 JSON 형식의 문자열로 반환합니다.
    """
    logging.info(f"Running Semgrep scan on {project_path}...")
    semgrep_executable = "/home/user/anaconda3/envs/ace4_sijune/bin/semgrep"  # 전체 경로 지정

    if not os.path.exists(semgrep_executable):
        logging.error(f"Semgrep executable not found at {semgrep_executable}")
        return '{"error": "Semgrep executable not found"}'

    try:
        command = [
            semgrep_executable,
            "scan",
            "--config", "auto",
            "--json",
            "."  # 현재 디렉토리(cwd)를 스캔하도록 변경
        ]
        
        # Semgrep 실행
        process = subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=True,
            cwd=project_path  # 작업 디렉토리를 project_path로 설정
        )
        
        logging.info("Semgrep scan completed successfully.")
        return process.stdout

    except FileNotFoundError:
        logging.error("Semgrep command not found. Please ensure Semgrep is installed and in your PATH.")
        return '{"error": "Semgrep not found"}'
    except subprocess.CalledProcessError as e:
        logging.error(f"Semgrep scan failed with exit code {e.returncode}.")
        logging.error(f"Semgrep stderr:\n{e.stderr}")
        return f'{{"error": "Semgrep scan failed", "details": {json.dumps(e.stderr)}}}'
    except Exception as e:
        logging.error(f"An unexpected error occurred during Semgrep scan: {e}")
        return f'{{"error": "An unexpected error occurred", "details": "{e}"}}'
