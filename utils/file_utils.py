import json
import os
import logging

def get_vuln_details(vuln_id: int, vul4j_results_path="evaluation/vul4j_results.json") -> dict:
    """
    지정된 ID에 해당하는 취약점 상세 정보를 JSON 파일에서 읽어옵니다.
    """
    logging.info(f"{vul4j_results_path} 파일에서 취약점 정보를 로드합니다.")
    try:
        with open(vul4j_results_path, 'r') as f:
            results = json.load(f)
    except FileNotFoundError:
        logging.error(f"오류: {vul4j_results_path} 파일을 찾을 수 없습니다.")
        return None
    except json.JSONDecodeError:
        logging.error(f"오류: {vul4j_results_path} 파일의 JSON 형식이 잘못되었습니다.")
        return None

    # 결과가 리스트 형태이므로, id가 일치하는 항목을 찾습니다.
    vuln_info = next((item for item in results if str(item.get("id")) == str(vuln_id)), None)

    if not vuln_info:
        logging.error(f"오류: ID {vuln_id}에 해당하는 취약점 정보를 찾을 수 없습니다.")
        return None

    project_dir = os.path.expanduser(f"~/vul4j_test/VUL4J-{vuln_id}")
    
    # files 리스트의 첫 번째 항목에서 파일 경로를 가져옵니다.
    files_list = vuln_info.get("files", [])
    if not files_list:
        logging.error(f"오류: ID {vuln_id}에 대한 정보에서 'files' 리스트를 찾을 수 없거나 비어있습니다.")
        return None
    
    file_path = files_list[0].get("filepath_before")
    if not file_path:
        logging.error(f"오류: ID {vuln_id}의 첫 번째 파일 정보에서 'filepath_before'를 찾을 수 없습니다.")
        return None

    absolute_file_path = os.path.join(project_dir, file_path)

    try:
        with open(absolute_file_path, 'r', encoding='utf-8') as f:
            code_before = f.read()
    except FileNotFoundError:
        logging.error(f"오류: 취약한 파일 원본을 찾을 수 없습니다: {absolute_file_path}")
        return None

    return {
        "id": vuln_id,
        "file_path": file_path,
        "code_before": code_before,
    }

def get_project_cve_id(project_dir: str) -> str:
    """
    프로젝트 디렉토리의 .vul4j.json 파일에서 CVE ID를 읽어옵니다.
    """
    vul4j_info_path = os.path.join(project_dir, ".vul4j.json")
    try:
        with open(vul4j_info_path, 'r') as f:
            data = json.load(f)
            return data.get("cve_id", "N/A")
    except (FileNotFoundError, json.JSONDecodeError):
        return "N/A" 