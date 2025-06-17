import os
import shutil
import subprocess
import logging
import tempfile

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def setup_test_workspace(project_path: str) -> str:
    """
    테스트를 위한 격리된 임시 작업 공간을 생성하고 원본 프로젝트를 복사합니다.

    :param project_path: 원본 프로젝트 경로.
    :return: 생성된 임시 워크스페이스의 경로.
    """
    try:
        if not os.path.isdir(project_path):
            raise FileNotFoundError(f"Project path does not exist or is not a directory: {project_path}")
        
        workspace_path = tempfile.mkdtemp(prefix="avr_workspace_")
        # Copy the entire directory tree
        shutil.copytree(project_path, os.path.join(workspace_path, os.path.basename(project_path)))
        logging.info(f"Created and populated test workspace at: {workspace_path}")
        return os.path.join(workspace_path, os.path.basename(project_path))
    except Exception as e:
        logging.error(f"Failed to setup test workspace: {e}")
        return ""

def apply_patch(workspace_path: str, patch_content: str) -> bool:
    """
    주어진 워크스페이스에 diff 형식의 패치를 적용합니다.
    'git apply' 명령어를 사용합니다.

    :param workspace_path: 패치를 적용할 워크스페이스 경로.
    :param patch_content: diff 형식의 패치 내용.
    :return: 패치 적용 성공 여부.
    """
    logging.info(f"Applying patch to workspace: {workspace_path}")
    patch_file_path = os.path.join(workspace_path, "patch.diff")
    with open(patch_file_path, "w") as f:
        f.write(patch_content)
    
    # 실제 구현 예시:
    # try:
    #     # git 저장소로 초기화해야 'git apply'를 사용할 수 있습니다.
    #     subprocess.run(["git", "init"], cwd=workspace_path, check=True, capture_output=True)
    #     subprocess.run(["git", "apply", patch_file_path], cwd=workspace_path, check=True, capture_output=True, text=True)
    #     logging.info("Patch applied successfully.")
    #     return True
    # except subprocess.CalledProcessError as e:
    #     logging.error(f"Failed to apply patch: {e.stderr}")
    #     return False
    # finally:
    #     os.remove(patch_file_path)

    logging.warning("Skipping actual patch application in test mode.")
    os.remove(patch_file_path)
    return True # 테스트를 위해 항상 성공을 반환합니다.

def run_build(workspace_path: str) -> dict:
    """
    워크스페이스에서 'mvn clean install'을 실행하여 프로젝트를 빌드합니다.

    :param workspace_path: 빌드를 실행할 워크스페이스 경로.
    :return: {"success": bool, "log": "빌드 로그 내용..."}
    """
    logging.info(f"Running build in workspace: {workspace_path}")
    # 실제 구현 예시:
    # try:
    #     process = subprocess.run(
    #         ["mvn", "clean", "install"],
    #         cwd=workspace_path,
    #         check=True,
    #         capture_output=True,
    #         text=True
    #     )
    #     return {"success": True, "log": process.stdout}
    # except subprocess.CalledProcessError as e:
    #     return {"success": False, "log": e.stdout + e.stderr}

    logging.warning("Skipping actual build in test mode.")
    return {"success": True, "log": "Build successful (simulated)."}

def run_vulnerability_test(workspace_path: str, poc_test_command: str) -> dict:
    """
    취약점 해결 여부를 검증하기 위한 특정 테스트(PoC)를 실행합니다.

    :param workspace_path: 테스트를 실행할 워크스페이스 경로.
    :param poc_test_command: PoC 테스트 실행 명령어 (e.g., "mvn test -Dtest=TestSpecificVulnerability")
    :return: {"success": bool, "log": "PoC 테스트 로그..."}
    """
    logging.info(f"Running vulnerability PoC test in: {workspace_path}")
    # 실제 구현 예시:
    # try:
    #     command = poc_test_command.split()
    #     process = subprocess.run(command, cwd=workspace_path, check=True, capture_output=True, text=True)
    #     return {"success": True, "log": process.stdout}
    # except subprocess.CalledProcessError as e:
    #     return {"success": False, "log": e.stdout + e.stderr}

    logging.warning("Skipping actual PoC test in test mode.")
    return {"success": True, "log": "PoC test passed (simulated)."}

def run_regression_tests(workspace_path: str) -> dict:
    """
    프로젝트의 전체 단위 테스트를 실행하여 회귀 오류를 확인합니다.

    :param workspace_path: 테스트를 실행할 워크스페이스 경로.
    :return: {"success": bool, "log": "전체 테스트 로그..."}
    """
    logging.info(f"Running regression tests in: {workspace_path}")
    # 실제 구현 예시:
    # try:
    #     process = subprocess.run(["mvn", "test"], cwd=workspace_path, check=True, capture_output=True, text=True)
    #     return {"success": True, "log": process.stdout}
    # except subprocess.CalledProcessError as e:
    #     return {"success": False, "log": e.stdout + e.stderr}
    
    logging.warning("Skipping actual regression tests in test mode.")
    return {"success": True, "log": "All regression tests passed (simulated)."}


def cleanup_workspace(workspace_path: str):
    """
    사용한 임시 워크스페이스를 삭제합니다.

    :param workspace_path: 삭제할 워크스페이스 경로.
    """
    # 임시 디렉토리의 부모(e.g., /tmp/avr_workspace_xxxxx/)를 삭제해야 합니다.
    parent_dir = os.path.dirname(workspace_path)
    if "avr_workspace_" in parent_dir:
        logging.info(f"Cleaning up workspace: {parent_dir}")
        shutil.rmtree(parent_dir, ignore_errors=True)
    else:
        logging.warning(f"Path {workspace_path} does not seem to be a valid workspace path, skipping cleanup of parent.")
