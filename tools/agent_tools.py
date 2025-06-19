import os
import shutil
import subprocess
import logging
import json
import ast
import difflib

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def create_report(agent, final_patch_diff, reason):
    """최종 보고서 내용을 생성합니다."""
    log_history = "\n".join(agent.full_log)
    
    # 보고서에 시스템 프롬프트는 제외하고 사용자 상호작용만 기록
    filtered_log = []
    for log in agent.full_log:
        if not log.startswith("🔧 System\n\n도구 실행 결과:"):
             filtered_log.append(log)

    return f"""# AVR Agent Report (ID: {agent.vuln_id})

## 최종 생성된 패치
```diff
{final_patch_diff}
```

## 에이전트 활동 기록
{''.join(filtered_log)}
"""

def save_report(agent):
    """생성된 보고서를 파일에 저장합니다."""
    report_dir = "reports"
    os.makedirs(report_dir, exist_ok=True)
    report_path = os.path.join(report_dir, f"report_{agent.vuln_id}_{agent.start_time}.md")
    with open(report_path, "w", encoding='utf-8') as f:
        f.write(agent.final_report)
    return report_path

def list_files(agent, directory: str) -> str:
    """지정된 디렉토리 내의 파일 및 폴더 목록을 재귀적으로 나열합니다."""
    abs_path = os.path.join(agent.project_dir, directory)
    if not os.path.isdir(abs_path):
        return f"오류: 디렉토리를 찾을 수 없습니다: {abs_path}"
    
    try:
        output = []
        for root, dirs, files in os.walk(abs_path):
            relative_root = os.path.relpath(root, abs_path)
            if relative_root == '.':
                relative_root = ''

            indent_level = relative_root.count(os.sep)
            indent = '  ' * indent_level
            
            if relative_root:
                output.append(f"{indent}{os.path.basename(relative_root)}/")
            
            sub_indent = '  ' * (indent_level + 1)
            for name in sorted(dirs):
                output.append(f"{sub_indent}{name}/")
            for name in sorted(files):
                output.append(f"{sub_indent}- {name}")
        return "\n".join(output)
    except Exception as e:
        return f"오류: 파일 목록을 나열하는 중 예외 발생: {e}"

def read_file_content(agent, file_path: str) -> str:
    """지정된 파일의 내용을 읽어오고, initial_code와 working_code를 설정합니다."""
    full_path = os.path.join(agent.project_dir, file_path)
    logging.info(f"파일 읽기: {full_path}")
    try:
        with open(full_path, 'r', encoding='utf-8') as f:
            content = f.read()
            agent.initial_code = content
            agent.working_code = content
            agent.file_path = file_path # 에이전트에 현재 작업 파일 경로 저장
            return content
    except Exception as e:
        error_message = f"오류: {file_path} 파일을 읽을 수 없습니다. 이유: {e}"
        logging.error(f"파일 읽기 실패 {full_path}: {e}")
        return error_message

def run_semgrep_scan(agent, file_path: str) -> str:
    """Semgrep으로 코드의 정적 분석을 수행합니다."""
    semgrep_path = "/home/user/anaconda3/envs/ace4_sijune/bin/semgrep"
    target_file = os.path.join(agent.project_dir, file_path)
    command = [semgrep_path, "scan", "--config", "p/java", "--json", target_file]
    
    logging.info(f"Semgrep 실행: {' '.join(command)}")
    
    try:
        process = subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=False 
        )
        
        stdout = process.stdout
        stderr = process.stderr

        if process.returncode != 0:
            if "No files were scanned" in stderr or "No rules detected" in stderr:
                 logging.warning(f"Semgrep 스캔은 실행되었으나, 대상 파일이나 규칙을 찾지 못했습니다: {stderr}")
                 return "Semgrep 스캔은 실행되었으나, 대상 파일이나 규칙을 찾지 못했습니다. 경로와 규칙 설정을 확인하세요."
            else:
                raise subprocess.CalledProcessError(process.returncode, command, output=stdout, stderr=stderr)

        if stdout and stdout.strip():
            logging.info(f"Semgrep 스캔 완료")
            return stdout
        else:
            logging.warning("Semgrep이 결과를 반환하지 않았습니다.")
            return "스캔이 완료되었지만, Semgrep이 아무런 결과를 반환하지 않았습니다. 이는 취약점이 없거나 스캔 설정이 특정 유형의 취약점을 감지하지 못했음을 의미할 수 있습니다."

    except subprocess.CalledProcessError as e:
        error_message = f"Semgrep 스캔 중 오류 발생 (종료 코드: {e.returncode}):\n{e.stderr}"
        logging.warning(error_message)
        return error_message
    except FileNotFoundError:
        error_message = f"'semgrep' 명령어를 찾을 수 없습니다. Semgrep이 설치되어 있고 PATH 환경 변수에 경로가 포함되어 있는지 확인하세요. (예: {semgrep_path})"
        logging.error(error_message)
        return error_message

def edit_code(agent, edits: list) -> str:
    """
    메모리 상의 코드를 주어진 편집 목록에 따라 수정합니다.
    LLM이 생성하는 형식(range, new_text)을 직접 처리합니다.
    """
    if not agent.working_code:
        return "오류: `read_file_content`를 사용하여 파일을 먼저 메모리로 읽어야 합니다."

    lines = agent.working_code.splitlines()
    
    # 교체 작업은 라인 번호가 큰 것부터 처리해야 인덱스가 꼬이지 않습니다.
    edits.sort(key=lambda x: x.get('range', {}).get('start', {}).get('line', 0), reverse=True)

    try:
        for edit in edits:
            # LLM이 생성하는 'range'와 'new_text' 키를 사용합니다.
            if 'range' not in edit or 'new_text' not in edit:
                raise KeyError("수정 항목에 'range' 또는 'new_text' 키가 없습니다.")

            start_line = edit['range']['start']['line']
            end_line = edit['range']['end']['line']
            new_text = edit['new_text']

            # 라인 번호는 1-based, 리스트 인덱스는 0-based
            start_idx = start_line - 1
            # LLM이 생성하는 end_line은 포함되지 않는 경우가 많으므로,
            # 삭제할 라인 수를 계산하여 end_idx를 결정하는 것이 더 안정적일 수 있습니다.
            # 하지만 우선은 주어진 그대로 사용합니다.
            end_idx = end_line

            if start_idx < 0 or end_idx > len(lines) or start_idx > end_idx:
                raise IndexError(f"라인 번호({start_line}-{end_line})가 파일 범위({len(lines)})를 벗어났습니다.")
            
            lines[start_idx:end_idx] = new_text.splitlines()

        agent.working_code = "\n".join(lines)
        return "메모리의 코드가 성공적으로 수정되었습니다."
    except (IndexError, ValueError, KeyError, TypeError) as e:
        # LLM이 이상한 형식을 줄 경우를 대비해 예외 처리를 강화합니다.
        error_message = f"코드 수정 중 오류 발생: 잘못된 형식입니다. ({e}). 받은 edits: {edits}"
        logging.error(error_message)
        return error_message

def compile_and_test(agent) -> str:
    """
    메모리에 있는 수정된 코드를 파일에 임시로 쓰고, 'vul4j compile'를 실행하여 컴파일을 검증합니다.
    검증 후 파일은 항상 원래 상태로 복구됩니다.
    """
    if agent.working_code == agent.initial_code:
        return "코드가 변경되지 않았습니다. 컴파일 검증을 건너뜁니다."

    if not agent.file_path:
        return "오류: 작업 대상 파일이 설정되지 않았습니다. `read_file_content`를 먼저 호출해야 합니다."

    absolute_file_path = os.path.join(agent.project_dir, agent.file_path)
    
    try:
        # 1. 메모리의 코드를 파일에 임시 저장
        logging.info(f"컴파일 검증을 위해 수정된 코드를 파일에 임시 저장: {absolute_file_path}")
        with open(absolute_file_path, 'w', encoding='utf-8') as f:
            f.write(agent.working_code)

        # 2. 컴파일 명령어 실행
        command = f"vul4j compile -d ~/vul4j_test/VUL4J-{agent.vuln_id}"
        logging.info(f"컴파일 명령어 실행: {command}")
        
        process = subprocess.run(
            command,
            shell=True, # 홈 디렉토리(~) 해석을 위해 shell=True 사용
            capture_output=True,
            text=True,
            check=False 
        )
        if process.returncode == 0:
            return f"컴파일 성공:\n{process.stdout}"
        else:
            return f"컴파일 실패 (종료 코드: {process.returncode}):\nSTDOUT:\n{process.stdout}\nSTDERR:\n{process.stderr}"

    except Exception as e:
        return f"컴파일 검증 중 예외 발생: {e}"
    
    finally:
        # 3. 파일을 원본 상태로 복구
        logging.info(f"파일을 원본 상태로 복구합니다: {absolute_file_path}")
        try:
            with open(absolute_file_path, 'w', encoding='utf-8') as f:
                f.write(agent.initial_code)
        except Exception as e_revert:
            logging.error(f"파일 복구 중 치명적인 오류 발생: {e_revert}")
            # 복구 실패는 심각한 문제일 수 있으나, 일단 주된 결과는 컴파일 결과이므로 로그만 남김

def finish_patch(agent, reason: str) -> str:
    """모든 분석과 수정을 마친 후, 최종 보고서를 생성하고 임무를 종료합니다."""
    logging.info(f"패치 프로세스 종료. 이유: {reason}")
    final_patch_diff = "코드 변경 사항이 없습니다."

    absolute_file_path = os.path.join(agent.project_dir, agent.file_path)
    if agent.initial_code != agent.working_code:
        logging.info(f"수정된 내용을 파일에 저장합니다: {absolute_file_path}")
        try:
            with open(absolute_file_path, 'w', encoding='utf-8') as f:
                f.write(agent.working_code)
            logging.info("파일 저장 완료.")
            
            diff = difflib.unified_diff(
                agent.initial_code.splitlines(keepends=True),
                agent.working_code.splitlines(keepends=True),
                fromfile='original',
                tofile='patched'
            )
            final_patch_diff = ''.join(diff)
        except Exception as e:
            error_message = f"파일 저장 또는 diff 생성 중 오류 발생: {e}"
            logging.error(error_message)
            final_patch_diff = error_message
    
    agent.final_report = create_report(agent, final_patch_diff, reason)
    report_path = save_report(agent)
    logging.info(f"최종 보고서 저장 완료: {report_path}")

    agent.is_running = False
    return f"에이전트 작업이 종료되었습니다. 이유: {reason}"

def revert_to_vulnerable(agent) -> str:
    """
    'vul4j' 명령어를 사용하여 프로젝트를 원본 취약점 상태로 되돌립니다.
    성공 시, 에이전트의 내부 코드 상태도 초기화합니다.
    """
    command = f"vul4j apply --version vulnerable -d ~/vul4j_test/VUL4J-{agent.vuln_id}"
    logging.info(f"프로젝트를 원본 상태로 되돌립니다: {command}")

    try:
        process = subprocess.run(
            command,
            shell=True, # 홈 디렉토리(~) 해석을 위해 shell=True 사용
            capture_output=True,
            text=True,
            check=False
        )
        if process.returncode == 0:
            # 성공 시, 에이전트의 코드 상태도 초기화하여 혼동을 방지
            agent.working_code = ""
            agent.initial_code = ""
            agent.file_path = None
            logging.info("프로젝트가 성공적으로 원본 상태로 복구되었습니다.")
            return f"프로젝트가 성공적으로 원본 상태로 복구되었습니다.\n{process.stdout}"
        else:
            error_message = f"프로젝트 복구 실패 (종료 코드: {process.returncode}):\nSTDOUT:\n{process.stdout}\nSTDERR:\n{process.stderr}"
            logging.error(error_message)
            return error_message
    except Exception as e:
        error_message = f"프로젝트 복구 중 예외 발생: {e}"
        logging.error(error_message)
        return error_message

# 모든 함수가 정의된 후, 마지막에 tool_definitions를 구성합니다.
tool_definitions = [
    {
        "name": "revert_to_vulnerable",
        "function": revert_to_vulnerable,
        "description": "프로젝트를 원본 취약점 상태로 되돌려, 깨끗한 환경에서 분석을 시작합니다."
    },
    {
        "name": "list_files",
        "function": list_files,
        "description": "지정된 디렉토리의 파일 목록을 확인합니다."
    },
    {
        "name": "read_file_content",
        "function": read_file_content,
        "description": "파일의 전체 내용을 읽어 메모리에 저장합니다. `initial_code`와 `working_code`가 이 내용으로 설정됩니다."
    },
    {
        "name": "run_semgrep_scan",
        "function": run_semgrep_scan,
        "description": "Semgrep으로 코드의 정적 분석을 수행합니다."
    },
    {
        "name": "edit_code",
        "function": edit_code,
        "description": """메모리 상의 코드를 주어진 편집 목록에 따라 수정합니다.
    LLM이 생성하는 형식(range, new_text)을 직접 처리합니다.
    """
    },
    {
        "name": "finish_patch",
        "function": finish_patch,
        "description": "모든 분석과 수정을 마친 후, 최종 보고서를 생성하고 임무를 종료합니다. 이 함수는 메모리에 있는 최종 수정 코드를 실제 파일에 쓰고, 원본 코드와의 차이점을 담은 diff 리포트를 생성합니다."
    }
]

def find_tool_by_name(name: str):
    """도구 이름으로 `tool_definitions`에서 도구 함수를 찾아 반환합니다."""
    for tool in tool_definitions:
        if tool["name"] == name:
            return tool["function"] # 함수 객체를 직접 반환
    return None

def copy_project_to_workspace(project_path: str, workspace_path: str) -> str:
    """
    Copies the entire project from a source path to a destination workspace.
    This is the first step to create an isolated environment for the agents.
    
    :param project_path: The absolute path to the source project directory.
    :param workspace_path: The path to the directory where the project should be copied.
    :return: A success or failure message.
    """
    logging.info(f"Copying project from {project_path} to {workspace_path}...")
    try:
        # We expect the workspace_path to be the agent's working dir.
        # Let's create a subdirectory within it for the project.
        project_name = os.path.basename(project_path)
        dest_path = os.path.join(workspace_path, project_name)
        
        if os.path.exists(dest_path):
            shutil.rmtree(dest_path)
            
        shutil.copytree(project_path, dest_path)
        logging.info(f"Project copied successfully to {dest_path}")
        return f"Project copied successfully to {dest_path}. All further commands should be run from this directory."
    except Exception as e:
        logging.error(f"Failed to copy project: {e}")
        return f"Failed to copy project: {e}"

def apply_patch(workspace_path: str, patch_content: str) -> str:
    """
    Applies a given diff patch to the code in the workspace.
    It uses 'git apply' and must be run in the project's root directory.

    :param workspace_path: The path to the project workspace where the patch should be applied.
    :param patch_content: The content of the diff patch.
    :return: A success or failure message with logs.
    """
    logging.info(f"Applying patch to workspace: {workspace_path}")
    patch_file_path = os.path.join(workspace_path, "patch.diff")
    with open(patch_file_path, "w") as f:
        f.write(patch_content)
    
    try:
        subprocess.run(["git", "init"], cwd=workspace_path, check=True, capture_output=True, text=True)
        subprocess.run(["git", "add", "."], cwd=workspace_path, check=True, capture_output=True, text=True)
        result = subprocess.run(
            ["git", "apply", "--ignore-whitespace", patch_file_path],
            cwd=workspace_path, 
            check=True, 
            capture_output=True, 
            text=True
        )
        logging.info("Patch applied successfully.")
        return "Patch applied successfully."
    except subprocess.CalledProcessError as e:
        error_log = e.stderr
        logging.error(f"Failed to apply patch: {error_log}")
        return f"Failed to apply patch:\nSTDOUT:\n{e.stdout}\nSTDERR:\n{e.stderr}"
    finally:
        os.remove(patch_file_path)

def run_build_and_tests(workspace_path: str) -> str:
    """
    Runs 'mvn clean install' to build the project and run all tests.
    
    :param workspace_path: The path to the project workspace.
    :return: A success or failure message with logs.
    """
    logging.info(f"Running build and tests in workspace: {workspace_path}")
    try:
        process = subprocess.run(
            ["mvn", "clean", "install"],
            cwd=workspace_path,
            check=True,
            capture_output=True,
            text=True,
            timeout=1200  # 20분 타임아웃
        )
        log = f"Build and tests successful.\nSTDOUT:\n{process.stdout}"
        logging.info(log)
        return log
    except subprocess.CalledProcessError as e:
        logging.error(f"Build and tests failed with error: {e.stderr}")
        return {"status": "failure", "logs": e.stderr}
    except subprocess.TimeoutExpired as e:
        log = f"Build and/or tests timed out: {e}"
        logging.error(log)
        return log

def read_file(file_path: str, workspace_path: str) -> str:
    """
    Reads the content of a specific file within the project workspace.
    
    :param file_path: The relative path of the file from the project root.
    :param workspace_path: The path to the project workspace.
    :return: The content of the file, or an error message.
    """
    full_path = os.path.join(workspace_path, file_path)
    logging.info(f"Reading file: {full_path}")
    try:
        with open(full_path, 'r', encoding='utf-8') as f:
            return f.read()
    except Exception as e:
        logging.error(f"Failed to read file {full_path}: {e}")
        return f"Error: Could not read file {file_path}. Reason: {e}"

def list_files_recursive(workspace_path: str) -> str:
    """
    Lists all files in the workspace recursively.
    
    :param workspace_path: The path to the project workspace.
    :return: A string containing the list of files, or an error message.
    """
    logging.info(f"Listing files recursively in: {workspace_path}")
    try:
        result = subprocess.run(['ls', '-R'], cwd=workspace_path, capture_output=True, text=True, check=True)
        return result.stdout
    except subprocess.CalledProcessError as e:
        logging.error(f"Failed to list files: {e}")
        return f"Error listing files: {e.stderr}"
    except Exception as e:
        logging.error(f"An unexpected error occurred while listing files: {e}")
        return f"An unexpected error occurred: {e}"

def read_file_range(file_path, start_line, end_line):
    """
    Reads a specific range of lines from a file.

    Args:
        file_path (str): The path to the file.
        start_line (int): The starting line number (1-indexed).
        end_line (int): The ending line number (1-indexed).

    Returns:
        str: The content of the specified line range, or an error message.
    """
    try:
        with open(file_path, 'r') as f:
            all_lines = f.readlines()
        
        # Adjust for 0-based indexing
        start_index = start_line - 1
        end_index = end_line

        if start_index < 0 or end_index > len(all_lines):
            return "Error: Line range is out of bounds."

        return "".join(all_lines[start_index:end_index])
    except FileNotFoundError:
        return f"Error: File not found at {file_path}"
    except Exception as e:
        return f"An error occurred: {e}"

def write_file_range(file_path, start_line, end_line, new_content, mode='update'):
    """
    Writes, updates, or deletes a range of lines in a file.

    Args:
        file_path (str): The path to the file.
        start_line (int): The starting line number for the operation (1-indexed).
        end_line (int): The ending line number for the operation (1-indexed).
        new_content (str): The new content to write or insert. For deletion, this can be empty.
        mode (str): 'update' to replace lines, 'delete' to remove lines.

    Returns:
        dict: A status report of the operation.
    """
    try:
        with open(file_path, 'r') as f:
            all_lines = f.readlines()

        start_index = start_line - 1
        end_index = end_line

        if start_index < 0 or start_index > len(all_lines) or end_index < start_index:
            return {"status": "error", "message": "Invalid line range specified."}
        
        new_lines = new_content.splitlines(True) if new_content else []

        if mode == 'update':
            # Replace the specified range with new content
            all_lines[start_index:end_index] = new_lines
        elif mode == 'delete':
            # Delete the specified range
            del all_lines[start_index:end_index]
        else:
            return {"status": "error", "message": f"Invalid mode: {mode}. Use 'update' or 'delete'."}

        with open(file_path, 'w') as f:
            f.writelines(all_lines)
            
        return {"status": "success", "message": f"File {file_path} modified successfully."}
    except FileNotFoundError:
        return {"status": "error", "message": f"File not found at {file_path}"}
    except Exception as e:
        return {"status": "error", "message": f"An error occurred: {e}"}

def extract_ast(file_path):
    """
    Extracts the Abstract Syntax Tree (AST) from a Python file.

    Args:
        file_path (str): The path to the Python file.

    Returns:
        str: A string representation of the AST, or an error message.
    """
    if not file_path.endswith(".py"):
        return "Error: This function currently only supports Python (.py) files."
        
    try:
        with open(file_path, 'r') as f:
            content = f.read()
        tree = ast.parse(content)
        return ast.dump(tree, indent=4)
    except FileNotFoundError:
        return f"Error: File not found at {file_path}"
    except SyntaxError as e:
        return f"Error: Could not parse file {file_path} due to a syntax error: {e}"
    except Exception as e:
        return f"An error occurred while generating AST: {e}"

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

def update_file_content(file_path: str, new_content: str, agent) -> str:
    """메모리 내에서 파일 내용을 업데이트합니다."""
    agent.working_code = new_content
    logging.info(f"파일 '{file_path}'의 내용이 메모리에서 업데이트되었습니다.")
    return f"파일 '{file_path}'의 내용이 메모리에서 성공적으로 업데이트되었습니다."

def apply_patch_to_file(file_path: str, patch_content: str) -> str:
    """
    Applies a given diff patch to the file at the specified path.

    :param file_path: The path to the file to be patched.
    :param patch_content: The content of the diff patch.
    :return: A success or failure message with logs.
    """
    logging.info(f"Applying patch to file: {file_path}")
    patch_file_path = os.path.join(os.path.dirname(file_path), "patch.diff")
    with open(patch_file_path, "w") as f:
        f.write(patch_content)
    
    try:
        result = subprocess.run(
            ["git", "apply", "--ignore-whitespace", patch_file_path],
            cwd=os.path.dirname(file_path),
            check=True,
            capture_output=True,
            text=True
        )
        logging.info("Patch applied successfully.")
        return "Patch applied successfully."
    except subprocess.CalledProcessError as e:
        error_log = e.stderr
        logging.error(f"Failed to apply patch: {error_log}")
        return f"Failed to apply patch:\nSTDOUT:\n{e.stdout}\nSTDERR:\n{e.stderr}"
    finally:
        os.remove(patch_file_path) 