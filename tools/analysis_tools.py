import logging

def read_file_content(file_path: str) -> str:
    """
    지정된 파일 경로의 전체 내용을 문자열로 읽어 반환합니다.

    :param file_path: 읽을 파일의 경로.
    :return: 파일의 전체 내용 또는 에러 메시지.
    """
    logging.info(f"Reading content from file: {file_path}")
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            return f.read()
    except FileNotFoundError:
        logging.error(f"File not found at {file_path}")
        return f"Error: File not found at {file_path}"
    except Exception as e:
        logging.error(f"Error reading file {file_path}: {e}")
        return f"Error reading file: {e}"

def get_code_context(file_path: str, line_number: int, span: int = 10) -> str:
    """
    지정된 파일의 특정 라인 주변 코드를 지정된 줄 수(span)만큼 가져옵니다.
    중심 라인을 포함하여 위, 아래로 각각 span 만큼의 라인을 추출합니다.

    :param file_path: 대상 파일 경로.
    :param line_number: 중심이 될 라인 번호.
    :param span: 주변에 가져올 코드 라인 수.
    :return: 중심 라인과 주변 코드가 포함된 문자열.
    """
    logging.info(f"Getting code context from {file_path} around line {line_number} with span {span}")
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            lines = f.readlines()
        
        start = max(0, line_number - 1 - span)
        end = min(len(lines), line_number + span)
        
        context_lines = lines[start:end]
        
        # Add line numbers for better context
        context_with_line_numbers = ""
        for i, line in enumerate(context_lines, start=start + 1):
            prefix = ">> " if i == line_number else "   "
            context_with_line_numbers += f"{prefix}{i:4d}: {line}"
            
        return context_with_line_numbers

    except FileNotFoundError:
        logging.error(f"File not found at {file_path}")
        return f"Error: File not found at {file_path}"
    except Exception as e:
        logging.error(f"Error getting code context from {file_path}: {e}")
        return f"Error getting code context: {e}"
