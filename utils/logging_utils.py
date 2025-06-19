import os
import logging
from datetime import datetime

def setup_logging(vuln_id):
    """ID별로 로그 파일을 설정합니다."""
    log_dir = 'log'
    if not os.path.exists(log_dir):
        os.makedirs(log_dir)
    
    # ID가 없는 경우를 대비한 기본 로그 파일 이름
    log_filename = f"{vuln_id}-{datetime.now().strftime('%Y-%m-%d')}.log" if vuln_id else f"agent_run-{datetime.now().strftime('%Y-%m-%d')}.log"
    
    # 기존 핸들러 제거
    for handler in logging.root.handlers[:]:
        logging.root.removeHandler(handler)
        
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(os.path.join(log_dir, log_filename)),
            logging.StreamHandler()
        ]
    )

def ensure_reports_dir():
    """보고서 디렉토리가 존재하는지 확인하고 없으면 생성합니다."""
    if not os.path.exists('reports'):
        os.makedirs('reports') 