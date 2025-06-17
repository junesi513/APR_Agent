import argparse
import os
import logging
from agents.manager import AVRManagerAgent

def main():
    """
    AVR 에이전트 시스템의 메인 실행 함수입니다.
    """
    # 로깅 기본 설정
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - [%(levelname)s] - (%(module)s) - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )

    # 커맨드 라인 인자 파싱
    parser = argparse.ArgumentParser(description="Automated Vulnerability Repair (AVR) Agent System")
    parser.add_argument(
        "--project-path",
        type=str,
        required=True,
        help="분석하고 수리할 Java 프로젝트의 전체 경로"
    )
    parser.add_argument(
        "--auto-approve",
        action="store_true",
        help="검증된 패치를 사용자 상호작용 없이 자동으로 승인합니다."
    )
    args = parser.parse_args()

    project_path = args.project_path

    # 입력 경로 유효성 검사
    if not os.path.isdir(project_path):
        logging.error(f"Error: The provided project path is not a valid directory: {project_path}")
        return

    logging.info("======================================================")
    logging.info("  Starting Automated Vulnerability Repair (AVR) System  ")
    logging.info("======================================================")

    # AVR 매니저 에이전트 생성 및 워크플로우 실행
    manager = AVRManagerAgent(project_path=project_path, auto_approve=args.auto_approve)
    final_report = manager.run_workflow()

    logging.info("======================================================")
    logging.info("                 AVR System Finished                  ")
    logging.info("======================================================")
    
    print("\n--- Final Summary Report ---")
    print(final_report)
    print("--------------------------")


if __name__ == '__main__':
    main()
