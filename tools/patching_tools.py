# tools/patching_tools.py

# Patch_Generator_Agent는 패치를 생성하기 위해 원본 파일 내용을 읽어야 합니다.
# 이 기능은 analysis_tools에 이미 구현되어 있으므로, 해당 함수를 가져와 사용합니다.
# 이를 통해 코드 중복을 방지하고 일관성을 유지합니다.

from .analysis_tools import read_file_content

# 별칭(alias)을 사용하여 의도를 더 명확하게 할 수 있습니다.
read_file_for_patch = read_file_content

# 향후 패치 생성 또는 검증과 관련된 도우미 함수가 필요할 경우 여기에 추가할 수 있습니다.
# 예를 들어, 생성된 diff가 유효한 형식인지 확인하는 함수 등입니다.
