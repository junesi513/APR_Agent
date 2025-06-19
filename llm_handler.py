import logging
import json
import os
import google.generativeai as genai
import re
from typing import Optional

MODEL = None

def configure_gemini():
    """
    config_list.json에서 Gemini API 키를 찾아 모델을 설정합니다.
    이 함수는 에이전트 시작 시 한 번만 호출되어야 합니다.
    """
    global MODEL
    try:
        with open("OAI_CONFIG_LIST") as f: # Corrected file name
            config_data = json.load(f)
        gemini_config = next((config for config in config_data if config.get("model") and "gemini" in config["model"]), None)
        
        if gemini_config and gemini_config.get("api_key"):
            genai.configure(api_key=gemini_config["api_key"])
            MODEL = genai.GenerativeModel('gemini-1.5-pro-latest')
            logging.info("Gemini API가 성공적으로 설정되었습니다.")
        else:
            logging.error("OAI_CONFIG_LIST에서 Gemini API 설정을 찾을 수 없습니다.")
            MODEL = None
    except Exception as e:
        logging.error(f"Gemini 설정 중 오류 발생: {e}")
        MODEL = None

def call_gemini_api(messages: list[dict], system_prompt: str) -> Optional[dict]:
    """
    주어진 메시지 목록과 시스템 프롬프트를 사용하여 Gemini API를 호출하고,
    JSON 응답을 파싱하여 반환합니다.
    """
    if not MODEL:
        logging.error("Gemini 모델이 설정되지 않았습니다.")
        return None

    try:
        # 모델 재생성 대신 system_instruction을 직접 전달
        model_with_prompt = genai.GenerativeModel(
            model_name='gemini-1.5-pro-latest',
            system_instruction=system_prompt
        )
        
        generation_config = genai.types.GenerationConfig(
            candidate_count=1,
            temperature=0.7,
            response_mime_type="application/json",
        )
        
        logging.info("Gemini API 호출...")
        response = model_with_prompt.generate_content(
            messages,
            generation_config=generation_config
        )

        if response.parts:
            response_text = response.parts[0].text
            
            # LLM이 생성한 JSON 문자열에서 불필요한 백슬래시와 제어 문자를 제거합니다.
            cleaned_json_str = re.sub(r'\\(?!["\\/bfnrt]|u[0-9a-fA-F]{4})', r'\\\\', response_text)
            
            # JSON 블록을 추출합니다. (마크다운 형식 대응)
            match = re.search(r"```(json)?\n?(.*)\n?```", cleaned_json_str, re.DOTALL)
            if match:
                json_str = match.group(2)
            else:
                json_str = cleaned_json_str

            try:
                response_json = json.loads(json_str)
                logging.info(f"Gemini API 응답 수신: {json.dumps(response_json, ensure_ascii=False)}")
                return response_json
            except json.JSONDecodeError as e:
                logging.error(f"Gemini API 응답 JSON 파싱 오류: {e}")
                logging.error(f"파싱 실패한 문자열: {json_str}")
                return None
        else:
            logging.warning("Gemini API로부터 비어 있는 응답을 받았습니다.")
            return {"tool": "finish_patch", "parameters": {"reason": "API로부터 유효한 응답을 받지 못했습니다."}}

    except Exception as e:
        logging.error(f"Gemini API 호출 중 오류 발생: {e}")
        return None 