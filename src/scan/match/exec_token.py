#XSS 실행 식별 토큰 - 우리 payload의 dialog와 페이지 자체 dialog를 구분하는 case별 숫자 nonce
from __future__ import annotations

import re
import secrets

# alert/prompt/confirm 인자만 치환, 이중 인코딩(%253Ealert) 대응 위해 \b 미사용
_DIALOG_PAREN = re.compile(r"(alert|prompt|confirm)\s*\(([^)]*)\)")
_DIALOG_TEMPLATE = re.compile(r"(alert|prompt|confirm)\s*`([^`]*)`")


# 10자리 숫자 토큰 생성 - 따옴표 문맥에서도 문법이 안 깨지고, case마다 새로 만들어 다른 case 발화와 구분
def new_exec_token() -> str:
    return str(1_000_000_000 + secrets.randbelow(9_000_000_000))


# payload의 dialog 호출 인자를 토큰으로 치환
def inject_exec_token(payload: str, token: str) -> str:
    payload = payload.replace("{token}", token)  # 정규식으로 못 잡는 간접 호출(setTimeout, onerror=alert 등)은 룰의 {token} 자리 치환
    payload = _DIALOG_PAREN.sub(lambda m: f"{m.group(1)}({token})", payload)  # alert(...) -> alert(token)
    payload = _DIALOG_TEMPLATE.sub(lambda m: f"{m.group(1)}`{token}`", payload)  # 백틱 호출은 괄호 차단 우회용이라 백틱 유지
    return payload
