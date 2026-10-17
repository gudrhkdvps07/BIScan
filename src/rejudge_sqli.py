import json
import os
from collections import Counter
from dataclasses import asdict

from analyzer.sqli_detector import analyze_family
from utilities.file_utils import append_jsonl

# 재판정할 실행 결과 폴더 (None이면 results 아래 가장 최근 폴더)
RUN_DIR = None
STAGES = (0, 1, 2, 3)
_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_RESULTS_ROOT = os.path.join(_PROJECT_ROOT, "results")


# RUN_DIR이 비어 있으면 results 아래 가장 최근 collection_* 폴더 선택
def _resolve_run_dir() -> str:
    if RUN_DIR:
        return RUN_DIR
    names = sorted(n for n in os.listdir(_RESULTS_ROOT) if n.startswith("collection_"))
    return os.path.join(_RESULTS_ROOT, names[-1])


# 단계별로 판정이 실제로 읽는 응답 목록 (기준 응답 + 공격 응답, E1부터 기준 2회 비교용 1건 추가, E2부터 대조 응답 포함)
# 판정부 호출이 아니라 판정부 코드 읽기 기준의 집계라, 판정부가 바뀌면 이 규칙도 함께 확인 필요
def _used_responses(fam: dict, stage: int) -> list[dict]:
    ok = [m for m in fam.get("mutations", []) if m.get("send_status") == "ok"]
    technique = str(fam.get("technique") or "")
    if technique.startswith("boolean"):
        is_control = lambda m: (m.get("case") or {}).get("role") == "control"
    elif technique.startswith("time"):
        is_control = lambda m: ((m.get("case") or {}).get("role") or (m.get("case") or {}).get("step")) == "control"
    else:
        is_control = lambda _: False  # 오류 계열은 대조 응답 개념이 없고 모든 단계에서 같은 응답을 사용
    used = [m for m in ok if stage >= 2 or not is_control(m)]
    baseline = [fam["baseline"]] if fam.get("baseline") else []
    if technique.startswith("boolean") and stage >= 1 and fam.get("baseline_match_ratio") is not None:
        baseline.append(fam["baseline"])  # 기준 응답 2회 비교분 (두 번째 기준 응답은 별도 저장이 없어 같은 응답으로 대신 계수)
    return baseline + used


# request_results.jsonl의 SQLi family를 단계별로 다시 판정해 findings_E{n}.jsonl로 저장
def rejudge(run_dir: str) -> dict[int, Counter]:
    with open(os.path.join(run_dir, "request_results.jsonl"), encoding="utf-8") as f:
        families = [fam for fam in map(json.loads, f) if fam.get("vuln_type") == "sqli" and fam.get("mutations")]  # 준비 실패 줄 등 변형 없는 줄 제외

    summary = {}
    for stage in STAGES:
        out_path = os.path.join(run_dir, f"findings_E{stage}.jsonl")
        if os.path.exists(out_path):
            os.remove(out_path)  # append_jsonl은 이어쓰기라 재실행 시 중복 방지
        counts = Counter()
        used_requests, used_elapsed = 0, 0.0
        for fam in families:
            try:
                findings = analyze_family(fam, stage=stage)
            except Exception as e:  # 한 family 실패가 전체 재판정을 막지 않도록 기록 후 계속
                print(f"[ERROR] E{stage} 재판정 실패: family={fam.get('family_id')} - {e}")
                counts["error"] += 1
                continue
            for finding in findings:
                append_jsonl(out_path, {**asdict(finding), "sqli_stage": f"E{stage}"})
                counts[finding.final_status] += 1
            used = _used_responses(fam, stage)
            used_requests += len(used)
            used_elapsed += sum(float(r.get("elapsed") or 0.0) for r in used)
        summary[stage] = {"verdicts": dict(counts), "used_requests": used_requests, "used_elapsed": round(used_elapsed, 2)}
        print(f"[REJUDGE] E{stage} -> {out_path} {summary[stage]}")
    with open(os.path.join(run_dir, "sqli_stage_summary.json"), "w", encoding="utf-8") as f:
        json.dump({f"E{s}": v for s, v in summary.items()}, f, ensure_ascii=False, indent=2)
    return summary


if __name__ == "__main__":
    rejudge(_resolve_run_dir())
