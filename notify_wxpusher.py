"""
WxPusher notification step for GitHub Actions.
Reads output/status.json and pushes a summary to WxPusher SPT via the simple-push API.
Runs as the last step of the Action:  python notify_wxpusher.py
"""
import json, os, sys, urllib.request
from datetime import datetime, timezone

WXPUSHER_SPT = os.environ.get("CFA_WXPUSHER_SPT", "SPT_0jSa4BhaRevCwrjNRQen3Y6yGiff")
WXPUSHER_API = "https://wxpusher.zjiecode.com/api/send/message/simple-push"
STATUS_FILE  = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "output", "status.json")
REPO_RAW     = "https://raw.githubusercontent.com/bruce0madao/clash-free-auto/master/output/clash.yaml"

def load_status():
    try:
        with open(STATUS_FILE, encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        return {"error": str(e)}

def build_content(status):
    ok = not status.get("error")
    ts = status.get("updated_at", "?")
    lines = [
        "<h2>Clash 免费节点自动更新</h2>",
        "<p>状态：" + ("正常" if ok else "异常 - " + status["error"]) + "</p>",
        "<p>时间：" + ts + "</p>",
        "<table border='1' cellpadding='4'>",
        "<tr><td>来源成功/总数</td><td>" + str(status.get("sources_success","?")) + " / " + str(status.get("sources_total","?")) + "</td></tr>",
        "<tr><td>原始节点</td><td>" + str(status.get("raw_nodes","?")) + "</td></tr>",
        "<tr><td>去重后</td><td>" + str(status.get("deduplicated_nodes","?")) + "</td></tr>",
        "<tr><td>TCP 验证通过</td><td>" + str(status.get("validated_tcp","?")) + "</td></tr>",
        "<tr><td><b>最终发布</b></td><td><b>" + str(status.get("final_nodes","?")) + " 个节点</b></td></tr>",
        "</table>",
        "<p><a href='" + REPO_RAW + "'>Clash 订阅 Raw 链接</a></p>",
        "<p><i>订阅地址（Clash Verge Rev / Mihomo 填入）：</i></p>",
        "<p><code>" + REPO_RAW + "</code></p>",
    ]
    return "\n".join(lines)

def main():
    status = load_status()
    content = build_content(status)
    summary = "Clash 节点更新 | " + str(status.get("final_nodes","?")) + " 节点 | " + status.get("updated_at","")[:10]

    payload = {
        "content": content,
        "summary": summary,
        "contentType": 2,
        "spt": WXPUSHER_SPT,
    }
    req = urllib.request.Request(
        WXPUSHER_API,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            body = json.loads(resp.read().decode("utf-8","replace"))
            print("[WxPusher] " + json.dumps(body, ensure_ascii=False))
            if not body.get("success"):
                print("[WxPusher] push FAILED - see above")
                sys.exit(1)
    except Exception as e:
        print("[WxPusher] ERR: " + str(e))
        # non-fatal: don't fail the Action just because notification failed
        sys.exit(0)

if __name__ == "__main__":
    main()
