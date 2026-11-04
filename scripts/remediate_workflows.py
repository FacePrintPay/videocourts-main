#!/usr/bin/env python3
"""
remediate_workflows.py — act on the failed-run audit: REMOVE or REFACTOR whatever
is producing deployment failures.

Reads  work/failed_runs/raw.json + failed_runs.csv  (produced by audit_failed_runs.py)
and decides, per repo and per workflow FILE, one of:

  DISABLE   workflow has recent runs and every one failed -> switch it off.
            Reversible: --undo re-enables it. No file is touched, no history changes.
  REFACTOR  workflow sometimes succeeds, or the failure has a known mechanical fix
            -> patch the YAML and commit it to the default branch.
  DELETE    workflow file is dead weight (always fails, auto-generated) -> remove it
            from the default branch. Recoverable from git history / the `sovereign`
            branch snapshot.
  KEEP      healthy, or not enough evidence.

Modes
  --plan                 (default) write the plan, change nothing
  --apply disable        execute DISABLE actions
  --apply refactor       execute REFACTOR actions (commits YAML fixes)
  --apply delete         execute DELETE actions
  --apply all            disable + refactor + delete
  --undo                 re-enable everything this tool disabled (reads its own log)
  --only-repo NAME       restrict (repeatable)
  --only-family REGEX    restrict to workflow files whose path matches
  --min-fails N          only act on workflows with >= N recent failures (default 1)
  --include-mixed        also DISABLE workflows that have some successes (default: no)
  --dry-apply            show the API calls without making them

Every write is appended to work/failed_runs/remediation_log.csv so it can be undone.
"""
import argparse
import csv
import json
import os
import re
import sys
import time
import urllib.error
import urllib.request
from collections import Counter, defaultdict

API = "https://api.github.com"
HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
AUDIT = os.path.join(ROOT, "work", "failed_runs")
TOKEN = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN") or ""
CALLS = [0]


def gh(method, path, body=None, accept="application/vnd.github+json"):
    url = path if path.startswith("http") else API + path
    data = json.dumps(body).encode() if body is not None else None
    for attempt in range(4):
        req = urllib.request.Request(url, data=data, method=method)
        req.add_header("Accept", accept)
        req.add_header("User-Agent", "c25-remediation")
        req.add_header("X-GitHub-Api-Version", "2022-11-28")
        if TOKEN:
            req.add_header("Authorization", "Bearer " + TOKEN)
        if data:
            req.add_header("Content-Type", "application/json")
        CALLS[0] += 1
        try:
            with urllib.request.urlopen(req, timeout=40) as r:
                raw = r.read()
                return r.status, (json.loads(raw) if raw and not isinstance(raw, bytes) or raw[:1] == b"{" or raw[:1] == b"[" else raw.decode("utf-8", "replace"))
        except urllib.error.HTTPError as e:
            payload = e.read().decode("utf-8", "replace")
            if e.code in (403, 429):
                reset = e.headers.get("X-RateLimit-Reset")
                wait = int(e.headers.get("Retry-After", 0) or 0)
                if not wait and reset and reset.isdigit():
                    wait = max(3, min(90, int(reset) - int(time.time()) + 2))
                sys.stderr.write("  rate limited (%s), waiting %ss\n" % (e.code, wait or 20))
                time.sleep(wait or 20)
                continue
            return e.code, payload
        except Exception as e:
            if attempt == 3:
                return 0, str(e)
            time.sleep(2 + attempt * 2)
    return 0, "retries exhausted"


# --------------------------------------------------------------- YAML refactors
# Each fix: (cause-keyword, function(text)->(new_text, note) or None)
def fix_setup_node_cache(text):
    """`cache: npm` (or yarn/pnpm) with no lockfile in the repo -> drop the cache key."""
    new, n = re.subn(r"^\s*cache:\s*(npm|yarn|pnpm)\s*$", "", text, flags=re.M)
    if not n:
        return None
    new = re.sub(r"\n{3,}", "\n\n", new)
    return new, "removed `cache: %s` from setup-node (repo has no lockfile)" % n


def fix_pages_permissions(text):
    """peaceiris/actions-gh-pages or actions/deploy-pages failing with git exit 128
    -> the default GITHUB_TOKEN is read-only; grant contents: write."""
    if not re.search(r"peaceiris/actions-gh-pages|actions/deploy-pages", text):
        return None
    if re.search(r"^\s*permissions:\s*$", text, re.M) and re.search(r"contents:\s*write", text):
        return None
    if re.search(r"^permissions:", text, re.M):
        new = re.sub(r"^permissions:\s*$", "permissions:\n  contents: write", text, count=1, flags=re.M)
    else:
        # insert a top-level permissions block after the `on:`/`name:` header
        m = re.search(r"^(jobs:)", text, re.M)
        if not m:
            return None
        new = text[: m.start()] + "permissions:\n  contents: write\n\n" + text[m.start():]
    if new == text:
        return None
    return new, "added `permissions: contents: write` (git exit 128 = read-only token)"


def fix_vercel_guard(text):
    """amondnet/vercel-action with no VERCEL_TOKEN -> skip the step instead of failing."""
    if not re.search(r"amondnet/vercel-action|vercel-action|vercel deploy", text, re.I):
        return None
    if "VERCEL_TOKEN" not in text:
        return None
    lines = text.split("\n")
    out, changed = [], False
    for i, ln in enumerate(lines):
        out.append(ln)
        if re.match(r"^\s*-\s*(name|uses):", ln) and not changed:
            pass
    # guard every step that uses the vercel action
    new = re.sub(
        r"^(\s*)-\s*name:([^\n]*)\n(\s*)uses:\s*amondnet/vercel-action",
        lambda m: "%s- name:%s\n%s  if: ${{ env.VERCEL_TOKEN != \'\' }}\n%s  uses: amondnet/vercel-action"
        % (m.group(1), m.group(2), m.group(1) + "  ", m.group(3)),
        text, flags=re.M)
    if new == text:
        new = re.sub(r"^(\s*)-\s*uses:\s*amondnet/vercel-action",
                     lambda m: "%s- if: ${{ env.VERCEL_TOKEN != \'\' }}\n%s  uses: amondnet/vercel-action"
                     % (m.group(1), m.group(1)), text, flags=re.M)
    if new == text:
        return None
    return new, "guarded the Vercel step with `if: env.VERCEL_TOKEN != \'\'` so a missing token skips instead of failing"


FIXES = [
    ("lock file is not found", fix_setup_node_cache),
    ("exit code 128", fix_pages_permissions),
    ("github pages", fix_pages_permissions),
    ("vercel", fix_vercel_guard),
]


def build_fix(yaml_text, causes):
    applied, notes, text = [], [], yaml_text
    for cause in causes:
        low = cause.lower()
        for key, fn in FIXES:
            if key in low:
                res = fn(text)
                if res:
                    text, note = res
                    if note not in notes:
                        notes.append(note)
                        applied.append(fn.__name__)
    return (text, notes) if notes else (None, [])


# ------------------------------------------------------------------ planning
def plan(args):
    raw = json.load(open(os.path.join(AUDIT, "raw.json")))
    rows = list(csv.DictReader(open(os.path.join(AUDIT, "failed_runs.csv"))))
    by_repo_runs = defaultdict(list)
    for r in rows:
        by_repo_runs[r["repo"]].append(r)

    actions = []
    for rec in raw:
        repo = rec["repo"]
        if args.only_repo and not any(o == repo or o == repo.split("/")[-1] for o in args.only_repo):
            continue
        runs = rec.get("runs") or []
        if not runs:
            continue
        # group runs by workflow file
        per_file = defaultdict(list)
        for x in runs:
            per_file[x.get("path") or "(unknown)"].append(x)
        # causes recorded for this repo's failures
        causes = {r["suspected_cause"] for r in by_repo_runs.get(repo, [])}
        wf_state = {w["path"]: w for w in (rec.get("workflows") or [])}

        for path, fruns in sorted(per_file.items()):
            if args.only_family and not re.search(args.only_family, path):
                continue
            fails = [x for x in fruns if x["conclusion"] in ("failure", "timed_out", "action_required")]
            oks = [x for x in fruns if x["conclusion"] == "success"]
            if len(fails) < args.min_fails:
                continue
            always_fails = not oks
            state = (wf_state.get(path) or {}).get("state", "?")
            wfid = (wf_state.get(path) or {}).get("id")
            blob = " ".join([
                " ".join((x.get("annotations") or [])) for x in fruns if x.get("annotations")
            ] + [x.get("name") or "" for x in fruns] + list(causes))
            fix_text = None
            notes = []
            if always_fails and not args.include_mixed:
                act = "DISABLE"
            elif fails:
                act = "REFACTOR"
            else:
                continue
            # a mechanical fix upgrades DISABLE -> REFACTOR when we know how to repair it
            if act == "DISABLE":
                yaml_txt = None
                if wfid:
                    st, body = gh("GET", "/repos/%s/contents/%s" % (repo, path.replace(" ", "%20")))
                    if st == 200 and isinstance(body, dict):
                        import base64
                        yaml_txt = base64.b64decode(body.get("content", "")).decode("utf-8", "replace")
                        fix_text, notes = build_fix(yaml_txt, sorted(causes) or [blob[:200]])
                if fix_text:
                    act = "REFACTOR"
            actions.append({
                "repo": repo, "path": path, "workflow_id": wfid or "",
                "workflow_state": state, "recent_runs": len(fruns),
                "failed": len(fails), "succeeded": len(oks),
                "always_fails": always_fails, "action": act,
                "fix_notes": "; ".join(notes),
                "last_failure": max((x.get("created_at") or "" for x in fails), default=""),
                "example_url": (fails[0].get("url") if fails else ""),
                "causes": " | ".join(sorted(causes))[:200],
                "_fix_text": fix_text,
            })
    return actions


def write_plan(actions, path):
    fields = ["repo", "path", "workflow_id", "workflow_state", "recent_runs", "failed",
              "succeeded", "always_fails", "action", "fix_notes", "last_failure",
              "example_url", "causes"]
    with open(path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
        w.writeheader()
        w.writerows(actions)


def apply(actions, mode, args):
    log_path = os.path.join(AUDIT, "remediation_log.csv")
    new_file = not os.path.exists(log_path)
    log = open(log_path, "a", newline="")
    lw = csv.writer(log)
    if new_file:
        lw.writerow(["ts", "repo", "path", "workflow_id", "action", "http", "detail"])
    done = Counter()
    for a in actions:
        act = a["action"]
        if mode != "all" and act.lower() != mode:
            continue
        repo, path, wfid = a["repo"], a["path"], a["workflow_id"]
        if args.dry_apply:
            print("  [dry] %-9s %-46s %s" % (act, repo, path))
            done[act + "(dry)"] += 1
            continue
        if act == "DISABLE":
            if not wfid:
                lw.writerow([time.strftime("%FT%TZ"), repo, path, "", "DISABLE", "SKIP", "no workflow id"])
                done["DISABLE-skipped"] += 1
                continue
            st, body = gh("PUT", "/repos/%s/actions/workflows/%s/disable" % (repo, wfid))
            ok = st in (200, 204)
            lw.writerow([time.strftime("%FT%TZ"), repo, path, wfid, "DISABLE", st, "" if ok else str(body)[:160]])
            done["DISABLE-ok" if ok else "DISABLE-fail"] += 1
            print("  %-9s %-46s %s -> HTTP %s" % ("DISABLE", repo, path, st))
        elif act == "DELETE":
            st, body = gh("GET", "/repos/%s/contents/%s" % (repo, path.replace(" ", "%20")))
            if st != 200 or not isinstance(body, dict):
                lw.writerow([time.strftime("%FT%TZ"), repo, path, wfid, "DELETE", st, "file not found"])
                done["DELETE-skipped"] += 1
                continue
            st2, body2 = gh("DELETE", "/repos/%s/contents/%s" % (repo, path.replace(" ", "%20")),
                            {"message": "chore: remove always-failing workflow %s" % os.path.basename(path),
                             "sha": body.get("sha"), "branch": body.get("branch") or None})
            ok = st2 in (200, 201)
            lw.writerow([time.strftime("%FT%TZ"), repo, path, wfid, "DELETE", st2, "" if ok else str(body2)[:160]])
            done["DELETE-ok" if ok else "DELETE-fail"] += 1
            print("  %-9s %-46s %s -> HTTP %s" % ("DELETE", repo, path, st2))
        elif act == "REFACTOR":
            if not a.get("_fix_text"):
                done["REFACTOR-nofix"] += 1
                lw.writerow([time.strftime("%FT%TZ"), repo, path, wfid, "REFACTOR", "SKIP", "no mechanical fix"])
                continue
            st, body = gh("GET", "/repos/%s/contents/%s" % (repo, path.replace(" ", "%20")))
            if st != 200 or not isinstance(body, dict):
                done["REFACTOR-skipped"] += 1
                continue
            st2, body2 = gh("PUT", "/repos/%s/contents/%s" % (repo, path.replace(" ", "%20")),
                            {"message": "fix(ci): %s" % (a["fix_notes"] or "repair failing workflow"),
                             "content": __import__("base64").b64encode(a["_fix_text"].encode()).decode(),
                             "sha": body.get("sha"), "branch": body.get("branch") or None})
            ok = st2 in (200, 201)
            lw.writerow([time.strftime("%FT%TZ"), repo, path, wfid, "REFACTOR", st2,
                         (a["fix_notes"] if ok else str(body2))[:160]])
            done["REFACTOR-ok" if ok else "REFACTOR-fail"] += 1
            print("  %-9s %-46s %s -> HTTP %s" % ("REFACTOR", repo, path, st2))
        time.sleep(0.15)
    log.close()
    return done


def undo(args):
    log_path = os.path.join(AUDIT, "remediation_log.csv")
    if not os.path.exists(log_path):
        sys.exit("no remediation log to undo")
    rows = list(csv.DictReader(open(log_path)))
    dis = [r for r in rows if r["action"] == "DISABLE" and r["http"] in ("200", "204") and r["workflow_id"]]
    print("re-enabling %d disabled workflows..." % len(dis))
    ok = fail = 0
    for r in dis:
        st, _ = gh("PUT", "/repos/%s/actions/workflows/%s/enable" % (r["repo"], r["workflow_id"]))
        ok += st in (200, 204)
        fail += st not in (200, 204)
        print("  ENABLE %-46s %s -> HTTP %s" % (r["repo"], r["path"], st))
        time.sleep(0.1)
    print("re-enabled %d, failed %d" % (ok, fail))
    print("note: DELETE and REFACTOR are undone with git (revert the commit, or restore")
    print("      the file from the `sovereign` branch snapshot created earlier).")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--plan", action="store_true", default=True)
    ap.add_argument("--apply", choices=["disable", "refactor", "delete", "all"], default=None)
    ap.add_argument("--undo", action="store_true")
    ap.add_argument("--dry-apply", action="store_true")
    ap.add_argument("--only-repo", action="append", default=[])
    ap.add_argument("--only-family", default=None)
    ap.add_argument("--min-fails", type=int, default=1)
    ap.add_argument("--include-mixed", action="store_true")
    ap.add_argument("--out", default=os.path.join(AUDIT, "remediation_plan.csv"))
    a = ap.parse_args()

    if a.undo:
        if not TOKEN:
            sys.exit("GITHUB_TOKEN not set")
        undo(a)
        return
    if not TOKEN and not a.dry_apply:
        sys.exit("GITHUB_TOKEN not set (needed to plan: it reads workflow YAML)")

    actions = plan(a)
    write_plan(actions, a.out)
    c = Counter(x["action"] for x in actions)
    print("\n=== plan: %d workflow targets across %d repos" % (len(actions), len({x["repo"] for x in actions})))
    for k, v in c.most_common():
        print("    %-10s %d" % (k, v))
    print("    wrote %s" % a.out)
    fam = Counter(os.path.basename(x["path"]) for x in actions)
    print("    top workflow files:", fam.most_common(8))

    if a.apply:
        print("\n=== applying %s%s" % (a.apply, " (DRY)" if a.dry_apply else ""))
        done = apply(actions, a.apply, a)
        print("    ", dict(done))
        print("    log: %s" % os.path.join(AUDIT, "remediation_log.csv"))
    print("api calls: %d" % CALLS[0])


if __name__ == "__main__":
    main()
