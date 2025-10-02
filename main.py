import os
import sys
import re
import json
import base64
import subprocess
import shlex
import textwrap
import hashlib
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple
from urllib.parse import quote
import requests
from dotenv import load_dotenv

load_dotenv()

# ====== CONFIGURATION ======
ORG = os.getenv("ADO_ORG", "")
PROJECT = os.getenv("ADO_PROJECT", "")
REPO_NAME = os.getenv("ADO_REPO", "")
PR_ID = os.getenv("ADO_PR_ID", "")
ADO_PAT = os.getenv("ADO_PAT", "")

AOAI_ENDPOINT = os.getenv("AZURE_OPENAI_ENDPOINT", "")
AOAI_KEY = os.getenv("AZURE_OPENAI_KEY", "")
AOAI_DEPLOYMENT = os.getenv("AZURE_OPENAI_DEPLOYMENT", "gpt-4o-mini")
AOAI_API_VERSION = os.getenv("AZURE_OPENAI_API_VERSION", "2024-02-15-preview")
print(f"[info] Using AOAI endpoint: {AOAI_ENDPOINT}, deployment: {AOAI_DEPLOYMENT}")

# Review limits
MAX_FILE_BYTES = 300_000
MAX_CHARS_PER_CHUNK = 10_000
MAX_FILES = 200

WORKDIR = Path("./work_pr_repo")
REPORT_JSON = Path("report.json")
REPORT_MD = Path("report.md")

# Severity order for sorting
SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1}


def die(msg: str):
    """Exit with error message."""
    print(f"[ERROR] {msg}", file=sys.stderr)
    sys.exit(1)


def auth_header_pat(pat: str) -> Dict[str, str]:
    """Create Azure DevOps authentication header with PAT."""
    token = base64.b64encode(f":{pat}".encode("utf-8")).decode("ascii")
    return {"Authorization": f"Basic {token}"}


def ado_get(url: str, params: Dict[str, Any] = None) -> Dict[str, Any]:
    """Make authenticated GET request to Azure DevOps API."""
    headers = auth_header_pat(ADO_PAT)
    response = requests.get(url, headers=headers, params=params, timeout=60)
    
    if response.status_code in (401, 403, 404):
        die(f"{response.status_code} at {url}\n{response.text[:400]}")
    
    response.raise_for_status()
    return response.json()


def run_command(cmd: str, cwd: Optional[Path] = None) -> Tuple[int, str, str]:
    """Execute shell command and return results."""
    process = subprocess.Popen(
        shlex.split(cmd),
        cwd=str(cwd) if cwd else None,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8"
    )
    stdout, stderr = process.communicate()
    return process.returncode, stdout, stderr


def is_text_file(path: Path) -> bool:
    """Check if file is text-based using extension and content heuristics."""
    binary_extensions = {
        ".png", ".jpg", ".jpeg", ".gif", ".pdf", ".zip", ".exe", ".dll", ".so", ".dylib",
        ".mp4", ".mov", ".avi", ".jar", ".7z", ".gz", ".tar", ".tgz", ".ico", ".ttf", ".otf",
        ".xlsx", ".xls", ".doc", ".docx", ".ppt", ".pptx"
    }
    
    if path.suffix.lower() in binary_extensions:
        return False
        
    try:
        with path.open("r", encoding="utf-8") as file:
            file.read(2048)
        return True
    except (UnicodeDecodeError, IOError):
        return False


def chunk_text(text: str, max_chars: int) -> List[str]:
    """Split text into chunks of specified maximum size."""
    return [text[i:i + max_chars] for i in range(0, len(text), max_chars)]


# ====== 1) Get PR source/target information ======
def get_pr_info() -> Dict[str, Any]:
    """Fetch PR metadata from Azure DevOps."""
    url = f"https://dev.azure.com/{ORG}/{quote(PROJECT, safe='')}/_apis/git/repositories/{REPO_NAME}/pullRequests/{PR_ID}"
    return ado_get(url, params={"api-version": "7.1-preview.1"})


# ====== 2) Clone and checkout branches ======
def ensure_repo(https_url: str, branch: str, target_branch: str) -> None:
    """Ensure repository is cloned and branches are checked out."""
    WORKDIR.mkdir(parents=True, exist_ok=True)
    
    # Clone repository if not exists
    if not (WORKDIR / ".git").exists():
        print("[git] cloning repository...")
        returncode, _, stderr = run_command(f"git clone {shlex.quote(https_url)} .", cwd=WORKDIR)
        if returncode != 0:
            die(f"git clone failed: {stderr}")
    
    # Fetch all references and ensure branches are up to date
    run_command("git fetch --all --prune", cwd=WORKDIR)
    
    # Checkout and update target branch
    run_command(f"git checkout {shlex.quote(target_branch)}", cwd=WORKDIR)
    run_command(f"git pull origin {shlex.quote(target_branch)}", cwd=WORKDIR)
    
    # Fetch and checkout source branch
    run_command(f"git fetch origin {shlex.quote(branch)}:{shlex.quote(branch)}", cwd=WORKDIR)
    returncode, _, stderr = run_command(f"git checkout {shlex.quote(branch)}", cwd=WORKDIR)
    if returncode != 0:
        die(f"source branch checkout failed: {stderr}")
    
    run_command(f"git pull origin {shlex.quote(branch)}", cwd=WORKDIR)


# ====== 3) Get changed files in PR ======
def get_changed_files(source_branch: str, target_branch: str) -> List[str]:
    """Get list of files changed between target and source branches."""
    returncode, stdout, stderr = run_command(
        f"git diff --name-only {shlex.quote(target_branch)}...{shlex.quote(source_branch)}", 
        cwd=WORKDIR
    )
    
    if returncode != 0:
        die(f"git diff failed: {stderr}")
    
    return [line.strip() for line in stdout.splitlines() if line.strip()]


# ====== 4) Azure OpenAI Integration ======
def aoai_chat(messages: List[Dict[str, str]], temperature: float = 0.2) -> str:
    """Send chat completion request to Azure OpenAI."""
    url = f"{AOAI_ENDPOINT}/openai/deployments/{AOAI_DEPLOYMENT}/chat/completions?api-version={AOAI_API_VERSION}"
    
    headers = {
        "api-key": AOAI_KEY,
        "Content-Type": "application/json"
    }
    
    payload = {
        "messages": messages,
        "temperature": temperature
    }
    
    response = requests.post(url, headers=headers, json=payload, timeout=120)
    
    if response.status_code in (401, 403, 404, 429, 500):
        raise RuntimeError(f"Azure OpenAI error {response.status_code}: {response.text[:400]}")
    
    response.raise_for_status()
    data = response.json()
    return data["choices"][0]["message"]["content"]


def build_review_prompt(repo_name: str, file_path: str, code_chunk: str) -> List[Dict[str, str]]:
    """Build system and user prompts for code review."""
    system_prompt = textwrap.dedent("""
    You are a senior code reviewer named Henrique Eduardo Souza. Review code diffs or files focusing on:
      - Edge cases and corrections
      - Security (secrets, injections, path traversal, unsafe deserialization, SSRF, SCARF, XSS, CSRF)
      - Performance and scalability
      - Reliability (exceptions, resource leaks)
      - Maintainability (naming, structure, tests)
      - Cloud/Azure DevOps best practices when relevant
    
    Return STRICT JSON with:
    {
      "file": "<string>",
      "issues": [
        {
          "title": "<short description>",
          "severity": "critical|high|medium|low",
          "line": <int|null>,
          "description": "<What is wrong>",
          "recommendation": "<How to fix>",
          "tags": ["security"|"performance"|"readability"|...]
        }
      ]
    }

    If no issues found: return {"file":"...", "issues":[]}.
    Never include Markdown code fences. Do not write text outside JSON.
    """).strip()

    user_prompt = f"Repository: {repo_name}\nFile: {file_path}\n\nCODE:\n{code_chunk}"
    
    return [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": user_prompt}
    ]


# ====== 5) Post comment to PR (optional) ======
def post_pr_comment(summary_markdown: str) -> None:
    """Post comment to Azure DevOps PR."""
    url = f"https://dev.azure.com/{ORG}/{quote(PROJECT, safe='')}/_apis/git/repositories/{REPO_NAME}/pullRequests/{PR_ID}/threads?api-version=7.1-preview.1"
    
    payload = {
        "comments": [{
            "parentCommentId": 0,
            "content": summary_markdown,
            "commentType": 1
        }],
        "status": 1
    }
    
    headers = auth_header_pat(ADO_PAT) | {"Content-Type": "application/json"}
    response = requests.post(url, headers=headers, json=payload, timeout=60)
    
    if response.status_code not in (200, 201):
        print(f"[warning] Could not post PR comment ({response.status_code}): {response.text[:300]}")


def analyze_file(file_path: Path, relative_path: str) -> Dict[str, Any]:
    """Analyze a single file and return review results."""
    if not file_path.exists() or not is_text_file(file_path):
        return {"file": relative_path, "issues": []}
    
    file_size = file_path.stat().st_size
    if file_size > MAX_FILE_BYTES:
        print(f"[skip] {relative_path} ({file_size} bytes) > MAX_FILE_BYTES")
        return {"file": relative_path, "issues": []}
    
    try:
        code_text = file_path.read_text(encoding="utf-8", errors="replace")
    except Exception as e:
        print(f"[skip] {relative_path}: {e}")
        return {"file": relative_path, "issues": []}
    
    chunks = chunk_text(code_text, MAX_CHARS_PER_CHUNK)
    all_issues = []
    
    for chunk_index, chunk in enumerate(chunks, 1):
        messages = build_review_prompt(REPO_NAME, relative_path, chunk)
        
        try:
            content = aoai_chat(messages)
            result = json.loads(content)
            
            # Use response file name or fallback to original
            file_name = result.get("file") or relative_path
            issues = result.get("issues", [])
            all_issues.extend(issues)
            
        except json.JSONDecodeError as e:
            # Fallback for parsing errors
            all_issues.append({
                "title": f"AI Review (chunk {chunk_index}) parse error",
                "severity": "low",
                "line": None,
                "description": f"Failed to parse response as JSON: {e}",
                "recommendation": "Rerun review for this chunk.",
                "tags": ["tooling"]
            })
        except Exception as e:
            print(f"[error] AOAI processing failed for {relative_path} chunk {chunk_index}: {e}")
            continue
    
    return {"file": relative_path, "issues": all_issues}


def generate_reports(results: List[Dict[str, Any]], source_branch: str, target_branch: str) -> Dict[str, int]:
    """Generate JSON and Markdown reports."""
    # Calculate statistics
    total_issues = sum(len(file_result["issues"]) for file_result in results)
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    
    for file_result in results:
        for issue in file_result["issues"]:
            severity = (issue.get("severity") or "low").lower()
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
    
    # Generate JSON report
    report_data = {
        "org": ORG,
        "project": PROJECT,
        "repo": REPO_NAME,
        "prId": PR_ID,
        "sourceBranch": source_branch,
        "targetBranch": target_branch,
        "totals": {
            "files": len(results),
            "issues": total_issues,
            **severity_counts
        },
        "results": results
    }
    
    REPORT_JSON.write_text(
        json.dumps(report_data, ensure_ascii=False, indent=2),
        encoding="utf-8"
    )
    
    # Generate Markdown report
    markdown_lines = [
        "# Code Quality Report",
        f"- **Org/Project/Repo**: `{ORG}/{PROJECT}/{REPO_NAME}`",
        f"- **PR**: `{PR_ID}`",
        f"- **Branches**: `{source_branch}` → `{target_branch}`",
        f"- **Files analyzed**: {len(results)}",
        f"- **Issues**: {total_issues} (critical: {severity_counts['critical']}, "
        f"high: {severity_counts['high']}, medium: {severity_counts['medium']}, "
        f"low: {severity_counts['low']})",
        "\n---\n"
    ]
    
    for file_result in results:
        if not file_result["issues"]:
            continue
            
        markdown_lines.append(f"## `{file_result['file']}`")
        
        # Sort issues by severity
        sorted_issues = sorted(
            file_result["issues"],
            key=lambda x: SEVERITY_ORDER.get((x.get('severity') or 'low').lower(), 1),
            reverse=True
        )
        
        for issue in sorted_issues:
            severity = issue.get('severity', 'low').upper()
            title = issue.get('title', 'Issue')
            line_info = f" (line {issue['line']})" if issue.get("line") else ""
            
            markdown_lines.append(f"- **[{severity}]** {title}{line_info}")
            markdown_lines.append(f"  - *Description*: {issue.get('description', '')}")
            markdown_lines.append(f"  - *Recommendation*: {issue.get('recommendation', '')}")
            
            tags = issue.get("tags") or []
            if tags:
                markdown_lines.append(f"  - *Tags*: {', '.join(tags)}")
        
        markdown_lines.append("")
    
    if total_issues == 0:
        markdown_lines.append("No issues found in analyzed files.")
    
    REPORT_MD.write_text("\n".join(markdown_lines), encoding="utf-8")
    
    return severity_counts


# ====== MAIN EXECUTION ======
def main():
    """Main execution function."""
    # Validate configuration
    required_env_vars = {
        "ADO_ORG": ORG,
        "ADO_PROJECT": PROJECT, 
        "ADO_REPO": REPO_NAME,
        "ADO_PR_ID": PR_ID,
        "ADO_PAT": ADO_PAT,
        "AZURE_OPENAI_ENDPOINT": AOAI_ENDPOINT,
        "AZURE_OPENAI_KEY": AOAI_KEY,
        "AZURE_OPENAI_DEPLOYMENT": AOAI_DEPLOYMENT
    }
    
    missing_vars = [var for var, value in required_env_vars.items() if not value]
    if missing_vars:
        die(f"Missing required environment variables: {', '.join(missing_vars)}\n"
            f"Configure .env with ADO_* and AZURE_OPENAI_* (see instructions at the top).")
    
    # 1) Get PR information
    print("[step] Fetching PR information...")
    pr_info = get_pr_info()
    source_ref = pr_info["sourceRefName"]  # e.g., refs/heads/feature/x
    target_ref = pr_info["targetRefName"]  # e.g., refs/heads/main
    source_branch = source_ref.replace("refs/heads/", "")
    target_branch = target_ref.replace("refs/heads/", "")
    
    # 2) Setup authenticated repository URL and ensure repository
    project_encoded = quote(PROJECT, safe="")
    repo_url = f"https://{ORG}@dev.azure.com/{ORG}/{project_encoded}/_git/{REPO_NAME}"
    
    print("[step] Setting up repository...")
    ensure_repo(repo_url, source_branch, target_branch)
    
    # 3) Get changed files
    print("[step] Identifying changed files...")
    changed_files = get_changed_files(source_branch, target_branch)
    
    if not changed_files:
        print("No changed files in PR.")
        REPORT_JSON.write_text(
            json.dumps({"summary": "no changes", "files": []}, ensure_ascii=False, indent=2),
            encoding="utf-8"
        )
        REPORT_MD.write_text(
            "# Code Quality Report\n\nNo changes detected.\n", 
            encoding="utf-8"
        )
        return
    
    if len(changed_files) > MAX_FILES:
        print(f"[warning] PR has {len(changed_files)} files; analyzing first {MAX_FILES}.")
        changed_files = changed_files[:MAX_FILES]
    
    # 4) Analyze files via Azure OpenAI
    print(f"[step] Analyzing {len(changed_files)} files...")
    review_results = []
    
    for relative_path in changed_files:
        file_path = WORKDIR / relative_path
        print(f"[analyze] Processing {relative_path}...")
        result = analyze_file(file_path, relative_path)
        review_results.append(result)
    
    # 5) Generate reports
    print("[step] Generating reports...")
    severity_counts = generate_reports(review_results, source_branch, target_branch)
    
    total_issues = sum(severity_counts.values())
    print(f"[success] Generated {REPORT_JSON} and {REPORT_MD}")
    
    # 6) Post comment to PR
    try:
        with REPORT_MD.open("r", encoding="utf-8") as file:
            report_content = file.read()
        
        post_pr_comment(report_content)
        print("[success] Comment posted to PR.")
    except Exception as e:
        print(f"[warning] Could not post PR comment: {e}")


if __name__ == "__main__":
    main()