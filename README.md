# PR Code Quality Reviewer (Azure DevOps + Azure OpenAI)

## Overview
This Python utility analyzes changed **files from an Azure DevOps Pull Request (PR)** and generates a code quality report focused on security, performance, reliability, and maintainability. It also **automatically comments on the PR** with a summary of the report.

**Generated outputs:**
- `report.json` — structured result by file and severity
- `report.md` — Markdown report, ready for reading/sharing
- Working directory: `./work_pr_repo` (copy of the repository/branches for diff)

## How it works (pipeline)
1. Reads PR metadata via Azure DevOps API.
2. Clones the repository, checks out the **target branch** and the **PR branch**.
3. Discovers changed files (`git diff --name-only target...source`).
4. Ignores binaries and large files, splits texts into chunks.
5. Sends each chunk to Azure OpenAI (chat completions) with a review prompt that requires strict JSON.
6. Consolidates *issues* by severity and generates `report.json`/`report.md`.
7. Publishes a **comment on the PR** with the summary (if the PAT has permission).

## Requirements
- **Python** 3.10+
- **Git** installed and authenticated to clone/fetch the repository
- **Azure DevOps PAT** (Personal Access Token) with minimum scopes:
	- **Code (Read)** — to list PR and metadata
	- **Pull Requests (Read & Write)** — to comment on the PR
- **Azure OpenAI** (active resource, chat model deployment, and access key)

> Tip: To avoid interactive password prompts during `git clone/fetch`, configure a Git **credential helper**, for example:
> - Windows: `git config --global credential.helper manager-core`
> - macOS: `git config --global credential.helper osxkeychain`
> - Linux: `git config --global credential.helper store` (or libsecret/manager equivalent)

## Configuration (.env)
Create a `.env` file in the project root (or copy from `.env.example`) and fill in:
```
ADO_ORG=your-company-org
ADO_PROJECT=Project Name (can have spaces)
ADO_REPO=repository-name
ADO_PR_ID=12345
ADO_PAT=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
AZURE_OPENAI_ENDPOINT=https://<your-resource>.openai.azure.com
AZURE_OPENAI_KEY=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
AZURE_OPENAI_DEPLOYMENT=gpt-4o-mini
AZURE_OPENAI_API_VERSION=2024-02-15-preview
```

**Variable Description**
- `ADO_ORG`: organization slug in DevOps (e.g., `contoso`).
- `ADO_PROJECT`: project name (the script automatically URL-encodes it).
- `ADO_REPO`: Git repository name within the project.
- `ADO_PR_ID`: numeric ID of the Pull Request to be analyzed.
- `ADO_PAT`: PAT with the scopes described above.
- `AZURE_OPENAI_ENDPOINT`: Azure OpenAI base endpoint (format `https://<resource>.openai.azure.com`). 
- `AZURE_OPENAI_KEY`: Azure OpenAI key.
- `AZURE_OPENAI_DEPLOYMENT`: chat model deployment name (e.g., `gpt-4o-mini`).
- `AZURE_OPENAI_API_VERSION`: API version (e.g., `2024-02-15-preview`).

> **Security**: Never *commit* `.env`. Use environment variables or *secret stores* in CI/CD.

## Installation
Recommended to use *virtualenv*:
``` bash
python -m venv .venv
# Windows
.venv\Scripts\activate
# Linux/macOS
source .venv/bin/activate

python -m pip install --upgrade pip
pip install requests python-dotenv
```

## Execution
1. Configure .env as above.
2. Ensure Git has access to the repository (credential helper/SSO).
3. Run:
``` bash
python main.py
```

During execution you will see informative logs (AOAI endpoint/model, cloning, file count, etc.). At the end, report.json and report.md files will be created in the project root and a comment will be attempted on the PR.

## Default Parameters and Limits
In the code (main.py), the following limits can be adjusted as needed:
- `MAX_FILE_BYTES = 300_000` — ignores text files larger than 300 KB
- `MAX_CHARS_PER_CHUNK = 10_000` — chunk size per AOAI call
- `MAX_FILES = 200` — maximum files analyzed per execution
- Binary directories/files are ignored by extension heuristics and read attempt

> Note: removed files are not analyzed (no content to review).

## Outputs
- **`report.json`**
General statistics (files, issues by severity) and list of issues by file.
- **`report.md`**
Human-readable summary, grouped by file and severity. Useful for pasting in comments or sending by email.

## Common Errors & Solutions
- `401/403/404 at https://dev.azure.com/...`
	Check PAT scopes, correct org/project/repo/PR, and if the PAT user has access.
- `git clone failed: ...`
	Validate if the built URL is correct and if Git has valid credentials. Configure credential helper.
- `Azure OpenAI error 401/403/404/429/500`
	Check endpoint, key, deployment, and AZURE_OPENAI_API_VERSION. For 429, reduce volume or increase rate limits on the resource.
- `No changed files in the PR.`
	There are no diffs between the PR branch and the target branch.

## CI Usage (Azure Pipelines example)
``` yaml
steps:
	- task: UsePythonVersion@0
	inputs:
		versionSpec: '3.11'
	- script: |
		python -m pip install --upgrade pip
		pip install requests python-dotenv
		python main.py
	env:
		ADO_ORG: $(ADO_ORG)
		ADO_PROJECT: $(ADO_PROJECT)
		ADO_REPO: $(ADO_REPO)
		ADO_PR_ID: $(System.PullRequest.PullRequestId)
		ADO_PAT: $(ADO_PAT) # store as secret
		AZURE_OPENAI_ENDPOINT: $(AOAI_ENDPOINT)
		AZURE_OPENAI_KEY: $(AOAI_KEY) # secret
		AZURE_OPENAI_DEPLOYMENT: $(AOAI_DEPLOYMENT)
		AZURE_OPENAI_API_VERSION: '2024-02-15-preview'
```
> In CI, the build agent already has Git installed. Ensure the PAT/Service Connection has read permission on the repository and permission to comment on the PR.

## Additional Notes
- The *prompt* requires **strict JSON** in the model's response. If parsing fails, a *tooling issue* is created guiding to re-run that *chunk*.
- The script uses the **Chat Completions** API from Azure OpenAI.
- The repository is cloned into `./work_pr_repo`. Cleanup is optional (not automatic).
---
**Author/Script**: refer to `main.py` in the project root.