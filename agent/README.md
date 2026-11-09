# Microsoft Foundry Security Review Agent

A Python command-line application that uses Agno and a Foundry-hosted Anthropic Claude deployment to review source code and configuration files in a ZIP archive.

## Overview

[agent.py](agent.py) runs a two-stage security review:

1. **Scan:** asks Claude to inspect eligible files in a selected ZIP archive and return a JSON array of vulnerability findings.
2. **Guidance:** reads the saved findings, asks Claude for remediation guidance using the same archive, and builds a SARIF 2.1.0 report.

This directory contains the application. Azure infrastructure is provisioned separately by the [Terraform configuration in `deploy`](../deploy/README.md).

## Features

- Read-only archive tools list entries and read UTF-8 text without extracting or executing archive contents.
- File reads enforce a **1,000,000-byte uncompressed limit** and reject non-UTF-8 content and text containing null bytes.
- Separate scan and guidance modes save JSON results for subsequent processing.
- Guidance processing adds finding GUIDs and wraps results in a SARIF 2.1.0 document.
- Console and timestamped file logging include model responses, run IDs, and available token and duration metrics.
- Both agents use a configured maximum response budget of `16,384` tokens.

## Requirements

- **Python 3.10 or later** for the script's type syntax; installed dependencies may require a newer version.
- A deployed Claude model in Microsoft Foundry, its deployment name, account endpoint, and API key.
- Network access to the Foundry endpoint and, for the guidance validation step, the OASIS SARIF schema URL.
- A local, valid `.zip` archive containing the source or configuration to review. No sample archive is currently included.

[requirements.txt](requirements.txt) declares these dependencies without version pins:

| Library | Purpose |
| --- | --- |
| `agno` | Agent orchestration, tool calls, and the Azure Claude model adapter |
| `anthropic` | Claude API client used by the model adapter |
| `jsonschema` | SARIF schema validation |
| `requests` | Downloads the SARIF schema |

The script also imports `urllib3` for HTTP retries; it is installed as a dependency of `requests`.

## Usage

### 1. Clone and install dependencies

The following commands use Bash on macOS or Linux:

```bash
git clone https://github.com/jaredmmartin/microsoft-foundry-agent.git
cd microsoft-foundry-agent/agent
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
mkdir -p files/out
```

If the repository is already cloned, start from its `agent` directory. Create `files/out` before running: the script creates `logs` automatically but does not create the output directory.

### 2. Configure the Foundry connection

The script reads `CLAUDE_DEPLOYMENT_NAME` directly. Its Agno Azure Claude adapter reads the `ANTHROPIC_FOUNDRY_*` connection variables described in the [Agno provider documentation](https://docs.agno.com/models/providers/cloud/azure-foundry-claude/overview).

| Environment variable | Required | Description |
| --- | --- | --- |
| `CLAUDE_DEPLOYMENT_NAME` | Yes | Azure model deployment name passed to `Claude(id=...)` |
| `ANTHROPIC_FOUNDRY_API_KEY` | Yes for this setup | Foundry account API key |
| `ANTHROPIC_FOUNDRY_BASE_URL` | One endpoint option | Full Anthropic API base URL |
| `ANTHROPIC_FOUNDRY_RESOURCE` | Alternative to base URL | Foundry account resource name; use only one endpoint option |
| `LOGLEVEL` | No | Python logging level; defaults to `INFO` |

For an existing deployment, export the values in your shell:

```bash
export CLAUDE_DEPLOYMENT_NAME="<deployment-name>"
unset ANTHROPIC_FOUNDRY_RESOURCE
export ANTHROPIC_FOUNDRY_BASE_URL="https://<custom-subdomain>.services.ai.azure.com/anthropic"
read -r -s -p "Foundry API key: " ANTHROPIC_FOUNDRY_API_KEY
echo
export ANTHROPIC_FOUNDRY_API_KEY
export LOGLEVEL="INFO"
```

Alternatively, if you have already applied this repository's Terraform configuration, obtain the names, endpoint, and key from the `agent` directory. This requires Terraform state in `../deploy`, Azure CLI authentication to the target subscription, and permission to list the account keys:

```bash
export CLAUDE_DEPLOYMENT_NAME="$(terraform -chdir=../deploy output -raw cognitive_deployment_name)"
unset ANTHROPIC_FOUNDRY_RESOURCE
export ANTHROPIC_FOUNDRY_BASE_URL="$(terraform -chdir=../deploy output -raw cognitive_deployment_url)"
export ANTHROPIC_FOUNDRY_API_KEY="$(az cognitiveservices account keys list \
  --resource-group "$(terraform -chdir=../deploy output -raw resource_group_name)" \
  --name "$(terraform -chdir=../deploy output -raw cognitive_account_name)" \
  --query key1 --output tsv)"
```

The application does not load `.env` files or configure an Entra token provider. Export variables in the shell used to run it.

### 3. Scan an archive

Replace the path with your own ZIP archive:

```bash
python agent.py --mode scan --path "/absolute/path/to/automation.zip"
```

The scan writes `files/out/findings.json`. It parses the model response as JSON and checks that it is an array; this does not establish complete scan coverage or validate individual findings against SARIF.

### 4. Generate remediation guidance

After a successful scan, use the **same archive**:

```bash
python agent.py --mode guidance --path "/absolute/path/to/automation.zip"
```

Guidance mode reads `files/out/findings.json`, writes `files/out/guidance.json`, and constructs `files/out/sarif.json`. Each invocation overwrites its corresponding output files. The code does not record which archive produced the findings, so keep the archive and findings paired yourself.

### Command-line options

| Option | Default | Description |
| --- | --- | --- |
| `-m`, `--mode` | `scan` | Choose `scan` or `guidance` |
| `-p`, `--path` | Required | Existing file with a `.zip` extension and valid ZIP contents |
| `-d`, `--debug` | Disabled | Enable Agno agent debug mode |
| `-h`, `--help` | — | Display command-line help |

```bash
python agent.py --help
python agent.py --mode scan --path "/absolute/path/to/automation.zip" --debug
```

### Outputs and current limitations

All generated paths are relative to the directory containing `agent.py`, regardless of the shell's working directory:

| Path | Contents |
| --- | --- |
| `files/out/findings.json` | Scan response as JSON |
| `files/out/guidance.json` | Guidance response as JSON |
| `files/out/sarif.json` | Constructed SARIF 2.1.0 report |
| `logs/<timestamp>.log` | Invocation logs, including raw model responses |

**SARIF validation currently fails:** `validate_sarif_file()` calls `.json()` on the HTTP response and then calls `.raise_for_status()` on the decoded object. A successful schema download therefore leads to an `AttributeError`, after the SARIF file has been written. Guidance mode then exits with status `1`. Treat the generated report as unvalidated until this implementation issue is fixed.

Guidance processing also expects findings to contain `ruleId` and location fields including `startLine` and `endLine`; malformed model output can stop report generation. Invalid or incomplete JSON is logged and reported as an error. Model findings require review, and a completed invocation does not guarantee that every eligible file was inspected.

## Documentation

- [Agno Azure AI Foundry Claude adapter](https://docs.agno.com/models/providers/cloud/azure-foundry-claude/overview)
- [Anthropic Python SDK](https://github.com/anthropics/anthropic-sdk-python)
- [Deploy and use Claude models in Microsoft Foundry](https://learn.microsoft.com/en-us/azure/foundry/foundry-models/how-to/use-foundry-models-claude)
- [Python virtual environments](https://docs.python.org/3/library/venv.html)
- [Requests](https://requests.readthedocs.io/en/latest/)
- [jsonschema](https://python-jsonschema.readthedocs.io/en/stable/)
- [OASIS SARIF 2.1.0 schema used by the script](https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json)
- [Terraform deployment instructions](../deploy/README.md)
