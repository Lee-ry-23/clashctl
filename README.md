# clashctl

A local terminal interface for Clash Verge and Mihomo. Browse nodes, compare download performance, connect to a cached winner, and inspect the rules used by active websites.

## Requirements

- Python 3.12 or later.
- Clash Verge Rev with its Mihomo core running and its HTTP controller enabled.
- macOS for automatic discovery and clipboard integration. Explicit `--config` and `--core` paths are available for other Unix installations; these have not received the same end-to-end validation. Windows is currently unsupported.
- TUN disabled during isolated node benchmarks, so that the live tunnel cannot intercept the benchmark core's traffic. Reading status and manual switching remain available with TUN enabled.

Mihomo and a proxy subscription are supplied by the user. Neither is bundled in this package.

## Install

Install [uv](https://docs.astral.sh/uv/getting-started/installation/), download a wheel from this repository's Releases page, and run:

```sh
uv tool install ./clashctl-0.1.0-py3-none-any.whl
clashctl
```

The tagged GitHub source can also be installed directly:

```sh
uv tool install git+https://github.com/Lee-ry-23/clashctl.git@v0.1.0
clashctl
```

To run a source checkout:

```sh
uv sync --frozen
uv run clashctl
```

On macOS, the program discovers the installed Clash Verge runtime configuration and reads its controller secret locally. For another layout, supply the runtime configuration and core executable:

```sh
clashctl --config /path/to/runtime.yaml --core /path/to/mihomo
```

For an environment-provided controller secret, use `--secret-env VARIABLE_NAME`. `clashctl --help` lists global options.

## Interactive commands

| Command | Action |
| --- | --- |
| `/nodes [keyword]` | Browse nodes and their stable ASCII IDs. |
| `/rank [keyword]` | View cached download results immediately. |
| `/connect <id or name>` | Select a node in the current working group. |
| `/best` | Connect the best fresh node from a complete cached scan. |
| `/bench` | Request a new background scan. |
| `/openai [node ID]` | Run independent OpenAI API connectivity checks. |
| `/openai stop` | Stop API checks and keep completed results. |
| `/watch status` | View the background schedule and traffic budget. |
| `/watch pause` / `/watch resume` | Pause or resume scheduled downloads. |
| `/watch interval <minutes>` | Change the scan interval for this session. |
| `/sites [keyword]` | View active Clash connections, matched rules, and routes. |
| `/rules sites [keyword]` | Open the same active-website view. |
| `/rules view [keyword]` | Browse the ordered routing rules. Bare `/rules` also works. |
| `/rules check [hosts]` | Preview rule changes from direct and proxy connectivity checks. |
| `/rules apply` | Apply and verify the preview, saving an undo backup. |
| `/rules refresh [hosts]` | Check websites and apply the resulting changes. |
| `/rules undo` | Restore and verify the preceding rule backup. |
| `/groups` / `/group <id or name>` | Inspect groups and choose the group used for switching. |
| `/mode rule` / `/mode global` / `/mode direct` | Change the live routing mode. |
| `/status` / `/logs` | Inspect controller status and background errors. |
| `/copy` | Copy the full current result, including off-screen rows. |
| `/help` / `/quit` | Show help or exit and stop the worker. |

Command names work with or without a leading slash. Type to see suggestions; Tab selects a completion. The mouse wheel and Page Up / Page Down scroll the result panel. Drag and release to select and copy text. Esc clears selection and resumes display updates; F2 or `/freeze` optionally pauses the display. Up / Down navigate command history. The background follows the terminal's default color.

The sites view refreshes every five seconds while visible. It shows connections currently visible to Clash, rather than a browser history or every connection on the computer. Existing connections retain their routes after a node switch. The rule table displays up to 200 matching rows; `/copy` exports all matches.

## What the measurements mean

The interactive shell scans hourly by default and reuses fresh results on restart. Each node finishes its download rounds and OpenAI check before the next node starts. Scheduled benchmarks use a private Mihomo instance with fixed per-node listeners. They retain the live mode and node selections; switching requires `/connect` or `/best`.

The default interactive scan uses two 1 MiB downloads per node from Cloudflare. Failed attempts can increase the traffic budget. Use `clashctl shell --include 'Demo' --size-mib 4 --interval-minutes 120` to limit nodes, increase sample size, or change the schedule.

Ranking uses the lower-quartile throughput multiplied by the fraction of rounds succeeding without retries. Eligibility also requires all rounds to complete and at least one round to succeed on its first attempt. Median speed, response time, and variation are shown alongside the score. The result is specific to the download destination, sample size, and measurement time.

The OpenAI column requests response headers from `https://api.openai.com/v1/models` without an API key. A normal HTTP 401 proves that the API endpoint responds; `fast` means the response arrived within two seconds. This checks network reachability, rather than authenticated model access or ChatGPT account availability.

Direct command usage is also available:

```sh
clashctl status
clashctl nodes
clashctl bench --include 'Demo' --rounds 2 --size-mib 1
```

The direct command `clashctl best` runs a new benchmark before switching. The interactive `/best` uses fresh cached measurements.

## Local data and privacy

The program reads your runtime configuration, local provider definitions, controller secret, node names, and active connection metadata on your machine. Download and HTTPS probes contact the configured test destinations. It has no built-in telemetry or GitHub upload feature.

Reports are stored locally in `reports/` relative to the working directory; `clashctl shell --cache-dir /path/to/private/cache` selects another location. Reports, rule previews, and backups can contain private node names, domains, paths, or configuration credentials. Treat them as private files. `/copy`, `inspect`, and other exports are explicit local actions; review their contents before sharing.

The repository and release packages include source, fictional test fixtures, build configuration, and this guide. Runtime configurations, provider caches, reports, rule backups, environment files, keys, machine paths, and terminal screenshots are excluded from publication. The build configuration selects package contents explicitly, and the package smoke check validates the resulting archives.

## Development and packaging

```sh
uv sync --frozen --group dev
uv run ruff format --check src tests
uv run ruff check src tests
uv run mypy src tests
uv build
uv run python tests/package_smoke.py --wheel dist/clashctl-0.1.0-py3-none-any.whl --sdist dist/clashctl-0.1.0.tar.gz
uv run python tests/terminal_smoke.py
```

The terminal smoke check uses fictional offline data and restores the macOS clipboard afterwards. Tests named `integration_smoke.py`, `menu_smoke.py`, `service_smoke.py`, and `routing_smoke.py` require an explicitly supplied real node; their docstrings list the commands. They use temporary private cores and real network requests. `performance_smoke.py` reads live Clash state without starting a download benchmark.

These checks run locally. Live-node tests require the user's own configuration.
