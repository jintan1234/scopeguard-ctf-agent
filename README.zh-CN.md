# ScopeGuard CTF Agent 中文说明

这是一个面向授权 CTF 场景的 Codex/MCP 安全工作区。重点不是“全自动解题”，
而是把 AI Agent 的靶场操作限制在明确范围内，并留下可复现的证据。

## 核心能力

- 每个任务必须显式授权，并绑定精确的 host、port 和 scheme；
- HTTP 重定向逐跳检查；
- Playwright 流量必须经过任务 Scope Proxy；
- Docker 容器默认使用 `--network none`；
- 工具调用、时间、重试和无进展次数有预算限制；
- 命令、HTTP 响应、截图和脚本会进入证据账本；
- 产物使用 SHA-256 固定；
- Flag 区分候选、格式匹配、可复现证据和平台验证。
- `scripts/bootstrap.ps1` 和 `scripts/bootstrap.sh` 负责一键初始化。

## 环境要求

- Python 3.11+
- Git
- Docker Desktop 或 Docker Engine
- Node.js 20+
- Codex

核心控制层只使用 Python 标准库。图片、PCAP、逆向等辅助能力需要
`requirements-core.txt` 中的可选依赖。

## 一键初始化

先安装外部依赖：Python 3.11+、Node.js 20+、Docker、Git 和 Codex。

Windows：

```powershell
cd "C:\你的目录\scopeguard-ctf-agent"
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\bootstrap.ps1 -ConfigureCodex
```

脚本会：

1. 创建 `.venv`；
2. 安装 Python 依赖和项目本身；
3. 执行 `npm ci`；
4. 把 Chromium 安装到仓库内的 Playwright 缓存；
5. 自动生成包含真实项目路径的 `.codex/config.toml`；
6. 运行 32 个测试；
7. 运行离线端到端 Demo。

可选参数：

```text
-TrustProject    将当前目录加入用户级 Codex 信任配置
-BuildAnalysis   构建 analysis Docker 镜像
-SkipBrowser     跳过 Playwright 和浏览器安装
```

Linux/macOS：

```bash
bash scripts/bootstrap.sh --configure-codex
```

初始化完成后，在另一个终端启动 Broker：

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\start-docker-broker.ps1
```

然后在本项目目录运行：

```powershell
codex
```

第一次任务可直接使用：

- `prompts/00-operator.zh-CN.md`
- `prompts/01-start-authorized-task.md`

详细排障教程见 `docs/BOOTSTRAP.md`。

### 已包含的初始化脚本

| 脚本 | 用途 |
| --- | --- |
| `bootstrap.ps1` / `bootstrap.sh` | 创建虚拟环境、安装依赖和 Chromium、配置 MCP、运行测试与 Demo |
| `enable-codex-mcp.ps1` / `.sh` | 自动生成包含真实项目路径的 Codex MCP 配置 |
| `trust-project.ps1` / `.sh` | 可选地加入用户级 Codex 项目信任 |
| `start-docker-broker.ps1` | 启动受限 Docker Broker |
| `restart-docker-broker.ps1` | 重启 Broker |
| `check-toolchain.ps1` | 检查所有 Docker profile |
| `doctor.ps1` | 输出本地环境状态 |
| `run-tests.ps1` | 运行回归测试 |
| `wsl-install-runtime.sh` | 安装可选 WSL/Linux 工具 |
| `wsl-finalize-tools.sh` | 创建可选工具 wrapper |
| `wsl-tool-check.sh` | 验证可选 WSL/Linux 工具 |

## 快速开始

Windows：

```powershell
py -3.12 -m venv .venv
& .\.venv\Scripts\python.exe -m pip install --upgrade pip
& .\.venv\Scripts\python.exe -m pip install -r requirements-core.txt
& .\.venv\Scripts\python.exe -m pip install -e .

$env:CTF_PYTHON = (Resolve-Path ".\.venv\Scripts\python.exe").Path
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\run-tests.ps1
```

Linux/macOS：

```bash
python3 -m venv .venv
./.venv/bin/python -m pip install --upgrade pip
./.venv/bin/python -m pip install -r requirements-core.txt
./.venv/bin/python -m pip install -e .
PYTHONPATH=tools ./.venv/bin/python -m unittest discover -s tests -v
```

## Playwright

```bash
cd mcp/playwright
npm ci
export PLAYWRIGHT_BROWSERS_PATH="$PWD/browsers"
npx playwright install chromium
cd ../..
```

然后设置：

```text
CTF_PLAYWRIGHT_BROWSER_EXECUTABLE=<Chromium 可执行文件路径>
```

## Codex MCP 配置

Windows 使用 `config/codex-mcp.project.toml.example`；Linux 使用
`config/codex-mcp.project.linux.toml.example`。初始化和
`enable-codex-mcp` 脚本会自动替换 `<PROJECT_ROOT>`。

不要提交真实的 `.codex/config.toml`。

## Docker Broker

Windows：

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\start-docker-broker.ps1
```

Linux/macOS：

```bash
./.venv/bin/python mcp/docker-broker/broker.py \
  --root "$PWD" --host 127.0.0.1 --port 8765
```

Broker token 会生成在 `config/docker-broker-token`，该文件已被 `.gitignore`
排除。

## 真实案例

`examples/case-studies` 中保留了真实内网靶场 IP、Flag、命令和攻击链，
只移除个人平台账号及本机绝对路径：

- x86-64 两阶段 `ret2libc`；
- Android Native Loader、隐藏 DEX、XOR+zlib、Twofish-256；
- stripped Go 二进制中的自定义整型栈 VM 和符号执行；
- Piwigo ORDER BY SQL 注入、Django ORM 别名 UNION 注入；
- sqli-labs Less-1 UNION SQL 注入；
- Windows PE 静态分析与 Unicorn 仿真；
- Base64 + XOR；
- ZIP 伪加密。

每个案例还提供真实结果的证据样例。完整案例索引见
`examples/case-studies/index.json`。

## 工作流和提示词

- `docs/WORKFLOW.md`：从建任务到生成报告的完整工作流；
- `prompts/`：可直接复制给 Codex 的任务创建、侦察分类、受控利用、验证报告和受阻交接提示词；
- `skills/`：按 Web、Pwn、Reverse、Crypto、Forensics、Misc、OSINT 分类的技能说明；
- `AGENTS.md`：不可越界的授权、Scope 和证据规则。

离线演示：

```bash
python examples/quickdemo/demo.py
```

## 安全边界

只允许对你拥有或获得明确授权的系统使用。项目不包含比赛平台自动提交适配器、
验证码绕过或“无授权扫描”模式。

当前版本验证 DNS 后再发起请求。高对抗网络环境应继续实现 IP 钉扎，防止
DNS rebinding。详见 `docs/THREAT_MODEL.md`。

## Acknowledgements

特别感谢 Conly-Zy 的原始 CTF-Agent 项目。

Original repository:
https://github.com/Conly-Zy/CTF-Agent

本项目独立开发，并受到原项目在 AI 辅助 CTF、多 Agent 工作流和安全题目组织
思路方面的启发。

感谢原作者的工作以及对 CTF 开源社区的贡献。

截至编写时，无法独立核实原项目采用的许可证。

所有第三方组件及任何来源于外部项目的代码仍受其各自许可证约束。

更多第三方归属见 `THIRD_PARTY_NOTICES.md`、`NOTICE` 和
`docs/upstream/`。

项目使用 Apache-2.0；上游 MIT 和 GPL-2.0 内容仍遵循其原始许可证。
