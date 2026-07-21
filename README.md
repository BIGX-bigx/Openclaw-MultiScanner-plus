# Openclaw-MultiScanner Plus

Openclaw-MultiScanner Plus 是一款面向 OpenClaw 的多阶段信任边界安全扫描工具。工具围绕 OpenClaw 的安装状态、Skill / Agent 生态、连接后方法授权边界和 Canary 影响面验证构建四层联动扫描架构，用于发现配置暴露、状态面风险、Agent 能力越界、供应链隐患、RPC / WebSocket 授权差异以及高价值能力触达链路。

当前版本为 v2.0 稳定优化版，已接入新版 Agent Skill Guard 深度引擎，并对 Web 控制台扫描流程进行了优化：扫描时优先生成统一 JSON 证据对象，再由同一份证据渲染 HTML 与 Markdown 报告，避免重复扫描导致的超时和报告不一致问题。

## 核心扫描架构

Openclaw-MultiScanner Plus 采用四层扫描模型：

1. **安装态与状态面审计**

   检查 OpenClaw 状态目录、`openclaw.json`、模型配置、认证文件、设备身份、日志、备份、哈希基线和 SQLite 状态数据库，建立运行环境安全基准。

2. **Skill / Agent 生态与供应链审计**

   分析 `SKILL.md` 声明能力、实现行为、依赖文件、MCP / Agent 配置、隐藏指令、prompt injection、远程安装、分阶段投递、凭证访问和外送风险。该层包含 ClawMatrix 轻量扫描逻辑和内置 Agent Skill Guard v2 深度引擎。

3. **连接后信任边界与方法授权验证**

   围绕 Gateway、JSON-RPC、WebSocket 和 Browser Control 生成方法级授权矩阵，覆盖 Host、Origin、loopback、nip.io、trusted proxy、WebSocket upgrade 等条件，用于判断连接建立后权限是否被正确保留。

4. **Canary 影响面验证**

   根据前序风险证据生成无害 Canary 验证点，用于评估文件、网络、任务、状态数据库、浏览器控制和记忆能力等高价值能力面的实际影响链路。

## v2.0 版本特性

- 四层联动扫描：从静态配置、Agent 生态、动态授权到影响验证形成完整证据链。
- 新版第二层深度引擎：内置 Agent Skill Guard v2，支持 AI BOM、MCP schema 审计、隐藏指令、声明/实现差异、toxic flow 和策略门禁。
- 统一证据模型：所有扫描结果进入 JSON 证据对象，再派生 HTML 和 Markdown 报告。
- 稳定优化报告生成：Web 控制台只执行一次核心扫描，避免 HTML / JSON / Markdown 重复扫描。
- 中文可视化报告：提供综合态势评估、风险指数、智能评价、优先处理建议和五维能力雷达图。
- 智能精简模式：默认仅展开存在风险或覆盖不足的层级，降低大型环境下报告阅读成本。
- 历史报告管理：本地保存历史 HTML、JSON、Markdown 报告，支持预览、下载、删除和多报告对比。
- 第二层独立入口：Web 控制台提供 Agent Skill Guard 深度引擎单独扫描入口。
- Windows 可执行交付：支持通过 `OpenClaw-MultiScanner-plus.exe` 启动本地 Web 控制台。

## 目录结构

```text
Openclaw-MultiScanner-plus/
  tools/
    clawmatrix_scan.py          # 命令行四层扫描器
    clawmatrix_web.py           # 本地 Web 控制台
    doctor.py                   # 环境自检工具
    clawmatrix/
      layer3.py                 # 第三层信任边界与方法授权逻辑
      report_diff.py            # 报告对比逻辑
      skill_analysis.py         # 第二层轻量 Skill / Agent 分析逻辑

  engines/
    agent-skill-guard/
      bin/
        agent-skill-guard.exe   # 第二层 Agent Skill Guard v2 深度引擎
      schemas/
        report.schema.json
      .openclaw-guard.yml

  schemas/
    clawmatrix-report.schema.json

  canary_templates/
    canary-plan.yaml

  docs/
    architecture.md

  reports/
    .gitkeep                    # 本地报告输出目录

  start-web.ps1                 # Windows 启动脚本
  start-web.sh                  # Linux / WSL 启动脚本
  README.md
```

## 环境要求

- Python 3.9+
- Windows、Linux、WSL 均可运行
- 默认不要求额外安装第三方依赖
- 第二层深度引擎已以内置二进制形式提供，无需用户自行编译

如果第二层深度引擎不可用，工具不会整体失败，会自动降级为 ClawMatrix 轻量扫描，并在报告中记录原因。

## 一键自检

下载仓库后，建议先运行环境自检：

```bash
python3 tools/doctor.py \
  --openclaw-home ~/.openclaw \
  --gateway-url http://127.0.0.1:18789/ \
  --browser-url http://127.0.0.1:18791/
```

Windows PowerShell 示例：

```powershell
python .\tools\doctor.py --openclaw-home "$env:USERPROFILE\.openclaw"
```

如果 OpenClaw 部署在 WSL / Ubuntu 中，可以填写 Windows 可访问的 UNC 路径，例如：

```text
\\wsl.localhost\Ubuntu\home\username\.openclaw
```

Skill / Agent 根目录可填写：

```text
\\wsl.localhost\Ubuntu\home\username\.openclaw\skills
```

## 命令行使用

基础扫描：

```bash
python3 tools/clawmatrix_scan.py \
  --openclaw-home ~/.openclaw \
  --gateway-url http://127.0.0.1:18789/ \
  --browser-url http://127.0.0.1:18791/ \
  --format html \
  --out reports/clawmatrix_latest.html
```

导出 JSON 证据：

```bash
python3 tools/clawmatrix_scan.py \
  --openclaw-home ~/.openclaw \
  --format json \
  --out reports/clawmatrix_latest.json
```

导出 Markdown 报告：

```bash
python3 tools/clawmatrix_scan.py \
  --openclaw-home ~/.openclaw \
  --format markdown \
  --out reports/clawmatrix_latest.md
```

扫描 Skill / Agent 根目录：

```bash
python3 tools/clawmatrix_scan.py \
  --openclaw-home ~/.openclaw \
  --skill-root ~/.openclaw/skills \
  --skill-guard-engine auto \
  --format html \
  --out reports/clawmatrix_with_skills.html
```

启用第三层动态 Probe 和第四层 Canary Lab：

```bash
python3 tools/clawmatrix_scan.py \
  --openclaw-home ~/.openclaw \
  --skill-root ~/.openclaw/skills \
  --gateway-url http://127.0.0.1:18789/ \
  --browser-url http://127.0.0.1:18791/ \
  --skill-guard-engine auto \
  --dynamic-mode probe \
  --method-probe-limit 16 \
  --canary-mode lab \
  --include-clean-sections \
  --format html \
  --out reports/clawmatrix_dynamic.html
```

`--dynamic-mode probe` 只执行安全的 metadata / dry-run 类探测，不执行真实命令、不创建持久任务、不读取真实敏感文件。`--method-probe-limit 0` 表示探测完整矩阵。

`--skill-guard-engine` 支持三种模式：

- `auto`：默认模式，自动使用内置 Agent Skill Guard v2 深度引擎。
- `off`：关闭深度引擎，仅运行 ClawMatrix 轻量扫描。
- `on`：强制尝试运行深度引擎，失败时在报告中记录原因。

## Web 控制台使用

Linux / WSL：

```bash
./start-web.sh
```

Windows PowerShell：

```powershell
.\start-web.ps1
```

然后打开：

```text
http://127.0.0.1:8765/
```

Web 控制台包含：

- 首页概览：展示四层扫描架构和快速启动入口。
- 扫描配置：配置 OpenClaw 状态目录、Skill / Agent 根目录、Gateway、Browser Control、第二层深度引擎、第三层 Probe、第四层 Canary。
- 第二层深度引擎：单独运行 Agent Skill Guard v2。
- 启动扫描：确认配置后执行多层级扫描。
- 报告分析：预览 HTML 报告，管理历史记录，下载 HTML、JSON、Markdown，支持多报告对比。

## 推荐配置

日常稳定体检：

```text
L2 Agent Skill Guard v2：auto
L2 Agent/MCP 生态解析：启用
L2 深度引擎超时：120
L3 运行时授权验证：Plan 模式
L4 Canary 验证：Plan 模式
报告展示策略：智能精简
```

完整深度测试：

```text
L2 Agent Skill Guard v2：auto
L2 Agent/MCP 生态解析：启用
L2 深度引擎超时：180 或 240
L3 运行时授权验证：Probe 模式
L4 Canary 验证：Lab 模式
报告展示策略：完整模式
```

完整 Probe / Lab 模式依赖 OpenClaw Gateway、Browser Control、Skill / Agent 目录和 Canary 实验目录配置正确。若环境不完整，工具仍可生成报告，但部分层级会以覆盖不足或跳过原因体现。

## Windows 可执行包

Windows 可执行交付包中包含：

```text
OpenClaw-MultiScanner-plus.exe
tools/
engines/
schemas/
canary_templates/
docs/
README.md
start-web.ps1
```

双击：

```text
OpenClaw-MultiScanner-plus.exe
```

即可启动本地 Web 控制台并打开：

```text
http://127.0.0.1:8765/
```

注意：不要单独移动 exe。该 exe 需要与 `tools/`、`engines/`、`schemas/` 等目录保持在同一工具根目录下。

## 报告输出

工具支持三种报告格式：

- HTML：适合本地查看和比赛展示。
- JSON：完整机器可读证据对象，适合复核、对比和自动化处理。
- Markdown：适合归档、审查和文档引用。

Web 控制台稳定优化版采用“一次扫描，多格式渲染”的流程：

```text
四层扫描 -> JSON 证据对象 -> HTML 报告 / Markdown 报告
```

这样可以减少重复扫描时间，并保证不同格式报告基于同一份证据。

## 安全边界

本工具默认用于本地授权环境下的 OpenClaw 安全审计。默认行为包括本地只读扫描、轻量 HTTP 探测和 plan-only Canary 生成。动态 Probe 和 Canary Lab 需要用户显式开启，并应在授权实验环境中使用。

工具不会主动执行危险 payload，不会创建持久化任务，不会向第三方目标发送验证流量。所有报告和证据默认保存在本地 `reports/` 目录中。

## 当前状态

当前 v2.0 稳定优化版已经实现：

- 四层联动扫描架构
- 新版 Agent Skill Guard v2 深度引擎接入
- Skill / Agent / MCP / AI BOM 生态风险识别
- 连接后信任边界与方法授权矩阵
- 风险驱动 Canary 影响面验证
- 中文 HTML / JSON / Markdown 报告
- Web 控制台和历史报告管理
- 第二层深度引擎独立入口
- Windows 可执行交付包启动方式

该工具适合作为 OpenClaw 环境的多阶段信任边界审计、Agent 生态供应链风险分析和比赛展示型安全扫描平台。
