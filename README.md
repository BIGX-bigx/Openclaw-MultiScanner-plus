# Openclaw-MultiScanner Plus

Openclaw-MultiScanner Plus 是一个面向 OpenClaw 的多阶段融合型信任边界扫描器。它不是单一的配置检查器，也不是单一的 Skill 扫描器，而是按四层架构组织 OpenClaw 的状态目录、Skill 生态、连接后方法授权矩阵和 canary 影响面验证计划。

Plus 版重点改进报告阅读体验：在详细四层结果之前增加“综合态势评估”，自动生成风险指数、智能评价、优先处理建议、五维能力值雷达图，并默认省略无明显问题的层级详情，避免高阶 OpenClaw 环境扫描量过大时报告难以翻阅。

## 功能范围

- 第一层：安装态与状态面审计。检查 `openclaw.json`、模型配置、认证文件、device identity、日志、资源状态和 SQLite 状态数据库。
- 第二层：Skill 生态与供应链审计。检查 `SKILL.md` 声明能力与实现行为差异，识别文件、网络、进程、浏览器、计划任务和 prompt injection 信号。
- 第三层：连接后信任边界与方法授权验证。生成 Host、Origin、loopback、nip.io、trusted proxy、WebSocket upgrade 条件下的方法族授权矩阵。
- 第四层：Canary 影响面验证。生成文件、网络、任务、状态数据库和记忆能力面的无害 canary 验证计划。

0.5.0-plus 开始，四层都具备实际证据输出，并在 HTML 报告中加入综合态势评估、智能评价和五维能力值面板：

- 第一层会解析 `openclaw.json` 语义信号、状态目录布局、日志、备份、哈希基线和 SQLite 数据价值。
- 第二层会在轻量扫描中识别声明/实现差异、依赖风险、远程安装、分阶段投递、混淆、凭证访问和外送信号。
- 第三层支持 `--dynamic-mode probe`，对常见 HTTP JSON-RPC / WebSocket 路径执行 metadata/dry-run 方法探测，并输出条件差异矩阵。
- 第四层支持 `--canary-mode lab`，布置本地 synthetic 文件和 SQLite canary，完成自检观测，并生成后续影响验证载荷。
- 报告首页会给出综合等级、风险指数、风险集中层、优先处理建议和正五边形雷达图。
- 默认报告为智能精简模式，只展开存在非信息级发现或覆盖不足的层；需要完整详情时可添加 `--include-clean-sections`。

## 目录结构

```text
Openclaw-MultiScanner/
  tools/
    clawmatrix_scan.py      # 命令行扫描器
    clawmatrix_web.py       # 本地 Web 前端
    doctor.py               # 环境自检
  schemas/
    clawmatrix-report.schema.json
  canary_templates/
    canary-plan.yaml
  engines/
    skill-guard/              # 内置队友 Skill Guard 深度引擎
  docs/
    architecture.md
  reports/
    .gitkeep
  start-web.ps1
  start-web.sh
  .gitignore
  README.md
```

## Plus 版报告特性

- 综合态势评估：将四层扫描结果汇总成一个整体风险等级。
- 智能评价：根据实际发现自动生成不同评价，不再使用固定模板话术。
- 优先处理建议：按发现项自动给出复核顺序。
- 五维能力值面板：覆盖配置状态、Skill 治理、动态授权、影响验证、证据完整度。
- 智能精简详情：默认省略无明显问题的层，降低大型环境下报告阅读成本。

## 环境要求

- Python 3.9+
- 不需要安装第三方依赖
- Windows、Linux、WSL 均可运行

## 一键自检

下载仓库后，建议先运行环境自检：

```bash
python3 tools/doctor.py \
  --openclaw-home ~/.openclaw \
  --gateway-url http://127.0.0.1:18789/ \
  --browser-url http://127.0.0.1:18791/
```

Windows PowerShell 可使用：

```powershell
python .\tools\doctor.py --openclaw-home "$env:USERPROFILE\.openclaw"
```

自检会确认 Python、OpenClaw CLI、状态目录、Gateway、browser-control、Skill Guard 源码、可选二进制和 cargo 是否可用。即使没有 cargo，工具也不会整体失效，只会把第二层 Skill Guard 深度引擎降级为 ClawMatrix 轻量 Skill 扫描，并在报告中说明。

## 命令行使用

在 OpenClaw 所在环境中运行：

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

启用第三层动态安全探测和第四层实验 canary：

```bash
python3 tools/clawmatrix_scan.py \
  --openclaw-home ~/.openclaw \
  --gateway-url http://127.0.0.1:18789/ \
  --browser-url http://127.0.0.1:18791/ \
  --dynamic-mode probe \
  --method-probe-limit 16 \
  --canary-mode lab \
  --format html \
  --out reports/clawmatrix_dynamic.html
```

`--dynamic-mode probe` 只发送 metadata/dry-run 类 JSON-RPC 探测，不执行命令、不创建任务、不读取真实敏感文件。`--method-probe-limit 0` 表示探测完整矩阵。

导出 Markdown：

```bash
python3 tools/clawmatrix_scan.py \
  --openclaw-home ~/.openclaw \
  --format markdown \
  --out reports/clawmatrix_latest.md
```

如需扫描 Skill 根目录：

```bash
python3 tools/clawmatrix_scan.py \
  --openclaw-home ~/.openclaw \
  --skill-root /path/to/skills \
  --skill-guard-engine auto \
  --format html \
  --out reports/clawmatrix_with_skills.html
```

`--skill-guard-engine` 支持三种模式：

- `auto`：默认模式。存在 Rust/cargo 且提供 Skill 根目录时，自动调用内置 Skill Guard 深度引擎。
- `off`：只运行 ClawMatrix 轻量 Skill 识别。
- `on`：强制尝试运行 Skill Guard 深度引擎，失败会在报告中记录原因。

## 图形化使用

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

页面中可以填写 OpenClaw 状态目录、Gateway 地址、browser-control 地址，并生成中文 HTML、JSON 或 Markdown 报告。

页面内置两个预设：

- 快速体检：偏静态，适合日常确认环境和配置风险。
- 研究增强模式：启用第三层 metadata/dry-run 动态探测和第四层本机 synthetic canary，更适合课题组汇报和版本对比。

## 安全边界

本工具默认只做本地只读扫描、HTTP 轻量探测和 plan-only canary。它不会主动执行危险 payload，不会读取真实敏感文件内容，不会创建持久任务，也不会向第三方目标发送验证流量。任何动态方法级验证都应在授权实验环境中单独开启。

## 当前状态

当前版本已经实现四层框架、中文 HTML 报告、本地 Web 前端、环境自检、第三层动态授权安全探测和第四层本机 canary 实验模式。下一阶段建议继续补充更多 OpenClaw 内部方法族样本，以及与其他 OpenClaw 扫描工具报告的自动融合对比。

## 关于 Skill Guard 引擎

本仓库内置 `engines/skill-guard`，用于保留队友原工具的 Skill 深度审计能力。ClawMatrix 的第二层由两部分组成：内置轻量能力识别和 Skill Guard 深度引擎。这样既保持四层扫描器的独立架构，也不会损失原 Skill 工具在供应链、prompt injection、权限声明和攻击路径分析方面的能力。
