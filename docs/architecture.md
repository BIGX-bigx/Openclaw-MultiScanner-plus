# ClawMatrix 多阶段融合型 OpenClaw 信任边界扫描器设计说明

## 1. 设计定位

ClawMatrix 的定位是一套独立的多阶段融合型 OpenClaw 信任边界扫描器，而不是单纯基于 Skill 扫描工具的附加模块。第二层深度引擎已升级为 Agent Skill Guard，但 ClawMatrix 的核心目标仍然是覆盖 OpenClaw 的配置、状态目录、Gateway、Control UI、browser-control、内部方法族、Skill/Agent 生态、记忆与任务等多个关键能力面。

该工具不是 exploit runner，不主动执行危险 payload。它的定位是“证据链生成器、授权差异验证框架和可视化安全评估前端”：先收集本地状态与 Skill 生态证据，再生成可复现、可审计、可向导师汇报的方法矩阵和 canary 计划，最后以中文 HTML/JSON/Markdown 形式输出。

## 2. 四层架构

### 第一层：安装态与状态面审计层

输入包括 `~/.openclaw`、`openclaw.json`、`models.json`、`auth-profiles.json`、`device.json`、日志目录和 SQLite 状态数据库。重点不是简单判断“文件存在”，而是记录文件权限、哈希、疑似 token/API key、数据库是否为 SQLite 明文格式、表结构、字段名、行数和跨版本稳定性。

本层特别关注 `registry.sqlite`、`runs.sqlite`、`main.sqlite`。这些数据库本身明文落地并不等同于远程漏洞，但一旦结合任意文件读、恶意 Skill、越权文件方法或本地低权限账户，就会成为影响面放大的关键证据。

### 第二层：Skill / Agent 生态与供应链审计层

该层吸收 OpenClaw Skill Guard / SkillDance 类工具的优点，对 `SKILL.md`、伴随文档、依赖文件和实现代码进行静态分析。重点包括声明能力与实际行为是否一致、文件/网络/进程/浏览器/计划任务等能力识别、prompt injection、staged delivery、exfiltration pattern、来源身份和安装链风险。

ClawMatrix 提供轻量能力识别，同时在 `engines/agent-skill-guard` 接入新版 Agent Skill Guard 深度审计引擎。新版引擎覆盖 Agent Skill、OpenClaw Skill、MCP 配置、Tool schema 和 prompt package，输出 AI BOM、MCP tool/schema 审计、隐藏指令/Trojan Source、claims-vs-evidence、toxic flow、策略门禁和中文 finding。若新版二进制不可用，第二层会自动降级为 ClawMatrix 轻量扫描，不影响其它三层运行。

第二层会把新版深度引擎输出归一化为 `risk_context`，供第三层生成风险驱动授权矩阵、供第四层生成风险驱动 canary 计划。因此第二层仍然承担 Skill/Agent 生态与供应链审计职责，但证据面更完整，并能驱动后续层级。

### 第三层：信任边界与方法授权验证层

该层是相对现有扫描工具的主要增量。传统扫描通常只能判断配置是否缺失、端口是否开放、WebSocket 是否可连接；ClawMatrix 关注的是连接建立之后，Gateway 是否继续把 `local/trusted` 结论继承到更高层内部方法。

方法矩阵覆盖 `sessions.*`、`config.*`、`node.*`、`browser.*`、`agents.files.*`、`memory.*`、`tasks.*`、`flows.*` 等家族。测试条件覆盖 loopback、localhost、nip.io loopback、X-Forwarded-For/trusted proxy、Origin/Host 差异和 WebSocket upgrade 场景。当前版本先生成安全的计划矩阵，后续可接入授权实验 harness，只比较允许/拒绝状态码和错误类型，不触发高危操作。

升级后，第三层会读取第二层 `risk_context`，将文件、网络、浏览器、任务、MCP、隐藏指令和 toxic flow 等信号映射到相应方法族，形成“基础矩阵 + 风险驱动优先级”的授权验证结构。

### 第四层：Canary 影响面验证层

该层用于证明风险是否从“能连接/能调用”继续扩大到“能触达能力面”。Canary 分为文件 canary、网络 canary、任务 canary、状态数据库 canary。所有 canary 都应在实验室目录或自控服务中进行，不访问第三方目标，不读取真实敏感数据。

升级后，第四层会基于第二层 `risk_context` 自动补充 MCP schema canary、prompt instruction canary、browser canary 和 egress canary 等风险驱动验证项。默认仍保持 plan-only；lab 模式只布置 synthetic 文件和 SQLite 标记。

本层的价值在于把扫描结论从泛化告警推进到影响证明：权限异常是否扩大、内部能力是否可触达、状态数据库/记忆/任务等高价值数据面是否被波及。

## 3. 输出与证据模型

ClawMatrix 输出 JSON、Markdown 和中文 HTML。JSON 用于后续自动化对比，Markdown 用于组会汇报，HTML 用于可视化展示。每个发现项包含层级、风险编号、严重度、标题、证据和解释。建议后续继续增加 SARIF 输出，并把四层扫描与 Agent Skill Guard v2 的结果统一归并为同一 evidence schema。

## 4. 与现有工具的差异

现有工具多数停留在配置静态扫描或 Skill 静态扫描。ClawMatrix 的改进点是跨层串联：状态目录证据解释为什么敏感，Skill 证据解释能力从哪里来，授权矩阵解释边界在哪里失效，canary 解释影响是否成立。这个链条更适合形成课题组自己的工具创新点，也更接近软著材料中的“核心算法流程”。

## 5. 可视化前端

ClawMatrix 新增本地 Web 控制台。控制台使用 Python 标准库实现，不依赖额外框架，适合在 WSL/Ubuntu 或本地实验环境中快速启动。前端页面提供扫描参数填写、报告生成、最近报告预览和 HTML/JSON 证据打开能力，用于增强工具的可视性、便携性和汇报展示效果。

## 6. 安全边界

ClawMatrix 默认只做本地只读扫描、HTTP 轻量探测和 plan-only canary。任何会修改 OpenClaw 状态、创建任务、读取真实用户文件、访问外部网络或执行 Skill 的动作，都应单独放入受控实验模式，并要求显式开关。
