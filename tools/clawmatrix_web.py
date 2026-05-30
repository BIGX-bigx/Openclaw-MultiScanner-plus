#!/usr/bin/env python3
"""
ClawMatrix local web console.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import subprocess
import sys
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse


ROOT = Path(__file__).resolve().parents[1]
SCAN = ROOT / "tools" / "clawmatrix_scan.py"
REPORTS = ROOT / "reports"
META_FILE = REPORTS / "meta.json"


INDEX_HTML = """<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>OpenClaw MultiScanner 工作台</title>
  <style>
    :root {
      --bg-color: #f3f4f6; --sidebar-bg: #1f2937; --sidebar-hover: #374151;
      --sidebar-text: #d1d5db; --sidebar-active: #ffffff; --brand: #ef4444;
      --brand-hover: #dc2626; --panel-bg: #ffffff; --text-main: #111827;
      --text-muted: #6b7280; --border: #e5e7eb; --radius: 12px;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background-color: var(--bg-color); color: var(--text-main); display: flex; height: 100vh; overflow: hidden; }
    
    /* 左侧主导航 */
    .sidebar { width: 260px; background-color: var(--sidebar-bg); display: flex; flex-direction: column; padding: 24px 0; box-shadow: 2px 0 8px rgba(0,0,0,0.1); z-index: 10; flex-shrink: 0;}
    .brand { padding: 0 24px 32px; color: white; font-size: 20px; font-weight: 700; display: flex; align-items: center; gap: 10px; }
    .brand-dot { width: 10px; height: 10px; background-color: var(--brand); border-radius: 50%; box-shadow: 0 0 8px var(--brand); }
    .nav-item { padding: 14px 24px; color: var(--sidebar-text); cursor: pointer; transition: all 0.2s; font-size: 15px; font-weight: 500; border-left: 3px solid transparent; }
    .nav-item:hover, .nav-item.active { background-color: var(--sidebar-hover); color: var(--sidebar-active); }
    .nav-item.active { border-left-color: var(--brand); }

    /* 主内容区框架布局 */
    .main-content { flex: 1; display: flex; flex-direction: column; min-width: 0; background: var(--bg-color); }
    
    /* 滚动视图 */
    .view-section { display: none; flex: 1; overflow-y: auto; padding: 32px; animation: fadeIn 0.3s ease-in-out; }
    .view-section.active { display: block; }
    
    /* 全高视图（适用于报告页） */
    .view-section.full-height { display: none; flex-direction: column; overflow: hidden; padding: 24px 32px; }
    .view-section.full-height.active { display: flex; }
    
    /* 核心居中容器 */
    .scroll-container { max-width: 1200px; margin: 0 auto; width: 100%; }

    @keyframes fadeIn { from { opacity: 0; transform: translateY(10px); } to { opacity: 1; transform: translateY(0); } }

    /* 徽章与通用组件 */
    .status-badge { display: inline-block; padding: 4px 8px; border-radius: 6px; font-size: 12px; font-weight: 600; background: #fee2e2; color: #991b1b; margin-bottom: 12px; }
    .header { margin-bottom: 24px; flex-shrink: 0;}
    .header h1 { font-size: 28px; font-weight: 600; margin-bottom: 8px; }
    .header p { color: var(--text-muted); line-height: 1.6;}
    
    .card { background: var(--panel-bg); border: 1px solid var(--border); border-radius: var(--radius); padding: 24px; margin-bottom: 24px; box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.05); }
    .card h2 { font-size: 18px; margin-bottom: 20px; padding-bottom: 12px; border-bottom: 1px solid var(--border); }
    
    .form-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 20px; }
    .form-group { display: flex; flex-direction: column; gap: 6px; }
    label { font-size: 14px; font-weight: 500; color: #374151; }
    input, select { padding: 10px 12px; border: 1px solid var(--border); border-radius: 8px; font-size: 14px; outline: none; transition: border-color 0.2s;}
    input:focus, select:focus { border-color: var(--brand); box-shadow: 0 0 0 2px rgba(239, 68, 68, 0.1); }
    .hint { font-size: 12px; color: var(--text-muted); line-height: 1.4; }
    
    .actions { display: flex; gap: 16px; margin-top: 10px; }
    button { padding: 12px 24px; border: none; border-radius: 8px; font-size: 14px; font-weight: 600; cursor: pointer; transition: all 0.2s; }
    .btn-primary { background: var(--brand); color: white; }
    .btn-primary:hover { background: var(--brand-hover); }
    .btn-primary:disabled { opacity: 0.6; cursor: not-allowed; }
    .btn-secondary { background: white; border: 1px solid var(--border); color: var(--text-main); }
    .btn-secondary:hover { background: #f9fafb; }
    .btn-secondary:disabled { opacity: 0.5; cursor: not-allowed; }
    
    .terminal { background: #111827; color: #10b981; padding: 16px; border-radius: 8px; font-family: "Fira Code", monospace; font-size: 13px; min-height: 180px; max-height: 400px; overflow-y: auto; margin-top: 24px; white-space: pre-wrap; box-shadow: inset 0 4px 6px rgba(0,0,0,0.3);}

    /* 下拉菜单 */
    .dropdown { position: relative; display: inline-block; }
    .dropdown-content { display: none; position: absolute; right: 0; top: 100%; margin-top: 4px; background-color: white; min-width: 150px; box-shadow: 0px 8px 20px rgba(0,0,0,0.12); z-index: 100; border-radius: 8px; border: 1px solid var(--border); overflow: hidden;}
    .dropdown-content a { color: var(--text-main); padding: 10px 16px; text-decoration: none; display: block; font-size: 13px; border-bottom: 1px solid #f3f4f6;}
    .dropdown-content a:last-child { border-bottom: none; }
    .dropdown-content a:hover { background-color: #f9fafb; color: var(--brand); }
    .dropdown-content.show { display: block; }

    /* 四层架构与环境检查 */
    .layer-grid { display: grid; grid-template-columns: repeat(4, minmax(200px, 1fr)); gap: 16px; margin-top: 8px; }
    .layer-card { padding: 20px 16px; background: #f9fafb; border: 1px solid var(--border); border-radius: 10px; transition: transform 0.2s, box-shadow 0.2s; }
    .layer-card:hover { transform: translateY(-2px); box-shadow: 0 4px 12px rgba(0,0,0,0.05); background: white; border-color: #fca5a5; }
    .layer-num { width: 32px; height: 32px; background: var(--brand); color: white; border-radius: 8px; display: flex; align-items: center; justify-content: center; font-weight: 800; font-size: 16px; margin-bottom: 14px; box-shadow: 0 2px 6px rgba(239, 68, 68, 0.3); }
    .layer-card h3 { font-size: 15px; margin-bottom: 8px; color: var(--brand-dark); font-weight: 600; }
    .layer-card p { font-size: 13px; color: var(--text-muted); line-height: 1.6; margin: 0; }
    
    .check-list { display: flex; flex-direction: column; gap: 12px; margin-bottom: 20px; }
    .check-item { display: flex; justify-content: space-between; align-items: center; padding: 12px 16px; background: #f9fafb; border-radius: 8px; border: 1px solid var(--border); font-size: 14px; }
    .check-name { font-weight: 500; color: var(--text-main); }
    .status-ok { color: #059669; font-weight: 600; }
    .status-warn { color: #d97706; font-weight: 600; }
    .status-error { color: #dc2626; font-weight: 600; }

    /* ========== 报告视图与分析框 ========== */
    .analysis-box { border-left: 4px solid var(--brand); background: #fff7f2; border-radius: 8px; padding: 16px 20px; line-height: 1.6; border-right: 1px solid var(--border); border-top: 1px solid var(--border); border-bottom: 1px solid var(--border);}
    .report-layout { display: flex; gap: 16px; flex: 1; min-height: 0; overflow: hidden; }
    .report-preview-pane { flex: 1; display: flex; flex-direction: column; background: white; border: 1px solid var(--border); border-radius: var(--radius); overflow: hidden; box-shadow: 0 4px 6px -1px rgba(0,0,0,0.05); }
    .report-preview-pane iframe { flex: 1; width: 100%; border: none; }
    .history-pane { width: 340px; background: white; border: 1px solid var(--border); border-radius: var(--radius); display: flex; flex-direction: column; flex-shrink: 0; box-shadow: 0 4px 6px -1px rgba(0,0,0,0.05); transition: width 0.3s cubic-bezier(0.4, 0, 0.2, 1), opacity 0.2s;}
    .history-pane.collapsed { width: 0; border: none; opacity: 0; margin-left: -16px; pointer-events: none;}
    .hp-header { padding: 14px 16px; border-bottom: 1px solid var(--border); display: flex; justify-content: space-between; align-items: center; background: #f9fafb; border-radius: var(--radius) var(--radius) 0 0;}
    .hp-header h3 { font-size: 14px; margin: 0; }
    .hp-list { flex: 1; overflow-y: auto; padding: 12px; display: flex; flex-direction: column; gap: 8px; background: #f3f4f6;}
    
    .h-item { padding: 12px; background: white; border: 1px solid var(--border); border-radius: 8px; cursor: pointer; transition: all 0.2s; display: flex; gap: 10px; align-items: flex-start;}
    .h-item:hover { border-color: #fca5a5; box-shadow: 0 2px 8px rgba(0,0,0,0.04); }
    .h-item.active { border-color: var(--brand); box-shadow: 0 0 0 1px var(--brand); }
    .h-checkbox { margin-top: 2px; cursor: pointer; }
    .h-content { flex: 1; min-width: 0; }
    .h-title-row { display: flex; justify-content: space-between; align-items: center; margin-bottom: 6px; }
    .h-title { font-size: 13px; font-weight: 600; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; color: #111827; }
    .h-actions { display: flex; gap: 4px;}
    .h-action-btn { background: none; border: none; color: #6b7280; cursor: pointer; font-size: 13px; padding: 0 4px; transition: color 0.2s;}
    .h-action-btn:hover.rename { color: var(--brand); }
    .h-action-btn:hover.delete { color: #dc2626; }
    .h-tags { display: flex; gap: 4px; flex-wrap: wrap; margin-bottom: 6px; }
    .htag { font-size: 10px; padding: 2px 6px; border-radius: 4px; font-weight: 600; }
    .htag.critical, .htag.high { background: #fee2e2; color: #991b1b; }
    .htag.medium { background: #fef3c7; color: #92400e; }
    .htag.low, .htag.info { background: #e0e7ff; color: #3730a3; }
    .htag.mode { background: #f3f4f6; color: #4b5563; border: 1px solid #e5e7eb;}
    .h-time { font-size: 11px; color: var(--text-muted); }
    
    @media (max-width: 1200px) { .layer-grid { grid-template-columns: repeat(2, 1fr); } }
    @media (max-width: 768px) { .layer-grid, .form-grid { grid-template-columns: 1fr; } }
  </style>
</head>
<body>

  <aside class="sidebar">
    <div class="brand"><div class="brand-dot"></div>OpenClaw Scanner</div>
    <div class="nav-item active" onclick="switchTab('overview')">首页概览</div>
    <div class="nav-item" onclick="switchTab('config-view')">扫描配置</div>
    <div class="nav-item" onclick="switchTab('start-view')">启动扫描</div>
    <div class="nav-item" onclick="switchTab('report-view')" id="nav-report">报告分析</div>
  </aside>

  <main class="main-content">
    
    <section id="overview" class="view-section active">
      <div class="scroll-container">
          <div class="header">
            <div class="status-badge">Engine v0.5.0-plus</div>
            <h1>控制台概览</h1>
            <p>独立四层架构扫描器，无需第三方依赖即可启动，专为 OpenClaw 信任边界安全测试设计。</p>
          </div>
          
          <div class="form-grid">
            <div class="card">
              <h2>⚡ 本机环境自检</h2>
              <p class="hint" style="margin-bottom: 16px;">自动化检查工具运行所需的依赖环境，结果仅供本次参考，不作保存。</p>
              <div id="env-check-results" class="check-list"><span class="hint">正在诊断...</span></div>
              <div class="actions">
                <button class="btn-secondary" onclick="runEnvCheck()" style="padding: 8px 16px; font-size: 13px;">重新检测</button>
              </div>
            </div>
            <div class="card">
              <h2>🎯 快速启动</h2>
              <p class="hint" style="margin-bottom: 16px;">一键应用预设参数并跳转至启动扫描页。</p>
              <div class="actions" style="flex-direction: column;">
                <button class="btn-secondary" onclick="applyPresetAndGo('quick')">快速静态体检 (仅 Plan 模式)</button>
                <button class="btn-secondary" onclick="applyPresetAndGo('research')">深度探测模式 (启用动态 Probe/Lab)</button>
              </div>
            </div>
          </div>
          
          <div class="card" style="margin-bottom: 0;">
            <h2>🛡️ 核心扫描架构</h2>
            <div class="layer-grid">
              <div class="layer-card"><div class="layer-num">1</div><h3>安装态与状态面</h3><p>检查 openclaw.json、明文 SQLite 状态库及权限风险，识别 Token 泄漏。</p></div>
              <div class="layer-card"><div class="layer-num">2</div><h3>Skill 生态与供应链</h3><p>分析 SKILL.md 声明与行为差异，识别越权访问、后门隐藏及提示词注入。</p></div>
              <div class="layer-card"><div class="layer-num">3</div><h3>信任边界与方法授权</h3><p>针对代理环境及 WebSocket 发送探测，生成细粒度的调用越权矩阵。</p></div>
              <div class="layer-card"><div class="layer-num">4</div><h3>Canary 影响面验证</h3><p>在文件、数据库和任务队列部署无害标记，实战验证漏洞真实触达链路。</p></div>
            </div>
          </div>
      </div>
    </section>

    <section id="config-view" class="view-section">
      <div class="scroll-container">
          <div class="header">
            <h1>扫描参数配置</h1>
            <p>在此页面调整目标引擎参数。修改完成后可保存为常驻预设，或直接送入启动台使用。</p>
          </div>
          
          <div class="card">
            <h2>基础目标环境</h2>
            <div class="form-grid">
              <div class="form-group"><label>OpenClaw 状态目录</label><input id="home" value="~/.openclaw"></div>
              <div class="form-group"><label>Skill 根目录 (可选)</label><input id="skill" placeholder="留空则自动探测"></div>
              <div class="form-group"><label>Gateway 探测地址</label><input id="gateway" value="http://127.0.0.1:18789/"></div>
              <div class="form-group"><label>Browser-control 地址</label><input id="browser" value="http://127.0.0.1:18791/"></div>
            </div>
          </div>
          
          <div class="card">
            <h2>扫描引擎深度配置</h2>
            <div class="form-grid">
              <div class="form-group"><label>Skill Guard 供应链引擎</label><select id="skillGuard"><option value="auto">自动探测</option><option value="off">关闭 (轻量扫描)</option><option value="on">强制启用</option></select></div>
              <div class="form-group"><label>L3 动态授权验证</label><select id="dynamicMode"><option value="plan">Plan 模式</option><option value="probe">Probe 模式</option></select></div>
              <div class="form-group"><label>L4 Canary 影响面验证</label><select id="canaryMode"><option value="plan">Plan 模式</option><option value="lab">Lab 模式</option></select></div>
              <div class="form-group"><label>报告展示策略</label><select id="includeClean"><option value="0">智能精简</option><option value="1">完整模式</option></select></div>
              <div class="form-group"><label>RPC/WS 探测字典</label><input id="rpcPaths" value=",/rpc,/api/rpc,/jsonrpc,/mcp,/ws,/gateway"></div>
              <div class="form-group"><label>Canary 实验目录</label><input id="canaryDir" placeholder="留空使用系统 temp"></div>
            </div>
          </div>
          
          <div class="actions" style="margin-bottom: 24px;">
              <button class="btn-secondary" style="border-color: var(--brand); color: var(--brand);" onclick="saveConfigPreset()">💾 保存为预设配置</button>
              <button class="btn-primary" onclick="useCurrentConfig()">⏭️ 使用当前配置(进入启动台)</button>
          </div>
      </div>
    </section>

    <section id="start-view" class="view-section">
      <div class="scroll-container">
          <div class="header">
            <h1>启动多层级扫描</h1>
            <p>确认下方即将使用的配置参数，点击执行后将在终端实时显示探测进度。</p>
          </div>
          
          <div class="card">
            <h2>⚙️ 选择并确认配置参数</h2>
            
            <div style="display: flex; gap: 12px; margin-bottom: 16px; align-items: center;">
                <select id="config-select" onchange="onConfigSelectChange()" style="flex: 1; max-width: 320px; font-weight: 600;"></select>
                <button class="btn-secondary" onclick="deleteConfigPreset()" id="btn-del-config" style="padding: 10px 16px; font-size:13px; color: #dc2626; border-color: #fca5a5;">🗑️ 删除此预设</button>
            </div>
            
            <div id="config-preview" class="analysis-box" style="font-family: monospace; font-size: 13px; color: #374151;">
                </div>
          </div>
          
          <div class="actions">
              <button id="scan-btn" class="btn-primary" style="font-size: 16px; padding: 14px 32px;" onclick="startScan()">🚀 执行多层级扫描</button>
              <button class="btn-secondary" style="padding: 14px 24px;" onclick="switchTab('config-view')">返回修改参数</button>
          </div>
          
          <div class="terminal" id="log">Ready to scan...</div>
      </div>
    </section>

    <section id="report-view" class="view-section full-height">
      <div class="header" style="display: flex; justify-content: space-between; align-items: flex-start;">
        <div>
          <h1>报告分析</h1>
          <p>勾选右侧多份报告可进行分屏对比。💡 <strong>提示：</strong>所有历史记录及 JSON 证据均保存在本地 <code>/reports</code> 中。</p>
        </div>
        <div style="display: flex; gap: 10px; align-items: center;">
          <button id="btn-open-html" class="btn-secondary" style="padding: 8px 16px;" onclick="openCurrentReport()" disabled>独立页面打开</button>
          
          <div class="dropdown">
            <button id="btn-download" class="btn-secondary" style="padding: 8px 16px;" onclick="toggleDropdown()" disabled>下载 ▾</button>
            <div class="dropdown-content" id="export-dropdown">
              <a href="#" id="dl-html" download>📄 HTML 报告</a>
              <a href="#" id="dl-md" download>📝 Markdown 报告</a>
              <a href="#" id="dl-json" download>📊 JSON 证据</a>
            </div>
          </div>

          <button id="toggle-history-btn" class="btn-secondary" onclick="toggleHistory()" style="padding: 8px 16px; font-weight: 800; border-color: #d1d5db;">收起历史 »</button>
        </div>
      </div>
      
      <div class="report-layout">
        <div class="report-preview-pane">
          <iframe id="preview" title="Report Preview"></iframe>
        </div>
        <div class="history-pane" id="history-pane">
          <div class="hp-header">
            <h3>历史扫描记录</h3>
            <button class="btn-primary" style="padding: 4px 10px; font-size:12px;" onclick="compareSelected()">对比勾选项</button>
          </div>
          <div class="hp-list" id="history-list">
             <span class="hint">加载中...</span>
          </div>
        </div>
      </div>
    </section>

  </main>

  <script>
    const $ = (id) => document.getElementById(id);
    
    // ========== 核心状态管理：配置持久化 ==========
    let savedConfigs = JSON.parse(localStorage.getItem('clawConfigs') || '[]');
    let lastUsedConfig = JSON.parse(localStorage.getItem('clawLastUsed') || 'null');
    let currentConfigToRun = null;

    function getFormConfig() {
        return {
            home: $("home").value, skill: $("skill").value,
            gateway: $("gateway").value, browser: $("browser").value,
            skillGuard: $("skillGuard").value, dynamicMode: $("dynamicMode").value,
            canaryMode: $("canaryMode").value, includeClean: $("includeClean").value,
            rpcPaths: $("rpcPaths").value, canaryDir: $("canaryDir").value
        };
    }

    function setFormConfig(cfg) {
        if(!cfg) return;
        $("home").value = cfg.home || "~/.openclaw";
        $("skill").value = cfg.skill || "";
        $("gateway").value = cfg.gateway || "http://127.0.0.1:18789/";
        $("browser").value = cfg.browser || "http://127.0.0.1:18791/";
        $("skillGuard").value = cfg.skillGuard || "auto";
        $("dynamicMode").value = cfg.dynamicMode || "plan";
        $("canaryMode").value = cfg.canaryMode || "plan";
        $("includeClean").value = cfg.includeClean || "0";
        $("rpcPaths").value = cfg.rpcPaths || ",/rpc,/api/rpc,/jsonrpc,/ws,/gateway";
        $("canaryDir").value = cfg.canaryDir || "";
    }

    // 初始化：加载最后使用的配置到表单
    if(lastUsedConfig) {
        setFormConfig(lastUsedConfig);
        currentConfigToRun = lastUsedConfig;
    } else {
        currentConfigToRun = getFormConfig();
        currentConfigToRun.name = "【未保存的临时配置】";
    }

    // ========== 视图切换逻辑 ==========
    function switchTab(tabId) {
      document.querySelectorAll('.nav-item').forEach(el => el.classList.remove('active'));
      event.currentTarget.classList.add('active');
      document.querySelectorAll('.view-section').forEach(el => el.classList.remove('active'));
      $(tabId).classList.add('active');
      
      if(tabId === 'start-view') updateStartScanView();
      if(tabId === 'report-view') fetchHistory();
    }

    function appendLog(text) {
      const logEl = $("log");
      logEl.textContent += `\\n[${new Date().toLocaleTimeString()}] ${text}`;
      logEl.scrollTop = logEl.scrollHeight;
    }

    // ========== 配置管理交互 ==========
    function applyPresetAndGo(kind) {
      let cfg = getFormConfig();
      if (kind === "quick") { 
          cfg.dynamicMode = "plan"; cfg.canaryMode = "plan"; cfg.name = "【快捷预设】静态体检";
      } else { 
          cfg.dynamicMode = "probe"; cfg.canaryMode = "lab"; cfg.name = "【快捷预设】深度探测";
      }
      cfg.id = null; // 标记为非固化预设
      setFormConfig(cfg); // 同步到表单
      currentConfigToRun = cfg;
      document.querySelectorAll('.nav-item')[2].click(); // 跳转到 start-view
      appendLog(`已自动加载 [${kind}] 临时预设，准备就绪。`);
    }

    function saveConfigPreset() {
        const name = prompt("请输入要保存的配置名称 (例如：本地深度测试)：");
        if(!name || name.trim() === "") return;
        
        const cfg = getFormConfig();
        cfg.name = name.trim();
        cfg.id = "preset_" + Date.now().toString(); // 生成唯一ID
        
        savedConfigs.push(cfg);
        localStorage.setItem('clawConfigs', JSON.stringify(savedConfigs));
        
        currentConfigToRun = cfg;
        document.querySelectorAll('.nav-item')[2].click(); // 跳转到 start-view
    }

    function useCurrentConfig() {
        currentConfigToRun = getFormConfig();
        currentConfigToRun.name = "【当前配置页面设定】";
        currentConfigToRun.id = null;
        document.querySelectorAll('.nav-item')[2].click(); // 跳转到 start-view
    }

    function deleteConfigPreset() {
        if(!currentConfigToRun.id || !confirm(`确定要删除预设 "${currentConfigToRun.name}" 吗？`)) return;
        
        savedConfigs = savedConfigs.filter(c => c.id !== currentConfigToRun.id);
        localStorage.setItem('clawConfigs', JSON.stringify(savedConfigs));
        
        // 删完后回退到临时配置
        currentConfigToRun = getFormConfig();
        currentConfigToRun.name = "【未保存的临时配置】";
        currentConfigToRun.id = null;
        updateStartScanView();
    }

    // 渲染启动页的看板
    function updateStartScanView() {
        const sel = $("config-select");
        sel.innerHTML = "";
        
        // 构建下拉选项
        if (!currentConfigToRun.id) {
            sel.innerHTML += `<option value="temp">${currentConfigToRun.name}</option>`;
        } else {
            sel.innerHTML += `<option value="temp">【回到当前表单修改设定】</option>`;
        }
        
        savedConfigs.forEach(c => {
            sel.innerHTML += `<option value="${c.id}">💾 ${c.name}</option>`;
        });
        
        sel.value = currentConfigToRun.id || "temp";
        $("btn-del-config").style.display = currentConfigToRun.id ? "inline-block" : "none";

        // 构建信息小看板
        const c = currentConfigToRun;
        $("config-preview").innerHTML = `
            <div style="margin-bottom: 8px;"><b>🎯 目标环境：</b> <span style="color:var(--brand); font-weight:bold;">${c.home}</span> | Skill目录: ${c.skill || '自动探测'}</div>
            <div style="margin-bottom: 8px;"><b>🌐 探测节点：</b> Gateway: <code>${c.gateway}</code> | Browser: <code>${c.browser}</code></div>
            <div style="margin-bottom: 8px;"><b>🛠️ 引擎深度：</b> 供应链(L2): <b>${c.skillGuard}</b> | 动态授权(L3): <b>${c.dynamicMode}</b> | Canary实验(L4): <b>${c.canaryMode}</b></div>
            <div style="color:var(--muted); font-size:12px; margin-top: 10px; border-top: 1px dashed #e5e7eb; padding-top: 8px;">
                报告策略: ${c.includeClean === '1' ? '完整展开' : '智能精简折叠'} | RPC字典: ${c.rpcPaths}
            </div>
        `;
    }

    // 下拉框选择事件：实现双向同步
    function onConfigSelectChange() {
        const val = $("config-select").value;
        if (val === "temp") {
            currentConfigToRun = getFormConfig();
            currentConfigToRun.name = "【当前配置页面设定】";
            currentConfigToRun.id = null;
        } else {
            const found = savedConfigs.find(c => c.id === val);
            if (found) {
                currentConfigToRun = found;
                setFormConfig(found); // 双向同步：选了预设，就把表单也填好，方便修改
            }
        }
        updateStartScanView();
    }


    // ========== 后端执行接口 ==========
    async function runEnvCheck() {
      const container = $("env-check-results");
      container.innerHTML = '<span class="hint" style="font-size:14px; margin-left: 16px;">正在诊断...</span>';
      try {
        const res = await fetch("/api/check_env");
        const data = await res.json();
        if (data.ok) {
          container.innerHTML = data.checks.map(c => 
            `<div class="check-item"><span class="check-name">${c.name}</span><span class="status-${c.status}">${c.status==='ok'?'✓':(c.status==='warn'?'⚠':'✖')} ${c.detail}</span></div>`
          ).join("");
        }
      } catch (err) { container.innerHTML = `<span class="status-error">✖ 后端未连接</span>`; }
    }

    async function startScan() {
      const btn = $("scan-btn"); btn.disabled = true;
      $("log").textContent = ">>> 初始化引擎环境，提取选用配置...";
      
      // 记录这次真正跑过的配置，方便下次打开浏览器恢复
      localStorage.setItem('clawLastUsed', JSON.stringify(currentConfigToRun));

      try {
        const c = currentConfigToRun;
        const body = new URLSearchParams({
          openclaw_home: c.home, skill_root: c.skill,
          gateway_url: c.gateway, browser_url: c.browser,
          skill_guard_engine: c.skillGuard, dynamic_mode: c.dynamicMode,
          method_probe_limit: "16", rpc_paths: c.rpcPaths,
          canary_mode: c.canaryMode, canary_dir: c.canaryDir,
          include_clean_sections: c.includeClean, format: "html"
        });
        
        appendLog(`准备向后端发射探测任务，目标：${c.home}`);
        const res = await fetch("/api/scan", { method: "POST", body });
        const data = await res.json();
        
        if (!data.ok) throw new Error(data.error || "扫描失败");
        appendLog("扫描完成！\\n" + (data.stdout || ""));
        
        document.getElementById('nav-report').click(); // 扫完切到报告页
      } catch (err) { 
        appendLog("✖ 错误：" + err.message); 
      } finally { 
        btn.disabled = false; 
      }
    }

    // ========== 历史记录、下载菜单与侧边栏控制 ==========
    
    let currentHistory = [];
    let historyCollapsed = false;

    function toggleHistory() {
        historyCollapsed = !historyCollapsed;
        const pane = $("history-pane");
        const btn = $("toggle-history-btn");
        if(historyCollapsed) {
            pane.classList.add("collapsed");
            btn.innerHTML = "« 展开历史";
        } else {
            pane.classList.remove("collapsed");
            btn.innerHTML = "收起历史 »";
        }
    }

    function toggleDropdown() { $("export-dropdown").classList.toggle("show"); }

    window.onclick = function(event) {
        if (!event.target.matches('#btn-download')) {
            var dropdowns = document.getElementsByClassName("dropdown-content");
            for (var i = 0; i < dropdowns.length; i++) {
                if (dropdowns[i].classList.contains('show')) dropdowns[i].classList.remove('show');
            }
        }
    }

    async function fetchHistory() {
      try {
        const res = await fetch("/api/history");
        const data = await res.json();
        if(data.ok) {
            currentHistory = data.history;
            renderHistory();
            if(!$("preview").src && currentHistory.length > 0) {
                previewReport(currentHistory[0].filename);
            }
        }
      } catch(e) { console.error("加载历史失败", e); }
    }

    function renderHistory() {
      const list = $("history-list");
      if(currentHistory.length === 0) {
          list.innerHTML = '<span class="hint" style="text-align:center; padding: 20px;">暂无扫描记录</span>';
          return;
      }
      const currentPreviewFile = $("preview").src.split('/').pop();
      list.innerHTML = currentHistory.map(item => {
        const isActive = currentPreviewFile === item.filename ? 'active' : '';
        const tagsHtml = item.tags.map(t => `<span class="htag ${t.type}">${t.label}</span>`).join('');
        return `
        <div class="h-item ${isActive}" onclick="previewReport('${item.filename}')" id="card-${item.filename}">
          <input type="checkbox" class="h-checkbox" value="${item.filename}" onclick="event.stopPropagation()">
          <div class="h-content">
            <div class="h-title-row">
              <span class="h-title" title="${item.name}">${item.name}</span>
              <div class="h-actions">
                  <button class="h-action-btn rename" onclick="renameReport(event, '${item.filename}', '${item.name}')" title="重命名">✎</button>
                  <button class="h-action-btn delete" onclick="deleteReport(event, '${item.filename}')" title="删除记录">🗑️</button>
              </div>
            </div>
            <div class="h-tags">${tagsHtml}</div>
            <div class="h-time">${item.time}</div>
          </div>
        </div>
        `;
      }).join('');
    }

    function previewReport(filename) {
        const reportItem = currentHistory.find(item => item.filename === filename);
        const customName = reportItem ? reportItem.name : filename.replace('.html', '');
        const reportUrl = "/reports/" + filename;
        $("preview").src = reportUrl;
        
        $("btn-open-html").disabled = false; $("btn-download").disabled = false;
        
        const base = filename.replace('.html', '');
        $("dl-html").href = reportUrl; $("dl-html").download = customName + ".html";
        $("dl-md").href = "/reports/" + base + ".md"; $("dl-md").download = customName + ".md";
        $("dl-json").href = "/reports/" + base + ".json"; $("dl-json").download = customName + ".json";

        document.querySelectorAll('.h-item').forEach(el => el.classList.remove('active'));
        const card = document.getElementById(`card-${filename}`);
        if(card) card.classList.add('active');
    }

    function openCurrentReport() {
        const src = $("preview").src;
        if(src) window.open(src, '_blank');
    }

    async function renameReport(event, filename, oldName) {
        event.stopPropagation();
        const newName = prompt("请输入新的报告备注名称：", oldName);
        if(newName && newName.trim() !== "" && newName !== oldName) {
            try {
                const body = new URLSearchParams({ filename: filename, name: newName.trim() });
                await fetch("/api/rename", { method: "POST", body });
                await fetchHistory();
                if ($("preview").src.endsWith(filename)) previewReport(filename);
            } catch(e) { alert("重命名失败"); }
        }
    }

    async function deleteReport(event, filename) {
        event.stopPropagation();
        if(!confirm("确定要彻底删除这份报告及其所有关联证据文件吗？此操作不可恢复。")) return;
        try {
            const body = new URLSearchParams({ filename: filename });
            const res = await fetch("/api/delete", { method: "POST", body });
            const data = await res.json();
            if(data.ok) {
                if ($("preview").src.endsWith(filename)) {
                    $("preview").src = ""; $("btn-open-html").disabled = true; $("btn-download").disabled = true;
                }
                await fetchHistory();
            } else { alert("删除失败：" + (data.error || "未知错误")); }
        } catch(e) { alert("网络错误，删除失败"); }
    }

    function compareSelected() {
        const checkboxes = document.querySelectorAll('.h-checkbox:checked');
        const selected = Array.from(checkboxes).map(cb => cb.value);
        if(selected.length < 2) { alert("请至少勾选 2 份报告进行对比！"); return; }
        if(selected.length > 4) { alert("最多支持同时对比 4 份报告。"); return; }
        window.open(`/compare?files=${selected.join(',')}`, '_blank');
    }

    // 页面启动执行
    runEnvCheck();
  </script>
</body>
</html>
"""

def get_meta() -> dict:
    if META_FILE.exists():
        try: return json.loads(META_FILE.read_text(encoding="utf-8"))
        except: pass
    return {}

def save_meta(data: dict):
    META_FILE.parent.mkdir(parents=True, exist_ok=True)
    META_FILE.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")

def timestamp() -> str:
    return dt.datetime.now().strftime("%Y%m%d-%H%M%S")

def resolve_report_artifact(name: str) -> Path | None:
    if not name or Path(name).name != name:
        return None
    target = (REPORTS / name).resolve()
    reports_root = REPORTS.resolve()
    try:
        target.relative_to(reports_root)
    except ValueError:
        return None
    return target

def report_family_paths(filename: str) -> list[Path]:
    if not filename.endswith(".html"):
        return []
    base = filename[:-5]
    artifacts: list[Path] = []
    for ext in [".html", ".json", ".md"]:
        target = resolve_report_artifact(base + ext)
        if target is not None:
            artifacts.append(target)
    return artifacts

class Handler(BaseHTTPRequestHandler):
    def _send(self, status: int, content: bytes, content_type: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(content)

    def _json(self, payload: dict, status: int = 200) -> None:
        self._send(status, json.dumps(payload, ensure_ascii=False, indent=2).encode("utf-8"), "application/json; charset=utf-8")

    def log_message(self, format: str, *args: object) -> None:
        pass # 静默后台日志

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        if parsed.path == "/":
            self._send(200, INDEX_HTML.encode("utf-8"), "text/html; charset=utf-8")
            return
            
        if parsed.path == "/api/check_env":
            import shutil, sqlite3
            checks = []
            checks.append({"name": "Python 版本 (>=3.9)", "status": "ok" if sys.version_info >= (3, 9) else "warn", "detail": f"{sys.version.split()[0]}"})
            try:
                sqlite3.connect(":memory:").close()
                checks.append({"name": "SQLite3 原生支持", "status": "ok", "detail": "已启用"})
            except: checks.append({"name": "SQLite3 原生支持", "status": "error", "detail": "缺失"})
            checks.append({"name": "Cargo (Rust 编译环境)", "status": "ok" if shutil.which("cargo") else "warn", "detail": "已安装" if shutil.which("cargo") else "未安装 (引擎降级)"})
            if (Path.home() / ".openclaw").exists():
                checks.append({"name": "OpenClaw 默认配置 (~/.openclaw)", "status": "ok", "detail": "已找到"})
            else:
                checks.append({"name": "OpenClaw 默认配置 (~/.openclaw)", "status": "warn", "detail": "未找到 (需指定)"})
            self._json({"ok": True, "checks": checks})
            return

        if parsed.path == "/api/history":
            history = []
            meta = get_meta()
            html_files = sorted(REPORTS.glob("clawmatrix_web_*.html"), key=lambda p: p.stat().st_mtime, reverse=True)
            for hf in html_files:
                jf = hf.with_suffix(".json")
                tags = []
                if jf.exists():
                    try:
                        data = json.loads(jf.read_text(encoding="utf-8"))
                        sev = data.get("summary", {}).get("highest_severity", "info")
                        tags.append({"label": sev.capitalize(), "type": sev})
                        mode = data.get("subject", {}).get("dynamic_mode", "plan")
                        tags.append({"label": f"L3:{mode.capitalize()}", "type": "mode"})
                    except: pass
                if not tags: tags.append({"label": "Unknown", "type": "default"})
                
                custom_name = meta.get(hf.name, "")
                default_name = hf.name.replace("clawmatrix_web_", "").replace(".html", "")
                history.append({
                    "filename": hf.name,
                    "name": custom_name or f"Scan_{default_name}",
                    "time": dt.datetime.fromtimestamp(hf.stat().st_mtime).strftime("%Y-%m-%d %H:%M"),
                    "tags": tags
                })
            self._json({"ok": True, "history": history})
            return

        if parsed.path == "/compare":
            files = parse_qs(parsed.query).get("files", [""])[0].split(",")
            files = [f for f in files if f.endswith(".html")]
            if not files:
                self._send(400, b"No valid files provided", "text/plain")
                return
            
            iframes_html = "".join([
                f'<div class="pane"><div class="title">{f}</div><iframe src="/reports/{f}"></iframe></div>' 
                for f in files
            ])
            compare_html = f"""<!DOCTYPE html><html><head><meta charset="utf-8"><title>报告横向对比</title>
            <style>
                body {{ display: flex; margin: 0; height: 100vh; background: #f3f4f6; font-family: sans-serif; gap: 2px;}}
                .pane {{ flex: 1; display: flex; flex-direction: column; background: white; border-right: 1px solid #ccc;}}
                .title {{ padding: 10px; text-align: center; font-size: 13px; font-weight: bold; background: #1f2937; color: white; word-break: break-all;}}
                iframe {{ flex: 1; border: none; width: 100%; }}
            </style>
            </head><body>{iframes_html}</body></html>"""
            self._send(200, compare_html.encode("utf-8"), "text/html; charset=utf-8")
            return

        if parsed.path.startswith("/reports/"):
            name = Path(parsed.path).name
            path = resolve_report_artifact(name)
            if path is None:
                self._send(404, b"not found", "text/plain; charset=utf-8")
                return
            if not path.exists() or not path.is_file():
                self._send(404, b"not found", "text/plain; charset=utf-8")
                return
            
            if path.suffix == ".html": ctype = "text/html; charset=utf-8"
            elif path.suffix == ".md": ctype = "text/markdown; charset=utf-8"
            else: ctype = "application/json; charset=utf-8"
            
            self._send(200, path.read_bytes(), ctype)
            return
            
        self._send(404, b"not found", "text/plain; charset=utf-8")

    def do_POST(self) -> None:
        parsed = urlparse(self.path)
        length = int(self.headers.get("Content-Length", "0"))
        body_text = self.rfile.read(length).decode("utf-8")
        form = parse_qs(body_text)

        if parsed.path == "/api/rename":
            filename = form.get("filename", [""])[0]
            new_name = form.get("name", [""])[0]
            if filename and new_name:
                meta = get_meta()
                meta[filename] = new_name
                save_meta(meta)
                self._json({"ok": True})
            else:
                self._json({"ok": False}, 400)
            return
            
        if parsed.path == "/api/delete":
            filename = form.get("filename", [""])[0]
            paths = report_family_paths(filename)
            if paths:
                for target_file in paths:
                    if target_file.exists() and target_file.is_file():
                        target_file.unlink()
                meta = get_meta()
                if filename in meta:
                    del meta[filename]
                    save_meta(meta)
                self._json({"ok": True})
            else:
                self._json({"ok": False, "error": "无效的报告文件"}, 400)
            return

        if parsed.path != "/api/scan":
            self._send(404, b"not found", "text/plain; charset=utf-8")
            return
            
        REPORTS.mkdir(parents=True, exist_ok=True)
        out = REPORTS / f"clawmatrix_web_{timestamp()}.html"
        
        args = [
            sys.executable, str(SCAN),
            "--openclaw-home", form.get("openclaw_home", ["~/.openclaw"])[0] or "~/.openclaw",
            "--skill-guard-engine", form.get("skill_guard_engine", ["auto"])[0] or "auto",
            "--dynamic-mode", form.get("dynamic_mode", ["plan"])[0] or "plan",
            "--method-probe-limit", form.get("method_probe_limit", ["16"])[0] or "16",
            "--rpc-paths", form.get("rpc_paths", [",/rpc,/api/rpc,/jsonrpc,/ws,/gateway"])[0],
            "--canary-mode", form.get("canary_mode", ["plan"])[0] or "plan",
            "--format", "html", "--out", str(out),
        ]
        if form.get("include_clean_sections", ["0"])[0] == "1":
            args.append("--include-clean-sections")
        
        for k in ["skill_root", "gateway_url", "browser_url", "canary_dir"]:
            val = form.get(k, [""])[0]
            if val: args.extend(["--" + k.replace("_", "-"), val])

        try:
            # 【关键修复】：注入环境变量，强制 Windows 子进程全局使用 UTF-8，彻底解决乱码
            env = os.environ.copy()
            env["PYTHONUTF8"] = "1"
            env["PYTHONIOENCODING"] = "utf-8"

            completed = subprocess.run(args, cwd=str(ROOT), text=True, capture_output=True, timeout=180, encoding="utf-8", env=env)
            if completed.returncode != 0: raise Exception(completed.stderr or completed.stdout)
            
            json_out = out.with_suffix(".json")
            json_args = args.copy()
            json_args[json_args.index("--format") + 1] = "json"
            json_args[json_args.index("--out") + 1] = str(json_out)
            subprocess.run(json_args, cwd=str(ROOT), text=True, capture_output=True, timeout=180, encoding="utf-8", env=env)

            md_out = out.with_suffix(".md")
            md_args = args.copy()
            md_args[md_args.index("--format") + 1] = "markdown"
            md_args[md_args.index("--out") + 1] = str(md_out)
            subprocess.run(md_args, cwd=str(ROOT), text=True, capture_output=True, timeout=180, encoding="utf-8", env=env)
            
            self._json({"ok": True, "message": "扫描完成", "stdout": completed.stdout})
        except Exception as exc:
            self._json({"ok": False, "error": str(exc)}, 500)

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="ClawMatrix local web console")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--no-open", action="store_true")
    return parser.parse_args()

def main() -> int:
    args = parse_args()
    REPORTS.mkdir(parents=True, exist_ok=True)
    server = ThreadingHTTPServer((args.host, args.port), Handler)
    url = f"http://{args.host}:{args.port}/"
    print(f"ClawMatrix 控制台：{url}")
    if not args.no_open: webbrowser.open(url)
    try: server.serve_forever()
    except KeyboardInterrupt: print("\n已停止。")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
