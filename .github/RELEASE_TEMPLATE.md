# Release Notes Template / 版本发布说明模板

> 本模板用于 GitHub Release、PyPI 发版与社区公告。所有发版说明必须遵循中英双语规范，段落一一对应、结构对称。
> This template is for GitHub Releases, PyPI announcements, and community notes. All release notes must adhere to the bilingual specification with symmetric, paired paragraphs.

---

## 🌟 版本亮点 / Highlights

### 🇨🇳 中文
- **[核心特性/变更 1]**：简明扼要说明该特性解决的痛点及价值。
- **[核心特性/变更 2]**：说明对系统安全性、成本或使用体验的提升。

### 🇬🇧 English
- **[Core Feature/Change 1]**: Concise explanation of the pain point solved and its value.
- **[Core Feature/Change 2]**: Improvement on system security, cost ledger accuracy, or user experience.

---

## 🛡️ 安全与对账机制 / Security & Ledger Mechanisms

### 🇨🇳 中文
- **安全拦截能力**：说明新增或优化的防火墙规则、密钥脱敏与阻断机制。
- **Token 与成本对账**：说明一手 Token 台账更新、官方公开单价支持与保鲜守护状态。

### 🇬🇧 English
- **Security Mitigation**: New or enhanced firewall rules, credential vault redaction, and Lethal Trifecta mitigation.
- **Token & Cost Accounting**: Updates to first-hand token accounting, official rate verification, and freshness monitoring.

---

## 📦 安装与升级方式 / Installation & Upgrade

```bash
# 方式一：免安装直接运行 (uvx) / Ephemeral execution via uvx
uvx metergate serve --mode observe

# 方式二：隔离 CLI 安装 (pipx) / Isolated CLI install via pipx
pipx install --upgrade metergate

# 方式三：标准 pip 升级 / Standard pip upgrade
pip install --upgrade metergate
```

---

## 📋 详细变更清单 / Detailed Changelog

- **Added / 新增**:
  - `Feature`: 详细说明 / Detailed description
- **Fixed / 修复**:
  - `Bugfix`: 详细说明 / Detailed description
- **Changed / 变更**:
  - `Change`: 详细说明 / Detailed description
