# Trailblazer Katana

基于 [ProjectDiscovery Katana](https://github.com/projectdiscovery/katana) 的二次开发版本。它保留 Katana 的标准/无头浏览器爬取能力，并将浏览器运行时请求沉淀为可复用、可审计的 API 资产，用于**已获授权**的 API 发现、文档生成与安全验证。

> 完整的原始爬虫功能、参数说明、Docker 使用方式和高级配置，请参阅 [Katana 官方仓库](https://github.com/projectdiscovery/katana) 与其 [官方文档](https://docs.projectdiscovery.io/opensource/katana/overview)。本仓库只说明二开新增能力。

## 二开功能

### 1. API 上下文采集

启用无头混合爬虫后，可捕获 XHR 与 Fetch 请求的完整上下文，而不仅是 URL。每条 API 资产包含：

- HTTP 方法和参数化路径，例如 `/api/users/{id}`；
- 路径、查询、请求体参数及推断类型；
- 请求/响应 Content-Type、请求体和响应 Schema；
- Bearer、Cookie 等认证迹象；
- 来源页面、运行时观测等证据；
- 保留原文的敏感头和敏感字段值。

重复观测会按 `method + pathTemplate` 合并，保留较可靠的成功响应、字段信息、证据与观测次数。

### 2. Observed API Docs 与 OpenAPI 3.1

`pkg/apicontext` 可将合并后的 API 资产导出为 OpenAPI 3.1 文档，包括路径、方法、参数、请求/响应 Schema 与认证方案。

该文档来自运行时观测和推断，不是服务端正式契约。置信度、证据和观测次数会一并输出，避免将推断结果误认为接口承诺。

### 3. 授权对照实验

`pkg/apiaudit` 可基于已捕获的带认证请求，构造去除凭据的匿名变体，并与原始响应进行对照。判定会综合比较：

- 状态码；
- Content-Type；
- 顶层 JSON 字段相似度。

通用错误页、空/过短响应和泛化 JSON 会被排除，以降低误报。此能力默认不通过 CLI 自动执行，且只应在明确授权的目标上由调用方启用。

当前刻意不覆盖低权限账号对照和 IDOR 变体；这些场景需要额外账号、对象归属和业务规则，不能用简单的匿名请求替代。

## 快速开始

需要 Go 1.26+ 和可用的 Chrome/Chromium（无头模式）。

```bash
git clone https://github.com/qiwentaidi/katana.git
cd katana
git checkout trailblazer-dev
CGO_ENABLED=1 go build -o katana ./cmd/katana
```

采集 API 上下文：

```bash
./katana \
  -u https://target.example \
  -headless \
  -system-chrome \
  -api-capture \
  -jsonl \
  -o api-contexts.jsonl
```

`-apic` 是 `-api-capture` 的短参数。观测到 API 请求时，JSONL 输出会包含 `api_contexts` 字段。

## 作为 Go 库使用

新增包：

- `github.com/qiwentaidi/katana/pkg/apicontext`：构建、合并 API 上下文并导出 OpenAPI；
- `github.com/qiwentaidi/katana/pkg/apiaudit`：执行授权对照实验。

本 fork 使用独立的 Go 模块路径，可以被其他项目直接依赖：

```go
go get github.com/qiwentaidi/katana@latest
```

## 安全边界

- 只对已获得授权的目标进行爬取和验证。
- 本仓库版本的 API 上下文保留认证材料和敏感字段原文。
- 授权对照实验会发送额外请求；应设置范围、速率和请求预算。
- OpenAPI 导出是观测结果，不应替代服务端接口文档或安全评审。

## 与上游同步

本仓库的 `upstream` 指向 [ProjectDiscovery Katana](https://github.com/projectdiscovery/katana)。同步上游时应先评估无头网络事件、结果模型与 CLI 选项的兼容性，再合并到 `trailblazer-dev`。
