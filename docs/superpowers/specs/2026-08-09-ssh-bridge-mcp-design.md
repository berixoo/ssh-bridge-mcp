# SSH Bridge MCP — 设计文档

日期：2026-08-09

## 背景与目标

开发工作一部分在物理机（Windows），一部分在局域网内的一台或多台 Linux（物理机或虚拟机）上。为了让 Claude Code、Codex、Claude Desktop 等本机 agent 能统一、可靠地操作远程 Linux 进行项目开发（上传下载文件、代码开发、运行部署、git 协作），需要一个 MCP server 把 SSH 封装成结构化工具。

### 要解决的问题

- 本机 agent 手工拼 `ssh user@ip "cmd"` 命令经常出现引号转义、管道、sudo 处理等拼接错误。
- Claude Desktop 没有 SSH / 文件系统能力，唯一的扩展通道是 MCP。
- 多客户端（Claude Code / Codex / Claude Desktop）希望统一连到同一组 Linux，行为一致，凭据集中管理。

## 架构

```
Claude Desktop / Claude Code / Codex
        │  MCP (stdio/HTTP)
        ▼
本机 Windows 上运行的 MCP server (Node + @modelcontextprotocol/sdk + ssh2)
        │  SSH（密码来自本地配置）
        ▼
多台远程 Linux（配置文件里列出）
```

- Server 常驻本机，配置在本地。
- **LLM 侧永远只看到工具与输出，看不到配置文件、看不到密码** —— 密码由 server 自己持有，绝不作为工具参数出现。
- 文件传输走 SFTP，不经过 shell，杜绝引号/转义错误。

## 技术栈

- Node.js + 官方 `@modelcontextprotocol/sdk`（与 mimo-search 同模式）
- `ssh2` 库：SSH/SFTP/PTY 支持成熟，是事实标准
- `zod`：参数校验
- 无构建步骤，纯 JS

## 配置（config.json）

```json
{
  "default": "dev01",
  "hosts": {
    "dev01": {
      "host": "192.168.1.10",
      "port": 22,
      "user": "roooi",
      "password": "...",
      "sudoPassword": "..."
    }
  }
}
```

- 主机名是 agent 调用工具时的唯一标识。
- `default` 指定缺省主机，允许工具调用省略 `host` 参数。
- `sudoPassword` 可选，缺省与 `password` 相同。
- 配置文件名/内容在工具输出中**永不出现**。
- 建议 `chmod 600`，字段名固定（`password` / `sudoPassword`），不做加密（局域网自用）。

## 工具设计原则

**一个万能执行器 + 结构化文件传输**。

- `run_command` 覆盖一切命令类操作（git、npm、部署、构建等），通过参数解决引号/转义/环境变量/多行等 shell 拼接问题。
- 文件走 SFTP（`upload`/`download`）与文本读写（`read_file`/`write_file`），不经过 shell。
- **不堆专用工具**（git、npm、apt、部署等）：专用工具本质仍是让 agent 拼参数，且工具面翻倍；真正的报错源（如 git 加错文件）是 agent 判断问题，不是 shell 语法问题，结构化也修不好。
- 可执行命令不受工具面限制 —— 任何 shell 命令都可通过 `run_command` 执行。

## 工具面

### 连接与基础（`host` 参数可选，缺省连默认主机）

- `list_hosts()` — 列出可用主机名及地址（不含任何凭据）

- `run_command(host, command, cwd, timeout_ms, sudo, pty, env, input)` — 核心工具
  - `command` 为 shell 字符串，可含换行，多行内容以 `bash -c` 语义执行（支持脚本/heredoc）
  - `env`（可选）对象注入环境变量，避免手拼 `FOO=bar cmd` 的引号问题
  - `sudo=true` 时自动用 `sudo -S` 喂密码
  - `pty=true` 时在 PTY 下执行（获得 tty 环境，解决 npm 等 CLI 需要 tty 才能跑的问题）
  - `input`（可选）一次性写入 stdin 后关闭 —— 用于需要一次性输入的命令；持续交互对话不在范围（见「非目标」）
  - 返回 `{ exitCode, stdout, stderr }`

### 文件（全部走 SFTP，不经 shell）

- `read_file(host, path)` — 读远程文本文件（面向文本/小文件；大文件用 `download`）
- `write_file(host, path, content)` — 写远程文本文件，自动建目录（面向文本/小文件；大文件用 `upload`）
- `upload(host, local_path, remote_path)` — 本机 → Linux
- `download(host, remote_path, local_path)` — Linux → 本机

### 后台进程

- `start_background(host, command, cwd)` — 启动长驻进程（dev server、训练任务），返回 `task_id`
- `background_logs(task_id, tail)` — 读后台进程日志（增量，从上次读的位置起）
- `stop_background(task_id)` — 终止进程

## 关键行为

- **命令失败**返回真实 exit code，不抛异常；命令超时返回 timeout 状态。
- **后台进程**：server 端维护 `task_id → { conn, channel, buffer }` 映射，日志按行缓冲，`background_logs` 返回增量（从上次读的位置起）。`stop_background` 发 SIGKILL。server 重启后后台进程清理，不跨重启恢复。
- **多客户端各自独立进程**：每个 MCP 客户端（Claude Desktop / Claude Code / Codex）通过 stdio 各自拉起一个 server 进程，后台进程池（task_id）**不跨客户端共享**。跨客户端共享后台进程不在范围。
- **sudo 密码喂入**：通过 `sudo -S -p ''` 写入 channel stdin，不出现在远端命令行参数（避免出现在进程列表 / shell 历史）。
- **连接池**：每个 host 维护一个可复用的连接（失败自动重建），多 host 并行；`background_logs` / `stop_background` 必须命中同一连接。

## 安全

- 配置文件内容在工具输出中**永不出现**。
- SSH 连接错误信息剥离凭据。
- 配置文件放项目根目录 `config.json`（可用环境变量 `SSH_BRIDGE_CONFIG` 指定路径），server 进程能读，LLM 读不到。
- 自用局域网场景，不做过度加密。

## 错误处理

- 连接失败 / 认证失败 → 清晰报错，不泄漏密码。
- 每个工具在 server 侧 catch，返回结构化错误而非崩掉。

## 测试

- `scripts/self-check.mjs` 用 assert 验证核心逻辑。
- 每个非平凡逻辑留一个可运行的检查。

## 使用说明（面向 agent）

本 MCP 的所有能力通过以下约定使用，避免命令拼接错误：

### 1. 环境变量

- `env` 参数注入，不要手拼 `FOO=bar cmd` 或 `export FOO=bar && cmd`。
  ```
  run_command(command: "npm test", env: { NODE_ENV: "test", DEBUG: "1" })
  ```

### 2. 多行命令

- `command` 传多行字符串即脚本，作为单个参数交给 `bash -c` 执行，支持 heredoc。注意外层 shell 不保留 cd —— 多条命令用 `&&` 串联。
  ```
  run_command(command: "cd /app && npm ci && npm run build")
  ```
- heredoc 通过 `<<'EOF'` 避免变量展开：
  ```
  run_command(command: "cat > /tmp/x.sh <<'EOF'\necho keep_literal\nEOF\nbash /tmp/x.sh")
  ```

### 3. sudo 提权

- 需要 root 时设 `sudo: true`，server 自动喂密码。不要手写 `echo password | sudo`。
  ```
  run_command(command: "apt-get update && apt-get install -y python3", sudo: true)
  ```

### 4. 命令失败与超时

- 命令非零退出**不会抛异常**，返回真实 exit code。检查 `exitCode` 而不是捕获异常。
- 超过 `timeout_ms` 返回 timeout 状态，考虑拆短命令或改用 `start_background`。

### 5. 文件操作

- 文本/小文件：`read_file` / `write_file`（UTF-8，自动建目录）。
- 大文件/二进制/整个目录：`upload` / `download`（SFTP 流式，路径不经 shell，无转义问题）。
- 本地路径是本机 Windows 路径，远程路径是目标 Linux 路径，勿混淆。

### 6. 长驻进程

- dev server、训练等长驻任务用 `start_background`，返回 `task_id`，用 `background_logs` 增量看日志，`stop_background` 终止。
- 后台进程池**仅限当前客户端进程**，Claude Desktop 起的进程 Codex 看不到。

### 7. 常用开发组合（示意）

- 跑测试：`run_command(command: "npm test", cwd: "/project")`
- git 提交（多行消息）：`run_command(command: "git commit -F -", input: "feat: 新增 X\n\n- a\n- b")`
- 查看日志：`run_command(command: "journalctl -u myapp --no-pager -n 50", sudo: true)`
- 构建并部署：`run_command(command: "npm ci && npm run build && ./deploy.sh")`

## 明确的非目标（YAGNI）

- 不专门做 git 工具 —— 用 `run_command` 跑 `git` 即可。
- 不专门做部署工具 —— 同理由 `run_command` 覆盖。
- 不做持久交互会话（start_session / send_input）—— 由 pty 标志 + `input` 参数 + 后台进程覆盖一次性/持续输出场景；`python -i` 这类需要反复喂输入的持续对话不在范围。
- 不做跨 server 重启的后台进程恢复。
- 不做凭据加密存储。
