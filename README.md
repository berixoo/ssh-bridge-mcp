# ssh-bridge-mcp

让 Claude Code / Codex / Claude Desktop 通过 MCP 统一操作局域网 Linux 的 SSH 桥。本机常驻一个 MCP server（Node + `@modelcontextprotocol/sdk` + `ssh2`），把 SSH 封装成结构化工具；LLM 侧永远只看到工具与输出，看不到配置文件、看不到密码。

```
Claude Desktop / Claude Code / Codex
        |  MCP (stdio)
        v
本机 Windows 上运行的 MCP server (Node + @modelcontextprotocol/sdk + ssh2)
        |  SSH（密码来自本地配置）
        v
多台远程 Linux（配置文件里列出）
```

## 快速开始

1. `npm install`
2. 复制 `config.example.json` 为 `config.json` 并填写主机与密码（`sudoPassword` 缺省同 `password`）

   ```json
   {
     "default": "dev01",
     "hosts": {
       "dev01": {
         "host": "<remote-host-ip>",
         "port": 22,
         "user": "<username>",
         "password": "<ssh-password>",
         "sudoPassword": "<sudo-password>"
       }
     }
   }
   ```

3. 启动：`npm start`（或用 `SSH_BRIDGE_CONFIG=/path/to/config.json npm start` 指定配置路径）

配置文件默认在项目根目录 `config.json`，可用环境变量 `SSH_BRIDGE_CONFIG` 覆盖。配置文件内容在工具输出中永不出现。

## 接入

### Claude Desktop

在 `claude_desktop_config.json` 增加：

```json
{
  "mcpServers": {
    "ssh-bridge": {
      "command": "node",
      "args": ["<path-to>/ssh-bridge-mcp/src/server.js"]
    }
  }
}
```

### Claude Code

```bash
claude mcp add ssh-bridge -- node <path-to>/ssh-bridge-mcp/src/server.js
```

## 工具

| 工具 | 作用 |
|---|---|
| `list_hosts` | 列出可用主机名与地址（不含任何凭据） |
| `run_command` | 运行 shell 命令，返回 `{ exitCode, stdout, stderr }` |
| `read_file` | 读远程文本文件（面向文本/小文件；大文件用 `download`） |
| `write_file` | 写远程文本文件，自动建目录（面向文本/小文件；大文件用 `upload`） |
| `upload` | 本机 -> Linux，SFTP 传文件（大文件/目录） |
| `download` | Linux -> 本机，SFTP 传文件（大文件/目录） |
| `start_background` | 启动长驻进程（dev server、训练任务），返回 `task_id` |
| `background_logs` | 读后台进程日志（增量，从上次读的位置起） |
| `stop_background` | 终止后台进程 |

`run_command` 参数：`host` / `command` / `cwd` / `timeout_ms` / `sudo` / `pty` / `env` / `input`。`host` 可省略，缺省连配置的默认主机。

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

## 测试

```bash
npm test
```
