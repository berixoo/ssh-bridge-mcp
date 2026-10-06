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
     "hostKeyPolicy": "insecure",
     "localRoots": ["<allowed-local-dir>"],
     "maxDownloadBytes": 2147483648,
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

`hostKeyPolicy` 与 `localRoots` 都是**可选**的加固项，默认关闭（自用局域网 + 本地虚拟机场景）。不想要就直接删掉那两行，见「[安全边界](#安全边界)」。`maxDownloadBytes` 默认 2 GiB，只在你要传更大的文件时才需要动。

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
| `read_file` | 读远程文本文件（上限 500 KB，超了报错；大文件用 `download`） |
| `write_file` | 写远程文本文件，自动建目录（面向文本/小文件；大文件用 `upload`） |
| `upload` | 本机 -> Linux，SFTP 传文件（大文件/目录）。配了 `localRoots` 时本机路径须落在其中 |
| `download` | Linux -> 本机，SFTP 传文件（大文件/目录）。超过 `maxDownloadBytes`（默认 2 GiB）拒绝；配了 `localRoots` 时本机路径须落在其中 |
| `start_background` | 启动长驻进程（dev server、训练任务），返回 `task_id` |
| `background_logs` | 读后台进程日志（增量，从上次读的位置起；`truncated: true` 表示还有，继续调） |
| `stop_background` | 终止后台进程 |

`run_command` 参数：`host` / `command` / `cwd` / `timeout_ms` / `sudo` / `pty` / `env` / `input`。`host` 可省略，缺省连配置的默认主机。

## 安全边界

本项目默认面向**自用局域网 + 本地虚拟机**：两项校验默认关闭，不打扰开发。需要时按下面的开关打开，启动时若两项都没开会在 stderr 提示一次。

### 主机密钥校验

`ssh2` 在没有 `hostVerifier` 时**接受任意主机密钥**（见 ssh2 README：*Default: (auto-accept if hostVerifier is not set)*）——也就是谁在那个 IP 上应答，密码就交给谁。策略由 `hostKeyPolicy` 决定：

| 取值 | 行为 |
|---|---|
| `insecure`（默认） | 不校验。README 已写明风险，不做任何额外动作 |
| `tofu` | 首次连接记录密钥到 `known_hosts`，此后必须一致；不一致一律拒绝 |
| `strict` | 必须已在 known_hosts 中，否则拒绝 |

`tofu` 与本地虚拟机重建这种场景是冲突的：VM 重建会换主机密钥，连接会被拒到你把那一行删掉。频繁重建的 VM 就别开，或者用 `hostKeyFingerprint` 钉。

- 可信密钥存放于 `known_hosts`（OpenSSH 格式，默认在 `config.json` 同目录；`knownHosts` 可指定路径或路径数组，第一个是写入目标）。若 `~/.ssh/known_hosts` 存在，会一并**只读**参与匹配，所以你在 Git Bash 里连过的主机不用重新录。
- `knownHosts` 和 `localRoots` 里的相对路径按 `config.json` 所在目录解析（不是进程 cwd——那个由拉起 server 的客户端决定）。
- 预置密钥直接照抄 OpenSSH 的习惯：

  ```bash
  ssh-keyscan -p 22 <remote-host-ip> >> known_hosts
  ```

- 不想用 known_hosts 的话，按主机钉指纹：`"hostKeyFingerprint": "SHA256:..."`（`ssh-keygen -lf` 的输出）。这一项与 `hostKeyPolicy` 无关，配了就生效。
- `@revoked` 条目会被硬拒；`@cert-authority` 不支持，也会被拒（不会偷偷降级成 tofu）。
- 密钥变了就报错并列出新旧指纹：主机确实重装过，删掉 known_hosts 里那一行再连。

### 本机路径边界

`upload` / `download` 的本机路径由模型传入，没有边界时被 prompt injection 的 agent 可以把本机任意文件（含 `config.json` 里的明文密码）传到远程主机，或用 `download` 覆盖本机任意路径。`localRoots`（目录数组，可选）用来把范围圈住：

- **不配 = 不限制**（默认，开发时最省事）；配了就只允许这些目录。
- 比较前先解析真实路径（symlink 逃不出去），Windows 下大小写不敏感，`..` 和同名前缀的兄弟目录都会被拒。
- 配了不存在的目录会启动报错并列出实际解析到的绝对路径。

另外有一条**始终生效、不可关闭**：配置文件本身永远不可传输。它零成本（没人需要把自己的凭据库传到虚拟机上），且正好是上面那条泄露路径的入口。

### 传输大小上限

`download` 在传第一个字节之前先 `stat` 远端文件，超过 `maxDownloadBytes` 就拒绝，默认 **2 GiB**（`0` = 不限制）。这是防「远端把本机磁盘写满」，不是防大文件——50 MB ~ 1 GB 这类正常传输不受影响，实测 50 MB 文件约 47 MB/s 且逐字节一致。

拒了就把 `maxDownloadBytes` 调大；限额是配置项而不是硬编码，正是为了不挡住正当的大文件。传完还会核对本地文件字节数与远端声明的一致，写少了会报错而不是当成功返回。

### 算法套件

ssh2 自己的默认提议列表**本来就是现代的**——CBC、3DES、arcfour、ssh-dss、sha1 系列密钥交换只在它的 "supported" 列表里，不主动提议。所以默认列表里唯一过时的东西是 SHA-1，本 server 把它减掉：

- `serverHostKey` 去掉 `ssh-rsa`（SHA-1 签名方案）
- `hmac` 去掉 `hmac-sha1` 与 `hmac-sha1-etm@openssh.com`

用的是 ssh2 的 `remove` 操作，从默认列表里做减法，所以 ssh2 的能力探测仍然生效，不会出现「请求了本机 crypto 不支持的算法」而直接抛错。实测发出去的 KEXINIT 为：

```
serverHostKey: ssh-ed25519, ecdsa-sha2-nistp256, ecdsa-sha2-nistp384, ecdsa-sha2-nistp521, rsa-sha2-512, rsa-sha2-256
mac          : hmac-sha2-256-etm@openssh.com, hmac-sha2-512-etm@openssh.com, hmac-sha2-256, hmac-sha2-512
```

- 要按主机自定义就写 `algorithms`（ssh2 的格式：精确数组，或 `append` / `prepend` / `remove` 对象；对象形式会与上面的减法合并，数组形式则整体替换该组）。
- 遇到只支持 ssh-rsa 的老设备，写 `"allowLegacyAlgorithms": true` 恢复 ssh2 的完整默认提议。

`sudoPassword` 缺省等于 `password`（见 `src/config.js`）：sudo 与 SSH 共用同一个密码时，一台主机失守就等于那台机器 root 失守。密码不同的话显式写 `sudoPassword`。


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

- 文本/小文件：`read_file` / `write_file`（UTF-8，自动建目录）。`read_file` 上限 500 KB。
- 大文件/二进制/整个目录：`upload` / `download`（SFTP 流式，路径不经 shell，无转义问题）。
- 本地路径是本机 Windows 路径，远程路径是目标 Linux 路径，勿混淆。
- 配了 `localRoots` 时本机路径必须在其中，越界会被拒绝——那是策略，不是权限故障，别改成别的路径重试。

### 6. 长驻进程

- dev server、训练等长驻任务用 `start_background`，返回 `task_id`，用 `background_logs` 增量看日志，`stop_background` 终止。
- 后台进程池**仅限当前客户端进程**，Claude Desktop 起的进程 Codex 看不到。

### 7. 常用开发组合（示意）

- 跑测试：`run_command(command: "npm test", cwd: "/project")`
- git 提交（多行消息）：`run_command(command: "git commit -F -", input: "feat: 新增 X\n\n- a\n- b")`
- 查看日志：`run_command(command: "journalctl -u myapp --no-pager -n 50", sudo: true)`
- 构建并部署：`run_command(command: "npm ci && npm run build && ./deploy.sh")`
