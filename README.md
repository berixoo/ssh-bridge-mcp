# ssh-bridge-mcp

让 Claude Code / Codex / Claude Desktop 通过 MCP 统一操作局域网 Linux 的 SSH 桥。本机运行一个 MCP server（Node + `@modelcontextprotocol/sdk` + `ssh2`），把任意 shell 命令、sudo、文件操作、截图、托管后台任务与本地 TCP 转发封装成结构化工具。

```text
Claude Desktop / Claude Code / Codex
        |  MCP (stdio)
        v
本机 MCP server（配置与凭据保留在本机）
        |  SSH（密码 / 私钥 / 本机 agent）
        v
配置中的远程 Linux 主机
```

**定位不变：可信局域网 + 本地虚拟机，不是沙箱。** 不增加命令白名单，不取消任意命令与 sudo，也不做凭据加密存储。工具不会主动列出凭据，但不能阻止具有其他本机文件访问能力的客户端读取配置。

## 快速开始

1. `npm install`
2. 复制 `config.example.json` 为 `config.json`，只保留需要的主机条目，填写连接信息。最小密码配置如下：

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

3. 启动：`npm start`。配置默认是项目根目录的 `config.json`，可用 `SSH_BRIDGE_CONFIG=/path/to/config.json npm start` 指定其他路径。

`sudoPassword` 缺省回落到 `password`。密码不是必填项：也可使用私钥或本机 SSH agent，见「[认证](#认证)」。

`hostKeyPolicy` 与 `localRoots` 是**可选加固**：默认分别为 `insecure` 与不限制本机路径，不想启用就不配置。示例文件中的 `localRoots` 是占位目录，需替换或删除。`maxDownloadBytes` 默认 2 GiB；`poolSize` 默认 4，`channelsPerConnection` 默认 6。

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

`host` 可省略，依次使用配置的 `default`、第一个主机。各工具可传 `timeout_ms`，默认命令 30 秒、截图 90 秒、其他操作 60 秒；这是包含连接、排队与执行的整次操作预算，不是每个子步骤各获一份预算。客户端取消请求也会触发清理。

| 工具 | 作用 |
|---|---|
| `list_hosts` | 列出主机名、地址、端口与用户，不列凭据 |
| `run_command` | 任意 shell 命令；返回 `exitCode`、`stdout`、`stderr`、`timedOut`、`truncated`，必要时含 `outcome` |
| `read_file` | UTF-8 文本与 SHA-256；默认完整读取至多 500 KiB，也支持有界行范围、head/tail |
| `write_file` | 写文本，自动建父目录；先暂存再提交 |
| `patch_file` | 基于整文件哈希的唯一字面量替换，可 `dry_run` |
| `list_dir` | SFTP 列目录，含名称、类型、大小、mtime、权限，目录排前 |
| `search_files` | 优先 ripgrep、回退 grep；返回 `{file, line, text}`，无匹配不是错误 |
| `rename` | SFTP 移动/重命名路径，自动建目标父目录 |
| `delete` | 删文件、链接、空目录；`recursive: true` 删树，链接只解除不跟随 |
| `screenshot` | 查找已登录图形会话，直接返回桌面图片 |
| `upload` / `download` | SFTP 传输**单个文件，不支持目录**；本机路径受可选 `localRoots` 约束 |
| `persistent_shell_close` | 关闭当前 host 的持久 bash，清空其 shell 状态 |
| `start_background` | 启动可跨 MCP 重启恢复的托管任务，返回 `task_id` |
| `background_logs` | 按字节游标读取有限量增量日志及任务状态 |
| `stop_background` | 尽力终止托管任务；可显式清理已终态任务的远程文件 |
| `list_background` | 从远程元数据恢复并列出托管任务，不把不可达误当完成 |
| `open_tunnel` | 创建进程内本地 TCP 转发，默认仅监听 loopback |
| `list_tunnels` / `close_tunnel` | 列出当前进程的转发 / 幂等关闭监听器及其流 |

### 命令、取消与不确定结果

`run_command` 参数包括 `command` / `cwd` / `env` / `input` / `sudo` / `pty` / `pipefail` / `session`，以及 `host`、`timeout_ms`。

- 默认一次性 shell；支持多行脚本与 heredoc，`input` 一次性写入后关闭 stdin。
- `sudo: true` 使用配置的 sudo 密码经 stdin 交给 `sudo -S`，不把密码放进远端命令行。`pty: true` 可为一次性命令申请终端，但不是持续交互接口。
- `pipefail: true` 让管道任一段失败影响退出码；默认关闭，避免改变 `cmd | head` 的常用行为。
- 非零退出码不是工具异常；检查 `exitCode`。输出有界，超出会标记 `truncated`。
- **没有自动重试或自动重放**，包括 exec 打开被明确拒绝时也不重试。后续新调用可以复用仍健康的连接，或建立新连接，但不会补跑旧命令、文件修改或任务启动。
- 连接在派发后断开，可能返回 `outcome: "unknown"` / `OUTCOME_UNKNOWN`；超时可能返回 `timedOut: true` 与 `termination: "best_effort"`。客户端取消或文件操作错误也不证明远端没有产生副作用。不要机械重试：先查文件、任务或业务状态。
- 终止是尽力而为，不承诺杀死所有后代，也不保证回滚已经发生的修改。

### 持久 shell 会话

`session: true` 使用每 host 一个**串行、非 PTY、非交互的 bash**。`cwd`、环境变量与 shell 函数在同一存活会话中保留，不是 Python REPL 或密码提示等反复交互终端。

```text
run_command(command="cd /project", session=true)
run_command(command="pwd", session=true)                  -> /project
run_command(command="export FOO=1; f() { echo $FOO; }", session=true)
run_command(command="f", session=true)                    -> 1
persistent_shell_close()
```

每次提交作为一个完整命令单元执行；用随机标记识别该单元的结束，而不是等待每一行的 shell prompt。多行命令不会在中间提示符处提前完成。`src/shell.js` 的旧交互式 `PROMPT_COMMAND` / OSC parser 是遗留代码，不是当前生产执行路径；这些标记也不是对不可信命令输出的安全隔离。

**限制**：session 模式拒绝 `sudo: true`、任何 `input` 和 `pty: true`，请改用一次性执行。断线、取消或显式关闭会丢失该 shell 的状态；恢复会话不恢复旧 cwd/env/functions。shell 状态丢失不表示独立托管任务也已结束。

### 文件读取、补丁与提交边界

`read_file` 不带范围时，最多完整读取 **500 KiB（512000 字节）**，返回 `content`、`sha256`、`hash_scope: "whole_file"`、`bytes`、`truncated: false`。过大报错，改用范围或下载。

- 范围参数：`start_line` / `end_line`（从 1 开始，包含端点）、`head` 或 `tail`；head/tail 与行范围互斥。`max_bytes` 不超过 512000。
- 读取预算同时约束扫描量，不会为寻找很远的行号而无限扫描。目标行超出扫描窗口可能返回空内容及 `truncated: true`；tail 只查看末尾的有限字节窗口，不能保证找到请求的全部行。
- 范围结果含 `range`（字节区间左闭右开）、`scanned_bytes`、`next_offset`、`file_size` 与 `truncated`。`next_offset` 是本次扫描进度，不是另一个已公开的字节偏移输入参数。tail 窗口中无法确定绝对行号时返回 `null`。
- `hash_scope: "range"` 只校验返回片段，**不能当作整文件版本**交给 `patch_file`；确实完整覆盖文件时才返回 `whole_file`。

补丁示意：

```text
read_file(path="/project/app.js")
patch_file(path="/project/app.js", expected_hash="<whole-file sha256>",
           edits=[{old_text:"const n = 1;", new_text:"const n = 2;"}], dry_run=true)
patch_file(path="/project/app.js", expected_hash="<same whole-file sha256>",
           edits=[{old_text:"const n = 1;", new_text:"const n = 2;"}])
```

`patch_file` 要求文件是合法 UTF-8，原文件与结果都不超过文本读取上限。每个 `old_text` 必须在**原文件**恰好出现一次，各编辑不能重叠；不做模糊匹配，保留 BOM 与原有换行。整文件 SHA-256 不匹配会报 `FILE_CONFLICT`，提交前还会复核。`dry_run` 不写文件，返回拟议结果哈希。

**哈希检查是乐观冲突检测，不是文件系统 compare-and-swap（CAS）**：最后一次检查与 rename 之间仍存在外部写入窗口。同一桥实例会串行化同 host / 规范化路径的 write、upload、patch，但不能锁住其他进程、其他 MCP 实例、路径别名或远端编辑器。

写入与传输采用同目录随机暂存文件，校验暂存字节数后提交；下载也先写本机同目录暂存文件，再 rename 到目标。失败时尽力清理暂存文件；断连导致清理无法完成时可能留下 `.sshbridge-*.tmp`。

- 远端覆盖已有文件要求 OpenSSH `posix-rename@openssh.com` 扩展；不支持时报 `ATOMIC_REPLACE_UNSUPPORTED`，**不先删除原文件来模拟覆盖**。新文件使用标准 SFTP rename。
- 写目标的叶子为符号链接、目录或非普通文件会被拒绝；这是避免误覆盖，不是对远端恶意并发进程或父目录替换的隔离保证。
- 提交保留已有目标的权限位，不保证保留 owner、ACL、扩展属性或硬链接身份。rename 的可见性不等于断电持久性：没有 fsync 事务保证，也不是目录树事务。
- `upload` / `download` **只支持单个普通文件，不支持目录递归**。需要整目录时自行打包，再传单个归档。
- 传输核对字节数，下载还核对远端前后大小；这不等于端到端内容哈希验证，也不能检测所有同长度并发修改。

### 托管后台任务

`start_background` 把命令、环境、日志与版本化元数据写入远端用户的 `~/.cache/ssh-bridge/jobs/`，由独立 supervisor 执行。依赖 Linux `/proc`、bash、`setsid`、`nohup` 等常用工具与文件系统硬链接能力，不需安装常驻服务。

- `start_background(command, cwd?, env?, input?)` 返回 `task_id`（兼容 `taskId` 别名）。**不支持托管 sudo 标志**：`sudo: true` 明确拒绝；若远端权限策略允许，可在命令里显式使用非交互 `sudo -n ...`，桥不为此喂密码。也不支持 session、pty 或 pipefail 选项。
- 日志在远端落盘，stdout/stderr 合并。**磁盘日志无大小上限，不自动轮转、不自动删除**，会占满磁盘；调用方负责监控空间和清理。
- `background_logs(task_id, cursor?, limit?)` 返回 `content`、下一字节 `cursor`、`truncated` 与状态。`limit` 默认 65536 字节，允许 4..1048576；`truncated: true` 说明还有待读日志。未传 cursor 时使用当前 manager 的增量位置；重启后该隐式位置重置，要续读请保存并显式传回 cursor。
- `list_background(host?, cursor?, limit?)` 从远端恢复任务；分页 cursor 是任务枚举偏移，不是日志字节偏移。任务 ID 包含配置中的 canonical host 名；重启后恢复要求保留相应主机名与远端用户/任务目录。
- `running` / `succeeded` / `failed` / `stopped` 是可识别状态；失联、身份无法确认等情况返回 `status: "unknown"`、`running: null`，不是“已完成”。若启动回执丢失，不重复启动，先用列表或已有 ID 核对。
- `stop_background(task_id, grace_ms?, cleanup?)` 校验启动时间、boot ID 与会话身份，再尝试 TERM，宽限后 KILL。默认宽限 2 秒，停止可重复调用；主动 daemonize / `setsid` 逃离原会话的后代不在可靠管控范围内，不是 cgroup 隔离。
- 终态也保留日志与元数据。**显式调用 `stop_background(task_id, cleanup=true)` 才删除这些文件**；活动或 unknown 任务不能清理。清理前先取走需要的日志。
- MCP 重启、SSH 断线或桥关闭不主动杀掉托管任务。其他 MCP 进程在使用相同 host 配置名、同一远端用户时也可恢复这些元数据；旧版仅内存 task ID 不属于此恢复协议。

### 本地 TCP 转发

```text
open_tunnel(host="dev01", remote_host="127.0.0.1", remote_port=3000,
            local_host="127.0.0.1", local_port=0)
```

返回 `tunnel_id`、`host`、`local_host`、实际 `local_port`、`remote_host`、`remote_port`。`local_port: 0` 自动选空闲端口，`remote_host` 与 `local_host` 默认均为 `127.0.0.1`；remote_host 从 SSH 服务端的网络环境解释。

**仅当前 MCP 进程有效**，不是远端端口开放或持久代理。可显式绑定可信 LAN 地址或 `0.0.0.0`，但这会让其他能访问该地址的人通过监听端口访问远端服务，桥不会额外为流量增加认证。

每条 TCP 流使用 ssh2 `forwardOut` 的 direct-tcpip，不占 sshd 的 `MaxSessions` session 配额；仍受服务端转发策略与资源限制。每条流的打开等待最多 15 秒，连接后双向 pipe 保留背压。绑定端口冲突报错而不关闭既有监听器；取消打开操作不遗留监听器。所属 SSH transport 失效会关闭监听器和流，**不重连重放流量、不跨重启恢复**，需显式重新打开。`close_tunnel(tunnel_id)` 幂等关闭监听器及其活动流。

### 截图

`screenshot` 自行通过 `loginctl` 找当前用户已登录的图形会话，不需传 `DISPLAY`，SSH 的 tty 会话不会当作图形桌面。

- GNOME/Wayland：尝试 `gnome-screenshot` / Xwayland 路径。
- wlroots/sway/KDE：尝试 `grim` / `spectacle`。
- X11：尝试 `scrot` / `maim` / ImageMagick。

工具须已安装，能否截图取决于桌面权限与 compositor；每次尝试有超时。默认缩到 1600px、JPEG q82，要原尺寸传 `max_width: 0`。特定桌面版本的既有实测不是所有系统的兼容保证。

### 连接与性能

每 host 懒加载连接池，`poolSize` 默认 4（1..16），`channelsPerConnection` 默认 6（1..8）。SFTP 会话和持久 shell 在其存活期间各占一个 session 配额；上限需与目标 sshd 配置协调。SFTP 按 host 复用，失败时丢弃；后续调用可重建，**当前操作不重放**。

连接使用 TCP_NODELAY、TCP keepalive 与 SSH keepalive。排队、连接和子步骤都受当前操作预算限制；TCP 连接与 SSH 握手另有各 15 秒上界。单个 transport 失效只清理其拥有的资源，不无条件清空整台 host。重连并不能恢复已丢失的持久 shell 状态，也不意味着独立后台任务已消失。

### 已知语义限制

- `/proc/self/*` 经 SFTP 读到的是 `sftp-server`，不是执行命令的 shell。对于报告 size=0 的伪文件会尝试实际读取，但仍受大小预算；要观察 shell 自身请用 `run_command`。
- `delete` 使用 `lstat`，符号链接只解除，目标目录不受影响；这不把任意远端 shell 变成受限文件系统。

## 认证

每 host 可配置 `password`、`privateKeyPath`、`passphrase`、`agent`，都不是必填。桥显式按以下优先级尝试可用方法：

```text
none -> privateKeyPath 对应的 publickey -> 本机 agent -> password
```

这是**桥的显式顺序，不是 ssh2 默认顺序**；未配置的方法跳过。`privateKeyPath` 相对配置文件目录解析，`passphrase` 用于加密私钥；文件不存在或无法读取会报错，不会偷偷忽略后直接降级到密码。`agent` 是本机 SSH agent socket 路径，Windows Pageant 可按 ssh2 约定配置 `"pageant"`；它不是远端 agent 路径，且不自动读取 `SSH_AUTH_SOCK` 代填。

例如，用私钥时可将主机条目中的 `password` 换为 `"privateKeyPath": "./keys/dev_ed25519"`，按需另加 `passphrase`；用 agent 时可换为 `"agent": "<local-agent-socket-or-pageant>"`。**agent forwarding 固定关闭**，本机 agent 认证不等于把它转发给远端。没有 SSH 密码时若仍要 `sudo: true` 自动喂密码，需单独配置 `sudoPassword`。

不引入凭据加密库或保险库；应依靠本机访问权限保护配置和私钥，不提交真实配置。

## 安全边界

本项目保留自用 LAN/VM 的宽松默认：不限制任意 shell 命令与 sudo，`hostKeyPolicy` 默认 `insecure`，`localRoots` 缺省不限制。两项加固都未启用时启动会在 stderr 提示一次，而不是启动失败。

### 主机密钥校验

| `hostKeyPolicy` | 行为 |
|---|---|
| `insecure`（默认） | 接受应答主机的密钥，无法抵御冒充目标主机 |
| `tofu` | 首次记录，后续必须匹配；首次连接仍依赖网络可信 |
| `strict` | 必须已有受信任密钥，否则拒绝 |

- `knownHosts` 可为路径或数组，相对路径按配置文件目录解析；第一个是写入目标。默认使用配置目录的 `known_hosts`，存在的 `~/.ssh/known_hosts` 也只读参与匹配。
- 可按主机配置 `hostKeyPolicy`；`hostKeyFingerprint: "SHA256:..."` 不受全局 insecure 开关影响，配置即校验。
- VM 重建会换密钥；应核实后移除旧记录或更新固定指纹，不能把不匹配当成可自动重试故障。
- `@revoked` 硬拒绝，`@cert-authority` 不支持，不静默降级。
- 可用 `ssh-keyscan -p 22 <remote-host-ip> >> known_hosts` 收集密钥，**收集不等于认证**，需经可信渠道核对指纹。

### 本机路径边界

`localRoots` 仅约束 upload/download 的本机路径：不配置即不限制，配置后解析真实路径、处理链接、拒绝 `..` 和同名前缀目录逃逸；Windows 比较不区分大小写。相对 roots 按配置文件目录解析。

配置了不存在的根目录时，**启动只警告，服务继续运行，不会因此启动失败**。实际传输仍按当时可解析的真实路径和 roots 边界检查；不要把启动警告当成文件系统隔离或目录已创建的保证。无论是否配置 roots，桥都拒绝传输配置文件本身。

这些防线不等于完整隔离：任意命令能力、本机其他工具及恶意并发路径替换不在该传输检查的承诺范围内。

### 下载上限与算法

`maxDownloadBytes` 默认 2 GiB，`0` 表示不限制。下载前核对远端声明大小，读取也受已核验大小约束；超限报错，不应绕过配置盲目重试。需要更大文件可显式提高限额。

默认从 ssh2 的算法提议中移除 `ssh-rsa`（SHA-1 签名）与 `hmac-sha1` / `hmac-sha1-etm@openssh.com`。可用全局 `algorithms` 配置做列表覆盖或 append/prepend/remove；`allowLegacyAlgorithms: true` 恢复 ssh2 默认提议以兼容旧设备，不代表更安全。

## 面向 agent 的常用组合

```text
# 环境变量与工作目录，不手拼密码
run_command(command="npm test", cwd="/project", env={NODE_ENV:"test"})

# 一次性 stdin / sudo，均不使用 session:true
run_command(command="git commit -F -", input="feat: change\n\nDetails\n")
run_command(command="journalctl -u myapp --no-pager -n 50", sudo=true)

# 长任务：保存 task_id 和日志 cursor
start_background(command="npm run dev", cwd="/project")
background_logs(task_id="<id>", cursor=0)
stop_background(task_id="<id>")
# 终态且日志已取走之后才清理
stop_background(task_id="<id>", cleanup=true)
```

目录先通过任意命令自行打包，再用 upload/download 传单个文件。处理 `FILE_CONFLICT` 先重读整文件再重新构造补丁；遇到 unknown 先核对状态，不把重新连接视为可以重放操作的依据。

## 验证

默认入口不需要 VM，也不读取真实配置：

```bash
npm test
```

包含原有回归、执行/会话失败注入、SFTP 生命周期、文件、任务、隧道，以及真实 loopback SSH + MCP stdio 协议检查。仅使用临时测试配置、本机进程、fake transport / SFTP 与本机 socket；不会连接配置中的主机。持久 bash 测试需要本机 bash（可用 `SSH_BRIDGE_TEST_BASH` 指定路径）；缺失时仅该项明确打印 SKIP，其他检查继续。

额外的 Linux 任务生命周期检查使用本机已有的 Docker 镜像，不自动拉取：

```bash
npm run test:jobs:linux
```

真机测试需显式设置 `SSH_BRIDGE_CONFIG`，再传配置中的主机名。以下为 Git Bash / POSIX shell 示例：

```bash
SSH_BRIDGE_CONFIG='/path/to/config.json' npm run test:vm -- ubuntu
```

真机脚本只经配置加载器内部使用凭据，不打印配置内容；会创建随机临时目录、任务和隧道，结束时清理本轮工件。测试要求目标具备 bash、Linux `/proc`、setsid、sudo 配置和 Python 3。它验证本工作树源码，不代表正在运行的旧 MCP 进程已更新。桌面截图与其他目标文件系统的兼容性仍需另行验证；本机或单台 VM 通过不代表所有平台均兼容。

## 调研来源（2026-11-15）

当前契约以本仓库实现与上述离线检查为准；外部项目仅用于了解设计取舍，**不是质量背书，也不表示 API 完全兼容**。

- [ssh-mcp](https://github.com/ErcinDedeoglu/ssh-mcp)：SSH 工具与持久会话的参考项目。
- [portal-mcp-server](https://github.com/TMYTiMidlY/portal-mcp-server)：远端开发、状态化会话与哈希编辑的参考项目。
- [MCP filesystem reference server](https://github.com/modelcontextprotocol/servers/tree/main/src/filesystem)：有界文本读取、编辑匹配与 dry-run 的另一组设计取舍。
- [ssh2 README](https://github.com/mscdex/ssh2/blob/master/README.md) / [SFTP API](https://github.com/mscdex/ssh2/blob/master/SFTP.md)：认证、agent、forwardOut 与 SFTP 方法；桥的认证优先级由自身代码指定。
- [TypeScript SDK 1.30.0 protocol 文档](https://github.com/modelcontextprotocol/typescript-sdk/blob/1.30.0/docs/protocol.md)：请求超时和 `extra.signal` 取消传递；取消通知本身不等于远端副作用回滚。
- [OpenSSH PROTOCOL](https://github.com/openssh/openssh-portable/blob/master/PROTOCOL)：POSIX rename 与独立 fsync 扩展，勿把 rename 描述为 CAS 或持久化事务。

`docs/superpowers/` 中 2026-08-09 的设计与实施计划是历史记录，不是当前运行契约。
