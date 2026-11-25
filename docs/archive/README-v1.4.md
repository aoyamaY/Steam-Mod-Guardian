# Steam Mod Guardian / Steam 模组安全卫士 v1.4.0

Windows x64 · .NET 8 · WPF · Mono.Cecil 0.11.6。独立工具，不是游戏 Mod。此包是源码发行版，未附带已编译 EXE。

## 编译与运行

1. 安装 [.NET 8 SDK](https://dotnet.microsoft.com/download/dotnet/8.0)（不是只安装 Runtime）。首次构建需访问 NuGet。
2. 解压全部文件，双击 `build.bat`。脚本先执行纯内存测试，再生成自包含的 `publish-v1.4.0\DuckovModGuardian.exe`。
3. 在启动游戏之前，打开生成的程序。不要以管理员身份运行。扫描期间退出游戏，尽量避免 Steam 下载更新。

也可在 PowerShell 中执行：

```powershell
dotnet run --project .\Guardian.Tests\Guardian.Tests.csproj -c Release
dotnet publish .\Guardian.App\Guardian.App.csproj -c Release -r win-x64 --self-contained true -p:PublishSingleFile=false -p:PublishTrimmed=false -o .\publish-v1.4.0
```

## 保留的 v1.0.3 启动修复与诊断

- 修复三处 DataTrigger.Binding 将普通字符串误当成 BindingBase 的错误，恢复风险颜色。
- `build.bat` 发布后自动运行 `--smoke-test-ui`，等待窗口实际触发 ContentRendered 后退出；跳过 Steam 自动识别和所有模组扫描，不执行任何模组。测试失败或 30 秒超时即报告失败。窗口短暂出现并自动关闭是正常现象。
- 也可在发布目录执行 `Start-Process .\DuckovModGuardian.exe -ArgumentList '--smoke-test-ui' -Wait -PassThru`，退出码 0 代表渲染测试通过。


- 修复 CS1061：空 App.xaml 不需要调用 App.InitializeComponent()；主窗口仍正常初始化 XAML。
- 保留 v1.0.1 的启动日志、异步 Steam 路径检测及诊断脚本。

- 使用显式 STA 启动入口，记录 WPF 初始化、窗口渲染和退出状态；未处理的托管异常弹窗并保存堆栈。
- 窗口先显示，Steam 目录识别随后在线程池执行；即使目录访问缓慢也可以手动选择路径并扫描。
- 默认采用多文件自包含发布，避免单文件解包问题。必须保留整个 `publish-v1.4.0` 目录，不要单独移动 EXE。
- 如果双击无反应，运行发布目录下的 `diagnose.bat`。该脚本等待进程退出，显示退出码，并开启 .NET 8 原生宿主跟踪。手工 publish 时请将源码根目录的 `diagnose.bat` 复制到发布目录。
- 日志默认位于 `%LOCALAPPDATA%\DuckovModGuardian\startup.log`，以及诊断脚本生成的 `host-trace.log`、`last-exit-code.txt`；无法创建目录时尝试 `%TEMP%\DuckovModGuardian`。日志可能含有本机路径，分享前请检查。若连宿主日志都没有生成，可查看 Windows 事件查看器 → Windows 日志 → 应用程序，以及 Windows 安全中心保护历史记录。不要关闭杀毒软件或以管理员身份运行。
- 原 v1.0.3 已根据 v1.0.2 启动日志定位 XAML 异常，并核对源码中对应的三处错误。修复版仍需在 Windows 上实际编译和运行验证。

## 功能

- 从 Steam 注册表、libraryfolders.vdf 和各 appmanifest_*.acf 自动识别多个本地 Steam 库，支持手工添加目录。
- 扫描所选游戏的 `steamapps\workshop\content\<AppID>` 和鸭科夫 `Duckov_Data\Mods`，其他本地模组目录由用户添加；递归识别 DLL、EXE、常见可执行脚本和安装包。
- Mono.Cecil 仅读取托管程序集 IL，不执行模组、不会调用 Assembly.Load 或解析外部程序集依赖。
- 检查联网、进程启动、动态程序集加载、P/Invoke、注册表写入、敏感路径线索；结合有限的本地方法调用关系生成风险提示。高风险也可能是合法功能，尤其语音工具、联网 AI、资源加载器。
- 每次重新读取文件并计算 SHA-256；同一扩展名、哈希及规则版本的缓存结果才可复用。文件变化自动重新分析。勾选“忽略缓存”重新扫描全部文件。
- 结果筛选、文件哈希、工坊 ID 跳转、方法及 IL 偏移证据、JSON 导出；报告含本地路径，分享前检查隐私。
- 本地黑名单位于 `%LOCALAPPDATA%\DuckovModGuardian\blacklist.txt`，一行一个经核实的 SHA-256；默认空。每次扫描都优先检查黑名单，不依赖缓存。另有 `cache.json`。不要从不可信来源下载缓存或规则。

## 风险解释

| 标签 | 含义 |
|---|---|
| 极高风险 | 黑名单命中或存在重点行为组合；隔离并人工复核，避免加载 |
| 高风险 | 进程执行、动态加载、注册表写入、可执行文件等高权限能力；并非恶意定论 |
| 需复核 | 联网、原生调用、路径字符串等线索；需要结合模组功能判断 |
| 未完成/未知 | 无法读取、原生/无效 DLL、过大或解析失败等；不等于安全 |
| 未发现风险 | 未命中本版本规则，不等于经过认证的安全 |

## 局限与安全边界

- 本工具是静态扫描器，不是杀毒软件或沙箱。提供经确认的手动文件隔离及启动前复查，但不提供自动隔离或强制加载拦截；监控仅在窗口打开时周期检查。社区名单与 YARA 需自行配置。
- 不自动删除、移动、修改模组，不自动启动游戏；只有用户明确确认才移动隔离文件、恢复或请求 Steam 启动，不联网上传样本。可选 Steam 标题查询和手动社区名单同步会联网。
- 组合规则是行为相关性，不是严格数据流/污点追踪；不能证明下载的数据真的被执行。调用关系分析限同一模块、最多四层、限节点数；跨 DLL、反射、间接调用、动态生成及混淆代码可能漏报。P/Invoke 和字符串也有误报。原生代码、混合模式或藏在资源/压缩包/非扫描扩展名中的内容无法完整检查。
- 文件最大 64 MiB，IL 指令最大 300 万，记录最多 300 条证据。跳过重解析点；权限和枚举错误会记录。解析器本身处理不可信文件也存在风险，请勿用管理员权限运行，特别可疑样本可在隔离虚拟机内扫描。
- 缓存只是本地加速，并非防篡改信任库。怀疑缓存被修改时勾选忽略缓存并检查数据目录。
- 当前交付环境无 .NET SDK/Windows WPF 运行环境，源码仅经静态结构核对，未实际编译执行。自带无害测试样例及 WPF 窗口启动测试，用户构建时自动执行；不使用真实木马样本。

## 目录

- `Guardian.Core`: 扫描、规则、缓存、报告。
- `Guardian.App`: WPF 中文界面与 Steam 路径识别。
- `Guardian.Tests`: 无害 IL 元数据测试。
- `build.bat`: 一键测试和发布。

依赖来源：https://www.nuget.org/packages/Mono.Cecil/0.11.6

## v1.3.0 合并更新（1.1 / 1.2 / 1.3）

- 工坊名称默认通过 Steam 官方 GetPublishedFileDetails API 查询（仅提交工坊 ID，不发送本地路径或 DLL）。关闭勾选可完全离线扫描。读取 info.ini 的 displayName/name 作为回退，不能读取时显示 ID；名称来源明确区分。自动监控复用本会话已获取的标题，手动扫描刷新。名称不是信任凭据。
- 文件下载行为单列，支持 WebClient.DownloadFile*、Unity DownloadHandlerFile、HttpClient/GetByteArray/GetStream、网络响应读取及本地写入共现。直接 API 表示具有该代码能力，不表示已下载；共现非严格数据流，FileStream 构造也可能仅为读取。仅接收数据并非文件下载。未识别不代表没有行为。静态扫描不会发出模组代码中的网络请求。
- 同类识别：归一化可疑方法 IL 操作码与部分外部 API 名称后计算 SHA-256 (`il-v1`)，忽略多数常量、本地方法名等；跨包共享指纹提示，并可使用已审核指纹名单匹配。不是模糊相似度百分比，不保证识别混淆或改变结构的套壳；公共库也会命中，不自动判恶。保留 4096 个指纹/模块，短方法不生成指纹。
- YARA：下载可信官方 Windows CLI（https://github.com/VirusTotal/yara/releases），通过“配置 YARA”选择其 EXE 和可信 `.yar` 文件；发布目录自带 `rules/guardian.yar` 两条启发式规则，非已验证木马签名。不会搜索或运行模组目录中的 EXE，扫描的是本次读取的字节快照。未配置显示未启用；单文件超时或错误显示失败，清白结果降为未知。第三方引擎未打包，需自行安装；YARA 逐文件运行，可能较慢。不要用来自可疑模组的引擎或规则。
- 监控：勾选每 60 秒检查更新，在窗口打开且没有其他扫描时自动扫描，按 SHA-256 比对会话基线，新增/变更显示标签，并保留本次会话更新记录。IL 缓存复用，YARA 若启用仍逐文件运行。并非实时阻止 Steam 更新或 DLL 加载；关闭窗口后不监控，重启后重新建立基线。仅监控现有扫描目录，新增 Steam 库需重新识别。
- 社区名单：支持经过 RSA-SHA256 签名的 HTTPS JSON，同步由用户主动触发，无默认可信发布方，不随包提供真实恶意名单；缺少配置、过期、签名错误、下载失败时不会信任新名单。名单 SHA-256 命中极高风险，工坊 ID / IL 指纹命中高风险并人工复核。每次扫描重新核对签名名单，不污染基础 IL 缓存。
- 举报证据：选择一行后导出对应工坊 Mod 的全部扫描文件、SHA-256、检测方法/IL 偏移、风险和工坊链接。省略显式绝对文件路径，但异常消息、方法名称等仍可能含隐私。不会自动举报或上传。请人工复核后通过工坊页面举报。
- 保留 WPF 窗口渲染测试及原六项测试，加入无害下载、IL 指纹、名称、签名验证测试。未运行 Windows 编译测试。

### 社区名单配置（管理员/社区维护者）

点击“打开配置目录”，创建 `community-url.txt`（一行可信 HTTPS URL）和 `community-public.pem`（通过独立渠道核实的 RSA 公钥，PEM SubjectPublicKeyInfo 格式，至少 2048 位）。点击同步后获取数据。不要从名单自身提供的链接取得信任根。也可将签名包手动置于 `community-signed.json`；离线导入仍会验签与检查有效期，但手工替换可绕过同步时的版本检查。

签名包格式：`{"Payload":"base64编码的原始 UTF-8 JSON 字节","Signature":"base64编码的 RSA PKCS#1 v1.5 SHA-256 签名"}`。Payload 的 JSON 使用 PascalCase 属性，例如空名单：`{"Version":1,"ExpiresUtc":"2027-01-01T00:00:00Z","Entries":[]}`。Entries 元素格式 `{"Kind":"sha256|il-v1|workshop（选其一）","Value":"64位十六进制或工坊数字ID","Reason":"经人工核实的证据说明"}`。每次发布必须增加 Version，设置短有效期。签名私钥仅保留在社区维护者受保护环境，不分发给用户。此版本没有公开社区服务器或审核团队。

参考： https://partner.steamgames.com/doc/webapi/ISteamRemoteStorage 、https://github.com/xvrsl/duckov_modding 、https://yara.readthedocs.io/en/latest/commandline.html


## v1.4.0：通用 Steam 游戏库与安全启动

- 点击“自动识别 Steam”，然后“选择 Steam 游戏…”（Ctrl/Shift 多选，或全选）或“检查整个本地游戏库”。读取本机已安装游戏 manifest 和有工坊内容的 AppID；不需要 Steam API Key，也不会读取账号拥有的全部未安装游戏。工坊仅残留的游戏显示 AppID（没有本地 manifest 时无法确认名字）。游戏无工坊目录不代表无 Mod。首次启动若检测到鸭科夫模组目录，默认仍选鸭科夫。
- 选择游戏会替换扫描目录，包含手工添加项（有确认）。其他游戏的非工坊模组目录需手工添加，不默认扫描整个游戏安装目录；避免把游戏本体当成模组。手动路径仅在选中单个游戏时归属该游戏；多选时无可识别归属的显示未关联。目录设置和选择本版仅在当前会话保留。新增工坊根目录需要重新识别并重新选择；监控仍按当前扫描目录运行。
- 结果新增游戏和 AppID 列，工坊标题、下载行为列、YARA、IL 指纹、社区名单、报告和旧缓存全部保留。底层 IL 规则版本仍为 1.3.0-r1，因为规则未改变。程序及发布文件夹版本为 1.4.0；保留 DuckovModGuardian.exe 文件名与旧配置目录，避免迁移丢失。
- **隔离所选高危文件**：先退出游戏、暂停 Steam 更新，选中高风险或极高风险文件；确认后仅移动该文件，不删除整个模组。原扫描 SHA-256 必须匹配当前文件。隔离库 `%LOCALAPPDATA%\DuckovModGuardian\quarantine\<随机ID>\` 中包含 `entry.json`（原路径/扫描根/哈希/游戏/Mod/时间）和 `payload.bin`（原文件，非原扩展名）。不执行隔离文件，不自动删除。原路径或隔离路径涉及重解析点会拒绝操作。失败或跨盘移动中断时保留日志及可能存在的文件，请人工核对。隔离库并非强制 ACL 沙箱，不要打开或执行其中的内容。
- **隔离库 / 恢复**：只在确认误报时使用，校验原始哈希并且不覆盖原路径已存在的文件。如果 Steam 已重新下载同一文件，先人工核对；若原目录已不存在，需人工确认并创建原目录后再恢复。恢复后重新扫描，保留审计记录。Steam 可能自动补回已隔离文件，因此务必取消订阅经确认的恶意 Mod，并重新扫描。
- **安全检查后启动游戏**：仅选择一个已安装游戏，手工补齐所有本地模组目录。重新识别该游戏的工坊目录，并对当前扫描范围忽略 IL 缓存全面复查。高危、极高危、未知、YARA 失败或任何扫描警告阻止本工具发起启动。需复核项要求人工核对。确认后再查游戏目录和所有文件哈希，若新增、缺失、变化或风险变化则取消。仅通过后才调用 `steam://rungameid/<AppID>`。此流程不能阻止 Steam 更新、其他程序替换文件或用户直接启动游戏；无法为所有游戏提供加载拦截/沙箱，不能保证绝对安全。原生 DLL 等未知项可能阻止合法游戏启动；本版不提供跳过未知项的一键启动。
- 新增多 Steam 库/通用 AppID、本地游戏名称、隔离哈希与边界校验、无覆盖恢复及启动快照比较的无害测试。实际 Windows 构建和 WPF 渲染仍需通过 build.bat 验证。
