<p align="center"><img src="Guardian.App/Assets/AppIcon.png" width="96" alt="Steam Mod Guardian 应用图标"></p>

# Steam Mod Guardian · Steam 模组安全卫士

**支持离线运行的 Steam 创意工坊及本地 Mod 风险检测工具。**

[English](README.md) · [安全反馈](SECURITY.md) · [贡献指南](CONTRIBUTING.md) · [更新日志](CHANGELOG.md)

![Windows](https://img.shields.io/badge/platform-Windows%20x64-0078D4) ![Version](https://img.shields.io/badge/version-2.1.0-blue) ![.NET](https://img.shields.io/badge/.NET-8-512BD4) ![License](https://img.shields.io/badge/license-MIT-green)

Steam Mod Guardian 是一款非官方 Windows 桌面工具，帮助玩家在运行游戏前检查创意工坊和本地 Mod 中的可疑代码与行为线索。支持多个 Steam 库、多选游戏和自定义扫描目录，扫描不加载或执行被检测的 DLL、脚本。**不是杀毒软件或沙箱，不保证 Mod 安全。**

## 主要功能

- 自动识别 Steam 游戏及工坊目录，获取实际 Mod 标题和可选的中文游戏名称。
- SHA-256、签名社区名单、域名/IP 名单、哈希缓存、持久化更新记录。
- IL 指令分析、有限调用图、异步状态机关联、脚本规则、原生 PE 导入表、隐藏载荷及 ZIP 分析。
- **2.1.0 新增：** 基于控制流的有限方法内污点分析、静态常量还原、归一化 IL 的 SimHash 近似匹配。
- 传统 YARA 一键配置或手动接入 YARA-X、可选 AMSI；内置规则为启发式特征，不是完整病毒库。
- 可选 capa、FLOSS、TLSH 本地分析；TCP/模块观察和限时 ETW 事件统计。
- 风险卡片筛选、证据导出、哈希验证隔离/恢复、启动前复查。

## 下载及免安装使用

维护者发布后，在仓库 Releases 下载 `SteamModGuardian-2.1.0-win-x64-portable.zip` 与 `.sha256`，或从成功运行的 Actions 构建中下载。核对 SHA-256 后，将整个压缩包解压到任意独立目录，双击 `Steam Mod Guardian.exe`。无需安装软件或 .NET Runtime；普通静态扫描无需管理员权限。不要只取出单独的 EXE。当前仅打包 Windows x64，建议 Windows 11 以获得 Acrylic 效果。

1. 刷新 Steam 库并选择游戏；非工坊目录可在高级设置中添加。
2. 点击一键推荐扫描。
3. 优先查看红色高危、文件下载及未知项目；核对证据后再考虑取消订阅或隔离。
4. 可选配置增强检测工具；Mod 更新后重新检查。

## 检测技术与离线能力

| 技术 | 运行方式 | 实现范围 |
| --- | --- | --- |
| SHA-256 / IL / 调用图 / PE / 脚本 / 载荷 | 内置、本地 | 静态启发式与有限解析 |
| CFG / 污点分析 | 内置、本地 | 支持部分 IL 来源和写入/加载目标、分支、局部变量和栈；非完整跨方法分析 |
| 常量传播 | 内置、本地 | 有限拼接和 Base64 主机名还原，不是通用脱壳 |
| IL SimHash | 内置、本地 | 跨包近似结构，比较预算有限，不是 TLSH |
| YARA / YARA-X | 可选本地 CLI | 二选一；传统 YARA 一键下载需要首次联网，YARA-X 手动配置 |
| capa / FLOSS / TLSH | 可选本地 CLI | 所选文件的能力、字符串域名及 TLSH 摘要/参考文件距离独立报告 |
| AMSI | Windows 可选 | 受本机安全提供程序及其云策略影响 |
| TCP/模块 / ETW | 本地观察 | ETW 需管理员权限，最多 60 秒，按 PID 统计事件类型和数量 |
| VirusTotal / 社区同步 / 标题查询 | 可选联网 | 本地扫描不依赖这些服务 |

### 可选专业分析器

从官方来源获取并独立校验 [YARA](https://github.com/VirusTotal/yara/releases)、[YARA-X](https://github.com/VirusTotal/yara-x/releases)、[capa](https://github.com/mandiant/capa/releases)、[FLOSS](https://github.com/mandiant/flare-floss/releases)、[TLSH](https://github.com/trendmicro/tlsh) 的 Windows CLI，保存在可信的非 Mod 目录中。发布包不附带这些外部工具。选择「配置 YARA-X」并指定 `yr.exe`，或者扫描后选中一行并点击「本地专业分析…」使用 capa、FLOSS 或 TLSH。后三者输出独立辅助报告，不改变原有扫描评级。外部程序并非沙箱，切勿选择 Mod 内的 EXE 作为分析器。

## 风险评级和已知限制

直接文件下载及疑似下载落盘按用户策略列为极高风险，合法资源下载器也可能触发。普通网络请求不会仅因联网被直接归为极高。保留旧版较保守的共现规则，新增数据流证据用于辅助复核，不自动降低旧风险。指纹相似、YARA 命中不能证明恶意。方法间参数传播、完整异步数据流、任意混淆、机器码深度分析和多层加密载荷不完全支持。超出预算的分析可能不完整。预启动复查仅控制本工具发起的启动，无法保证 Steam 不在之后更新或重新下载文件；不要为测试运行可疑模组。

## 隐私与安全

本地扫描不直接上传样本。工坊名称、YARA 下载、VirusTotal 查询、社区名单同步可选联网。AMSI 取决于安全软件的云保护与样本提交策略。关闭在线标题查询即可避免扫描时的 Steam 标题请求。第三方分析器不是网络隔离环境；为 ETW 提权时不要扫描不可信文件。ETW 短时启用内核事件提供程序，仅在工具中保留指定 PID 的事件类型与计数。请勿公开包含私人路径、账号信息、密钥的日志。为兼容旧版，配置数据仍存储在 `%LOCALAPPDATA%\DuckovModGuardian`，便携指程序本身无需安装，而非所有数据都放在程序目录。

## 从源码编译

开发环境：Windows x64、.NET 8 SDK、能够访问 NuGet 的网络。

```powershell
.\build.bat
# 或直接执行非交互发布脚本
pwsh -File .\scripts\build-release.ps1
```

脚本先执行无害合成测试，然后发布自包含程序、复制规则和说明、执行 TCP 与 WPF 启动测试，最后在 `dist/` 生成便携 ZIP 与 SHA-256。无交互桌面环境可明确使用 `-SkipUiSmoke`，但发布前仍须在真实桌面验证。GitHub Actions 会上传构建产物；维护者审核后手动发布 Release。本源码包不代表已经编译完成的 EXE。2.1.0 作者环境没有 .NET SDK 或 Windows 桌面，尚未实机验证。

```text
Guardian.App/      WPF 主界面、弹窗与运行时观察
Guardian.Core/     核心扫描、规则、本地工具、缓存、隔离
Guardian.Tests/    不执行样本的合成测试
rules/             内置 YARA 启发式规则
scripts/           便携发布脚本
.github/           自动构建与 Issue 模板
docs/              技术文档和历史记录
```

## 许可证

项目源码采用 MIT（见 [LICENSE](LICENSE)）。第三方组件保留其各自许可证，见 [第三方声明](THIRD-PARTY-NOTICES.txt)。项目与 Valve、Steam 或各游戏开发商无隶属关系。应用程序图标由 AI 生成，界面图标为 Feather 开源矢量图标。
