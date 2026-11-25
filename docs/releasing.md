# Release checklist / 发布检查清单

1. Review the project MIT license and third-party notices; verify redistribution rights and package licenses.
2. Run `build.bat` on an interactive Windows x64 desktop using the .NET 8 SDK. Confirm every fixture and both smoke tests pass; test optional analyzers separately with harmless samples.
3. Extract the generated ZIP on a clean Windows VM without .NET installed. Check the application icon, startup, scan, filters, archive warnings and quarantine recovery. Test optional ETW separately and without scanning untrusted files while elevated.
4. Verify the ZIP SHA-256 and inspect the contents for secrets, personal paths, malware, or build caches.
5. Push source to GitHub, confirm Actions succeeds, create a tag `v2.1.0`, then create a Release and attach the portable ZIP and its `.sha256`. Do not upload the source ZIP as the runnable app. Sign the executable with an Authenticode certificate if available; otherwise do not claim it is signed.

中文：核对许可证；在真实 Windows 桌面运行编译脚本和无害测试；在无 .NET 的干净虚拟机解压启动；验证校验值、发布文件和隐私；将源码推送 GitHub，检查 Actions 成功后建立 `v2.1.0` 标签并发布便携 ZIP 及校验文件。可选代码签名；未签名不得声称已经签名。
