# Contributing / 贡献指南

Use .NET 8 SDK on Windows, run `dotnet run --project Guardian.Tests/Guardian.Tests.csproj -c Release` and `scripts/build-release.ps1`. Keep new tests inert: generate metadata-only fixtures or use harmless text. Never commit malware samples, credentials, user-specific data or build outputs. Detection rules should identify the evidence source and limits; similarity and heuristic matches are not verdicts. Prefer focused pull requests with regression fixtures and bilingual release notes.

使用 Windows 与 .NET 8 SDK，提交前运行测试与发布脚本。测试仅使用无害文本或不执行的合成 IL/PE；禁止提交真实木马样本、个人数据、密钥与编译产物。规则需说明证据来源及局限，避免把特征命中直接视为恶意定论。
