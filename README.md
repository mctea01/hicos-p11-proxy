# hicos-p11-proxy
HiCOS PKCS#11 Proxy（防 CKR_BUFFER_TOO_SMALL、auto-padding)
公開授權協議: Apache License 2.0 <br />
開發人員: ChatGPT o3、林哲全<jclin22873794@gmail.com>、Gemini 3 Pro<br />
初始版本(主要由ChatGPT O3) 於2025/4/28生成，後續增補不計，可參閱Git log<br />
測試環境: Windows 11 專業版 24H2 OS組建 26100.3775 Windows 功能體驗套件 1000.26100.66.0 <br />
HiCOS PKCS11 版本: 3.1.0.00012 AMD64 <br />
建議編譯指令(我的編譯指令): <br />
`clang-cl -fuse-ld=lld-link /D_USRDLL /D_WINDLL /I"%OPENSSL_DIR%/include" /MT hip11.c "%OPENSSL_DIR%/lib/libcrypto.lib" /link /DLL /OUT:hiP11.dll `<br />
```
#JAVA CFG#
name = HiCOS
library = /where/the/dll/path/hiP11.dll
slotListIndex = 0
attributes = compatibility
handleStartupErrors = ignoreAll
showInfo = false
#END of JAVA CFG#
```
主要測試工具: Jsign 7.1 (Java HotSpot(TM) 64-Bit Server VM Oracle GraalVM 21.0.7+8.1 (build 21.0.7+8-LTS-jvmci-23.1-b60, mixed mode, sharing) java 21.0.7 2025-04-15 LTS) <br />
提示: 自然人憑證於HiCOS PKCS#11之cert1為數位簽署、cert2為檔案加、解密、資料交換
