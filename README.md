# OpenSysKit Driver

> Windows 内核驱动，为 OpenSysKit 提供内核级系统管理能力。

## 功能

- 进程枚举
- 内核级进程终止
- 进程冻结 / 解冻
- 进程保护 / 取消保护

## 编译

### 环境要求

- Visual Studio 2022 (含 C++ 桌面开发)
- Windows Driver Kit (WDK) 10
- CMake 3.16+

### 构建

```powershell
cmake -B build -G "Visual Studio 17 2022" -A x64
cmake --build build --config Release
```

产物位于 `build/Release/OpenSysKit.sys`

## 架构

```
前端 UI  <-->  Go 后端  <-- DeviceIoControl -->  本驱动 (kernel)
```

## 许可证

待定
