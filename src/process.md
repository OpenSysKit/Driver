# PspTerminateThreadByPointer 逆向分析

## 背景

`PspTerminateThreadByPointer` 是 Windows 内核未导出函数，可用于强制终止指定线程。驱动通过导出函数 `PsTerminateSystemThread` 的函数体进行特征码扫描来定位它。

在 Win11 Build 26100+ 上，微软修改了 `PsTerminateSystemThread` 的编译产物，导致原有的单字节 `E9` 扫描逻辑失效。

## Win10 x64 函数布局

`PsTerminateSystemThread` 在 Win10 上非常简短，开头直接跳转：

```
PsTerminateSystemThread:
  E9 xx xx xx xx        ; jmp PspTerminateThreadByPointer
```

函数体仅一条指令，`E9` 在偏移 0 处。

## Win11 x64 (Build 26200) 函数布局

通过 `dumpbin /exports` 获取 `PsTerminateSystemThread` 的 RVA（`0x9D8000`），再根据 PE Section Header 计算文件偏移，读取原始字节：

```
+0x00: 48 83 EC 28           ; sub  rsp, 28h          ← 完整 stack frame
+0x04: 8B D1                 ; mov  edx, ecx
+0x06: 65 48 8B 0C 25 88 01  ; mov  rcx, gs:[188h]    ← 读取 KTHREAD (gs:[188h])
+0x0D: 00 00
+0x0F: F7 41 74 00 04 00 00  ; test [rcx+74h], 00000400h  ← 检查线程标志
+0x16: 75 0B                 ; jnz  +0Bh               ← 标志不匹配则继续
+0x18: B8 0D 00 00 C0        ; mov  eax, 0xC000000D    ← STATUS_INVALID_PARAMETER
+0x1D: 48 83 C4 28           ; add  rsp, 28h
+0x21: C3                    ; ret
+0x22: CC                    ; int 3 (padding)
+0x23: 41 B0 01              ; mov  r8b, 1             ← bDirectTerminate = TRUE
+0x26: E8 xx xx xx xx        ; call PspTerminateThreadByPointer  ← 目标
+0x2B: EB F0                 ; jmp  -10h (回到 add rsp,28h; ret)
```

### 关键差异

| 特性 | Win10 | Win11 (26200) |
|------|-------|---------------|
| Stack frame | 无 | `sub rsp, 28h` |
| 线程标志检查 | 无 | `test [rcx+74h], 400h` |
| 调用方式 | `E9 rel32` (jmp) | `E8 rel32` (call) |
| 调用前指令 | 无 | `mov r8b, 1` |
| 目标偏移 | +0x00 | +0x26 |

## 旧代码的 Bug

旧代码在 0xFF 范围内先搜索单字节 `E9`，找不到再搜 `E8`：

```cpp
PVOID pRelOffset = SearchPattern(pBase, pEnd, &patternE9, 1);  // 搜 E9
if (!pRelOffset)
    pRelOffset = SearchPattern(pBase, pEnd, &patternE8, 1);    // 搜 E8
```

在 Win11 上，偏移 `0xA6` 处存在一个不相关的 `E9`（跳转到其他函数），旧代码会优先匹配到它，解析出错误的地址。

实际扫描结果：

| 偏移 | 字节 | 含义 |
|------|------|------|
| 0x26 | `E8` | **正确** — `call PspTerminateThreadByPointer` |
| 0x75 | `E8` | 其他 call |
| 0x9C | `E8` | 其他 call |
| 0xA6 | `E9` | **误匹配** — 不相关的 jmp |

## 修复方案：三级特征码匹配

```
优先级 1 (Win11):  搜索 41 B0 01 E8 (mov r8b,1; call)
优先级 2 (Win10):  在前 16 字节内搜索 E9 (限制范围避免误匹配)
优先级 3 (回退):   全范围搜索 E8
```

Win11 模式 `41 B0 01 E8` 的含义：
- `41 B0 01` = `mov r8b, 1`（设置 `bDirectTerminate = TRUE`）
- `E8` = `call` 的操作码

这个 4 字节序列在 `PsTerminateSystemThread` 函数体内是唯一的，不会误匹配。

## 逆向工具与方法

### 获取函数 RVA

```powershell
dumpbin /exports C:\Windows\System32\ntoskrnl.exe | Select-String "PsTerminateSystemThread"
# 输出示例: 1750  6D7 009D8000 PsTerminateSystemThread
#                              ^^^^^^^^ RVA
```

### RVA 转文件偏移

通过 `dumpbin /headers` 获取 `.text` section 信息：

```
SECTION HEADER #1
  .text name
  9B7D88 virtual size
  1000 virtual address        ← Section VA
  9B7E00 size of raw data
  600 file pointer to raw data ← Section 文件偏移
```

```
文件偏移 = RVA - Section_VA + Section_FileOffset
         = 0x9D8000 - 0x1000 + 0x600
         = 0x9D7600
```

### 读取原始字节

```powershell
$bytes = [System.IO.File]::ReadAllBytes("C:\Windows\System32\ntoskrnl.exe")
$offset = 0x9D7600  # 计算得到的文件偏移（注意：不同版本需要重新计算）
for ($i = 0; $i -lt 48; $i += 16) {
    $hex = ($bytes[($offset+$i)..($offset+$i+15)] | ForEach-Object { $_.ToString("X2") }) -join " "
    Write-Host ("{0:X}: {1}" -f ($offset+$i), $hex)
}
```

### 验证目标地址

匹配到 `E8` 后，计算目标 RVA：

```
目标 RVA = 当前 RVA + 5 + rel32偏移
         = 0x9D802B + (signed)0xFFECFC85
         = 0x8A7CB0
```

再读取目标地址的字节，确认是有效函数入口（典型的 `sub rsp, ...` 或 `push rbx` 等 prologue）。
