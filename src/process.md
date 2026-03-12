# process.cpp 逆向笔记 — PspTerminateThreadByPointer

## 起因

驱动在 Win11 (Build 26200) 上跑的时候，`ResolvePspTerminateThread()` 解析出来的地址是错的，调用直接炸。排查发现是特征码扫描逻辑有问题。

## 思路

`PspTerminateThreadByPointer` 没有被 ntoskrnl 导出，但 `PsTerminateSystemThread` 是导出的，而且它内部一定会调用/跳转到 `PspTerminateThreadByPointer`。所以从 `PsTerminateSystemThread` 的函数体里找 call/jmp 指令就能拿到目标地址。

## Win10 的情况

Win10 上 `PsTerminateSystemThread` 就一条指令，开头直接 `jmp`：

```
E9 xx xx xx xx    ; jmp PspTerminateThreadByPointer
```

所以搜一个 `E9` 就完事了，没什么好说的。

## Win11 出了什么问题

拿 dumpbin 看了一下 Win11 26200 的 ntoskrnl，`PsTerminateSystemThread` 变复杂了：

```
+00: 48 83 EC 28        sub  rsp, 28h           ; 多了栈帧
+04: 8B D1              mov  edx, ecx
+06: 65 48 8B 0C 25 ... mov  rcx, gs:[188h]     ; 取当前 KTHREAD
+0F: F7 41 74 ...       test [rcx+74h], 400h    ; 查线程标志位
+16: 75 0B              jnz  short ...
+18: B8 0D 00 00 C0     mov  eax, C000000Dh     ; 不满足就返回 STATUS_INVALID_PARAMETER
+1D: 48 83 C4 28        add  rsp, 28h
+21: C3                 ret
+22: CC                 padding
+23: 41 B0 01           mov  r8b, 1             ; bDirectTerminate = TRUE
+26: E8 xx xx xx xx     call PspTerminateThreadByPointer   <-- 在这
+2B: EB F0              jmp  short (回去 ret)
```

问题就在于：旧代码先搜 `E9`，搜 0xFF 范围。Win11 上函数头附近根本没有 `E9`，但偏移 `0xA6` 的地方有一个完全不相关的 `E9`（跳到别的函数去了），被误匹配了。

手动扫了一遍 0xFF 范围内所有 E9/E8：

```
偏移 0x26: E8 → call PspTerminateThreadByPointer  ✓ 这才是对的
偏移 0x75: E8 → 别的 call
偏移 0x9C: E8 → 别的 call
偏移 0xA6: E9 → 不相关的 jmp                      ✗ 旧代码匹配到了这个
```

## 怎么修的

改成三级匹配：

1. 先搜 `41 B0 01 E8`（`mov r8b, 1` + `call`），这是 Win11 上调用 psp 前的固定搭配，4 字节够长不会撞
2. 没匹配到就在前 16 字节找 `E9`，给 Win10 用（限制范围，不会匹配到后面那个野 E9）
3. 都没有就全范围搜 `E8` 兜底

## 怎么离线逆向的

没开内核调试，纯离线分析 ntoskrnl.exe：

**1) 拿函数 RVA**

```
dumpbin /exports C:\Windows\System32\ntoskrnl.exe | findstr PsTerminateSystemThread
→ 009D8000
```

**2) RVA 转文件偏移**

```
dumpbin /headers ntoskrnl.exe
```

找 .text section：VA=0x1000, FileOffset=0x600

```
文件偏移 = 0x9D8000 - 0x1000 + 0x600 = 0x9D7600
```

（注：实际跑的时候发现 dumpbin 输出的 section 信息和预期有偏差，最终用 `0x951000` 作为文件偏移才对上，可能是 ntoskrnl 的 section alignment 比较特殊，建议以实际 hexdump 对照为准。）

**3) PowerShell 读字节**

```powershell
$bytes = [IO.File]::ReadAllBytes("C:\Windows\System32\ntoskrnl.exe")
# 从文件偏移处读 48 字节，手动反汇编确认
```

**4) 验证目标**

算出 call 的目标 RVA 后，再去读那个地址的字节，看是不是正常的函数 prologue（`sub rsp, xx` 之类的），确认没算错。

## 注意事项

- 不同 Win11 版本的 ntoskrnl 编译产物可能不同，`41 B0 01 E8` 这个模式不保证永远有效，后续大版本更新需要复查
- Win10 各版本目前都是开头直接 `E9`，比较稳定
- `SearchPattern` 返回的是 pattern 末尾之后的地址，所以匹配 `41 B0 01 E8` 后 `pRelOffset` 直接指向 rel32 偏移，不需要额外 +1
