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

搜一个 `E9` 就完事了。

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

旧代码先搜 `E9`，搜 0xFF 范围。Win11 上函数头附近根本没有 `E9`，但偏移 `0xA6` 的地方有一个完全不相关的 `E9`（跳到别的函数去了），被误匹配了。

手动扫了一遍 0xFF 范围内所有 E9/E8：

```
偏移 0x26: E8 → call PspTerminateThreadByPointer  ✓ 这才是对的
偏移 0x75: E8 → 别的 call
偏移 0x9C: E8 → 别的 call
偏移 0xA6: E9 → 不相关的 jmp                      ✗ 旧代码匹配到了这个
```

## 最终方案：不再依赖固定字节模式

一开始的修法是搜 `41 B0 01 E8`（Win11 特有的 `mov r8b, 1; call` 组合），但这个模式不保证以后每个版本都长这样——编译器换个心情可能就变了。

后来换了个思路：既然 `PsTerminateSystemThread` 是个很小的 wrapper，里面调用的第一个"有效的未导出函数"就是 `PspTerminateThreadByPointer`，那就不搜固定模式了，改成：

1. 遍历函数体 0xFF 范围内所有 `E8`/`E9` 指令
2. 算出每个 call/jmp 的目标地址
3. 跳过已知导出函数（`PsGetCurrentThread` 之类的，用 `MmGetSystemRoutineAddress` 排除）
4. 检查目标地址是不是一个合法的函数入口（看 prologue 字节，`48 89 xx`/`48 83 EC`/`push rbx` 等常见开头）
5. 第一个通过验证的就是目标

在 Win11 26200 上验证：第一个 `E8` 在 `+0x26`，目标 prologue 是 `48 89 5C 24 08`（`mov [rsp+8], rbx`），直接命中。中间不需要知道 `41 B0 01` 之类的上下文。

这个方案的好处是不依赖任何版本特定的字节序列，只要微软不把 `PsTerminateSystemThread` 改成完全不调用 `PspTerminateThreadByPointer`（那它就没法终止线程了），逻辑就能工作。

## 怎么离线逆向的

没开内核调试，纯离线分析 ntoskrnl.exe。

**1) 拿函数 RVA**

```
dumpbin /exports C:\Windows\System32\ntoskrnl.exe | findstr PsTerminateSystemThread
→ 009D8000
```

**2) RVA 转文件偏移**

ntoskrnl 的 section layout 比较特殊（36 个 section，`.text` 的 VA 不是常见的 `0x1000`），得用 `dumpbin /headers` 看清楚：

```
PAGE section: VA=0x6F5000, RawPtr=0x66E000
```

RVA `0x9D8000` 落在 PAGE section：

```
文件偏移 = 0x9D8000 - 0x6F5000 + 0x66E000 = 0x951000
```

**3) PowerShell 读字节**

```powershell
$bytes = [IO.File]::ReadAllBytes("C:\Windows\System32\ntoskrnl.exe")
# 从文件偏移处读，手动反汇编确认
```

**4) 验证目标**

算出 call 的目标 RVA 后，再去读那个地址的字节，确认是正常的函数 prologue（`48 89 5C 24 08` = `mov [rsp+8], rbx`），没算错。
