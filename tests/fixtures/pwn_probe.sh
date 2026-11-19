set -eu
export TERM=xterm

cat > /challenge/work/vuln.c <<'EOF'
#include <stdio.h>
void win(void) { puts("PWN_WIN_OK"); }
int main(void) {
    char buf[32];
    puts("input:");
    gets(buf);
    return 0;
}
EOF

gcc -fno-stack-protector -no-pie -z execstack -o /challenge/work/vuln /challenge/work/vuln.c
pwn checksec /challenge/work/vuln
ROPgadget --binary /challenge/work/vuln --only 'ret' | head -n 10

python - <<'PY'
from pwn import ELF, ROP, context
elf = ELF('/challenge/work/vuln', checksec=False)
print('win', hex(elf.symbols['win']))
rop = ROP(elf)
print('ret_gadget', hex(rop.find_gadget(['ret']).address))
PY

printf 'gdb='; gdb --version | head -n 1
printf 'gdb-multiarch='; gdb-multiarch --version | head -n 1
printf 'qemu='; qemu-i386 --version | head -n 1
echo pwn-sandbox-ok
