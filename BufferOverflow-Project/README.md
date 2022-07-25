Disable ASLR.
```
sudo su
echo 0 > /proc/sys/kernel/randomize_va_space
exit
```
Compile `vulnerable.c` without stack and control-flow protection.
```
gcc -no-pie -fcf-protection=none -fno-stack-protector -z execstack -mpreferred-stack-boundary=4 -o vulnerable -ggdb vulnerable.c
```
Run with
```
gdb -q vulnerable
run < textFile.1
./payloadGenerator.py > textFile.1
./vulnerable < textFile.1
```

> note: valid arguments to ‘-fcf-protection=’ are: branch check full none return;
> https://sourceware.org/annobin/annobin.html/Test-cf-protection.html
> https://zoepla.github.io/2018/04/gcc的编译关于程序保护开启的选项/

prepare
```
# install dependency
sudo apt install gcc-multilib
# compile
gcc -m32 -no-pie ex2.c -o ex2
```

```
   High Address  |                 |
                 +-----------------+
                 | args            |
                 +-----------------+ 
                 | return address  | 
    0x4(%ebp) => +-----------------+ ; push   %ebp
                 | old ebp         |
       (%ebp) => +-----------------+ ; mov    %esp,%ebp
                 | ebx             | 
    0x4(%ebp) => +-----------------+ ; push   %ebx
                 |                 |
   -0x8(%ebp) => +-----------------+
                 | canary          |
   -0xc(%ebp) => +-----------------+ ; mov    %gs:0x14,%eax; mov    %eax,-0xc(%ebp)
                 | buf[100]        |
  -0x70(%ebp) => +-----------------+ ; lea    -0x70(%ebp),%eax
                 | i               | 
  -0x74(%ebp) => +-----------------+ ; movl   $0x0,-0x74(%ebp)
                 |                 |
  -0x78(%ebp) => +-----------------+ ; sub    $0x4,%esp
                 | 0x00000200      |
  -0x7c(%ebp) => +-----------------+ ; push   $0x200
                 | &buf            | 
  -0x80(%ebp) => +-----------------+ ; lea    -0x70(%ebp),%eax; push   %eax; 
                 | 0x00000000      |
  -0x8c(%ebp) => +-----------------+ ; push   $0x0; call   0x80490c0 <read@plt>
                 |                 | 
  -0x90(%ebp) => +-----------------+ ; sub    $0xc,%esp
                 | &buf            | 
  -0x94(%ebp)    +-----------------+ ; lea    -0x70(%ebp),%eax; push   %eax; 
                 | 0x00000000      |
  -0x98(%ebp)    +-----------------+ ; call   0x80490d0 <printf@plt>
                 |                 |
  -0x9c(%ebp) => +-----------------+ ; add    $0x10,%esp
```

```
pip install -U ipykernel
```


```
gcc -no-pie -fcf-protection=none -z execstack -mpreferred-stack-boundary=4 -o vulnerable -ggdb vulnerable.c
gcc -no-pie -fcf-protection=none -fno-stack-protector -z execstack -mpreferred-stack-boundary=4 -o vulnerable -ggdb vulnerable.c
```
```
   High Address  |                 |
                 +-----------------+
                 | args            |
                 +-----------------+ 
                 | return address  | 
    0x8(%rbp) => +-----------------+ ; push   %rbp
                 | old rbp         |
       (%rbp) => +-----------------+ ; mov    %rsp,%rbp
                 | canary          |
   -0x8(%rbp) => +-----------------+ ; mov    %fs:0x28,%rax; mov    %rax,-0x8(%rbp)
                 |                 |
  -0x10(%rbp) => +-----------------+
                 | ............... |
                 |                 |
                 +-----------------+
                 | &array          |
 -0x1a0(%rbp) => +-----------------+ ; sub    $0x190,%rsp
```