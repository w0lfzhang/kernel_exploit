## Exploit
It's been a very long time I have not do the pwning-exercise. And I got a easy kernel challenge of QWB 2018.
First thing is packing and unpacking. It's be mentioned in [here](https://github.com/w0lfzhang/kernel_exploit/blob/master/2017-ncstisc-babydriver/README.md). And it provides a script to pack: gen_cpio.sh.
In start.sh, option '-s' represents -gdb tcp::1234. So you can debug the kernel with gdb.

Using objdump to find your gadgets, not just ROPgadget!! It's fast.
```
objdump -d vmlinux | grep iretq
ROPgadget --binary vmlinux > ropgadget.txt
grep 'swapgs' ropgadget.txt
```

I find a interesting thing when looking for the gadget of 'swapgs'. 

```
The instructions when kernel running:
gdb-peda$ x/10i native_load_gs_index
   0xffffffff818012d0 <native_load_gs_index>:   add    al,0x84
   0xffffffff818012d2 <native_load_gs_index+2>: ror    BYTE PTR [rax+0x1082494],cl
   0xffffffff818012d8 <native_load_gs_index+8>: add    BYTE PTR [rax],al
   0xffffffff818012da <native_load_gs_index+10>:    
    js     0xffffffff818014c5 <general_protection+5>

The instructions of the binary vmlinux:
gdb-peda$ x/10i native_load_gs_index
   0xffffffff818012d0 <native_load_gs_index>:   pushf  
   0xffffffff818012d1 <native_load_gs_index+1>: cli    
   0xffffffff818012d2 <native_load_gs_index+2>: swapgs 
   0xffffffff818012d5 <native_load_gs_index+5>: mov    gs,edi
   0xffffffff818012d7 <native_load_gs_index+7>: nop
   0xffffffff818012d8 <native_load_gs_index+8>: nop
   0xffffffff818012d9 <native_load_gs_index+9>: nop
   0xffffffff818012da <native_load_gs_index+10>:    swapgs 
   0xffffffff818012dd <native_load_gs_index+13>:    popf   
   0xffffffff818012de <native_load_gs_index+14>:    ret
```
So you must find another way to find 'swapgs;ret'. And I did not know how the author got the address of it in the [article](https://www.anquanke.com/post/id/103920).