Bryan Valarezo
110362410

This is a write up reverse engineering the 2 binaries
-Number
-Key
================================================================================================================================================================================
## Number

After downloading the binary, I ran `file(1)` on it to get relevant information.

$ file ./number

> ./number: ELF 32-bit LSB shared object, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, BuildID[sha1]=f8ca93addd368c65d626901f74c3c9eb79b8ec1a, stripped

What is important to note is that the binary is
-stripped
-32-bit Intel x86
-linked with a shared object

Running `ldd(1)` reveals that the shared object is libc
$ldd ./number

> linux-gate.so.1 (0xb7f1b000)
libc.so.6 => /lib/i386-linux-gnu/libc.so.6 (0xb7d21000)
/lib/ld-linux.so.2 (0xb7f1c000)

Nothing quite interesting yet, I then ran `strings(1)` to find any interesting data in the binary.

$ strings ./number

This reveals some information.

libc functions...
fflush
exit
__isoc99_scanf
puts
stdin
printf
strlen
memset
atoi
strcmp

and some custom strings too...
Wrong number
Enter the right number:
%27s
CSE363ESC
Your number corresponds to %s, well done!    

If we run the binary normally...we can see some of these strings in action.

$ ./number 
Enter the right number: 12
Wrong number

I can run the binary with `strace(1)` and `ltrace(1)` to see which of the libc functions and syscalls were being called.

$ strace ./number
$ ltrace ./number

So far, I can guess that the program uses `scanf(3)` to read the number from STDIN. Then at the end, print the result of the comparison via `printf(3)`. However, it isn't clear how the comparison is done.

Lets actually look into the binary itself, with `objdump(1)`.

$ objdump -xd ./number

This reveals important information, such as

start address 0x000010e0 //beginning of .text
__libc_start_main: //Perhaps where main is
00001000 <.init> //the beginning of init

Which we can use as a breakpoint in a debugger.

Lets run this in a debugger like `gdb(1)` to grasp a better understanding

$ gdb ./number

AT&T syntax sucks, lets use Intel

> set disassembly-flavor intel

Trying to disassemble from main isn't so simple(Since the binary was stripped :/ ).

> disassemble main
No symbol table is loaded.  Use the "file" command.

However, we do know __libc_start_main exists, so lets set up a breakpoint there.

(gdb) break __libc_start_main
Breakpoint 1 at 0xb7dfe720: file ../csu/libc-start.c, line 141.

We have to find a better location for the breakpoint. Single stepping into scanf immediately exits...
Its hard to guess where we should be looking at, so...
Its time to whip out the big guns 8-) (Ghidra).

Ghidra is a very powerful tool that upon importing the binary, it found the function that called scanf and printf.

Now, all we need todo is to analyze the function to see what input will invoke the printf.
#######################################################################
undefined4 FUN_00011251(void)

{
  size_t sVar1;
  int iVar2;
  undefined4 in_ECX;
  char local_66;
  char local_65;
  char local_64;
  undefined local_63;
  char local_62 [64];
  char local_22 [10];
  int local_18;
  int local_14;
  uint local_10;
  undefined4 local_c;
  
  local_c = in_ECX;
  printf("Enter the right number: ");
  local_18 = __isoc99_scanf(&DAT_0001202e,local_62);
  if (local_18 != 1) { //if scanf did not read 1 input(it failed)
    FUN_00011219(); 
  } 
  if (local_62[0] != '0') {
    FUN_00011219(); 
  }
  if (local_62[1] != '6') {
    FUN_00011219(); 
  }
  fflush(stdin);
  memset(local_22,0,10);
  local_63 = 0;
  local_10 = 0;
  local_14 = 0;
  while( true ) {
    sVar1 = strlen(local_22);
    if (8 < sVar1) break;
    sVar1 = strlen(local_62);
    if (sVar1 <= local_10) break;
    local_66 = local_62[local_10];
    local_65 = local_62[local_10 + 1];
    local_64 = local_62[local_10 + 2];
    iVar2 = atoi(&local_66);
    local_22[local_14] = (char)iVar2;
    local_22[local_14] = local_22[local_14] + '\x03';
    local_10 = local_10 + 3;
    local_14 = local_14 + 1;
  }
  local_22[local_14] = '\0';
  iVar2 = strcmp(local_22,"CSE363ESC");
  if (iVar2 == 0) {
    printf("Your number corresponds to %s, well done!\n",local_22);
  }
  else {
    FUN_00011219();
  }
  return 0;
}
#######################################################################
Below is my simplified version
#######################################################################
int main(void)

{
  size_t strlen_retval;
  int x_int;
  int strcmp_retval
  char x
  char input [64];
  char final_number [10];
  int scanf_retval;
  int c;
  uint b;

  printf("Enter the right number: ");
  scanf_retval = __isoc99_scanf(&DAT_0001202e,input);
  if (scanf_retval != 1) {
    exit();
  }
  if (input[0] != '0') {
    exit();
  }
  if (input[1] != '6') {
    exit();
  }
  fflush(stdin);
  memset(final_number,0,10);
  b = 0;
  c = 0;
  while( true ) {

    strlen_retval = strlen(final_number); // returns 0 if '==', -1 for '<', 1 for '>'
    if (8 < strlen_retval)
    {
        break;
    }
    strlen_retval = strlen(input);
    if (strlen_retval <= b) 
    {
        break;
    }
    ############### THIS IS NOT CORRECT
    x = input[b]; //b = 0 ,3 ,6 ,9 ,12, 15, 18, 21, 24, 27, 30
    x_int = atoi(&x); //convert str `x` to ascii int ########################
    final_number[c] = (char)x_int;
    final_number[c] = final_number[c] + '\x03'; // + 3
    b = b + 3; 
    c++;
    ################
  }
  //input = ['x30','x36',x,'x50',x, x,'x42',x,x,'x30',x,x,'x33',x,x,'x30',x,x,'x42',x,x,'x50',x,x,'x40']
  //final_number = [x40, x50, x42, x30, x33, x30, x42, x50, x40, x00]
  //final_number = [64, 80, 66, 48, 51, 48, 66, 80, 64, 0]
  final_number[c] = '\0';
  strcmp_retval = strcmp(final_number,"CSE363ESC"); //CSE363ESC ==> [67,83,69,51,54,51,69,83,67,0]
  if (strcmp_retval == 0) {
    printf("Your number corresponds to %s, well done!\n",final_number);
  }
  else {
    exit();
  }
  return 0;
}
#######################################################################
Now we have a basic idea as to what the function is doing, we can run it with a debugger!

Unfortunately, the decompiler is lying to us. 
We know for a fact that based on the if statements, the number must being with the numbers
06

However, this is the most critical part of the code.(I used binary ninja to get this).
#######################################################################
000012ef  lea     edx, [ebp-0x5e {var_66}]
000012f2  mov     eax, dword [ebp-0xc {var_14}]
000012f5  add     eax, edx {var_66}
000012f7  movzx   eax, byte [eax]
000012fa  mov     byte [ebp-0x62 {var_6a}], al
000012fd  mov     eax, dword [ebp-0xc {var_14}]
00001300  add     eax, 0x1
00001303  movzx   eax, byte [ebp+eax-0x5e {var_66}]
00001308  mov     byte [ebp-0x61 {var_69_1}], al
0000130b  mov     eax, dword [ebp-0xc {var_14}]
0000130e  add     eax, 0x2
00001311  movzx   eax, byte [ebp+eax-0x5e {var_66}]
00001316  mov     byte [ebp-0x60 {var_68_1}], al
00001319  sub     esp, 0xc
0000131c  lea     eax, [ebp-0x62 {var_6a}]
0000131f  push    eax {var_6a} {var_80_2}
00001320  call    atoi 					//atoi conversion
00001325  add     esp, 0x10
00001328  mov     ecx, eax
0000132a  lea     edx, [ebp-0x1e {var_26}]
0000132d  mov     eax, dword [ebp-0x10 {var_18}]
00001330  add     eax, edx {var_26}
00001332  mov     byte [eax], cl 			//Only use 1 byte
00001334  lea     edx, [ebp-0x1e {var_26}]
00001337  mov     eax, dword [ebp-0x10 {var_18}]
0000133a  add     eax, edx {var_26}
0000133c  movzx   eax, byte [eax]
0000133f  add     eax, 0x3 				// Add 3
00001342  mov     ecx, eax
00001344  lea     edx, [ebp-0x1e {var_26}]
00001347  mov     eax, dword [ebp-0x10 {var_18}]
0000134a  add     eax, edx {var_26}
0000134c  mov     byte [eax], cl
0000134e  add     dword [ebp-0xc {var_14}], 0x3
00001352  add     dword [ebp-0x10 {var_18}], 0x1
#######################################################################
I had to use GDB again to help me analyze what was going on.

I had to constanly check the registers...
$ info reg

The stack...
$ x/20s $esp

And the assembly instructions
$ x/20i $eip

Here were my breakpoints, with no ASLR. The last 3 digits are the offset(translate based on your proc mappings)

(gdb) info break
Num     Type           Disp Enb Address    What
7       breakpoint     keep y   0x56556<356> //offset
        breakpoint already hit 4 times
8       breakpoint     keep y   0x56556<2ef> 
        breakpoint already hit 3 times
9       breakpoint     keep y   0x56556<325> 
        breakpoint already hit 3 times
10      breakpoint     keep y   0x56556<31f>
        breakpoint already hit 3 times
11      breakpoint     keep y   0x56556<382> 

After analyzing the code in execution, I came up with this conclusion.

Basically, the function will take every 3 numbers, chop the first one, take the other 2 as a number and add it by 3. Then finally, cast it as a `char`(the number itself has become an ascii code).

Here is an example

456789 ==> 456,789

456 becomes ==> 56, then +3 makes it 59

59 in ascii is `;`

If you notice the CSE363ESC string, this is what the final number needs to mutate to in order to win.
We can convert the string to its ascii codes 
//CSE363ESC ==> [67,83,69,51,54,51,69,83,67,0]

Then subtract 3 
// [64, 80, 66, 48, 51, 48, 66, 80, 64, 0]

The first number must begin with 06. 67 is 'C' in ascii. Subtract that by 3 and its '@' or 64
Our input should look like this

064,080,066,048,051,048,066,080,064 //Do you see the pattern? ===>[64, 80, 66, 48, 51, 48, 66, 80, 64]

Lets input this number...

bryan@thinkpad-t450s $ ./number
Enter the right number: 064080066048051048066080064
Your number corresponds to CSE363ESC, well done!

We did it!
================================================================================================================================================================================
## Key

After downloading the binary, I ran `file(1)`, `string(1)`, `ldd(1)`, and 'objdump(1)` on it to get relevant information.

$ file ./key
key: ELF 32-bit LSB pie executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, BuildID[sha1]=b53ba5b802cbba7fa58131c3a17c6d923f0eadef, stripped

$ strings ./key

oy/*/szzoy
.,.,
Usage: %s <key>
Hty<wye<uo<
snny
h2<_sr{n}hip}husro=
Knsr{<wye2
;*2$"
 
$ ldd ./key
        linux-gate.so.1 (0xf7fd0000)
        libc.so.6 => /usr/lib32/libc.so.6 (0xf7d90000)
        /lib/ld-linux.so.2 => /usr/lib/ld-linux.so.2 (0xf7fd1000)

$ objdump -xd ./key

start address 0x000010c0
//Couldn't find a main function :(

I see a bunch of strings, no symbol table, and libc imports.

Lets run `strace(1)` and `ltrace(1)` to see which of the libc functions and syscalls were being called.

$ strace ./key 4
$ ltrace ./key 4

Now this tells us alot of whats going on. I see the rand(3) function being called, followed up by strlen(3), calloc(3), and puts(3). It looks like the strings...

Knsr{<wye2
oy/*/szzoy

are important in deriving the key. 

Lets decompile this in Ghidra and try to understand whats going on.

Looks like Ghidra found the main function again(Awesome!). Here it is.
#######################################################################
undefined4 FUN_00011311(int param_1,undefined4 *param_2)
{
  undefined4 uVar1;
  int iVar2;
  char local_11c [256];
  char *local_1c;
  int local_18;
  int local_14;
  undefined4 *local_10;
  
  local_10 = &param_1;
  if (param_1 == 2) {
    strncpy(local_11c,(char *)param_2[1],0x100);
    local_14 = 0;
    local_18 = 0;
    while (local_18 < 0x27a) {
      iVar2 = rand();
      local_14 = local_14 + iVar2;
      local_18 = local_18 + 1;
    }
    local_14 = FUN_000112ef(local_14);
    iVar2 = FUN_0001126a(local_11c);
    if (iVar2 == 1) {
      local_1c = (char *)FUN_000111f9(&DAT_0001202c);
      puts(local_1c);
    }
    else {
      local_1c = (char *)FUN_000111f9("Knsr{<wye2");
      puts(local_1c);
    }
    free(local_1c);
    uVar1 = 0;
  }
  else {
    printf("Usage: %s <key>\n",*param_2);
    uVar1 = 1;
  }
  return uVar1;
}
#######################################################################

Below is my simplified version of it.
It also came along with some other subroutines, which I simplified below.
#######################################################################
int main(int argc,char **argv)
{
  int retval;
  int cmp_retval;
  char input [256];
  char *out_message;
  int b;
  int a;
  undefined4 *local_10;
  
  local_10 = &argc;
  if (argc == 2) {
    strncpy(input,argv[1],0x100);
    //Nonsense below
    a = 0;
    b = 0;
    while (b < 0x27a) {
      cmp_retval = rand();
      a = a + cmp_retval;
      b = b + 1;
    }
    a = add_10(a);
    //Nonsense above
    cmp_retval = compare_keys(input);
    if (cmp_retval == 1) {
      out_message = (char *)decrypt_xor_x1c(&SUCCESS_MSG); //THE ADDRESS IN MEMORY OF THE SUCCESS MESSAGE
      puts(out_message);
    }
    else {
      out_message = (char *)decrypt_xor_x1c("Knsr{<wye2"); // Wrong Key.
      puts(out_message);
    }
    free(out_message);
    retval = 0;
  }
  else {
    printf("Usage: %s <key>\n",*argv);
    retval = 1;
  }
  return retval;
}

int compare_keys(char *param_1)

{
  size_t length;
  int real_key;
  int retval;
  uint i;
  
  length = strlen(param_1);
  real_key = decrypt_xor_x1c(&REAL_KEY); //THE ADDRESS IN MEMORY OF THE KEY TO COMPARE TO
  if (length == 0x10) {
    i = 0;
    while (i < 0x10) {
      if (*(char *)(i + real_key) != param_1[i]) {
        return 0;
      }
      i = i + 1;
    }
    retval = 1;
  }
  else {
    retval = 0;
  }
  return retval;
}

void * decrypt_xor_x1c(char *encrypted_input)
{
  void *decrypted_input;
  size_t length;
  uint i;
  
  decrypted_input = calloc(0x100,1);
  length = strlen(encrypted_input);
  i = 0;
  while (i < length) {
    *(byte *)(i + (int)decrypted_input) = encrypted_input[i] ^ 0x1c; //WEAK DECRYPTION
    i = i + 1;
  }
  return decrypted_input;
}
#######################################################################
After analyzing the decompiled code, I can infer that:

The while loop with rand() does nothing, ignore it.
The input MUST be 16 in length.
The input is compared to an encrypted string in memory...
	During the comparison, the encrypted string gets decrypted, then its a regular strcmp with the decrypted key and the input

There is a decryption routine in the program. However, this is a weak encryption since all it does is XOR the byte with 0x1c
//    *(byte *)(i + (int)decrypted_input) = encrypted_input[i] ^ 0x1c;

If we take a look at the strings...

oy/*/szzoy
.,.,

and 

Hty<wye<uo<
snny
h2<_sr{n}hip}husro=

They are actually the key and success messages, encrypted.

Since the encryption is so weak, we can decrypt ourselves.

Here is my python script to decrypt the key. I used the hex values of the strings in the binary and just coded them to my script.

#!/usr/bin/env python3 

def decrypt(input):
    out = []
    for i in input:
        out += [0x1c ^ i]
    return out

encrypted_key_hex = ["7f","6f","79","2f","2a","2f","73","7a","7a","6f","79","7f","2e","2c","2e","2c"]
encrypted_success_hex = ["48","74","79","3c","77","79","65","3c","75","6f","3c","7f","73","6e","6e","79","7f","68","32","3c","5f","73","72","7b","6e","7d","68","69","70","7d","68","75","73","72","6f","3d"]
encrypted_key = [int(''.join(c),16) for c in encrypted_key_hex ]
encrypted_success = [int(''.join(c),16) for c in encrypted_success_hex ]
key = "".join(chr(c) for c in decrypt(encrypted_key))
success = "".join(chr(c) for c in decrypt(encrypted_success))
print(key)
print(success)

The python script decrypts the key to be...
cse363offsec2020

Lets try that with the binary...

bryan@thinkpad-t450s $ ./key cse363offsec2020
The key is correct. Congratulations!

We did it!
