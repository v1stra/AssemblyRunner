# AssemblyRunner


### Basic Examples

```bash
# Rubeus
AssemblyRunner.exe /encrypt:Rubeus.exe /outfile:rubeus_encrypted.exe

AssemblyRunner.exe /decrypt:1 /assembly:rubeus_encrypted.exe /amsi:1 /args:"hash /password:Password12!! /user:administrator /domain:test.local"
```
```

[+] Decrypting...
[+] Got .NET assembly version: v4.0.30319



   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.0.2


[*] Action: Calculate Password Hash(es)

[*] Input password             : Password12!!
[*] Input username             : administrator
[*] Input domain               : test.local
[*] Salt                       : TEST.LOCALadministrator
[*]       rc4_hmac             : 55EE14B508B76D85CE3E2A771110D0D9
[*]       aes128_cts_hmac_sha1 : 42D6B8081979387478502D1DAA6B349F
[*]       aes256_cts_hmac_sha1 : 05B074F8A7FFEDF7D22B5BE7CA3FCCE93E74F21CA0171A05F9B5CF426C0F6A23
[*]       des_cbc_md5          : F80D0D2CEF406183


[+] inlineExecute-Assembly Finished
```