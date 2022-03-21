# ZXYR
A remote access trojan made mainly in C++. This serves for me as a study of system programming and a first look into the world of malware.\
The main module is the TCP Revshell, this is made as a DLL(Dynamic-link library) file.\
By using RtlCreateUserThread dll injection method i can hook it up to chrome which I start minimized. This will all be done by launching the dropper and then setting everything up for the injector.

<img width="1178" alt="FUCK YES DLL INJECTION BBYa" src="https://user-images.githubusercontent.com/86436966/159288532-0cb83554-0ac0-4ced-84c4-6a5d62f8aeda.png">


# PLANS AND TODO:
***Backdoor:***
- Undetectable and lightweight. Serves one purpose for now.

***RtlCreateUserThread Injector:***
- POC finished

***Dropper:***
- IN PROGRESS

***TODO:***
- File Upload and Download
- Antidebugging features
- TaskManager kill
- AutoStartup user persistance
- Client and finish dropper
- I might make some studies about how I made this but for now I will focus on finishing the product.

# Last Update(XZYR 1.01):
- Bugfixing injector
- Minimized chrome start and an overhaul of the dll.
- System breaking problems are done
- Everything executes a bit faster

![ZXYR 1 01](https://user-images.githubusercontent.com/86436966/159282869-d1c4382d-c867-4014-921f-c10ffe46a047.gif)
> ZXYR 1.01 SHOWCASE
