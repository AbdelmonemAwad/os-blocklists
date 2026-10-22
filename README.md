# Block Lists for OPNsense

Block lists in one place: addresses, DNS names, countries and JA4 fingerprints of TLS clients, gathered into one page - and on a Sophos XGS cut by the coprocessor in hardware.

> **Planned - nothing here runs yet.** This repository was opened on 2026-10-22 to hold
> Block Lists as a plugin of its own. No code has been written or moved into it, and there is no
> release.

## What it is to do

- the sources of a block - IP lists, DNS lists, countries, JA4 fingerprints - in one page;
- on a Sophos XGS, the blocked traffic cut by the coprocessor in hardware;
- a page in the XGS section of OPNsense's menu.

## Where it fits

It is one part of the [os-xgs-npu](https://github.com/AbdelmonemAwad/os-xgs-npu) project, which puts OPNsense on Sophos XGS hardware, and works the way its other plugins do: changes by pull request, a release installed from **XGS: Updates**, its Arabic in [opnsense-arabic](https://github.com/AbdelmonemAwad/opnsense-arabic)'s catalogue.

## Licence

BSD 2-Clause - see [LICENSE](LICENSE).
