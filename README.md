# meltdownspectre-patches
Summary of the patch status for Meltdown / Spectre

What?
=====

Meltdown and Spectre are hardware design vulnerabilities in all modern CPUs based on
speculative execution. Background infos:

 * https://spectreattack.com/ or https://meltdownattack.com/ (both pages serve identical content)
 * https://googleprojectzero.blogspot.dk/2018/01/reading-privileged-memory-with-side.html

The bug is in the hardware, but mitigations in operating systems are possible and are getting
shipped now. I'm collecting notes on the patch status in various software products. This will
change rapidly and may contain errors. If you have better info please send pull requests.

Linux upstream kernel
=====================

[Kernel Page Table Isolation](https://en.wikipedia.org/wiki/Kernel_page-table_isolation#cite_note-:2-4)
is a mitigation in the Linux Kernel, originally named KAISER.

 * [Version 4.14](https://cdn.kernel.org/pub/linux/kernel/v4.x/ChangeLog-4.14.11) contains KPTI.
 * [Version 4.15-rc6](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/log/?h=v4.15-rc6) contains KPTI.
 * The patches have not been backported to the longterm kernels like 4.9 (state: 4.9.74).

minipli patches
===============

minipli is an unofficial fork of the former grsecurity patches (original grsecurity is no longer publicly
available). minipli is based on the longterm kernel 4.9 which does not contain KPTI yet.

 * [bug report with discussion about backporting KPTI](https://github.com/minipli/linux-unofficial_grsec/issues/25)

Android
=======

 * Fixed with [Android Security Bulletin—January 2018](https://source.android.com/security/bulletin/2018-01-01).

Windows
=======

 * [Microsoft Advisory](https://portal.msrc.microsoft.com/en-us/security-guidance/advisory/adv180002)

OS X
====

 * Unclear, [some Info](https://twitter.com/aionescu/status/948610973987831809).

Linux distributions
===================

 * [Red Hat Advisory](https://access.redhat.com/security/vulnerabilities/speculativeexecution)
 * CentOS - [CESA-2018:0007](https://lists.centos.org/pipermail/centos-announce/2018-January/022696.html) (kernel), [CESA-2018:0012](https://lists.centos.org/pipermail/centos-announce/2018-January/022697.html) (microcode_ctl), [CESA-2018:0014](https://lists.centos.org/pipermail/centos-announce/2018-January/022698.html) (linux-firmware)
 * Ubuntu - nothing yet ([recap page](https://wiki.ubuntu.com/SecurityTeam/KnowledgeBase/SpectreAndMeltdown))
   * [Details about CVE-2017-5753 (variant 1, aka "Spectre")](https://people.canonical.com/~ubuntu-security/cve/2017/CVE-2017-5753)
   * [Details about CVE-2017-5715 (variant 2, aka "Spectre")](https://people.canonical.com/~ubuntu-security/cve/2017/CVE-2017-5715)
   * [Details about CVE-2017-5754 (variant 3, aka "Meltdown")](https://people.canonical.com/~ubuntu-security/cve/2017/CVE-2017-5754.html)
 * Debian - nothing yet, https://security-tracker.debian.org/tracker/CVE-2017-5754
 * [SUSE Advisory](https://www.suse.com/c/suse-addresses-meltdown-spectre-vulnerabilities/)
 * Scientific Linux:
   * 7 - [SLSA-2018:0007-1](https://www.scientificlinux.org/category/sl-errata/slsa-20180007-1/) (kernel), [SLSA-2018:0012-1](https://www.scientificlinux.org/category/sl-errata/slsa-20180012-1/) (microcode_ctl), [SLSA-2018:0014-1](https://www.scientificlinux.org/category/sl-errata/slsa-20180014-1/) (linux-firmware) 
   * 6 - [SLSA-2018:0008-1](https://www.scientificlinux.org/category/sl-errata/slsa-20180008-1/) (kernel), [SLSA-2018:0013-1](https://www.scientificlinux.org/category/sl-errata/slsa-20180013-1/) (microcode_ctl) 

Virtualization
==============

* XEN - [XSA-254](https://xenbits.xen.org/xsa/advisory-254.html), no patches yet
* QEMU - nothing yet, discussion: https://lists.nongnu.org/archive/html/qemu-devel/2018-01/msg00613.html
* VMware - [VMSA-2018-0002](https://lists.vmware.com/pipermail/security-announce/2018/000397.html)
* Red Hat Enterprise Virtualization - [Impacts of CVE-2017-5754, CVE-2017-5753, and CVE-2017-5715 to Red Hat Virtualization products](https://access.redhat.com/solutions/3307851)

Browsers
========

* Mozilla: [Mitigations landing for new class of timing attack](https://blog.mozilla.org/security/2018/01/03/mitigations-landing-new-class-timing-attack/)
* Chrome: [Actions Required to Mitigate Speculative Side-Channel Attack Techniques](https://www.chromium.org/Home/chromium-security/ssca)
* Microsoft Edge: [Mitigating speculative execution side-channel attacks in Microsoft Edge and Internet Explorer](https://blogs.windows.com/msedgedev/2018/01/03/speculative-execution-mitigations-microsoft-edge-internet-explorer/)

Cloud Providers
========
* Amazon AWS: [Processor Speculative Execution Research Disclosure](https://aws.amazon.com/security/security-bulletins/AWS-2018-013/)
* Google Cloud: [Google’s Mitigations Against CPU Speculative Execution Attack Methods](https://support.google.com/faqs/answer/7622138)
* Microsoft Azure: [Securing Azure customers from CPU vulnerability](https://azure.microsoft.com/en-us/blog/securing-azure-customers-from-cpu-vulnerability/)
* DigitalOcean: [A Message About Intel Security Findings](https://blog.digitalocean.com/a-message-about-intel-security-findings/)
* Scaleway: [Emergency security update required on all hypervisors](https://status.online.net/index.php?do=details&task_id=1116)

Chip Manufacturers
==================
* Intel: nothing yet
* AMD: nothing yet
* ARM: [Security Update](https://developer.arm.com/support/security-update)
* NVIDIA: [Security Notice: Speculative Side Channels](https://nvidia.custhelp.com/app/answers/detail/a_id/4609)

CERTs
==================
* CERT/CC: [Vulnerability Note VU#584653 - CPU hardware vulnerable to side-channel attacks](https://www.kb.cert.org/vuls/id/584653)

CPU microcode
=============

Latest [Intel microcode](https://downloadcenter.intel.com/download/27337) update is 20171117.
It is unclear whether microcode updates are needed and which version contains
them. The microcode update does not contain any changelog.  
If it will become necessary to update Intel (or AMD) microcode under Windows, before the release of official OS-level patches, [this VMware Labs fling](https://labs.vmware.com/flings/vmware-cpu-microcode-update-driver) - though formally experimental - can serve the purpose, at least temporarily.

Antiviruses
===========

Some Antiviruses do things that break when installing the Windows patches,
therefore Microsoft doesn't automatically install the patches on those systems.

Mitigation: Remove Antivirus.

Vendor overview: https://docs.google.com/spreadsheets/d/184wcDt9I9TUNFFbsAVLpzAtckQxYiuirADzf3cL42FQ/htmlview?usp=sharing&sle=true
