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
 * [Windows Server Guidance](https://support.microsoft.com/en-gb/help/4072698/windows-server-guidance-to-protect-against-the-speculative-execution-s) and [Windows Client Guidance](https://support.microsoft.com/en-gb/help/4073119/windows-client-guidance-for-it-pros-to-protect-against-speculative-exe). Note: both links include a Powershell tool to query the status of Windows mitigations for CVE-2017-5715 (branch target injection) and CVE-2017-5754 (rogue data cache load).
   

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
* VMware - [VMSA-2018-0002](https://www.vmware.com/us/security/advisories/VMSA-2018-0002.html)
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

**Update - Thu 4 Jan 2018, 15:30 UTC**

It seems that the new Intel’s microcode archive (2017-12-15) provided with the latest Red Hat’s microcode_ctl update includes three new files: 06-3f-02, 06-4f-01, 06-55-04.

Based on what we know:
1. it adds one new CPUID and two MSR for the variant of Spectre that uses indirect branches
2. it forces LFENCE to terminate the execution of all previous instructions, thus having the desired effect for the variant of Spectre that uses conditional branches (out-of-bounds-bypass)

Those IDs belong to the following processor microarchitectures: Haswell, Broadwell, Skylake ([official reference](https://software.intel.com/en-us/articles/intel-architecture-and-processor-identification-with-cpuid-model-and-family-numbers))

**Update - Thu 4 Jan 2018, 16:30 UTC**

Regarding AMD's microcode update: it seems to be only for EPYC (maybe Ryzen, not sure!) and it only adds one of the two MSRs (IA32_PRED_CMD). It uses a different bit than Intel's in the CPUID. It is also for Spectre with indirect branches. Previous microprocessors resolved it with a chicken bit. Please note that the same solution implemented at kernel level works for both Intel and AMD.

Antiviruses
===========

Some Antiviruses do things that break when installing the Windows patches,
therefore Microsoft doesn't automatically install the patches on those systems.

Mitigation: Remove Antivirus.

Vendor overview: https://docs.google.com/spreadsheets/d/184wcDt9I9TUNFFbsAVLpzAtckQxYiuirADzf3cL42FQ/htmlview?usp=sharing&sle=true

* Trend Micro: [Important Information for Trend Micro Solutions and Microsoft January 2018 Security Updates (Meltdown and Spectre)](https://success.trendmicro.com/solution/1119183-important-information-for-trend-micro-solutions-and-microsoft-january-2018-security-updates)
* Emsisoft: [Chip vulnerabilities and Emsisoft: What you need to know](https://blog.emsisoft.com/2018/01/04/chip-vulnerabilities-and-emsisoft-what-you-need-to-know/)
* Sophos: [Advisory: Kernel memory issue affecting multiple OS (aka F..CKWIT, KAISER, KPTI, Meltdown & Spectre)](https://community.sophos.com/kb/en-us/128053)
* Webroot: [Microsoft Patch Release - Wednesday, January 3, 2018](https://community.webroot.com/t5/Announcements/Microsoft-Patch-Release-Wednesday-January-3-2018/m-p/310146
)


Embedded Devices
================

 * Synology: https://www.synology.com/en-us/support/security/Synology_SA_18_01
