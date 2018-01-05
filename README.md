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

 * [Version 4.14.11](https://cdn.kernel.org/pub/linux/kernel/v4.x/ChangeLog-4.14.11) contains KPTI.
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
   

Apple
====

Apple has already released mitigations in iOS 11.2, macOS 10.13.2, and tvOS 11.2 to help defend against Meltdown. 
In the coming days they plan to release mitigations in Safari to help defend against Spectre. They continue to develop and test further mitigations for these issues and will release them in upcoming updates of iOS, macOS, tvOS, and watchOS.

 * [Official statement](https://support.apple.com/en-us/HT208394)
 
The security patch released on December 6, 2017 includes Meltdown mitigation also for Sierra and El Capitan
 
 * [About the security content of macOS High Sierra 10.13.2, Security Update 2017-002 Sierra, and Security Update 2017-005 El Capitan](https://support.apple.com/en-us/HT208331)
 

Linux distributions
===================

 * [Red Hat Advisory](https://access.redhat.com/security/vulnerabilities/speculativeexecution)
 * CentOS - [CESA-2018:0007](https://lists.centos.org/pipermail/centos-announce/2018-January/022696.html) (kernel), [CESA-2018:0012](https://lists.centos.org/pipermail/centos-announce/2018-January/022697.html) (microcode_ctl), [CESA-2018:0014](https://lists.centos.org/pipermail/centos-announce/2018-January/022698.html) (linux-firmware)
 * Fedora - Fixed in [FEDORA-2018-8ed5eff2c0](https://bodhi.fedoraproject.org/updates/FEDORA-2018-8ed5eff2c0) (Fedora 26) and [FEDORA-2018-22d5fa8a90](https://bodhi.fedoraproject.org/updates/FEDORA-2018-22d5fa8a90) (Fedora 27).  
 * Ubuntu (tl;dr - Ubuntu users of the 64-bit x86 architecture (aka, amd64) can expect updated kernels by the original January 9, 2018 coordinated release date, and sooner if possible.):
   * [Ubuntu Wiki SecurityTeam KnowledgeBase](https://wiki.ubuntu.com/SecurityTeam/KnowledgeBase/SpectreAndMeltdown)
   * [Ubuntu Insights blog - Ubuntu Updates for the Meltdown / Spectre Vulnerabilities](https://insights.ubuntu.com/2018/01/04/ubuntu-updates-for-the-meltdown-spectre-vulnerabilities/)
   * [Details about CVE-2017-5753 (variant 1, aka "Spectre")](https://people.canonical.com/~ubuntu-security/cve/2017/CVE-2017-5753)
   * [Details about CVE-2017-5715 (variant 2, aka "Spectre")](https://people.canonical.com/~ubuntu-security/cve/2017/CVE-2017-5715)
   * [Details about CVE-2017-5754 (variant 3, aka "Meltdown")](https://people.canonical.com/~ubuntu-security/cve/2017/CVE-2017-5754.html)
 * Debian: Fixed in stretch (4.9.65-3+deb9u2, [DSA-4078-1](https://security-tracker.debian.org/tracker/DSA-4078-1))
   * [Details about CVE-2017-5753 (variant 1, aka "Spectre")](https://security-tracker.debian.org/tracker/CVE-2017-5753)
   * [Details about CVE-2017-5715 (variant 2, aka "Spectre")](https://security-tracker.debian.org/tracker/CVE-2017-5715)
   * [Details about CVE-2017-5754 (variant 3, aka "Meltdown")](https://security-tracker.debian.org/tracker/CVE-2017-5754)
 * [SUSE Advisory](https://www.suse.com/c/suse-addresses-meltdown-spectre-vulnerabilities/)
 * Scientific Linux:
   * 7 - [SLSA-2018:0007-1](https://www.scientificlinux.org/category/sl-errata/slsa-20180007-1/) (kernel), [SLSA-2018:0012-1](https://www.scientificlinux.org/category/sl-errata/slsa-20180012-1/) (microcode_ctl), [SLSA-2018:0014-1](https://www.scientificlinux.org/category/sl-errata/slsa-20180014-1/) (linux-firmware) 
   * 6 - [SLSA-2018:0008-1](https://www.scientificlinux.org/category/sl-errata/slsa-20180008-1/) (kernel), [SLSA-2018:0013-1](https://www.scientificlinux.org/category/sl-errata/slsa-20180013-1/) (microcode_ctl) 
 * CoreOS Container Linux: a [tweet](https://twitter.com/CoreOSsecurity/status/949080108739936257) posted by CoreOS' Security Team states that the team is now testing a round of patches developed by the Linux Kernel community to address the Meltdown vulnerabilities and crash issues identified in 4.14.11. The patches being tested are [here](https://github.com/coreos/linux/compare/e2b917f...coreos:v4.14.11-coreos)
 * NixOS: According to [#33414](https://github.com/NixOS/nixpkgs/issues/33414), KPTI is in nixpkgs since [1e129a3](https://github.com/NixOS/nixpkgs/commit/1e129a3f9934ae62b77475909f6812f2ac3ab51f).

FreeBSD
=======

* [Statement](https://www.freebsd.org/news/newsflash.html#event20180104:01)

Virtualization
==============

* XEN - [XSA-254](https://xenbits.xen.org/xsa/advisory-254.html) and [Xen Project Spectre/Meltdown FAQ](https://blog.xenproject.org/2018/01/04/xen-project-spectremeltdown-faq/), no patches yet
* QEMU - unofficial patch published [here](https://lists.nongnu.org/archive/html/qemu-devel/2018-01/msg00811.html), [official blog post](https://www.qemu.org/2018/01/04/spectre/), [discussion on qemu-devel](https://lists.nongnu.org/archive/html/qemu-devel/2018-01/msg00613.html)
* VMware - [VMSA-2018-0002](https://www.vmware.com/us/security/advisories/VMSA-2018-0002.html)
Update 01/04/18: "OS vendors have begun issuing patches that address CVE-2017-5753, CVE-2017-5715, and CVE-2017-5754 for their operating systems. For these patches to be fully functional in a guest OS additional ESXi and vCenter Server updates will be required. These updates are being given the highest priority. Please sign up to the [Security-Announce mailing list](https://lists.vmware.com/cgi-bin/mailman/listinfo/security-announce) to be alerted when these updates are available."
* Red Hat Enterprise Virtualization - [Impacts of CVE-2017-5754, CVE-2017-5753, and CVE-2017-5715 to Red Hat Virtualization products](https://access.redhat.com/solutions/3307851)
* Citrix XenServer - [Citrix XenServer Multiple Security Updates](https://support.citrix.com/article/CTX231390)

Browsers
========

* Mozilla: [Mitigations landing for new class of timing attack (blog post)](https://blog.mozilla.org/security/2018/01/03/mitigations-landing-new-class-timing-attack/), [Security Advisory 2018-01](https://www.mozilla.org/en-US/security/advisories/mfsa2018-01/)
* Chrome: [Actions Required to Mitigate Speculative Side-Channel Attack Techniques](https://www.chromium.org/Home/chromium-security/ssca)
* Microsoft Edge: [Mitigating speculative execution side-channel attacks in Microsoft Edge and Internet Explorer](https://blogs.windows.com/msedgedev/2018/01/03/speculative-execution-mitigations-microsoft-edge-internet-explorer/)

Cloud Providers
========
* Amazon AWS: [Processor Speculative Execution Research Disclosure](https://aws.amazon.com/security/security-bulletins/AWS-2018-013/)
* Google Cloud: [Google’s Mitigations Against CPU Speculative Execution Attack Methods](https://support.google.com/faqs/answer/7622138)
* Microsoft Azure: [Securing Azure customers from CPU vulnerability](https://azure.microsoft.com/en-us/blog/securing-azure-customers-from-cpu-vulnerability/)
* DigitalOcean: [A Message About Intel Security Findings](https://blog.digitalocean.com/a-message-about-intel-security-findings/)
* Scaleway: [Emergency security update required on all hypervisors](https://status.online.net/index.php?do=details&task_id=1116)
* Linode: [CPU Vulnerabilities: Meltdown & Spectre](https://blog.linode.com/2018/01/03/cpu-vulnerabilities-meltdown-spectre/)
* Rackspace: [Rackspace is Tracking Vulnerabilities Affecting Processors by Intel, AMD and ARM](https://blog.rackspace.com/rackspace-is-tracking-vulnerabilities-affecting-processors-by-intel-amd-and-arm)
* OVH: [Meltdown, Spectre bug impacting x86-64 CPU - OVH fully mobilised](https://www.ovh.co.uk/news/articles/a2570.meltdown-spectre-bug-x86-64-cpu-ovh-fully-mobilised) (en), [Vulnérabilités Meltdown/Spectre affectant les CPU x86-64 : OVH pleinement mobilisé](https://www.ovh.com/fr/blog/vulnerabilites-meltdown-spectre-cpu-x86-64-ovh-pleinement-mobilise/) (fr)

Chip Manufacturers / HW Vendors
==================
* Intel: [INTEL-SA-00088 - Speculative Execution and Indirect Branch Prediction Side Channel Analysis Method](https://security-center.intel.com/advisory.aspx?intelid=INTEL-SA-00088&languageid=en-fr), [Intel Analysis of Speculative
Execution Side Channels (Whitepaper)](https://newsroom.intel.com/wp-content/uploads/sites/11/2018/01/Intel-Analysis-of-Speculative-Execution-Side-Channels.pdf), [Intel Issues Updates to Protect Systems from Security Exploits](https://newsroom.intel.com/news-releases/intel-issues-updates-protect-systems-security-exploits/)
* AMD: [An Update on AMD Processor Security](https://www.amd.com/en/corporate/speculative-execution)
* ARM: [Security Update](https://developer.arm.com/support/security-update)
* NVIDIA: [Security Notice: Speculative Side Channels](https://nvidia.custhelp.com/app/answers/detail/a_id/4609)
* Lenovo: [LEN-18282 - Reading Privileged Memory with a Side Channel](https://support.lenovo.com/it/en/solutions/len-18282)
* IBM: [Central Processor Unit (CPU) Architectural Design Flaws](https://exchange.xforce.ibmcloud.com/collection/Central-Processor-Unit-CPU-Architectural-Design-Flaws-c422fb7c4f08a679812cf1190db15441)
* Huawei: [huawei-sn-20180104-01 - Statement on the Media Disclosure of a Security Vulnerability in the Intel CPU Architecture Design](http://www.huawei.com/en/psirt/security-notices/huawei-sn-20180104-01-intel-en)
* F5: [K91229003 - Side-channel processor vulnerabilities CVE-2017-5715, CVE-2017-5753, and CVE-2017-5754](https://support.f5.com/csp/article/K91229003)
* Cisco [CPU Side-Channel Information Disclosure Vulnerabilities](https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20180104-cpusidechannel)
* Fortigate [CPU hardware vulnerable to Meltdown and Spectre attacks](https://fortiguard.com/psirt/FG-IR-18-002)

CERTs
==================
* CERT/CC: [Vulnerability Note VU#584653 - CPU hardware vulnerable to side-channel attacks](https://www.kb.cert.org/vuls/id/584653)
* US-CERT: [TA18-004A - Meltdown and Spectre Side-Channel Vulnerability Guidance](https://www.us-cert.gov/ncas/alerts/TA18-004A)
* NCSC-UK: [Meltdown and Spectre guidance](https://www.ncsc.gov.uk/guidance/meltdown-and-spectre-guidance)
* CERT-FR: [CERTFR-2018-ALE-001 - Multiples vulnérabilités de fuite d’informations dans des processeurs](https://www.cert.ssi.gouv.fr/alerte/CERTFR-2018-ALE-001/) (french only)
* CERT Nazionale: [Moderni processori vulnerabili ad attacchi side-channel](https://www.certnazionale.it/news/2018/01/04/moderni-processori-vulnerabili-ad-attacchi-side-channel/) (italian only)

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
* Sophos: [Advisory - Kernel memory issue affecting multiple OS (aka F..CKWIT, KAISER, KPTI, Meltdown & Spectre)](https://community.sophos.com/kb/en-us/128053)
* Webroot: [Microsoft Patch Release - Wednesday, January 3, 2018](https://community.webroot.com/t5/Announcements/Microsoft-Patch-Release-Wednesday-January-3-2018/m-p/310146
)
* McAfee: [Decyphering the Noise Around ‘Meltdown’ and ‘Spectre’](https://securingtomorrow.mcafee.com/mcafee-labs/decyphering-the-noise-around-meltdown-and-spectre/) and [Meltdown and Spectre – Microsoft update (January 3, 2018) compatibility issue with anti-virus products](https://kc.mcafee.com/corporate/index?page=content&id=KB90167)
* Kaspersky: [Compatibility of Kaspersky Lab solutions with the Microsoft Security update of January 9, 2018](https://support.kaspersky.com/14042)
* ESET: [Meltdown & Spectre: How to protect yourself from these CPU security flaws](https://www.eset.com/us/about/newsroom/corporate-blog-list/corporate-blog/meltdown-spectre-how-to-protect-yourself-from-these-cpu-security-flaws/)

Embedded Devices
================

 * Synology: [Synology-SA-18:01 Meltdown and Spectre Attacks](https://www.synology.com/en-us/support/security/Synology_SA_18_01)
 * Opengear: Nothing yet. Support claims an announcement is being prepared but did not provide a timeframe for public release.
 
Compilers
================

* [Google's Retpoline: a software construct for preventing branch-target-injection](https://support.google.com/faqs/answer/7625886) (technical write-up)
  * LLVM: An implementation is under review for official merge [here](https://reviews.llvm.org/D41723)
  * GCC: An implementation for GCC is available [here](http://git.infradead.org/users/dwmw2/gcc-retpoline.git/shortlog/refs/heads/gcc-7_2_0-retpoline-20171219)
