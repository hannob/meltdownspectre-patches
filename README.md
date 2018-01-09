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

PoCs
=====

* In a [recent tweet](https://twitter.com/mlqxyz/status/950744467736354816), Moritz Lipp (Graz University of Technology) has announced the release of their PoC implementations for Meltdown. 
  * [GitHub repository](https://github.com/iaik/meltdown)
* In a [recent tweet](https://twitter.com/tehjh/status/950774905544507393), Jann Horn (Google's Project Zero) has announced that the PoC code referenced in their recent blogpost about CPUs is now public.

Linux upstream kernel
=====================

[Kernel Page Table Isolation](https://en.wikipedia.org/wiki/Kernel_page-table_isolation#cite_note-:2-4)
is a mitigation in the Linux Kernel, originally named KAISER.

 * [Version 4.14.11](https://cdn.kernel.org/pub/linux/kernel/v4.x/ChangeLog-4.14.11) contains KPTI.
 * [Version 4.15-rc6](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/log/?h=v4.15-rc6) contains KPTI.
 * Longterm support kernels [Version 4.9.75](https://cdn.kernel.org/pub/linux/kernel/v4.x/ChangeLog-4.9.75) and [4.4.110](https://cdn.kernel.org/pub/linux/kernel/v4.x/ChangeLog-4.4.110) contain KPTI backports.

minipli patches
===============

minipli is an unofficial fork of the former grsecurity patches (original grsecurity is no longer publicly
available). minipli is based on the longterm kernel 4.9, which supports KPTI since
4.9.75, yet the patchset isn't ported yet.

 * [bug report with discussion about backporting KPTI](https://github.com/minipli/linux-unofficial_grsec/issues/25)

Android
=======

 * Fixed with [Android Security Bulletin—January 2018](https://source.android.com/security/bulletin/2018-01-01).

Windows
=======

 * [Microsoft Advisory](https://portal.msrc.microsoft.com/en-us/security-guidance/advisory/adv180002)
 * [Windows Server Guidance](https://support.microsoft.com/en-gb/help/4072698/windows-server-guidance-to-protect-against-the-speculative-execution-s) and [Windows Client Guidance](https://support.microsoft.com/en-gb/help/4073119/windows-client-guidance-for-it-pros-to-protect-against-speculative-exe). Note: both links include a Powershell tool to query the status of Windows mitigations for CVE-2017-5715 (branch target injection) and CVE-2017-5754 (rogue data cache load).
 * [Protecting guest virtual machines from CVE-2017-5715 (branch target injection)](https://docs.microsoft.com/en-us/virtualization/hyper-v-on-windows/CVE-2017-5715-and-hyper-v-vms)
 
**Update - Tue 9 Jan 09:00 UTC**

Microsoft has reports of some customers with AMD devices getting into an unbootable state after installing [this KB](https://support.microsoft.com/en-us/help/4056892/windows-10-update-kb4056892). To prevent this issue, Microsoft will temporarily pause Windows OS updates to devices with impacted AMD processors (older CPUs, eg. Athlon and Sempron) at this time. Microsoft is working with AMD to resolve this issue and resume Windows OS security updates to the affected AMD devices via Windows Update and WSUS as soon as possible. If you have experienced an unbootable state or for more information see [KB4073707](https://support.microsoft.com/en-us/help/4073707). For AMD specific information please contact AMD.
   

Apple
====

Apple has already released mitigations in iOS 11.2, macOS 10.13.2, and tvOS 11.2 to help defend against Meltdown. 

* [Official statement](https://support.apple.com/en-us/HT208394)

**Update Mon 8 Jan 18:00 UTC**

Apple has released security improvements to Safari and WebKit to mitigate the effects of Spectre (CVE-2017-5753 and CVE-2017-5715):
* [macOS High Sierra 10.13.2 Supplemental Update](https://support.apple.com/en-us/HT208397)
* [Safari 11.0.2](https://support.apple.com/en-us/HT208403) for Mac OS X El Capitan 10.11.6 and macOS Sierra 10.12.6
* [iOS 11.2.2 update](https://support.apple.com/en-us/HT208401) for iPhone and iPad

 
**Update - Sun 7 Jan 2018, 9:00 UTC**

Based on the Apple's response posted [here](https://twitter.com/GraveSpy720/status/949489861886537728), Meltdown (CVE-2017-5754) is currently only addressed in iOS 11.2, macOS 10.13.2, and tvOS 11.2. Apple cannot say at this time if there will be updates to OS versions prior to the ones listed in their article at this time. The same can be said for Spectre (CVE-2017-5753 and CVE-2017-5715) and any updates for Safari. This means that at this given time there are NO patches for 10.11.x (El Capitan) or 10.12.x (Sierra).

Linux distributions
===================

 * [Red Hat Advisory](https://access.redhat.com/security/vulnerabilities/speculativeexecution)
   * [Speculative Execution Exploit Performance Impacts - Describing the performance impacts to security patches for CVE-2017-5754 CVE-2017-5753 and CVE-2017-5715](https://access.redhat.com/articles/3307751)
 * CentOS:
   * 7 - [CESA-2018:0007](https://lists.centos.org/pipermail/centos-announce/2018-January/022696.html) (kernel), [CESA-2018:0012](https://lists.centos.org/pipermail/centos-announce/2018-January/022697.html) (microcode_ctl), [CESA-2018:0014](https://lists.centos.org/pipermail/centos-announce/2018-January/022698.html) (linux-firmware), [CESA-2018:0023](https://lists.centos.org/pipermail/centos-announce/2018-January/022705.html) (qemu-kvm), [CESA-2018:0029](https://lists.centos.org/pipermail/centos-announce/2018-January/022704.html) (libvirt)
   * 6 - [CESA-2018:0008](https://lists.centos.org/pipermail/centos-announce/2018-January/022701.html) (kernel), [CESA-2018:0013](https://lists.centos.org/pipermail/centos-announce/2018-January/022700.html) (microcode_ctl), [CESA-2018:0024](https://lists.centos.org/pipermail/centos-announce/2018-January/022702.html) (qemu-kvm), [CESA-2018:0030](https://lists.centos.org/pipermail/centos-announce/2018-January/022703.html) (libvirt)
 * Fedora - Fixed in [FEDORA-2018-8ed5eff2c0](https://bodhi.fedoraproject.org/updates/FEDORA-2018-8ed5eff2c0) (Fedora 26) and [FEDORA-2018-22d5fa8a90](https://bodhi.fedoraproject.org/updates/FEDORA-2018-22d5fa8a90) (Fedora 27).  
 * Ubuntu (tl;dr: Release candidate kernels with patches for *Meltdown* 4.4.x and 4.13.x are now available through a dedicated PPA; subsequent patches for *Spectre* are coming in the future before the kernels are pushed to official release branch):  
 **Update - Sun 7 Jan 2018, 22:00 UTC**  
 Release candidate kernels 4.4.x (Trusty HWE / Xenial GA) and 4.13.x (Xenial HWE-edge / Artful GA / Artful HWE) are now publicly available from a [dedicated Launchpad PPA](https://launchpad.net/~canonical-kernel-team/+archive/ubuntu/pti/) and currently contain patches for CVE-2017-5754 *aka Meltdown*, with support only some architactures. Support for a broader array of architectures and patches for CVE-2017-5715 and CVE-2017-5753 *aka Spectre* are expected in the near future.
 After some testing, the patched kernels will be pushed to the main release branch.  
  **Update - Mon 8 Jan 2018, 16:00 UTC**  
 Canonical Ltd. announced that, in order to speed up the patching process for all supported distribution versions and branches, the 4.10.x *Xenial HWE* kernel will be migrated early to version 4.13.x, thus leaving no supported kernel branch exposed to vulnerabilities. The migration will occur concurrently to the push of patched kernels to the main distribution repositories.
 In addition, Ubuntu 17.04, aka *Zesty Zapus*, will [reach End Of Life](https://lists.ubuntu.com/archives/ubuntu-announce/2018-January/000227.html) on Sat 13 Jan 2018 and will not receive any kind kernel patch support.
   * [Ubuntu Wiki SecurityTeam KnowledgeBase](https://wiki.ubuntu.com/SecurityTeam/KnowledgeBase/SpectreAndMeltdown)
   * [Ubuntu Insights blog - Ubuntu Updates for the Meltdown / Spectre Vulnerabilities](https://insights.ubuntu.com/2018/01/04/ubuntu-updates-for-the-meltdown-spectre-vulnerabilities/)
   * [Details about CVE-2017-5753 (variant 1, aka "Spectre")](https://people.canonical.com/~ubuntu-security/cve/2017/CVE-2017-5753)
   * [Details about CVE-2017-5715 (variant 2, aka "Spectre")](https://people.canonical.com/~ubuntu-security/cve/2017/CVE-2017-5715)
   * [Details about CVE-2017-5754 (variant 3, aka "Meltdown")](https://people.canonical.com/~ubuntu-security/cve/2017/CVE-2017-5754.html)
 * Debian: "Meltdown" fixed in stretch (4.9.65-3+deb9u2, [DSA-4078-1](https://security-tracker.debian.org/tracker/DSA-4078-1)). "Spectre" mitigations are a work in progress.
   * [Details about CVE-2017-5753 (variant 1, aka "Spectre")](https://security-tracker.debian.org/tracker/CVE-2017-5753)
   * [Details about CVE-2017-5715 (variant 2, aka "Spectre")](https://security-tracker.debian.org/tracker/CVE-2017-5715)
   * [Details about CVE-2017-5754 (variant 3, aka "Meltdown")](https://security-tracker.debian.org/tracker/CVE-2017-5754)
 * [SUSE Advisory](https://www.suse.com/c/suse-addresses-meltdown-spectre-vulnerabilities/)
 * Scientific Linux:
   * 7 - [SLSA-2018:0007-1](https://www.scientificlinux.org/category/sl-errata/slsa-20180007-1/) (kernel), [SLSA-2018:0012-1](https://www.scientificlinux.org/category/sl-errata/slsa-20180012-1/) (microcode_ctl), [SLSA-2018:0014-1](https://www.scientificlinux.org/category/sl-errata/slsa-20180014-1/) (linux-firmware) 
   * 6 - [SLSA-2018:0008-1](https://www.scientificlinux.org/category/sl-errata/slsa-20180008-1/) (kernel), [SLSA-2018:0013-1](https://www.scientificlinux.org/category/sl-errata/slsa-20180013-1/) (microcode_ctl) 
 * CoreOS Container Linux: Fixes for Meltdown are [available in all release channels now](https://coreos.com/blog/container-linux-meltdown-patch) (Alpha 1649.0.0, Beta 1632.1.0, Stable 1576.5.0). Auto-updated systems will receive the releases containing the patch on 2017-01-08. Spectre patches are still WIP.
 * NixOS: According to [#33414](https://github.com/NixOS/nixpkgs/issues/33414), KPTI is in nixpkgs since [1e129a3](https://github.com/NixOS/nixpkgs/commit/1e129a3f9934ae62b77475909f6812f2ac3ab51f).
 * [Arch Linux Advisory](https://lists.archlinux.org/pipermail/arch-security/2018-January/001110.html)
 * Gentoo:
   * [Gentoo Wiki - Project:Security/Vulnerabilities/Meltdown and Spectre](https://wiki.gentoo.org/wiki/Project:Security/Vulnerabilities/Meltdown_and_Spectre)
   * [Bugtracker - Bug#643228 - Security Tracking Bug](https://bugs.gentoo.org/643228)
 * Oracle Linux (ELSA Security Advisory):
   * [Details about CVE-2017-5753 (variant 1, aka "Spectre")](https://linux.oracle.com/cve/CVE-2017-5753.html)
   * [Details about CVE-2017-5715 (variant 2, aka "Spectre")](https://linux.oracle.com/cve/CVE-2017-5715.html)
   * [Details about CVE-2017-5754 (variant 3, aka "Meltdown")](https://linux.oracle.com/cve/CVE-2017-5754.html)
 * CloudLinux: [Intel CPU Bug - Meltdown and Spectre - KernelCare and CloudLinux](https://www.cloudlinux.com/cloudlinux-os-blog/entry/intel-cpu-bug-kernelcare-and-cloudlinux)
 * Parrot Security OS: [meltdown/spectre security patches](https://blog.parrotsec.org/meltdown-spectre-security-patches/)
 * Wind River Linux and Pulsar Linux: [Wind River Security Vulnerability Notice: Linux Kernel Meltdown and Spectre Break (Side-Channel Attacks)](https://knowledge.windriver.com/en-us/000_Products/000/010/050/010/000_Wind_River_Security_Vulnerability_Notice%3A__Linux_Kernel_Meltdown_and_Spectre_Break_(Side-Channel_Attacks)_-_CVE-2017-5754_CVE-2017-5753_CVE-2017-5715#)

FreeBSD
=======

* [Statement](https://lists.freebsd.org/pipermail/freebsd-security/2018-January/009719.html)

Virtualization
==============

* XEN - [XSA-254](https://xenbits.xen.org/xsa/advisory-254.html) and [Xen Project Spectre/Meltdown FAQ](https://blog.xenproject.org/2018/01/04/xen-project-spectremeltdown-faq/), no patches yet
* QEMU - unofficial patch published [here](https://lists.nongnu.org/archive/html/qemu-devel/2018-01/msg00811.html), [official blog post](https://www.qemu.org/2018/01/04/spectre/), [discussion on qemu-devel](https://lists.nongnu.org/archive/html/qemu-devel/2018-01/msg00613.html)
* VMware - [VMSA-2018-0002](https://www.vmware.com/us/security/advisories/VMSA-2018-0002.html)
  * [KB 52245](https://kb.vmware.com/s/article/52245) tracks vSphere status.
  * [KB 52264](https://kb.vmware.com/s/article/52264) tracks VMware appliance status (currently all unaffected or pending)
  * Update 01/04/18: "OS vendors have begun issuing patches that address CVE-2017-5753, CVE-2017-5715, and CVE-2017-5754 for their operating systems. For these patches to be fully functional in a guest OS additional ESXi and vCenter Server updates will be required. These updates are being given the highest priority. Please sign up to the [Security-Announce mailing list](https://lists.vmware.com/cgi-bin/mailman/listinfo/security-announce) to be alerted when these updates are available."
  * [William Lam suggests](https://twitter.com/lamw/status/949662333038559232) forthcoming patches for ESXi 5.5 and a vCenter patch to deliver microcode when using EVC.
* Red Hat Enterprise Virtualization - [Impacts of CVE-2017-5754, CVE-2017-5753, and CVE-2017-5715 to Red Hat Virtualization products](https://access.redhat.com/solutions/3307851)
* Citrix XenServer - [Citrix XenServer Multiple Security Updates](https://support.citrix.com/article/CTX231390)
* Nutanix - Nutanix Security Advisory #0007 v1 - [Nutanix Side-Channel Speculative Execution Vulnerabilities](http://download.nutanix.com/alerts/Security-Advisory_0007_v1.pdf)  
  **Update - Mon 8 Jan 2018**
  - New Nutanix Security Advisory #0007 v2 - [Nutanix Side-Channel Speculative Execution Vulnerabilities](http://download.nutanix.com/alerts/Security-Advisory_0007_v2.pdf)
* Virtuozzo - [Virtuozzo Addresses Intel Bug Questions](https://virtuozzo.com/virtuozzo-addresses-intel-bug-questions/)
* KVM: **Update - Tue 9 Jan 07:50 UTC** - Paolo Bonzini, KVM developer, posted [in a tweet](https://twitter.com/fagiolinux/status/950435721961144322) the following status update for CVE-2017-5715 (Spectre): 
   * Already in Linus's tree: clearing registers on vmexit 
   * First wave of KVM fixes here: https://marc.info/?l=kvm&m=151543506500957&w=2
   * He is also mentioning that a full solution will require all the Linux parts to be agreed upon, but this will unblock the QEMU updates.

Browsers
========

* Mozilla: [Mitigations landing for new class of timing attack (blog post)](https://blog.mozilla.org/security/2018/01/03/mitigations-landing-new-class-timing-attack/), [Security Advisory 2018-01](https://www.mozilla.org/en-US/security/advisories/mfsa2018-01/), [Firefox mitigation update 57.0.4](https://www.mozilla.org/en-US/firefox/57.0.4/releasenotes/)
* Chrome: [Actions Required to Mitigate Speculative Side-Channel Attack Techniques](https://www.chromium.org/Home/chromium-security/ssca)
* Microsoft Edge: [Mitigating speculative execution side-channel attacks in Microsoft Edge and Internet Explorer](https://blogs.windows.com/msedgedev/2018/01/03/speculative-execution-mitigations-microsoft-edge-internet-explorer/)
* Webkit (open source browser engine): [What Spectre and Meltdown Mean For WebKit](https://webkit.org/blog/8048/what-spectre-and-meltdown-mean-for-webkit/)
* Brave Browser: [New desktop release just out (0.19.131)](https://twitter.com/brave/status/950613194933874688) with various security enhancements, including Strict Site Isolation support.
  * [Release Notes](https://github.com/brave/browser-laptop/releases/tag/v0.19.131dev)

**Update Mon 8 Jan 2018, 13:00 UTC**

Tencent's Xuanwu Lab [has released a web-based tool](http://xlab.tencent.com/special/spectre/spectre_check.html) that can detect whether your browser is vulnerable to Spectre Attack and can be easily exploited. Official tweet: https://twitter.com/XuanwuLab/status/950345917013504001

Cloud Providers
========
* Amazon AWS: [Processor Speculative Execution Research Disclosure](https://aws.amazon.com/security/security-bulletins/AWS-2018-013/)
* Google Cloud: [Google’s Mitigations Against CPU Speculative Execution Attack Methods](https://support.google.com/faqs/answer/7622138)
* Microsoft Azure: [Securing Azure customers from CPU vulnerability](https://azure.microsoft.com/en-us/blog/securing-azure-customers-from-cpu-vulnerability/)
* DigitalOcean: [A Message About Intel Security Findings](https://blog.digitalocean.com/a-message-about-intel-security-findings/)
* Scaleway/Online: [Spectre and Meltdown vulnerabilities status](https://www.scaleway.com/meltdown-spectre-status/)
* Linode: [CPU Vulnerabilities: Meltdown & Spectre](https://blog.linode.com/2018/01/03/cpu-vulnerabilities-meltdown-spectre/)
* Rackspace: [Rackspace is Tracking Vulnerabilities Affecting Processors by Intel, AMD and ARM](https://blog.rackspace.com/rackspace-is-tracking-vulnerabilities-affecting-processors-by-intel-amd-and-arm)
* OVH: [Meltdown, Spectre bug impacting x86-64 CPU - OVH fully mobilised](https://www.ovh.co.uk/news/articles/a2570.meltdown-spectre-bug-x86-64-cpu-ovh-fully-mobilised) (en), [Vulnérabilités Meltdown/Spectre affectant les CPU x86-64 : OVH pleinement mobilisé](https://www.ovh.com/fr/blog/vulnerabilites-meltdown-spectre-cpu-x86-64-ovh-pleinement-mobilise/) (fr)
* Vultr: [Intel CPU Vulnerability Alert](https://www.vultr.com/news/Intel-CPU-Vulnerability-Alert/)
* Hetzner: [Spectre and Meltdown](https://wiki.hetzner.de/index.php/Spectre_and_Meltdown/en)
* UpCloud: [Information regarding the Intel CPU vulnerability (Meltdown)](https://www.upcloud.com/blog/intel-cpu-vulnerability-meltdown/)
* Heroku: [Meltdown and Spectre Security Update](https://blog.heroku.com/meltdown-and-spectre-security-update)
* Alibaba Cloud: [Intel Processor Meltdown and Specter Security Vulnerability Bulletin ](https://www.alibabacloud.com/forum/read-2878)
* Zscaler: [Meltdown and Spectre vulnerabilities: What you need to know](https://www.zscaler.com/blogs/research/meltdown-and-spectre-vulnerabilities-what-you-need-know)
* Gandi: [Meltdown and Spectre vulnerabilities](https://news.gandi.net/en/2018/01/meltdown-and-spectre-vulnerabilities/)

Chip Manufacturers / HW Vendors
==================
* Intel: [INTEL-SA-00088 - Speculative Execution and Indirect Branch Prediction Side Channel Analysis Method](https://security-center.intel.com/advisory.aspx?intelid=INTEL-SA-00088&languageid=en-fr), [Intel Analysis of Speculative
Execution Side Channels (Whitepaper)](https://newsroom.intel.com/wp-content/uploads/sites/11/2018/01/Intel-Analysis-of-Speculative-Execution-Side-Channels.pdf), [Intel Issues Updates to Protect Systems from Security Exploits](https://newsroom.intel.com/news-releases/intel-issues-updates-protect-systems-security-exploits/)
* AMD: [An Update on AMD Processor Security](https://www.amd.com/en/corporate/speculative-execution)
* ARM: [Security Update](https://developer.arm.com/support/security-update)
* Arista: [Security Advisories](https://www.arista.com/en/support/advisories-notices/security-advisories/4025-security-advisory-31)
* Raspberry Pi: [Why Raspberry Pi isn't vulnerable to Spectre or Meltdown](https://www.raspberrypi.org/blog/why-raspberry-pi-isnt-vulnerable-to-spectre-or-meltdown/)
* NVIDIA: [Security Notice: Speculative Side Channels](https://nvidia.custhelp.com/app/answers/detail/a_id/4609), [NVIDIA Shield Tablet Security Updates](https://nvidia.custhelp.com/app/answers/detail/a_id/4614), [NVIDIA Shield TV Security Updates](https://nvidia.custhelp.com/app/answers/detail/a_id/4613), [NVIDIA GPU Display Driver Security Updates](https://nvidia.custhelp.com/app/answers/detail/a_id/4611), [NVIDIA Tegra Jetson TX2 L4T Security Updates](https://nvidia.custhelp.com/app/answers/detail/a_id/4617), [NVIDIA Tegra Jetson TX1 L4T and Jetson TK1 L4T Security Updates](https://nvidia.custhelp.com/app/answers/detail/a_id/4616)
* Lenovo: [LEN-18282 - Reading Privileged Memory with a Side Channel](https://support.lenovo.com/it/en/solutions/len-18282)
* IBM: [Central Processor Unit (CPU) Architectural Design Flaws](https://exchange.xforce.ibmcloud.com/collection/Central-Processor-Unit-CPU-Architectural-Design-Flaws-c422fb7c4f08a679812cf1190db15441), [Potential Impact on Processors in the POWER family](https://www.ibm.com/blogs/psirt/potential-impact-processors-power-family/)
* Huawei: [huawei-sn-20180104-01 - Statement on the Media Disclosure of a Security Vulnerability in the Intel CPU Architecture Design](http://www.huawei.com/en/psirt/security-notices/huawei-sn-20180104-01-intel-en)
* F5: [K91229003 - Side-channel processor vulnerabilities CVE-2017-5715, CVE-2017-5753, and CVE-2017-5754](https://support.f5.com/csp/article/K91229003)
* Cisco [CPU Side-Channel Information Disclosure Vulnerabilities](https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20180104-cpusidechannel)
* Fortigate: [CPU hardware vulnerable to Meltdown and Spectre attacks](https://fortiguard.com/psirt/FG-IR-18-002)
* Cumulus Linux: [Meltdown and Spectre: Modern CPU Vulnerabilities](https://support.cumulusnetworks.com/hc/en-us/articles/115015951667-Meltdown-and-Spectre-Modern-CPU-Vulnerabilities)
* Check Point: [Check Point Response to Meltdown and Spectre (CVE-2017-5753, CVE-2017-5715, CVE-2017-5754)](https://supportcenter.checkpoint.com/supportcenter/portal?eventSubmit_doGoviewsolutiondetails=&solutionid=sk122205)
* Palo Alto Networks: [Information about Meltdown and Spectre findings (PAN-SA-2018-0001)](https://securityadvisories.paloaltonetworks.com/)
* HP Enterprise: [Side Channel Analysis Method Allows Improper Information Disclosure in Microprocessors (CVE-2017-5715, CVE-2017-5753, CVE-2017-5754)](https://support.hpe.com/hpsc/doc/public/display?docId=emr_na-a00039267en_us), [HPESBHF03805 Certain HPE products using Microprocessors from Intel, AMD, and ARM, with Speculative Execution, Elevation of Privilege and Information Disclosure](https://support.hpe.com/hpsc/doc/public/display?docId=emr_na-hpesbhf03805en_us)
* Juniper: [2018-01 Out of Cycle Security Bulletin: Meltdown & Spectre: CPU Speculative Execution and Indirect Branch Prediction Side Channel Analysis Method](https://kb.juniper.net/InfoCenter/index?page=content&id=JSA10842&actp=RSS), [Meltdown & Spectre: Modern CPU vulnerabilities](https://forums.juniper.net/t5/Security-Now/Meltdown-amp-Spectre-Modern-CPU-vulnerabilities/ba-p/317254)
* Infoblox: [#7346: Spectre/Meltdown Vulnerabilities - CVE-2017-5715, CVE-2017-5753, CVE-2017-5754](https://support.infoblox.com/app/answers/detail/a_id/7346) (Login required)
* FireEye: [FireEye Notice for CVE-2017-5754, CVE-2017-5753, and CVE-2017-5715 (“Meltdown” and “Spectre” vulnerabilities)](https://www.fireeye.com/blog/products-and-services/2018/01/fireeye-notice-for-meltdown-and-spectre-vulnerabilities.html), [Community Protection Event (CPE): CPU Security Flaws (Spectre/Meltdown)](https://community.fireeye.com/thread/2727) (Login required)
* Symantec: [Meltdown and Spectre: Are Symantec Products Affected?](https://support.symantec.com/en_US/article.INFO4793.html)
* Dell EMC: [Microprocessor Side-Channel Attacks (CVE-2017-5715, CVE-2017-5753, CVE-2017-5754): Impact on Dell EMC products (Dell Enterprise Servers, Storage and Networking)](http://www.dell.com/support/article/us/en/04/sln308588/microprocessor-side-channel-attacks--cve-2017-5715--cve-2017-5753--cve-2017-5754---impact-on-dell-emc-products--dell-enterprise-servers--storage-and-networking-?lang=en)
* NetApp: [NTAP-20180104-0001 - Processor Speculated Execution Vulnerabilities in NetApp Products](https://security.netapp.com/advisory/ntap-20180104-0001/)
* ASUS: [ASUS Motherboards Microcode Update for Speculative Execution and Indirect Branch Prediction Side Channel Analysis Method](https://www.asus.com/News/V5urzYAT6myCC1o2)
* Aruba Networks: [ARUBA-PSA-2018-001 - Unauthorized Memory Disclosure through CPU Side-Channel Attacks](http://www.arubanetworks.com/assets/alert/ARUBA-PSA-2018-001.txt)
* Pure Storage: [Advisory](https://support.purestorage.com/Field_Bulletins/The_Meltdown_and_Spectre_CPU_Vulnerabilities) (login required)
* Supermicro: [Security Vulnerabilities Regarding Side Channel Speculative Execution and Indirect Branch Prediction Information Disclosure](https://www.supermicro.com/support/security_Intel-SA-00088.cfm)
* A10 Networks: [SPECTRE/MELTDOWN - CVE-2017-5715/5753/5754](https://www.a10networks.com/sites/default/files/Spectre_Meltdown-CVE-2017-5715_5753_5754.pdf)
* Avaya: [Recent Potential CPU Vulnerabilities: Meltdown and Spectre](https://downloads.avaya.com/css/P8/documents/101045884)
* RSA: [000035890 - Microprocessor Side-Channel Attacks (CVE-2017-5715, CVE-2017-5753, CVE-2017-5754): Impact on RSA products ](https://community.rsa.com/docs/DOC-85418) (login required)
* Fujitsu: [CPU hardware vulnerable to side-channel attacks](http://www.fujitsu.com/global/support/products/software/security/products-f/jvn-93823979e.html)
* Veritas Appliance: [Veritas Appliance Statement on Meltdown and Spectre](https://www.veritas.com/support/en_US/article.100041496)
* Schneider Electric: [Security Notification: "Meltdown" (CVE-2017-5754) and "Spectre" (CVE-2017-5753 & CVE-2017-5715)​ - impact to APC products](https://www.schneider-electric.com/en/faqs/FA336892/)
* Polycom: [Security Advisory Relating to the “Speculative
Execution” Vulnerabilities with some microprocessors](https://support.polycom.com/content/dam/polycom-support/global/documentation/spectre-meltdown-vulnerability-1-1.pdf)
* Sonicwall: [Meltdown and Spectre Vulnerabilities: A SonicWall Alert](https://www.sonicwall.com/en-us/support/product-notification/meltdown-and-spectre-vulnerabilities-a-sonicwall)
* Aerohive Networks: [Aerohive's response to Meltdown and Spectre](https://www.aerohive.com/support/security-center/product-security-announcement-aerohives-response-to-meltdown-and-spectre-jan-5-2018/)
* Barracuda Networks: [Security Advisory](https://blog.barracuda.com/2018/01/05/barracuda-networks-security-advisory/)
* Netgate: [An update on Meltdown and Spectre](https://www.netgate.com/blog/an-update-on-meltdown-and-spectre.html)
* Silver Peak: [Security Advisory](https://www.silver-peak.com/sites/default/files/advisory/security_advisory_notice_-_meltdown-spectre.pdf)

CERTs
==================
* CERT/CC: [Vulnerability Note VU#584653 - CPU hardware vulnerable to side-channel attacks](https://www.kb.cert.org/vuls/id/584653)
* US-CERT: [TA18-004A - Meltdown and Spectre Side-Channel Vulnerability Guidance](https://www.us-cert.gov/ncas/alerts/TA18-004A)
* CERT-EU: [Security Advisory 2018-001 - Meltdown and Spectre Critical Vulnerabilities](http://cert.europa.eu/static/SecurityAdvisories/2018/CERT-EU-SA2018-001.pdf)
* NCSC-UK: [Meltdown and Spectre guidance](https://www.ncsc.gov.uk/guidance/meltdown-and-spectre-guidance)
* CERT-FR: [CERTFR-2018-ALE-001 - Multiples vulnérabilités de fuite d’informations dans des processeurs](https://www.cert.ssi.gouv.fr/alerte/CERTFR-2018-ALE-001/) (french only)
* CERT Nazionale: [Moderni processori vulnerabili ad attacchi side-channel](https://www.certnazionale.it/news/2018/01/04/moderni-processori-vulnerabili-ad-attacchi-side-channel/) (italian only)
* CERT-PA: [Meltdown e Spectre, vulnerabilità sui microprocessori mettono potenzialmente a rischio informazioni sensibili](https://www.cert-pa.it/web/guest/news?id=9378) (italian only)
* SingCERT: [Alert on Security Flaws Found in Central Processing Units (CPUs)](https://www.csa.gov.sg/singcert/news/advisories-alerts/alert-on-security-flaws-found-in-central-processing-units)
* CERT.BE: [Central Processor Unit (CPU) Architectural Design Flaws](https://www.cert.be/docs/central-processor-unit-cpu-architectural-design-flaws.html)
* CERT-IS: [Alvarlegur öryggisgalli í örgjörvum - Meltdown/Spectre](https://www.cert.is/is/node/41.html) (icelandic only)
* MyCERT: [MA-691.012018: Alert - CPU Hardware Side-Channel Attacks Vulnerability](https://www.mycert.org.my/en/services/advisories/mycert/2018/main/detail/1301/index.html)

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

**Update - Fri 5 Jan 2018, 03:35 UTC**

Debian Project package maintainers released an [updated version of the "intel-microcode" package (version 2017-12-15)](https://packages.debian.org/sid/intel-microcode) for the Sid (unstable) branch olny. Upon inspection, it seems to contain the same microcode additions observed in the Red Hat microcode_ctl update of Thu 4 Jan 2018, 15:30 UTC.
The package in compatible with all Debian-based distributions that support post-boot microcode updates.

Antiviruses
===========

Some Antiviruses do things that break when installing the Windows patches, therefore Microsoft doesn't automatically install the patches on those systems.

Vendor overview: https://docs.google.com/spreadsheets/d/184wcDt9I9TUNFFbsAVLpzAtckQxYiuirADzf3cL42FQ/htmlview?usp=sharing&sle=true

* Trend Micro: [Important Information for Trend Micro Solutions and Microsoft January 2018 Security Updates (Meltdown and Spectre)](https://success.trendmicro.com/solution/1119183-important-information-for-trend-micro-solutions-and-microsoft-january-2018-security-updates)
* Emsisoft: [Chip vulnerabilities and Emsisoft: What you need to know](https://blog.emsisoft.com/2018/01/04/chip-vulnerabilities-and-emsisoft-what-you-need-to-know/)
* Sophos: [Advisory - Kernel memory issue affecting multiple OS (aka F..CKWIT, KAISER, KPTI, Meltdown & Spectre)](https://community.sophos.com/kb/en-us/128053)
* Webroot: [Microsoft Patch Release - Wednesday, January 3, 2018](https://community.webroot.com/t5/Announcements/Microsoft-Patch-Release-Wednesday-January-3-2018/m-p/310146
)
* McAfee: [Decyphering the Noise Around ‘Meltdown’ and ‘Spectre’](https://securingtomorrow.mcafee.com/mcafee-labs/decyphering-the-noise-around-meltdown-and-spectre/) and [Meltdown and Spectre – Microsoft update (January 3, 2018) compatibility issue with anti-virus products](https://kc.mcafee.com/corporate/index?page=content&id=KB90167)
* Kaspersky: [Compatibility of Kaspersky Lab solutions with the Microsoft Security update of January 9, 2018](https://support.kaspersky.com/14042)
* ESET: [Meltdown & Spectre: How to protect yourself from these CPU security flaws](https://www.eset.com/us/about/newsroom/corporate-blog-list/corporate-blog/meltdown-spectre-how-to-protect-yourself-from-these-cpu-security-flaws/)
* Avira: [With our latest product update 15.0.34.17 Avira Antivirus Free, Avira Antivirus Pro and Avira Antivirus Server are compatible with the Microsoft update](https://www.avira.com/en/support-for-home-knowledgebase-detail/kbid/1925)
* Symantec: [Meltdown and Spectre: Are Symantec Products Affected?](https://support.symantec.com/en_US/article.INFO4793.html)
* Avast: [Meltdown and Spectre: Yes, your device is likely vulnerable](https://blog.avast.com/meltdown-and-spectre-yes-your-device-is-likely-vulnerable)
* eScan: [Meltdown and Spectre – CPU Vulnerabilities](http://blog.escanav.com/2018/01/meltdown-spectre-cpu-vulnerabilities/)

RDBMS
=====
* SQL Server: [SQL Server Guidance to protect against speculative execution side-channel vulnerabilities](https://support.microsoft.com/en-us/help/4073225/guidance-for-sql-server)

NOSQL
=====
* Elastic stack: [Elastic Cloud and Meltdown](https://www.elastic.co/blog/elastic-cloud-and-meltdown)

Embedded Devices
================

 * Synology: [Synology-SA-18:01 Meltdown and Spectre Attacks](https://www.synology.com/en-us/support/security/Synology_SA_18_01)
 * Opengear: [CVE-2017-5754, CVE-2017-5715, CVE-2017-5753 - Meltdown and Spectre CPU Vulnerabilities](https://opengear.zendesk.com/hc/en-us/articles/115003797711-CVE-2017-5754-CVE-2017-5715-CVE-2017-5753-Meltdown-and-Spectre-CPU-Vulnerabilities)
 * QNAP: [NAS-201801-08 - Security Advisory for Speculative Execution Vulnerabilities in Processors](https://www.qnap.com/en/security-advisory/nas-201801-08)
 
Compilers
================

* [Google's Retpoline: a software construct for preventing branch-target-injection](https://support.google.com/faqs/answer/7625886) (technical write-up)
  * LLVM: An implementation is under review for official merge [here](https://reviews.llvm.org/D41723)
  * GCC: An implementation for GCC is available [here](http://git.infradead.org/users/dwmw2/gcc-retpoline.git/shortlog/refs/heads/gcc-7_2_0-retpoline-20171219)
