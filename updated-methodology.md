# Using MITRE ATT&CK® to Describe Vulnerabilities

[ATT&CK](https://attack.mitre.org/) tactics and techniques can be used as a set of standard terms to describe the exploitation process of a vulnerability. For example, to exploit a vulnerability where credentials are sent in clear text, the following steps could be used:
1. Sniff the network ([T1040](https://attack.mitre.org/techniques/T1040/))
2. Which gets you the unsecured credentials ([T1552](https://attack.mitre.org/techniques/T1552/))
3. Which you can use to access a valid account ([T1078](https://attack.mitre.org/techniques/T1078/))

Once the attacker has access to the valid account, there are too many possible paths to list them all. 

When developing this mapping methodology, we found that three steps of an associated attack were as many as could be reasonably described. We define these steps as follows:
1. **Exploitation Method** - the method used to exploit the vulnerability (T1040 in the example).
2. **Primary Impact** - the initial benefit (impact) gained through exploitation of the vulnerability (T1552 in the example).
3. **Secondary Impact** - what the adversary can do by gaining the benefit of the primary impact (T1078 in the example).

Using these three components, a **Vulnerability Exploit-Impact Description (VEID)** can be developed:

> The vulnerability allows the attacker to use **[EXPLOITATION METHOD]** to gain **[Primary Impact]**, which leads to **[Secondary Impact]**.

![/new-cve-to-attack-sentence.png](/new-cve-to-attack-sentence.png)

Given a vulnerability, it may not be possible to identify an ATT&CK technique for each VEID component because ATT&CK's level of abstraction may not match that of the vulnerability. Also, ATT&CK defines techniques used in *real-world* attacks and does not include theoretical techniques. However, as shown in the examples below, a VEID with just one or two components is still useful.

##	Mapping Methodology

This methodology establishes a starting point for vulnerability reporters and researchers to standardize the way they describe vulnerability data. Generally, mapping vulnerabilities to ATT&CK techniques (identifying exploit method and impacts) requires consideration of one or more of the following:

- **Common Vulnerability Types** - vulnerabilities based on the same weakness (e.g., CWE-79: cross-site scripting) will often have the same ATT&CK mapping. The [Common Vulnerability Types](#common-vulnerability-types) section includes a list of common vulnerability types and their associated VEIDs.
- **Affected Object Types** - Vulnerabilities with the same underlying weakness can often be exploited in a variety of ways. However, details of the vulnerability can lead to identification of a specific exploit method. The [Affected Object Types](#affected-object-types) section includes a list of exploit method mappings based on the type of object (software, hardware, firmware, product, application, or code) that has the vulnerability. 
- **Vulnerability Objectives** - While many vulnerabilities can be mapped to ATT&CK by considering common vulnerability types, many more vulnerabilities require a custom mapping. In these cases, keywords in the vulnerability's description relating to adversary objectives can be used to identify the ATT&CK techniques associated with its exploit method and impact components. Details are given in the [Vulnerability Objectives](#vulnerability-objectives) section.

Example mappings, [Methodology Notes](#methodology-notes) and [References](#references) are included below. 

### Common Vulnerability Types

Vulnerabilities of the same type will often have the same or similar technique mappings. **Table 1** lists the most common vulnerability types (in order) based on the "2023 CWE Top 25 Most Dangerous Software Weaknesses" list [[1]](#1). Upward movers (showing upward trend in ranking) are shown in **bold face** font. A few higher-level CWE classes/categories, taken from [CWE-699 (Software Development)](https://cwe.mitre.org/data/definitions/699.html) and [CWE-1000 (Research Concepts)](https://cwe.mitre.org/data/definitions/1000.html), are included at the bottom of the table. Exploit methods and secondary impacts unlikely to be identified are marked "N/A." 

To map a vulnerability using its CWE information:

1. Identify the CWE associated with the vulnerability and **review the corresponding row of Table 1** to determine whether the given mapping applies. If options are listed for a component, read the notes in the table and the technique descriptions on the ATT&CK website to select the most appropriate. In some cases, the reader will be directed to identify the exploit method using the [Affected Object Types](#affected-object-types) section and impacts using the [Vulnerability Objectives](#vulnerability-objectives) section.
2. If the CWE is not listed in Table 1, or if the mapping in Table 1 is not appropriate, **refer to the CWE definition** ([[5]](#5) ID Lookup) for pointers to applicable ATT&CK mappings. Specifically, the CWE "Common Consequences" section can suggest likely impacts. For example, the common consequences given for CWE-190: Integer Overflow are "DOS," "Modify Memory," and "Execute Unauthorized Code." While the "Modify Memory" consequence is directly associated with exploiting the overflow, "DOS" and "Execute Unauthorized Code" suggest the impact mappings T1499 and T1574 that are given in Table 1.
3. If a vulnerability is not explicitly associated with a CWE, or if its associated CWE information does not provide a complete mapping, **map the vulnerability using keywords** from the vulnerability description (see [Vulnerability Objectives](#vulnerability-objectives)). Objective-based mapping should also be used when the vulnerability's details suggest that additional ATT&CK techniques apply. 

**Table 1. Common Vulnerability Types** *XXX Still adding mappings to table... The CWE Top 25 info (cwe.mitre.org/top25/index.html) says that in the coming months there will be an "Actively Exploited" list (ranking of weaknesses by CISA's KEV Catalog) - will want to cover that list... XXX*

| Associated CWE | Exploitation Method | Primary Impact | Secondary Impact | Notes |
| ---- | ---- | ---- | ---- | ------- |
| **CWE-787**: [Out-of-bounds Write](https://cwe.mitre.org/data/definitions/787.html) | see [Affected Object Types](#affected-object-types) | [T1574](https://attack.mitre.org/techniques/T1574) (Hijack Execution Flow) | [T1499.004](https://attack.mitre.org/techniques/T1499/004) (Endpoint Denial of Service: Application or System Exploitation); see [Vulnerability Objectives](#vulnerability-objectives) | A buffer overflow is an example of this vulnerability type. This mapping also applies to [CWE-119](https://cwe.mitre.org/data/definitions/119.html), which is a CWE class and parent of CWE-787. |
| CWE-79: [Cross-site Scripting](https://cwe.mitre.org/data/definitions/79.html) | [T1189](https://attack.mitre.org/techniques/T1189/) (Drive-by Compromise); [T1204.001](https://attack.mitre.org/techniques/T1204/001/) (User Execution: Malicious Link)| [T1059.007](https://attack.mitre.org/techniques/T1059/007) (Command and Scripting Interpreter: JavaScript) | [T1557](https://attack.mitre.org/techniques/T1557) (Adversary-in-the-Middle); see [Vulnerability Objectives](#vulnerability-objectives)  | The choice of exploitation method depends on whether the vulnerability is stored (T1189) or whether the victim must click on a malicious link (T1204.001).|
| **CWE-89**: [SQL Injection](https://cwe.mitre.org/data/definitions/89.html) | N/A | [T1059](https://attack.mitre.org/techniques/T1059) (Command and Scripting Interpreter) | [T1005](https://attack.mitre.org/techniques/T1005) (Data from Local System); [T1505.003](https://attack.mitre.org/techniques/T1505/003) (Server Software Component: Web Shell); [T1136](https://attack.mitre.org/techniques/T1136) (Create Account); [T1190](https://attack.mitre.org/techniques/T1190) (Exploit Public-Facing Application); [T1565.001](https://attack.mitre.org/techniques/T1565/001) (Data Manipulation) |  |
| CWE-416: [Use After Free](https://cwe.mitre.org/data/definitions/416.html) | see [Affected Object Types](#affected-object-types) (*application-related* content) | [T1499](https://attack.mitre.org/techniques/T1499) (Endpoint Denial of Service); [T1005](https://attack.mitre.org/techniques/T1005) (Data from Local System)  | N/A | |
| CWE-78: [OS Command Injection](https://cwe.mitre.org/data/definitions/78.html) | [T1133](https://attack.mitre.org/techniques/T1133) (External Remote Service) | [T1059](https://attack.mitre.org/techniques/T1059) (Command and Scripting Interpreter) | see [Vulnerability Objectives](#vulnerability-objectives) | The primary impact depends on the OS attacked, but is often T1059.004.  |
| CWE-20: [Improper Input Validation](https://cwe.mitre.org/data/definitions/918.html) | see [Affected Object Types](#affected-object-types) (*application-related* content) |  |  |  |
| CWE-125: [Out-of-bounds Read](https://cwe.mitre.org/data/definitions/125.html) | see [Affected Object Types](#affected-object-types) (*application-related* content) | [T1005](https://attack.mitre.org/techniques/T1005) (Data from Local System); [T1499.004](https://attack.mitre.org/techniques/T1499/004) (Endpoint Denial of Service: Application or System Exploitation) | [T1211](https://attack.mitre.org/techniques/T1211) (Exploitation for Defense Evasion); [T1212](https://attack.mitre.org/techniques/T1212) (Exploitation for Credential Access) | |
| CWE-22: [Path Traversal](https://cwe.mitre.org/data/definitions/22.html) | [T1202]() (Indirect Command Execution)  | see [Vulnerability Objectives](#vulnerability-objectives) (*file-related* content) | see [Vulnerability Objectives](#vulnerability-objectives) (*file-related* content) |  This mapping also applies to CWE-36: [Absolute Path Traversal](https://cwe.mitre.org/data/definitions/36.html) and CWE-23 [Relative Path Traversal](https://cwe.mitre.org/data/definitions/23.html). |
| CWE-352: [Cross-Site Request Forgery (CSRF)](https://cwe.mitre.org/data/definitions/352.html) | [T1204.001](https://attack.mitre.org/techniques/T1204/001) (User Execution: Malicious Link) | [T1068](https://attack.mitre.org/techniques/T1068) (Exploitation for Privilege Escalation) | see [Vulnerability Objectives](#vulnerability-objectives) | |
| **CWE-434**: [Unrestricted File Upload](https://cwe.mitre.org/data/definitions/434.html) | N/A | [T1505.003](https://attack.mitre.org/techniques/T1505/003) (Server Software Component: Web Shell); [T1505.004](https://attack.mitre.org/techniques/T1505/004) (Server Software Component: IIS Components); [T1505.005](https://attack.mitre.org/techniques/T1505/005) (Server Software Component: Terminal Services DLL) | [T1059](https://attack.mitre.org/techniques/T1059) (Command and Scripting Interpreter) | |
| **CWE-862**: [Missing Authorization](https://cwe.mitre.org/data/definitions/862.html) |  |  |  |  |
| CWE-476: [NULL Pointer Dereference](https://cwe.mitre.org/data/definitions/476.html) | [T1059](https://attack.mitre.org/techniques/T1059) (Command and Scripting Interpreter) | [T1499](https://attack.mitre.org/techniques/T1499) (Endpoint Denial of Service) | N/A |  |
| CWE-287: [Improper Authentication](https://cwe.mitre.org/data/definitions/287.html) |  |  |  |  |
| CWE-190: [Integer Overflow](https://cwe.mitre.org/data/definitions/190.html) | see [Affected Object Types](#affected-object-types) | [T1499](https://attack.mitre.org/techniques/T1499) (Endpoint Denial of Service); [T1574](https://attack.mitre.org/techniques/T1574) (Hijack Execution Flow) |  |  |
| CWE-502: [Deserialization of Untrusted Data](https://cwe.mitre.org/data/definitions/502.html) |  |  |  |  |
| CWE-77: [Command Injection](https://cwe.mitre.org/data/definitions/77.html) |  |  |  |  |
| CWE-119: [Improper Restriction of Operations within the Bounds of a Memory Buffer](https://cwe.mitre.org/data/definitions/119.html) |  |  |  |  |
| CWE-798: [Use of Hard-coded Credentials](https://cwe.mitre.org/data/definitions/798.html) | N/A | [T1078.001](https://attack.mitre.org/techniques/T1078/001) (Default Accounts) | N/A | |
| **CWE-918**: [Server-Side Request Forgery (SSRF)](https://cwe.mitre.org/data/definitions/918.html) | [T1133](https://attack.mitre.org/techniques/T1133) (External Remote Service) | [T1090](https://attack.mitre.org/techniques/T1090) (Proxy) | [T1135](https://attack.mitre.org/techniques/T1135) (Network Discovery); [T1005](https://attack.mitre.org/techniques/T1005) (Data from Local System) |  |
| CWE-306: [Missing Authentication for Critical Function](https://cwe.mitre.org/data/definitions/306.html) |  |  |  |  |
| CWE-362: [Race Condition](https://cwe.mitre.org/data/definitions/362.html) | [T1059](https://attack.mitre.org/techniques/T1059) (Command and Scripting Interpreter)  | [T1499.004](https://attack.mitre.org/techniques/T1499/004) (Endpoint Denial of Service: Application or System Exploitation) | see [Vulnerability Objectives](#vulnerability-objectives) |  |
| CWE-269: [Improper Privilege Management](https://cwe.mitre.org/data/definitions/269.html) |  | [TA0004](https://attack.mitre.org/tactics/TA0004) (Privilege Escalation)  |  |  |
| CWE-94: [Code Injection](https://cwe.mitre.org/data/definitions/94.html) |  |  |  |  |
| CWE-863: [Incorrect Authorization](https://cwe.mitre.org/data/definitions/863.html) |  |  |  |  |
| CWE-276: [Incorrect Default Permissions](https://cwe.mitre.org/data/definitions/276.html) |  |  |  |  |
| | | | | |
| CWE-284: [Improper Access Control](https://cwe.mitre.org/data/definitions/284.html) | see [Affected Object Types](#affected-object-types) | see [Vulnerability Objectives](#vulnerability-objectives) | see [Vulnerability Objectives](#vulnerability-objectives) | The exploitation and impacts of authentication, authorization, and permissions errors depend on the specific object with improper access control. CWE-285 is a CWE pillar. |
| CWE-285: [Improper Authorization](https://cwe.mitre.org/data/definitions/285.html) |  |  |  | CWE-285 is a CWE class. |
| CWE-255: [Credentials Management Errors](https://cwe.mitre.org/data/definitions/255.html) | see [Affected Object Types](#affected-object-types) | [T1552](https://attack.mitre.org/techniques/T1552) (Unsecured Credentials) | [T1078](https://attack.mitre.org/techniques/T1078) (Valid Accounts) | CWE-255 is a CWE category. |
| CWE-310: [Cryptographic Issues](https://cwe.mitre.org/data/definitions/310.html) | |  |  | CWE-310 is a CWE category. |
| CWE-400: [Uncontrolled Resource Consumption](https://cwe.mitre.org/data/definitions/400.html) | see [Affected Object Types](#affected-object-types) | [T1499](https://attack.mitre.org/techniques/T1499) (Endpoint Denial of Service) | N/A | A T1499 sub-technique may be chosen depending on the resource consumed. CWE-400 is a CWE class. |


#### Examples

The examples below illustrate how common vulnerability types can be used to define VEIDs. *XXX Would it be useful to include the CVSS score for the example CVEs? XXX*

[CVE-2020-6960](https://nvd.nist.gov/vuln/detail/CVE-2020-6960) 

> The following versions of MAXPRO VMS and NVR *--snip--* contain an SQL injection vulnerability that could give an attacker remote unauthenticated access to the web user interface with administrator-level privileges.

CVE-2020-6960 is a SQL injection vulnerability (**CWE-89**). The SQL injection entry in Table 1 contains mappings for the primary and secondary impacts. Ihere is one primary impact, which applies to the vulnerability: [T1059](https://attack.mitre.org/techniques/T1059) (Command and Scripting Interpreter). However, the CVE record does not provide enough information to identify a secondary impact.

[CVE-2018-17900](https://nvd.nist.gov/vuln/detail/CVE-2018-17900)

> Yokogawa STARDOM Controllers FCJ *--snip--* The web application improperly protects credentials which could allow an attacker to obtain credentials for remote access to controllers.

CVE-2018-17900 relates to insecure credential handling (**CWE-255**) and the impact mappings shown in Table 1 are appropriate. The primary impact is [T1552](https://attack.mitre.org/techniques/T1552) (Unsecured Credentials), which enables the secondary impact: [T1078](https://attack.mitre.org/techniques/T1078) (Valid Accounts). This example is continued in the [Affected Object Types](#affected-object-types) section where we show how the exploit method can be identified.

[CVE-2020-11036](https://nvd.nist.gov/vuln/detail/CVE-2020-11036) 

> In GLPI before version 9.4.6 there are multiple related stored XSS vulnerabilities. The package is vulnerable to Stored XSS in the comments of items in the Knowledge base. Adding a comment with content "<script>alert(1)</script>" reproduces the attack. This can be exploited by a user with administrator privileges in the User-Agent field. It can also be exploited by an outside party through the following steps: 1. Create a user with the surname `" onmouseover="alert(document.cookie)` and an empty first name. 2. With this user, create a ticket 3. As an administrator (or other privileged user) open the created ticket 4. On the "last update" field, put your mouse on the name of the user 5. The XSS fires This is fixed in version 9.4.6.

CVE-2020-11036 is a cross-site scripting (XSS) vulnerability (**CWE-79**). For XSS vulnerabilities, there are standard primary and secondary impact mappings (T1059.007 and T1185 respectively).  However, the exploitation method depends on the type of XSS vulnerability. Because CVE-2020-11036 involves a *stored* XSS vulnerability (the attack is stored in the webpage and victims are attacked when visiting), the mapping is [T1189](https://attack.mitre.org/techniques/T1189) (Drive-by Compromise).

[CVE-2020-5210](https://nvd.nist.gov/vuln/detail/CVE-2020-5210) 

> In NetHack before 3.6.5, an invalid argument to the -w command line option can cause a buffer overflow resulting in a crash or remote code execution/privilege escalation. This vulnerability affects systems that have NetHack installed suid/sgid and shared systems that allow users to influence command line options.

CVE-2020-5210 is a buffer overflow (**CWE-787**). Buffer overflows modify memory, which result in [T1574](https://attack.mitre.org/techniques/T1574) (Hijack Execution Flow) as the primary impact and [T1499.004](https://attack.mitre.org/techniques/T1499/004) (Endpoint Denial of Service: Application or System Exploitation) as the secondary impact. A search using "setuid" and "setgid" as keywords (see see [Vulnerability Objectives](#vulnerability-objectives)) indicates [T1548.001](https://attack.mitre.org/techniques/T1548/001) (Abuse Elevation Control Mechanism: Setuid and Setgid) as the exploitation method (Table 1 does not list T1548.001 as an exploitation technique because it is relatively rare). 

### Affected Object Types

As shown in the previous section, some common vulnerability types can be exploited in a variety of ways. In this section, we show how an exploit method can be mapped to an ATT&CK technique based on the type of the object that is affected - software, hardware, firmware, product, application, or code - what CVE refers to as “affected code bases.” Note the following:

- A vulnerability's exploit method technique is not necessarily the same technique that exploits the user/machine. For example, consider the VEID associated with the initial example where it is *Network Sniffing (T1040)* that exploits the vulnerability and *Valid Accounts (T1078)* that exploits the user/machine.
- Some vulnerabilities require no explicit exploitation. For example, hardcoded credentials or default credentials make systems vulnerable without explicit exploitation (off-network discovery of the credentials is not considered an exploitation method).
- Because the context surrounding vulnerabilities varies, the *exploit method* of one vulnerability may map to the same ATT&CK technique as an *impact* of another vulnerability. 
- User actions that do not involve a vulnerability are outside the scope of the methodology. For example, [T1204.002](https://attack.mitre.org/techniques/T1204/002) (User Execution: Malicious File) is only applicable when the file (malware) exploits a vulnerable object.
- Exploitation methods can also be identified using keywords from the vulnerability description. Please see [Vulnerability Objectives](#vulnerability-objectives) for details.

Exploit methods based on affected object type are given below. Where applicable, example impacts are given to illustrate the difference between exploiting the vulnerability and compromising the user/machine. Unless another source is cited, notes are based on ATT&CK technique descriptions. 

**Table 2. Exploit Method Based on Affected Object Type** 

| Affected Object | Exploit Method | Example Impact | Notes |
| ---- | ---- | ---- | ---- |
|**Internet-facing Host/System** (e.g., webserver, website, database, service)| [T1190](https://attack.mitre.org/techniques/T1190) (Exploit Public-Facing Application); [T1211](https://attack.mitre.org/techniques/T1211) (Exploitation for Defense Evasion) |  | Adversaries may attempt to exploit a weakness in an Internet-facing host or system, which may be a software bug, temporary glitch, or misconfiguration. Depending on the flaw being exploited, this may also involve [Exploitation for Defense Evasion](https://attack.mitre.org/techniques/T1211). |
|**Client Application** (e.g., browser, office app) | [T1203](https://attack.mitre.org/techniques/T1203) (Exploitation for Client Execution) | [T1574](https://attack.mitre.org/techniques/T1574) (Hijack Execution Flow) | Adversaries may exploit software vulnerabilities in client applications to execute code. For example, an application that fails to properly handle objects in memory may allow an attacker to run arbitrary code in the context of the current user. |
| | [T1204.001](https://attack.mitre.org/techniques/T1204/001) (User Execution: Malicious Link) | [T1203](https://attack.mitre.org/techniques/T1203) (Exploitation for Client Execution) | A user clicking a link may lead to other execution techniques such as exploitation of a browser or application vulnerability via Exploitation for Client Execution.|
| | [T1204.002](https://attack.mitre.org/techniques/T1204/002) (User Execution: Malicious File) | [T1203](https://attack.mitre.org/techniques/T1203) (Exploitation for Client Execution) | Malware may be written to compromise a vulnerable client application (the malware is executed by a user). |
| | [T1189](https://attack.mitre.org/techniques/T1189) (Drive-by Compromise) |  | Vulnerable web **browsers** are targets of drive-by compromises. |
| **Endpoint Security Solution** (e.g., host-based firewall, AV software)| [T1204.002](https://attack.mitre.org/techniques/T1204/002) (User Execution: Malicious File); [T1204.001](https://attack.mitre.org/techniques/T1204/001) (User Execution: Malicious Link); [T1566.001](https://attack.mitre.org/techniques/T1566/001) (Phishing: Spearphishing Attachment);  [T1566.002](https://attack.mitre.org/techniques/T1566/002) (Phishing: Spearphishing Link);[T1566.003](https://attack.mitre.org/techniques/T1566/003) (Phishing: Spearphishing via Service) | [T1203](https://attack.mitre.org/techniques/T1203) (Exploitation for Client Execution) | Vulnerable endpoint security solutions may enable users to execute malicious files (received as email attachments or via malicious links). |
| **Network-based Application** | [T1040](https://attack.mitre.org/techniques/T1040) (Network Sniffing); [T1059](https://attack.mitre.org/techniques/T1059) (Command and Scripting Interpreter) | [T1574](https://attack.mitre.org/techniques/T1574) (Hijack Execution Flow)| Adversaries may sniff network traffic to capture insecure/unencrypted credentials. Adversaries may also execute commands and compromise an application through an interactive terminal or shell. |
| **Operating System** (e.g., kernel, shell) | [T1574](https://attack.mitre.org/techniques/T1574) (Hijack Execution Flow) | [T1499.004](https://attack.mitre.org/techniques/T1499/004) (Endpoint Denial of Service: Application or System Exploitation) | Vulnerabilities in the kernel, such as a race condition, can be exploited to elevate privilege or crash the system (DoS). |
| | [T1091](https://attack.mitre.org/techniques/T1091) (Replication Through Removeable Media) |  | An operating system vulnerability may allow code execution from removeable media (even without Autorun enabled). |
| **Internal Remote Service** (e.g,. smb, netlogon, print spooler) | [T1210](https://attack.mitre.org/techniques/T1210) (Exploitation of Remote Services) | [TA0008](https://attack.mitre.org/tactics/TA0008) (Lateral Movement); [T1068](https://attack.mitre.org/techniques/T1068) (Exploitation for Privilege Escalation) | Once inside a network, adversaries may exploit remote services to gain unauthorized access to other internal systems. |
| **External Remote Service** (e.g., vpn, service, software) | [T1078](https://attack.mitre.org/techniques/T1078) (Valid Accounts); [T1133](https://attack.mitre.org/techniques/T1133) (External Remote Service) | | Adversaries may leverage external-facing remote services to initially access and/or persist within a network. |

 
#### Example

[**CVE-2018-17900**](http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-17900)

> Yokogawa STARDOM Controllers FCJ, *--snip--* The web application improperly protects credentials which could allow an attacker to obtain credentials for remote access to controllers.

We considered this vulnerability that relates to insecure credential handling (**CWE-255**) in the previous section. We were able to identify ATT&CK mappings for the primary and secondary impacts ([T1552](https://attack.mitre.org/techniques/T1552) (Unsecured Credentials) and [T1078](https://attack.mitre.org/techniques/T1078) (Valid Accounts), respectively), but a mapping for the exploit method could not be specified because too many options were associated with the common vulnerability type. The affected object is a *web application* and as shown in Table 2, its associated exploit method maps to [T1190](https://attack.mitre.org/techniques/T1190) (Exploit Public-Facing Application). The VEID for CVE-2018-17900 is now complete:

![/cve-2018-17900-mapping-example.png](/cve-2018-17900-mapping-example.png)

Note that the description of CVE-2018-17900 could be now re-written using the ATT&CK framework:

> Yokogawa STARDOM Controllers FCJ *--snip--* have Unsecured Credentials which could allow an attacker to Exploit the Public-Facing Application to obtain unsecured credentials and gain access to Valid Accounts.


### Vulnerability Objectives

A vulnerability description, which describes or implies the potential *objectives* of an attacker, can provide input for identifying ATT&CK techniques and sub-techniques appropriate to a VEID. Someone who knows ATT&CK well may only need to confirm the appropriateness of their mapping choice. Others can identify appropriate techniques via search on the associated keywords:

- **ATT&CK Search** - ATT&CK's search capability can find exact text sequences. The [ATT&CK Powered Suit](https://mitre-engenuity.org/cybersecurity/center-for-threat-informed-defense/attack-powered-suit/) browser extension enables quick searches for ATT&CK content without disrupting workflow.
- **Internet Search Engine** - Search engines will find options that include multiple keywords. For example, **XXX need example showing advantage of internet search over ATT&CK search XXX**
- **Chatbot** - A chatbot can help identify and highlight differences between mapping options (output must be carefully validated).

As the VEID for CVE-2020-5210 shows (see example above), a vulnerability that is generally "common" may involve "uncommon" aspects, in which case keywords relating to the adversary's objectives can be used to identify additional techniques. In the case of CVE-2020-5210, searching for *MITRE ATT&CK suid sgid* on the Internet returns the technique [T1548.001](https://attack.mitre.org/techniques/T1548/001) (Abuse Elevation Control Mechanism: Setuid and Setguid), which provides the mapping for the exploit method. 

**Table 3** lists adversary objectives commonly associated with vulnerabilities, along with impact mappings. The objectives were used as the input of an Internet search to identify the mappings. 

Cases where numerous secondary impacts are possible are marked "*many*" and cases where a secondary impact is unlikely are marked "N/A." The techniques given are those most likely to apply to vulnerabilities but in general, the entries are not exhaustive (especially for secondary impacts). Note that keywords taken from a description can also be used to identify appropriate mappings for exploit methods (exploit methods are not included in Table 3 because they are context-dependent, relative to impacts; see [Common Vulnerability Types](#common-vulnerability-types) for VEIDs that contain all three components).

**Table 3. Impact Mappings for Common Objectives**

| Adversary Objective | Primary Impact | Secondary Impact |
| ---- | ---- | ------ |
| create account | [T1136](https://attack.mitre.org/techniques/T1136) (Create Account) | [T1078](https://attack.mitre.org/techniques/T1078) (Valid Accounts)  |
| disable protections | [T1562](https://attack.mitre.org/techniques/T1562) (Impair Defenses) | *many* | 
| reboot system | [T1529](https://attack.mitre.org/techniques/T1529) (System Shutdown/Reboot) | N/A |
| install application | [T1203](https://attack.mitre.org/techniques/T1203) (Exploitation for Client Execution); [T1218]() (Signed Binary Proxy Execution) | *many* |
| modify configuration | [T1222](https://attack.mitre.org/techniques/T1222) (File and Directory Permissions Modification); [T1112](https://attack.mitre.org/techniques/T1112) (Modify Registry); [T1601](https://attack.mitre.org/techniques/T1601) (Modify System Image); [Mobile-T1632](https://attack.mitre.org/techniques/T1632) (Subvert Trust Controls); [T1556](https://attack.mitre.org/techniques/T1556) (Modify Authentication Process) | *many* |
| change permissions |  [T1222](https://attack.mitre.org/techniques/T1222) (File and Directory Permissions Modification) | *many* |
| password reset | [T1098](https://attack.mitre.org/techniques/T1098) (Account Manipulation) | *many* |
| read files | [T1005](https://attack.mitre.org/techniques/T1005) (Data from Local System) | [T1003.008](https://attack.mitre.org/techniques/T1003/008) (OS Credential Dumping: /etc/passwd and /etc/shadow); [T1552.001](https://attack.mitre.org/techniques/T1552/001) (Unsecured Credentials: Credentials in Files) |
| delete files | [T1485](https://attack.mitre.org/techniques/T1485) (Data Destruction) | [T1499.004](https://attack.mitre.org/techniques/T1499/004) (Endpoint Denial of Service: Application or System Exploitation) |
| exfiltration | [T1005](https://attack.mitre.org/techniques/T1005) (Data from Local System) | [TA0010](https://attack.mitre.org/tactics/TA0010) (Exfiltration) |
|create/upload file | [T1505.003](https://attack.mitre.org/techniques/T1505/003) (Server Software Component: Web Shell) | [T1059](https://attack.mitre.org/techniques/T1059) (Command and Scripting Interpreter) |
| write to file | [T1565.001](https://attack.mitre.org/techniques/T1565/001) (Data Manipulation) | [T1059](https://attack.mitre.org/techniques/T1059) (Command and Scripting Interpreter); [T1574](https://attack.mitre.org/techniques/T1574) (Hijack Execution Flow); [T1554](https://attack.mitre.org/techniques/T1554) (Compromise Client Software Binary) |
| obtain credentials | [T1552](https://attack.mitre.org/techniques/T1552) (Unsecured Credentials); [T1556](https://attack.mitre.org/techniques/T1556) (Modify Authentication Process); [T1649](https://attack.mitre.org/techniques/T1649) (Steal or Forge Authentication Certificates) | *many* |
| obtain data | [T1005](https://attack.mitre.org/techniques/T1005) (Data from Local System) | *many* |


For some vulnerabilities, there may be no reasonable choice of ATT&CK technique to which a primary and/or secondary impact can be mapped. However, it may be possible to use a higher-level [ATT&CK tactic](#higher-level-tactics) or a [generic exploitation technique](#generic-exploitation-techniques) (e.g., "exfiltration" above).

#### Higher-level Tactics

An [ATT&CK tactic](https://attack.mitre.org/tactics/enterprise) represents the "why" of an ATT&CK technique or sub-technique and serve as useful contextual categories for individual techniques [[4]](#4). For example, an adversary may take one action to achieve [Credential Access](https://attack.mitre.org/tactics/TA0006) and another action to achieve [Privilege Escalation](https://attack.mitre.org/tactics/TA0004).

When a technique can not be identified for an impact (or at least not immediately), it may suffice to identify a tactic, often an easier task because ATT&CK defines just fourteen tactics. In fact, some may find it easiest to *always* identify tactics before looking for lower level techniques. 

#### Generic Exploitation Techniques

Five ATT&CK tactics contain generic "exploitation" techniques, which can be used to map both exploit methods and impacts when it's not possible to identify more specific ATT&CK techniques. 

| Tactic | Generic Exploitation Technique |
| ---- | ---- |
| [TA0002](https://attack.mitre.org/tactics/TA0002) Execution | [T1203](https://attack.mitre.org/techniques/T1203) (Exploitation for Client Execution) |
| [TA0004](https://attack.mitre.org/tactics/TA0004) Privilege Escalation | [T1068](https://attack.mitre.org/techniques/T1068) (Exploitation for Privilege Escalation) |
| [TA0005](https://attack.mitre.org/tactics/TA0005) Defense Evasion | [T1211](https://attack.mitre.org/techniques/T1211) (Exploitation for Defense Evasion) |
| [TA0006](https://attack.mitre.org/tactics/TA0006) Credential Access | [T1212](https://attack.mitre.org/techniques/T1212) (Exploitation for Credential Access) |
| [TA0008](https://attack.mitre.org/tactics/TA0008) Lateral Movement | [T1210](https://attack.mitre.org/techniques/T1210) (Exploitation of Remote Services) |


## Methodology Notes

In this section, we summarize points made above. (*need to add all after draft complete*)

* Using ATT&CK should not require any more or less information than normally provided in a vulnerability record. Using ATT&CK enables you to *standardize* how you describe vulnerability information so that readers can leverage the resources built on top of ATT&CK.
* The methodology focuses on Enterprise ATT&CK, but content from Mobile and ICS ATT&CK is included as needed. These techniques are identified with "Mobile-" and "ICS-" prefixes.
* Technique mappings are only included for a vulnerability type when it is likely that different vulnerabilities in the group share that technique.  For example, vulnerabilities that modify memory (e.g., buffer overflow) share a primary impact, but the secondary impacts and exploitation techniques are so varied that the methodology refers the user to standard exploit methods and objective-based mapping. 
* Some vulnerabilities require no explicit exploitation (i.e., their VEID has no exploit method).
* Some groupings will have more than one technique listed for a mapping category because there are common variations within that grouping.  In these cases, select only the techniques that apply to the vulnerability.  For example, the cross-site scripting (XSS) vulnerability type includes an option of [T1189](https://attack.mitre.org/techniques/T1189) (Drive-by Compromise) or [T1204.001](https://attack.mitre.org/techniques/T1204/001) (User Execution: Malicious Link) depending on whether the attacked is stored or not.

## Examples - Using All Three Approaches

*XXX would it be useful to have a few examples that use one or more approaches? There is one example in the "Affected Object Types" section, but more might be helpful. e.g., using only objectives and searches, using all three approaches, etc. XXX*

## References

<a name="1">[1]</a> https://cwe.mitre.org/top25/archive/2023/2023_top25_list.html

<a name="2">[2]</a> ATT&CK Design and Philosophy paper.

<a name="3">[3]</a> https://www.thestack.technology/analysis-of-cves-in-2022-software-vulnerabilities-cwes-most-dangerous/ (see the *Top 25 most dangerous CWE codes as reflected in CVEs 2018-2022* graphic).

<a name="4">[4]</a> ATT&CK v13.1.

<a name="5">[5]</a> CWE Definitions, https://cwe.mitre.org/data
