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

Using these three components, a **Vulnerability Exploit-Impact Description (VEID)** can be developed (**XXX is it useful to define/use an acronyn??XXX**):

> The vulnerability allows the attacker to use **[EXPLOITATION METHOD]** to gain **[Primary Impact]**, which leads to **[Secondary Impact]**.

![/new-cve-to-attack-sentence.png](/new-cve-to-attack-sentence.png)

Given a vulnerability, it may not be possible to identify an ATT&CK technique for each VEID component because ATT&CK's level of abstraction may not match that of the vulnerability. Also, ATT&CK defines techniques used in *real-world* attacks and does not include theoretical techniques. However, as shown in the examples below, a VEID with just one or two components is still useful.

##	Mapping Methodology

This methodology establishes a starting point for vulnerability reporters and researchers to standardize the way they describe vulnerability data. Generally, mapping vulnerabilities to ATT&CK techniques (identifying exploit method and impacts) involves one or more of the following activities:

- **Consider Common Vulnerability Types** - vulnerabilities based on the same weakness (e.g., CWE-79: cross-site scripting) will often have the same ATT&CK mapping. The [Common Vulnerability Types](#common-vulnerability-types) section includes a list of common vulnerability types and their associated VEIDs. 
- **Identify Exploit Method** - Vulnerabilities of the same type can often be exploited in different ways. However, details of the vulnerability can lead to identification of a specific exploit method. The [Exploit Methods](#exploit-methods) section includes a list of mappings based the type of vulnerable object and the attack entry point. 
- **Identify Techniques Using Objective-oriented Keywords ** - While many vulnerabilities can be mapped to ATT&CK using the common vulnerability types table, many more vulnerabilities require a custom mapping. In these cases, keywords in the vulnerability's description relating to adversary objectives can be used to identify the ATT&CK techniques associated with its exploit method and impact components. Details are given in the [Objective-based Mapping](#objective-based-mapping) section.

Example mappings, [Methodology Notes](#methodology-notes) and [References](#references) are included below. 

### Common Vulnerability Types

Vulnerabilities of the same type will often have the same or similar technique mappings. **Table 1** lists the most common vulnerability types based on CWE, which are taken from [[1]](#1) (see the *Top 25 most dangerous CWE codes as reflected in CVEs 2018-2022* graphic), as well as the best-known types in the [CWE-699 (Software Development)](https://cwe.mitre.org/data/definitions/699.html) and [CWE-1000 (Research Concepts)](https://cwe.mitre.org/data/definitions/1000.html) views. 

To map a vulnerability using **Table 1**, identify the CWE associated with the vulnerability and review the corresponding row to determine whether the mapping applies. If options are listed for a component, read the notes in the table and the technique descriptions on the ATT&CK website to select the most appropriate. In some cases, the reader will be directed to identify the exploit method using the [Exploit Methods](#exploit-methods) section and impacts using the [Objective-based Mapping](#objective-based-mapping) section.

If a vulnerability is not explicitly associated with a CWE, or if its associated CWE is not listed in Table 1, it should be mapped using keywords (see [Objective-based Mapping](#objective-based-mapping)). Objective-based mapping should also be used in the cases where vulnerability details suggest other or additional ATT&CK techniques may apply. Vulnerability types for which a specific secondary impact is unlikely to be identified are marked "N/A."


**Table 1. Common Vulnerability Types** XXX Currently in the process of adding updated mappings to table. Upper table will contain the Top 25, lower part will be higher-level categories (CWE catagories/views vs CWE entries)... XXX

| Associated CWE | Exploitation Method | Primary Impact | Secondary Impact | Notes |
| ---- | ---- | ---- | ---- | ------- |
| CWE-79: [Cross-site Scripting](https://cwe.mitre.org/data/definitions/79.html) | [T1189](https://attack.mitre.org/techniques/T1189/) (Drive-by Compromise); [T1204.001](https://attack.mitre.org/techniques/T1204/001/) (User Execution: Malicious Link)| [T1059.007](https://attack.mitre.org/techniques/T1059/007) (Command and Scripting Interpreter: JavaScript) | [T1557](https://attack.mitre.org/techniques/T1557) (Adversary-in-the-Middle); see [Objective-based Mapping](#objective-based-mapping)  | The choice of exploitation method depends on whether the vulnerability is stored (T1189) or whether the victim must click on a malicious link (T1204.001).|
| CWE-787: [Out-of-bounds Write](https://cwe.mitre.org/data/definitions/787.html) (child of [CWE-119](https://cwe.mitre.org/data/definitions/119.html)) | see [Exploit Methods](#exploit-methods) | [T1574](https://attack.mitre.org/techniques/T1574) (Hijack Execution Flow) | [T1499.004](https://attack.mitre.org/techniques/T1499/004) (Endpoint Denial of Service: Application or System Exploitation); see [Objective-based Mapping](#objective-based-mapping) | A buffer overflow is an example of this vulnerability type. |
| CWE-125: [Out-of-bounds Read](https://cwe.mitre.org/data/definitions/125.html) | see [Exploit Methods](#exploit-methods) (*application-related* content) | [T1005](https://attack.mitre.org/techniques/T1005) (Data from Local System); [T1499.004](https://attack.mitre.org/techniques/T1499/004) (Endpoint Denial of Service: Application or System Exploitation) | [T1211](https://attack.mitre.org/techniques/T1211) (Exploitation for Defense Evasion); [T1212](https://attack.mitre.org/techniques/T1212) (Exploitation for Credential Access) | |
| CWE-416: [Use After Free](https://cwe.mitre.org/data/definitions/416.html) | see [Exploit Methods](#exploit-methods) (*application-related* content) | [T1499](https://attack.mitre.org/techniques/T1499) (Endpoint Denial of Service); [T1005](https://attack.mitre.org/techniques/T1005) (Data from Local System)  | N/A | |
| CWE-89: [SQL Injection](https://cwe.mitre.org/data/definitions/89.html) | N/A | [T1059](https://attack.mitre.org/techniques/T1059) (Command and Scripting Interpreter) | [T1005](https://attack.mitre.org/techniques/T1005) (Data from Local System); [T1505.003](https://attack.mitre.org/techniques/T1505/003) (Server Software Component: Web Shell); [T1136](https://attack.mitre.org/techniques/T1136) (Create Account); [T1190](https://attack.mitre.org/techniques/T1190) (Exploit Public-Facing Application); [T1565.001](https://attack.mitre.org/techniques/T1565/001) (Data Manipulation) |  |
| CWE-352: [Cross-Site Request Forgery (CSRF)](https://cwe.mitre.org/data/definitions/352.html) | [T1204.001](https://attack.mitre.org/techniques/T1204/001) (User Execution: Malicious Link) | [T1068](https://attack.mitre.org/techniques/T1068) (Exploitation for Privilege Escalation) | see [Objective-based Mapping](#objective-based-mapping) | |
| CWE-22: [Path Traversal](https://cwe.mitre.org/data/definitions/22.html) | [T1202]() (Indirect Command Execution)  | see [Objective-based Mapping](#objective-based-mapping) (*file-related* content) | see [Objective-based Mapping](#objective-based-mapping) (*file-related* content) |  This mapping also applies to CWE-36: [Absolute Path Traversal](https://cwe.mitre.org/data/definitions/36.html) and CWE-23 [Relative Path Traversal](https://cwe.mitre.org/data/definitions/23.html) |
| CWE-20: [Improper Input Validation](https://cwe.mitre.org/data/definitions/918.html) | see [Exploit Methods](#exploit-methods) (*application-related* content) |  |  |  |
| CWE-918: [Server-Side Request Forgery (SSRF)](https://cwe.mitre.org/data/definitions/918.html) | [T1133](https://attack.mitre.org/techniques/T1133) (External Remote Service) | [T1090](https://attack.mitre.org/techniques/T1090) (Proxy) | [T1135](https://attack.mitre.org/techniques/T1135) (Network Discovery); [T1005](https://attack.mitre.org/techniques/T1005) (Data from Local System) |  |
| CWE-798: [Use of Hard-coded Credentials](https://cwe.mitre.org/data/definitions/798.html) | N/A | [T1078.001](https://attack.mitre.org/techniques/T1078/001) (Default Accounts) | N/A | |
| CWE-434: [Unrestricted File Upload](https://cwe.mitre.org/data/definitions/434.html) | N/A | [T1505.003](https://attack.mitre.org/techniques/T1505/003) (Server Software Component: Web Shell); [T1505.004](https://attack.mitre.org/techniques/T1505/004) (Server Software Component: IIS Components); [T1505.005](https://attack.mitre.org/techniques/T1505/005) (Server Software Component: Terminal Services DLL) | [T1059](https://attack.mitre.org/techniques/T1059) (Command and Scripting Interpreter) | |
| CWE-78: [OS Command Injection](https://cwe.mitre.org/data/definitions/78.html) | [T1133](https://attack.mitre.org/techniques/T1133) (External Remote Service) | [T1059](https://attack.mitre.org/techniques/T1059) (Command and Scripting Interpreter) | see [Objective-based Mapping](#objective-based-mapping) | The primary impact depends on the OS attacked, but is often T1059.004.  |
| CWE-400: [Uncontrolled Resource Consumption](https://cwe.mitre.org/data/definitions/400.html) | see [Exploit Methods](#exploit-methods) | [T1499](https://attack.mitre.org/techniques/T1499) (Endpoint Denial of Service) | N/A | A T1499 sub-technique may be chosen depending on the resource consumed. |
| CWE-611: [Improper Restriction of XML External Entity (XXE) Reference](https://cwe.mitre.org/data/definitions/611.html) | see [Exploit Methods](#exploit-methods) | [T1059](https://attack.mitre.org/techniques/T1059) (Command and Scripting Interpreter) | [T1005](https://attack.mitre.org/techniques/T1005) (Data from Local System); [T1046](https://attack.mitre.org/techniques/T1046) (Network Service Scanning) | |
| | | | | |
| CWE-285: [Improper Access Control](https://cwe.mitre.org/data/definitions/285.html) | see [Exploit Methods](#exploit-methods) | see [Objective-based Mapping](#objective-based-mapping) | see [Objective-based Mapping](#objective-based-mapping) | The exploitation and impacts of authentication, authorization, and permissions errors depend on the specific object with improper access control. |
| CWE-255*: [Credentials Management Errors](https://cwe.mitre.org/data/definitions/255.html) | see [Exploit Methods](#exploit-methods) | [T1552](https://attack.mitre.org/techniques/T1552) (Unsecured Credentials) | [T1078](https://attack.mitre.org/techniques/T1078) (Valid Accounts) | *CWE category |


#### Examples

The examples below illustrate how the common vulnerability types can be used to define VEIDs.

[CVE-2020-6960](https://nvd.nist.gov/vuln/detail/CVE-2020-6960) 

> The following versions of MAXPRO VMS and NVR *--snip--* contain an SQL injection vulnerability that could give an attacker remote unauthenticated access to the web user interface with administrator-level privileges.

CVE-2020-6960 is a SQL injection vulnerability (CWE-89). The SQL injection entry in Table 1 contains mappings for the primary and secondary impacts. Ihere is one primary impact, which applies to the vulnerability: [T1059](https://attack.mitre.org/techniques/T1059) (Command and Scripting Interpreter). However, the CVE record does not provide enough information to identify a secondary impact.

[CVE-2018-17900](https://nvd.nist.gov/vuln/detail/CVE-2018-17900)

> Yokogawa STARDOM Controllers FCJ *--snip--* The web application improperly protects credentials which could allow an attacker to obtain credentials for remote access to controllers.

CVE-2018-17900 relates to insecure credential handling (CWE-255) and the impact mappings shown in Table 1 are appropriate. The primary impact is [T1552](https://attack.mitre.org/techniques/T1552) (Unsecured Credentials), which enables the secondary impact: [T1078](https://attack.mitre.org/techniques/T1078) (Valid Accounts). This example is continued in the [Exploit Methods](#exploit-methods) section where we show how the exploit method can be identified.

[CVE-2020-11036](https://nvd.nist.gov/vuln/detail/CVE-2020-11036) 

> In GLPI before version 9.4.6 there are multiple related stored XSS vulnerabilities. The package is vulnerable to Stored XSS in the comments of items in the Knowledge base. Adding a comment with content "<script>alert(1)</script>" reproduces the attack. This can be exploited by a user with administrator privileges in the User-Agent field. It can also be exploited by an outside party through the following steps: 1. Create a user with the surname `" onmouseover="alert(document.cookie)` and an empty first name. 2. With this user, create a ticket 3. As an administrator (or other privileged user) open the created ticket 4. On the "last update" field, put your mouse on the name of the user 5. The XSS fires This is fixed in version 9.4.6.

CVE-2020-11036 is a cross-site scripting (XSS) vulnerability (CWE-79). For XSS vulnerabilities, there are standard primary and secondary impact mappings (T1059.007 and T1185 respectively).  However, the exploitation method depends on the type of XSS vulnerability. Because CVE-2020-11036 involves a *stored* XSS vulnerability (the attack is stored in the webpage and victims are attacked when visiting), the mapping is [T1189](https://attack.mitre.org/techniques/T1189) (Drive-by Compromise).

[CVE-2020-5210](https://nvd.nist.gov/vuln/detail/CVE-2020-5210) 

> In NetHack before 3.6.5, an invalid argument to the -w command line option can cause a buffer overflow resulting in a crash or remote code execution/privilege escalation. This vulnerability affects systems that have NetHack installed suid/sgid and shared systems that allow users to influence command line options.

CVE-2020-5210 is a buffer overflow (CWE-787). Buffer overflows modify memory, which result in [T1574](https://attack.mitre.org/techniques/T1574) (Hijack Execution Flow) as the primary impact and [T1499.004](https://attack.mitre.org/techniques/T1499/004) (Endpoint Denial of Service: Application or System Exploitation) as the secondary impact. A search using "setuid" and "setgid" as keywords (see see [Objective-based Mapping](#objective-based-mapping)) indicates [T1548.001](https://attack.mitre.org/techniques/T1548/001) (Abuse Elevation Control Mechanism: Setuid and Setgid) as the exploitation method (Table 1 does not list T1548.001 as an exploitation technique because it is relatively rare). 

### Exploit Methods

As shown in the previous section, some common vulnerability types can be exploited in many different ways. In this section, we show how it may be possible to map an exploit method of a vulnerability to an ATT&CK technique based on the associated vulnerable object (e.g., browser) and entry point of the potential compromise (e.g., user action). First, note the following:

* A vulnerability's exploit method technique is not necessarily the same technique that exploits the user/machine. For example, consider the VEID associated with the initial example where it is Network Sniffing (T1040) that exploits the vulnerability and Valid Accounts (T1078) that exploits the user/machine.
* Some vulnerabilities require no explicit exploitation. For example, hardcoded credentials or default credentials make systems vulnerable without explicit exploitation (i.e., off-network discovery of the credentials is not considered exploitation).
* Because the context surrounding vulnerabilities varies, the *exploit method* of one vulnerability may map to the same ATT&CK technique as an *impact* of another vulnerability. 
* Exploitation methods can also be identified using keywords. Please see [Objective-based Mapping](#objective-based-mapping) for details.

Exploit methods based on vulnerable object and entry point are given below. Example impacts (not the only option) are also listed to illustrate the difference between exploiting a vulnerability and compromising a user/machine.

**Table 2. Derived Exploit Methods** -- **DRAFT - NEEDS DISCUSSION/REVIEW**

| Vulnerable Object | Entry Point | Exploit Method | Example Impact |
| ---- | ---- | ---- | ---- |
|internet-facing host/system (webserver, website, database, service)| internet | [T1190](https://attack.mitre.org/techniques/T1190) (Exploit Public-Facing Application) | [T1211](https://attack.mitre.org/techniques/T1211) (Exploitation for Defense Evasion) |
| network-based application | network, commandline |  [T1140](https://attack.mitre.org/techniques/T1140) (Network Sniffing); [T1059](https://attack.mitre.org/techniques/T1059) (Command and Scripting Interpreter) | [T1574](https://attack.mitre.org/techniques/T1574) (Hijack Execution Flow)|
|client application (browser, office app) | remote system | [T1203](https://attack.mitre.org/techniques/T1203) (Exploitation for Client Execution) | [T1574](https://attack.mitre.org/techniques/T1574) (Hijack Execution Flow) |
|browser|user action:visit website|[T1189](https://attack.mitre.org/techniques/T1189) (Drive-by Compromise)|  |
|external remote service (vpn, service, software) | external remote service | [T1133](https://attack.mitre.org/techniques/T1133) (External Remote Service) | |
|internal remote service (smb, netlogon, print spooler) | internal remote service | [T1210](https://attack.mitre.org/techniques/T1210) (Exploitation of Remote Services) | |
|endpoint security solution; mail server| user action:execute file (email/non-enterprise service) |[T1204.002](https://attack.mitre.org/techniques/T1204/002) (User Execution: Malicious File) | |
|endpoint security solution; mail server| user action:click link (email/non-enterprise service)|T1204.001 (User Execution: Malicious Link) | |
|endpoint security solution| user action:click link (non-enterprise service)| [T1566.003](https://attack.mitre.org/techniques/T1566/003) (Phishing: Spearphishing via Service) | |
|endpoint security solution; mail server | user action:execute file | T1566.001 (Phishing: Spearphishing Attachment) | |
|os; firmware | user action:insert media | [T1091](https://attack.mitre.org/techniques/T1091) (Replication Through Removeable Media) | |
|os |network | [T1574](https://attack.mitre.org/techniques/T1574) (Hijack Execution Flow) | |
 

#### Example

[**CVE-2018-17900**](http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-17900)

> Yokogawa STARDOM Controllers FCJ, *--snip--* The web application improperly protects credentials which could allow an attacker to obtain credentials for remote access to controllers.

**XXX This example appears above also - need to edit both so they work together XXX**

To find the VEID, start by identifying the vulnerability type. For CVE-2018-17900, the vulnerability is a credential management issue.  Looking through the list of vulnerability types in the methodology, the "General Credential Management Errors" vulnerability type appears to be the most appropriate.  Using one of the lower-level credential management vulnerability types is preferable but the CVE record does not provide the level of detail needed to do so.  

The ”General Credential Management Errors” vulnerability type maps to [T1552](https://attack.mitre.org/techniques/T1552) (Unsecured Credentials) for the primary impact and [T1078](https://attack.mitre.org/techniques/T1078) (Valid Accounts) for the secondary impact.  These mappings follow the description in the CVE record.  “improperly protects credentials which could allow an attacker to obtain credentials” matches T1552 and “for remote access to controllers” matches T1078.

The ”General Credential Management Errors” vulnerability type does not have a mapping for the exploitation technique because there are too many ways general credential management vulnerabilities can be exploited.  To find the exploitation technique for CVE-2018-17900, use the Exploit Technique section.  The Exploit Technique section documents a set of scenarios to help the user determine which exploitation technique(s) are appropriate for the vulnerability.  For CVE-2018-17900, the entry point is the web application so the “Attacker exploits remote system application” scenario applies, which makes [T1190](https://attack.mitre.org/techniques/T1190) (Exploit Public-Facing Application) the exploitation technique for the vulnerability.

The VEID for CVE-2018-17900 is:

![/cve-2018-17900-mapping-example.png](/cve-2018-17900-mapping-example.png)

Furthermore, its description could be re-written using the ATT&CK framework (compare to the version above):

> Yokogawa STARDOM Controllers FCJ *--snip--* have Unsecured Credentials which could allow an attacker to exploit the public-facing application to obtain unsecured credentials and gain access to Valid Accounts.


### Objective-based Mapping

Keywords from the vulnerability description, which describe or imply the potential objectives of an attacker, can be used to identify ATT&CK techniques and sub-techniques appropriate to a VEID. Someone who knows ATT&CK well may only need to confirm the appropriateness of their mapping choice. Others can identify appropriate techniques via search:

- **ATT&CK Search** - ATT&CK's search capability can find exact text sequences. The [ATT&CK Powered Suit](https://mitre-engenuity.org/cybersecurity/center-for-threat-informed-defense/attack-powered-suit/) browser extension enables quick searches for ATT&CK content without disrupting workflow.
- **Internet Search Engine** - Search engines will find options that include multiple keywords. For example, **XXX need example XXX**

As the VEID for CVE-2020-5210 shows, a vulnerability that is generally "common" may involve "uncommon" details, in which case keywords relating to the adversary's objectives can be used to identify additional techniques. In the case of CVE-2020-5210, searching for *MITRE ATT&CK suid sgid* on the Internet returns the technique [T1548.001](https://attack.mitre.org/techniques/T1548/001) (Abuse Elevation Control Mechanism: Setuid and Setguid). 

Table 3 lists adversary objectives commonly associated with vulnerabilities, along with typical impacts as related to ATT&CK techniques (the objectives serve as keywords). Cases where numerous secondary impacts are possible are marked "*many*" and cases where a secondary impact is unlikely are marked "N/A." The techniques given are those most likely to apply to vulnerabilities but in general, the entries are not exhaustive (especially for secondary impacts). Note that objective-based (keyword-based) mapping can also be used to identify appropriate mappings for exploit methods (exploit methods are not included in Table 3 because they are context-dependent, relative to impacts; see [Common Vulnerability Types](#common-vulnerability-types) for VEIDs that contain all three components).

**Table 3. Common Keyword Mapping**

| Adversary Objective | Primary Impact | Secondary Impact |
| ---- | ---- | ------ |
| create account | [T1136](https://attack.mitre.org/techniques/T1136) (Create Account) | [T1078](https://attack.mitre.org/techniques/T1078) (Valid Accounts)  |
| disable protections | [T1562](https://attack.mitre.org/techniques/T1562) (Impair Defenses) | *many* | 
| reboot system | [T1529](https://attack.mitre.org/techniques/T1529) (System Shutdown/Reboot) | N/A |
| install application | [T1203](https://attack.mitre.org/techniques/T1203) (Exploitation for Client Execution); [T1218]() (Signed Binary Proxy Execution) | *many* |
| modify configuration | [T1222](https://attack.mitre.org/techniques/T1222) (File and Directory Permissions Modification); [T1112](https://attack.mitre.org/techniques/T1112) (Modify Registry); [T1601](https://attack.mitre.org/techniques/T1601) (Modify System Image); [Mobile-T1632](https://attack.mitre.org/techniques/T1632) (Subvert Trust Controls); [T1556](https://attack.mitre.org/techniques/T1556) (Modify Authentication Process) | *many* |
| change permissions |  [T1222](https://attack.mitre.org/techniques/T1222) (File and Directory Permissions Modification) | *many* |
| password reset | [T1098](https://attack.mitre.org/techniques/T1098) (Account Manipulation) | *many* |
| read files | [T1005](https://attack.mitre.org/techniques/T1005) (Data from Local System) | [T1003.008](https://attack.mitre.org/techniques/T1003/008) (OS Credential Dumping: /etc/passwd and /etc/shadow), [T1552.001](https://attack.mitre.org/techniques/T1552/001) (Unsecured Credentials: Credentials in Files) |
| delete files | [T1485](https://attack.mitre.org/techniques/T1485) (Data Destruction) | [T1499.004](https://attack.mitre.org/techniques/T1499/004) (Endpoint Denial of Service: Application or System Exploitation) |
| exfiltration | [T1005](https://attack.mitre.org/techniques/T1005) (Data from Local System) | [TA0010](https://attack.mitre.org/tactics/TA0010) (Exfiltration) |
|create/upload file | [T1505.003](https://attack.mitre.org/techniques/T1505/003) (Server Software Component: Web Shell) | [T1059](https://attack.mitre.org/techniques/T1059) (Command and Scripting Interpreter) |
| write to file | [T1565.001](https://attack.mitre.org/techniques/T1565/001) (Data Manipulation) | [T1059](https://attack.mitre.org/techniques/T1059) (Command and Scripting Interpreter), [T1574](https://attack.mitre.org/techniques/T1574) (Hijack Execution Flow), [T1554](https://attack.mitre.org/techniques/T1554) (Compromise Client Software Binary) |
| obtain credentials | [T1552](https://attack.mitre.org/techniques/T1552) (Unsecured Credentials); [T1556](https://attack.mitre.org/techniques/T1556) (Modify Authentication Process); [T1649](https://attack.mitre.org/techniques/T1649) (Steal or Forge Authentication Certificates) | *many* |
| obtain data | T1005 (Data from Local System) | *many* |

For some vulnerabilities, there may be no reasonable choice of ATT&CK technique to which a primary and/or secondary impact can be mapped. However, it may be possible to use a higher-level [ATT&CK tactic](#higher-level-tactics) or a [generic exploitation technique](#generic-exploitation-techniques) (e.g., "exfiltration" above). In other cases, it may be sufficient to define only a secondary impact.

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

In this section, we summarize points made above.

* Using ATT&CK should not require any more or less information than normally provided in a vulnerability record. Using ATT&CK enables you to *standardize* how you describe vulnerability information so that readers can leverage the resources built on top of ATT&CK.
* The methodology focuses on Enterprise ATT&CK, but content from Mobile and ICS ATT&CK is included as needed. These techniques are identified with "Mobile-" and "ICS-" prefixes.
* Technique mappings are only included for a vulnerability type when it is likely that different vulnerabilities in the group share that technique.  For example, vulnerabilities that modify memory (e.g., buffer overflow) share a primary impact, but the secondary impacts and exploitation techniques are so varied that the methodology refers the user to standard exploit methods and objective-based mapping. 
* Some vulnerabilities require no explicit exploitation (i.e., their VEID has no exploit method).
* Some groupings will have more than one technique listed for a mapping category because there are common variations within that grouping.  In these cases, select only the techniques that apply to the vulnerability.  For example, the cross-site scripting (XSS) vulnerability type includes an option of [T1189](https://attack.mitre.org/techniques/T1189) (Drive-by Compromise) or [T1204.001](https://attack.mitre.org/techniques/T1204/001) (User Execution: Malicious Link) depending on whether the attacked is stored or not.

## References

<a name="1">[1]</a> https://www.thestack.technology/analysis-of-cves-in-2022-software-vulnerabilities-cwes-most-dangerous/

<a name="2">[2]</a> ATT&CK Design and Philosophy paper