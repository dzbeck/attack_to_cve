# Glossary of Terms

**XXX - PROOF OF CONCEPT - XXX**

| Term | Definition |
| ---- | ---- | 
| Buffer Overflow| A buffer overflows occur when a developer does not sanitize or validate the user input before allocating space for it in the buffer. [[4]](#4) a buffer overflow is a type of memory error that happens when a program writes too much data to a buffer. [[3]]|(#3)
|Cross-site Request Forgery (CSRF)| A Cross-site request forgery is a web security vulnerability that allows an attacker to make users to perform unintended actions.|
|File inclusion| File inclusion is the ability to trick the web server into executing a rogue file, provided by the attacker, without checking its validity.|
| Integer Overflow | An integer overflow occurs when a program attempts to perform an arithmetic operation that results in a value that is too large to be represented by the data type being used. |
|Server Side Request Forgery (SSRF) | SSRF is a server site attack that leads to sensitive information disclosure from the back-end server of the application. In server site request forgery attackers send malicious packets to any Internet-facing web server and this webserver sends packets to the back end server running on the internal network on behalf of the attacker. This vulnerability is mostly found in the application that has the facility to feed the URL for fetching data from the respective servers, also present in the application in which two or more servers from different hosts communicate with each other for information sharing. [[1]](#1)|
|SQL Injection| SQL injection is a code injection technique that allows an attacker to interfere with the queries that an application makes to its database. It can result in unauthorized access to sensitive data, such as passwords, credit card details, or personal user information. It can also allow an attacker to modify or delete data, or even compromise the underlying server or other back-end infrastructure.|
|XML external entity injection (XXE)| XXE is a web security vulnerability that allows an attacker to interfere with an application's processing of XML data. XML External Entity Expansion (XXE) attacks are used against applications that process XML input by exploiting XML external entity support.|
| [REMOVE??] Unrestricted File Upload | product allows the attacker to upload or transfer files of dangerous types that can be automatically processed within the product's environment.[[2]](#2)|

# References

<a name="1">[1]</a> 

<a name="2">[2]</a>	https://cwe.mitre.org/data/definitions/434.html#:~:text=The%20%22unrestricted%20file%20upload%22%20term%20is,which%20is%20a%20resource%20consumption%20issue.&text=The%20%22unrestricted%20file%20upload%22,a%20resource%20consumption%20issue.&text=file%20upload%22%20term%20is,which%20is%20a%20resource	

<a name="3">[3]</a>	ChatGPT

<a name="4">[4]</a>