## Domain 4.0: Security Operations

### 4.1 Given a scenario, apply common security techniques to computing resources

#### Secure Baselines
*   **Establish**: Create a standardized, secure configuration for a system or device.
*   **Deploy**: Apply the secure baseline configuration to all new and existing systems.
*   **Maintain**: Monitor systems for any deviation from the baseline and update the baseline as needed.

#### Hardening Targets
*   **Hardening**: The process of reducing a system's attack surface by disabling unnecessary services, changing default passwords, and applying secure configurations. This applies to all devices.
*   **Mobile devices**: Securing smartphones, tablets, and other portable devices against threats.
*   **Workstations**: Securing desktop and laptop computers used by end-users.
*   **Switches**: Securing network switches by disabling unused ports, changing default credentials, and configuring secure management protocols.
*   **Routers**: Securing network routers by disabling unused services, changing default credentials, updating firmware, and configuring secure access controls.
*   **Cloud infrastructure**: Implementing security configurations for virtual machines, storage, and networking components within cloud environments.
*   **Servers**: Securing dedicated machines that provide services, typically by minimizing installed software, applying least privilege, and regular patching.
*   **ICS/SCADA (Industrial Control Systems/Supervisory Control and Data Acquisition)**: Securing systems that control industrial processes, often involving physical isolation, strong access controls, and specialized protocols.
*   **Embedded systems**: Securing specialized computer systems designed for specific functions within a larger system, often requiring firmware updates and restricted access.
*   **RTOS (Real-time Operating Systems)**: Securing operating systems designed for applications with strict timing requirements, often focusing on reliability and integrity.
*   **IoT devices (Internet of Things)**: Securing interconnected devices beyond traditional computers, often requiring unique passwords, firmware updates, and network segmentation due to their varied nature.
*   **Wireless devices**: Securing any device that connects wirelessly, including access points, mobile devices, and IoT devices, focusing on strong encryption and authentication.
*   **Installation considerations**: Evaluating physical security, environmental factors, and network placement during device setup.
*   **Site surveys**: The process of assessing a location to determine the optimal placement and configuration of wireless access points for coverage and performance.
*   **Heat maps**: Visual representations of wireless signal strength and coverage across a physical area, often generated during a site survey.

#### Mobile Solutions
*   **Mobile device management (MDM)**: A centralized software solution for managing and securing mobile devices (phones, tablets) used by employees.
*   **Deployment models**:
    *   **BYOD (Bring your own device)**: Employees use their personal devices for work. Hard to secure.
    *   **COPE (Corporate-owned, personally enabled)**: The company owns the device, but allows personal use.
    *   **CYOD (Choose your own device)**: Employees choose from a list of company-approved devices.
*   **Connection methods**:
    *   **Cellular**: Using mobile network data (e.g., 4G, 5G) for connectivity.
    *   **Wi-Fi**: Connecting to wireless local area networks.
    *   **Bluetooth**: Short-range wireless technology for connecting peripherals or transferring data.

#### Wireless Security Settings
*   **WPA3**: The latest and most secure Wi-Fi security protocol, offering stronger encryption and protection against brute-force attacks.
*   **AAA/RADIUS (Remote Authentication Dial-In User Service)**: A framework for **A**uthentication, **A**uthorization, and **A**ccounting. RADIUS is a common protocol used to implement AAA for network access, including wireless.
*   **Cryptographic protocols**: Implementing strong encryption standards (e.g., AES) for data in transit over wireless networks.
*   **Authentication protocols**: Using robust methods (e.g., EAP-TLS with certificates) to verify user and device identities before granting wireless access.

#### Application Security
*   **Input validation**: The practice of checking and sanitizing all data received from a user to prevent attacks like SQL injection or cross-site scripting (XSS).
*   **Secure cookies**: Using flags on web cookies, such as **HttpOnly** (prevents client-side script access) and **Secure** (ensures transmission over HTTPS), to prevent them from being stolen or used maliciously.
*   **Static code analysis**: Analyzing an application's source code for vulnerabilities without actually running the program (often done during development).
*   **Code signing**: Using a digital signature to verify the author of a piece of code and ensure it hasn't been tampered with since it was signed.
*   **Sandboxing**: Running an application in an isolated environment with restricted access to system resources, limiting potential damage from malicious code.
*   **Monitoring**: Continuously observing application behavior, logs, and performance to detect anomalies or security incidents.

### 4.2 Explain the security implications of proper hardware, software, and data asset management

*   **Acquisition/procurement process**: The formal process for purchasing and introducing new hardware or software, including security reviews and vetting of vendors.
*   **Assignment/accounting**: Tracking who is responsible for an asset and what its purpose is.
    *   **Ownership**: Clearly defining which individual or department is accountable for an asset's security and lifecycle.
    *   **Classification**: Categorizing data and assets based on their sensitivity, value, and regulatory requirements (e.g., public, internal, confidential, restricted).
*   **Monitoring/asset tracking**: Continuously observing the location, status, and configuration of assets throughout their lifecycle to ensure compliance and security.
*   **Inventory**: A complete, accurate, and up-to-date list of all hardware and software assets an organization owns.
    *   **Enumeration**: The process of systematically identifying and listing all assets on a network or within an organization.
*   **Disposal/decommissioning**: The formal, secure process for retiring an asset at the end of its life, including data removal and physical disposition.
*   **Sanitization**: The process of securely and completely erasing data from a storage device, rendering it unrecoverable by common means (e.g., wiping with multiple passes).
*   **Destruction**: The physical destruction of a storage device (e.g., shredding, pulverizing, degaussing) to ensure data cannot be recovered, typically for the most sensitive data.
*   **Certification**: Providing documented proof that an asset has been properly sanitized or destroyed according to policy and standards.
*   **Data retention**: A policy that defines how long data must be kept for legal, regulatory, or business reasons, and when it should be securely destroyed.

### 4.3 Explain various activities associated with vulnerability management

#### Identification Methods
*   **Vulnerability scan**: An automated tool that scans systems, networks, and applications for known vulnerabilities, misconfigurations, and weaknesses.
*   **Application security**:
    *   **Static analysis**: Analyzing an application's source code for vulnerabilities without executing it (similar to static code analysis in 4.1).
    *   **Dynamic analysis**: Analyzing an application for vulnerabilities while it is running, simulating user input and observing behavior.
    *   **Package monitoring**: Tracking third-party libraries and components used in applications for known vulnerabilities.
*   **Threat feed**: A stream of real-time data about the latest threats, vulnerabilities, and attack indicators, often provided by security vendors or intelligence agencies.
*   **OSINT (Open-source intelligence)**: Information gathered from publicly available sources, such as social media, public websites, news articles, or public code repositories.
*   **Proprietary/third-party**: Threat intelligence acquired from commercial security vendors or specialized intelligence firms.
*   **Information-sharing organization**: Groups or communities (e.g., ISACs/ISAOs) that facilitate the exchange of threat intelligence and best practices among members.
*   **Dark web**: Monitoring illicit marketplaces, forums, and communities on the dark web for mentions of an organization, stolen data, or new attack techniques.
*   **Penetration testing**: An authorized, simulated attack on a system, network, or application to evaluate its security posture and identify exploitable vulnerabilities.
*   **Responsible disclosure program**: A policy where security researchers can privately report vulnerabilities to an organization, allowing time for remediation before public disclosure.
*   **Bug bounty program**: A program that rewards security researchers (bounty hunters) for finding and reporting vulnerabilities in an organization's systems or applications.
*   **System/process audit**: A formal review of systems, configurations, or operational procedures to ensure compliance with security policies and standards.

#### Analysis
*   **Confirmation**: Verifying that a reported vulnerability actually exists and is not a false positive.
*   **False positive**: A vulnerability scan incorrectly reports a vulnerability that does not actually exist.
*   **False negative**: A vulnerability scan fails to detect a vulnerability that does exist. This is the more dangerous of the two.
*   **Prioritize**: Ranking vulnerabilities based on their severity, exploitability, and potential impact to the organization.
*   **CVSS (Common Vulnerability Scoring System)**: A standardized scoring system (0-10) used to rate the severity of a vulnerability based on various metrics.
*   **CVE (Common Vulnerability Enumeration)**: A list of publicly known information security vulnerabilities, each with a unique ID number, used for consistent identification.
*   **Vulnerability classification**: Grouping vulnerabilities by type (e.g., SQL Injection, XSS, Buffer Overflow) to better understand common weaknesses.
*   **Exposure factor**: The percentage of an asset's value that would be lost if a specific threat were realized.
*   **Environmental variables**: Factors specific to an organization's environment (e.g., network segmentation, existing security controls) that can influence a vulnerability's true risk.
*   **Industry/organizational impact**: Assessing the potential financial, reputational, legal, or operational damage a vulnerability could cause specifically to the organization.
*   **Risk tolerance**: The level of risk an organization is willing to accept or endure in pursuit of its objectives.

#### Vulnerability Response and Remediation
*   **Patching**: Applying a vendor-supplied update or hotfix to fix a known vulnerability.
*   **Insurance**: Transferring financial risk associated with cyber incidents to a third party through cyber insurance policies.
*   **Segmentation**: Dividing a network into smaller, isolated segments to limit the spread of an attack if a vulnerability is exploited.
*   **Compensating controls**: Implementing an alternative security measure when a primary control is not feasible or effective. For example, using an IPS to protect an unpatched server.
*   **Exceptions and exemptions**: Formal approval to deviate from a security policy, often with a documented business justification, clear scope, and expiration date.
*   **Validation of remediation**: Ensuring that the applied fix or control has successfully mitigated the vulnerability.
    *   **Rescanning**: Running another vulnerability scan after remediation to confirm the vulnerability is no longer detected.
    *   **Audit**: A formal review of the remediation process and its effectiveness.
    *   **Verification**: Directly checking system configurations or logs to confirm the fix has been applied correctly.
*   **Reporting**: Communicating vulnerability findings, remediation status, and overall security posture to relevant stakeholders.

### 4.4 Explain security alerting and monitoring concepts and tools

#### Monitoring Computing Resources
*   **Systems**: Monitoring operating systems, applications, and hardware components for security-related events.
*   **Applications**: Monitoring software programs for unusual behavior, errors, and unauthorized access attempts.
*   **Infrastructure**: Monitoring network devices (routers, switches, firewalls) and cloud services for performance, availability, and security events.

#### Activities
*   **Log aggregation**: Collecting logs from multiple sources (e.g., firewalls, servers, applications, network devices) into a single, centralized location for easier analysis.
*   **Alerting**: Automatically notifying personnel (e.g., via email, SMS, ticketing system) when a specific event, threshold, or pattern is detected in the monitoring data.
*   **Scanning**: Regularly performing vulnerability scans, port scans, or configuration scans to identify weaknesses.
*   **Reporting**: Generating regular reports on security events, compliance status, and system health from aggregated log data.
*   **Archiving**: Storing log data for long periods for forensic analysis, compliance, and historical trending.
*   **Alert response and remediation/validation**: The process of investigating triggered alerts, taking corrective actions, and confirming that the issue has been resolved.
*   **Quarantine**: Isolating a system that is suspected of being compromised or showing malicious activity to prevent it from infecting other systems on the network.
*   **Alert tuning**: The process of adjusting alert rules, thresholds, and correlation logic to reduce the number of false positives and improve the accuracy of alerts.

#### Tools
*   **SCAP (Security Content Automation Protocol)**: A suite of standards for automating vulnerability management, measurement, and policy compliance evaluation.
*   **Benchmarks**: Standardized security configurations or hardening guides (e.g., CIS Benchmarks) used as a baseline for measuring system security.
*   **Agents/agentless**: **Agents** are software installed on endpoints for monitoring; **agentless** monitoring collects data remotely without installing software.
*   **SIEM (Security information and event management)**: A tool that collects, aggregates, and analyzes log data from across the network to provide real-time alerting, correlation, and analysis.
*   **Antivirus**: Software designed to detect, prevent, and remove malware (viruses, worms, Trojans, etc.) from endpoints.
*   **DLP (Data loss prevention)**: A set of tools and processes used to ensure that sensitive data is not lost, misused, or accessed by unauthorized users, often by monitoring data in transit, at rest, and in use.
*   **SNMP traps (Simple Network Management Protocol traps)**: Asynchronous alert messages sent by network devices to a central monitoring station when specific events or conditions occur.
*   **NetFlow**: A network protocol used to collect IP traffic information (metadata, not actual content) and monitor network traffic flow for analysis of usage, performance, and security.
*   **Vulnerability scanners**: Automated tools (e.g., Nessus, OpenVAS) specifically designed to identify known security weaknesses in systems and applications.

### 4.5 Given a scenario, modify enterprise capabilities to enhance security

#### Firewall
*   **Rules**: A set of instructions that tells a firewall what traffic to allow or deny based on criteria.
*   **Access lists**: A list of permissions or denials that dictate who can access what, often used interchangeably with firewall rules.
*   **Ports/protocols**: Specific criteria within firewall rules that define which communication channels (ports) and methods (protocols like TCP/UDP) are allowed or blocked.
*   **Screened subnets (DMZ - Demilitarized Zone)**: A semi-trusted network segment that is isolated from the internal network, where public-facing servers (like web servers) are placed to protect the internal network.

#### IDS/IPS (Intrusion Detection System/Intrusion Prevention System)
*   **IDS**: Monitors network or system activities for malicious activity or policy violations and alerts.
*   **IPS**: Detects and *prevents* malicious activities by blocking them in real-time.
*   **Trends**: Identifying patterns of attacks or suspicious behavior over time to predict and proactively defend against future threats.
*   **Signatures**: Predefined patterns (like malware signatures or attack patterns) that an IDS/IPS uses to identify known threats.

#### Web Filter
*   **Web filter**: A solution that controls access to websites and web content based on categories, reputation, or user policies.
*   **Agent-based**: Web filtering performed by software installed directly on endpoint devices.
*   **Centralized proxy**: A server that acts as an intermediary for web requests, filtering traffic before it reaches the user.
*   **URL scanning**: Inspecting the full Uniform Resource Locator (URL) of web requests to identify and block access to malicious or unauthorized websites.
*   **Content categorization**: Grouping websites and web content into predefined categories (e.g., social media, gambling, malware) for policy enforcement.
*   **Block rules**: Specific rules configured to deny access to certain websites, categories, or content types.
*   **Reputation**: Using databases that rate the trustworthiness and safety of websites to block access to known malicious sites.

#### Operating System Security
*   **Group Policy**: A feature in Microsoft Windows that allows administrators to manage and configure operating systems, applications, and user settings across a network from a central location.
*   **SELinux (Security-Enhanced Linux)**: A security module in the Linux kernel that provides a mechanism for supporting access control security policies, including Mandatory Access Control (MAC).

#### Implementation of Secure Protocols
*   **Protocol selection**: Choosing strong, secure versions of communication protocols (e.g., TLS v1.2/1.3 instead of SSL, SFTP instead of FTP, SSH instead of Telnet).
*   **Port selection**: Configuring services to use standard ports for discoverability or non-standard ports for obfuscation, and blocking all unused ports.
*   **Transport method**: Ensuring that data is encrypted and protected during transmission across networks (e.g., using VPNs, secure tunnels).

#### DNS Filtering
*   **DNS filtering**: Blocking access to known malicious domains or categorizing websites at the DNS level to prevent users from reaching harmful content.

#### Email Security
*   **SPF (Sender Policy Framework)**: An email authentication method that specifies which mail servers are authorized to send email on behalf of a domain. Helps prevent spoofing.
*   **DKIM (DomainKeys Identified Mail)**: Adds a digital signature to outgoing emails, allowing the receiving server to verify that the message was not tampered with in transit.
*   **DMARC (Domain-based Message Authentication Reporting and Conformance)**: A policy that tells a receiving mail server what to do if an email fails SPF or DKIM checks (e.g., quarantine, reject, or allow with reporting).
*   **Gateway**: A dedicated server or service that filters, scans, and protects email traffic entering and leaving the organization's network, often performing spam, malware, and DLP checks.

#### Other Tools
*   **File integrity monitoring (FIM)**: A process that checks for and alerts on any unauthorized changes to critical system or configuration files, helping detect tampering.
*   **DLP (Data loss prevention)**: A set of tools and processes used to ensure that sensitive data is not lost, misused, or accessed by unauthorized users, often by monitoring data in transit, at rest, and in use.
*   **NAC (Network access control)**: A security solution that enforces policies to control which devices (and users) can connect to the network, often requiring authentication and health checks.
*   **EDR (Endpoint detection and response)/XDR (Extended detection and response)**:
    *   **EDR**: A solution that continuously monitors endpoint devices (laptops, servers) for suspicious activities, detects advanced threats, and provides tools for investigation and response.
    *   **XDR**: An evolution of EDR that collects and correlates data from multiple security layers, including endpoints, email, network, cloud, and identity, for broader threat detection and response.
*   **User behavior analytics (UBA)**: A security process that collects and analyzes user data to identify unusual or suspicious behavior that may indicate a security threat or insider attack.

### 4.6 Given a scenario, implement and maintain identity and access management (IAM)

*   **Provisioning/de-provisioning user accounts**: The process of creating new user accounts, assigning initial permissions, and configuring access to systems (provisioning), and disabling or deleting them when a user leaves the organization or changes roles (de-provisioning).
*   **Permission assignments and implications**: The process of granting specific rights or privileges to users or roles, with an understanding of the potential security risks or benefits associated with those permissions.
*   **Identity proofing**: The process of verifying and validating an individual's identity (e.g., using government-issued IDs, background checks) before granting them access to systems or resources.
*   **Federation**: An arrangement where two or more organizations trust each other's user authentication, allowing a user from one organization to securely access resources in another without creating separate accounts.

#### Single Sign-On (SSO)
*   **SSO**: An authentication scheme that allows a user to log in with a single set of credentials (ID and password) to gain access to multiple independent systems or applications.
*   **Lightweight Directory Access Protocol (LDAP)**: A protocol used for accessing and maintaining distributed directory information services, often used for authentication and retrieving user attributes in an SSO context.
*   **Open authorization (OAuth)**: An open standard for access delegation, commonly used as a way for Internet users to grant websites or applications access to their information on other websites without giving them their passwords.
*   **Security Assertions Markup Language (SAML)**: An open standard (XML-based) used for exchanging authentication and authorization data between parties, often used to implement SSO for web applications.
*   **Interoperability**: The ability of different IAM systems, protocols, or components to work together seamlessly to share identity information and enforce access controls.
*   **Attestation**: The process of verifying and certifying that a user, device, or system meets specific security requirements or has a certain trusted state.

#### Access Controls
*   **Mandatory (MAC)**: Access is determined by security labels assigned to subjects (users) and objects (resources). The operating system or security kernel enforces the decision, not the owner. Used in high-security environments.
*   **Discretionary (DAC)**: The owner of a resource determines who has access to it and what permissions they have (e.g., read, write, execute).
*   **Role-based (RBAC)**: Access is assigned based on a user's job role or function within the organization (e.g., "Accountant," "Manager," "HR Specialist"). The most common access control model.
*   **Rule-based**: Access is granted or denied based on a set of predefined rules or conditions (e.g., firewall rules, "if X, then Y").
*   **Attribute-based (ABAC)**: Access is granted dynamically based on a set of attributes associated with the user (e.g., department, clearance level), the resource (e.g., sensitivity, type), and the environment (e.g., user location, time of day, device type).
*   **Time-of-day restrictions**: Limiting user access to systems or resources to specific hours or days.
*   **Least privilege**: The security principle that users or processes should only be granted the minimum necessary permissions to perform their job functions, and no more.

#### Multifactor Authentication (MFA)
*   **Implementations**: The various ways MFA can be deployed and used.
    *   **Biometrics**: Using unique biological characteristics for authentication (e.g., fingerprint, facial scan, iris scan).
    *   **Hard/soft authentication tokens**: Physical devices (hard tokens) or software-based applications (soft tokens) that generate one-time passwords or cryptographic keys.
    *   **Security keys**: Physical devices (e.g., FIDO U2F/WebAuthn keys) that provide strong, phishing-resistant authentication.
*   **Factors**: Requiring two or more distinct types of credentials for authentication.
    *   **Something you know**: A password, PIN, or passphrase.
    *   **Something you have**: A physical token, smart card, a security key, or a smartphone app.
    *   **Something you are**: A biometric characteristic, like a fingerprint or facial scan.
    *   **Somewhere you are**: Geolocation-based authentication, verifying the user's physical location.

#### Password Concepts
*   **Password best practices**: Guidelines for creating and managing strong, secure passwords.
    *   **Length**: Requiring a minimum number of characters to increase entropy.
    *   **Complexity**: Requiring a mix of character types (uppercase, lowercase, numbers, symbols).
    *   **Reuse**: Prohibiting the use of the same password across multiple accounts.
    *   **Expiration**: Requiring users to change their passwords after a set period (though often debated for effectiveness).
    *   **Age**: Minimum time a password must be used before it can be changed.
*   **Password managers**: Software applications that securely store, generate, and manage user passwords, promoting strong and unique passwords.
*   **Passwordless**: Authentication methods that eliminate the need for traditional passwords, relying instead on biometrics, security keys, or magic links.

#### Privileged Access Management (PAM) Tools
*   **Just-in-time (JIT) permissions**: Granting a user elevated permissions for a limited time, only when they specifically need it, and automatically revoking them afterward.
*   **Password vaulting**: A secure, centralized repository for storing, managing, and automatically rotating privileged account passwords, often with access controls and auditing.
*   **Ephemeral credentials**: Temporary credentials (e.g., API keys, session tokens) that are valid for only a single use or a very short period of time, reducing the risk of compromise.

### 4.7 Explain the importance of automation and orchestration related to secure operations

#### Use Cases of Automation and Scripting
*   **User provisioning**: Automatically creating new user accounts, assigning initial permissions, and configuring access to systems when an employee is hired.
*   **Resource provisioning**: Automatically deploying new servers, virtual machines, cloud resources, or network configurations based on demand or predefined templates.
*   **Guard rails**: Automated policies or configurations that prevent unauthorized or insecure actions in cloud environments or other systems.
*   **Security groups**: Automated management of network security groups or firewall rules to control traffic flow based on policies.
*   **Ticket creation**: Automatically generating a help desk or incident response ticket when a security alert is triggered, streamlining incident management.
*   **Escalation**: Automated notification and escalation of security incidents to appropriate personnel based on predefined severity levels and rules.
*   **Enabling/disabling services and access**: Automatically turning off unnecessary services or revoking user access based on security policies or incident response actions.
*   **Continuous integration and testing (CI/CT)**: Integrating automated security checks and tests (e.g., static/dynamic code analysis, vulnerability scans) into the software development and deployment pipeline.
*   **Integrations and Application programming interfaces (APIs)**: Using APIs to connect different security tools and systems, enabling automated data exchange and coordinated actions.

#### Benefits
*   **Efficiency/time saving**: Automating repetitive and mundane tasks frees up security personnel for more complex analysis, threat hunting, and strategic work.
*   **Enforcing baselines**: Automation ensures that all systems are configured consistently and securely according to the established baseline, reducing human error and configuration drift.
*   **Standard infrastructure configurations**: Automating the deployment of infrastructure using templates (e.g., Infrastructure as Code) ensures consistent, secure configurations.
*   **Scaling in a secure manner**: Automated processes allow security controls to be applied consistently as infrastructure scales up or down, without manual intervention.
*   **Employee retention**: Reducing repetitive, tedious tasks through automation can improve job satisfaction and retention for security professionals.
*   **Reaction time**: Automated responses to security incidents (e.g., quarantining an infected host, blocking a malicious IP) can happen much faster than manual responses, minimizing impact.
*   **Workforce multiplier**: Automation allows a smaller security team to manage a larger environment and handle more security tasks, effectively multiplying their capabilities.

#### Other Considerations
*   **Complexity**: Implementing and managing automation can be complex, requiring specialized skills and careful design to avoid errors.
*   **Cost**: Initial investment in automation tools, development, and integration can be significant.
*   **Single point of failure**: Over-reliance on a single automation platform or script can introduce a single point of failure that, if compromised, could have wide-ranging impacts.
*   **Technical debt**: Poorly designed or undocumented automation can become difficult to maintain, update, or troubleshoot over time.
*   **Ongoing supportability**: Automated systems require continuous monitoring, maintenance, and updates to remain effective and secure.

### 4.8 Explain appropriate incident response activities

#### Process (following NIST SP 800-61)
*   **Preparation**: Preparing the incident response team, developing policies and procedures, acquiring necessary tools, and training personnel before an incident occurs.
*   **Detection**: Identifying that an incident has occurred through alerts, logs, user reports, or other means.
*   **Analysis**: Gathering information about the detected incident, determining its scope, severity, root cause, and potential impact.
*   **Containment**: Isolating the affected systems or networks to prevent the incident from spreading further and causing more damage.
*   **Eradication**: Removing the root cause of the incident (e.g., malware, exploited vulnerability) and cleaning affected systems.
*   **Recovery**: Restoring all affected systems and services to normal operation, ensuring full functionality, security, and integrity.
*   **Lessons learned**: Documenting the incident, reviewing the response process, identifying areas for improvement, and updating policies, procedures, and training.
    *   **Training**: Developing and delivering training programs based on incident findings to improve future response capabilities.
    *   **Root cause analysis**: Deep dive investigation to identify the fundamental reason for an incident, beyond just the immediate symptoms.

#### Testing
*   **Testing**: Regularly evaluating the effectiveness of the incident response plan and team.
*   **Tabletop exercise**: A discussion-based session where participants talk through an incident scenario, identifying roles, responsibilities, and decision points.
*   **Simulation**: A more active exercise where systems and networks are used to mimic an actual attack, testing the response team's ability to detect and react.

#### Threat Hunting
*   **Threat hunting**: Proactively searching for undiscovered threats, intrusions, or vulnerabilities within a network that may have bypassed existing security controls.

#### Digital Forensics
*   **Legal hold**: A process that ensures potentially relevant electronically stored information (ESI) and other data is preserved for litigation or investigation, preventing its alteration or deletion.
*   **Chain of custody**: A detailed, chronological record that documents the collection, handling, storage, transfer, and disposition of evidence to ensure its integrity and admissibility in legal proceedings.
*   **Acquisition**: The process of creating a forensically sound, bit-for-bit copy of data from a system (e.g., hard drive, memory) in a way that preserves its integrity and doesn't alter the original.
*   **Reporting**: Documenting the findings of a forensic investigation, including the timeline of events, methods used, and conclusions drawn.
*   **Preservation**: Taking steps to protect potential evidence from alteration, damage, or destruction to maintain its integrity for analysis.
*   **E-discovery**: The process of identifying, collecting, and producing electronically stored information (ESI) in response to a legal request or investigation.

### 4.9 Given a scenario, use data sources to support an investigation

#### Log Data
*   **Firewall logs**: Show what network traffic has been allowed or blocked by the firewall, including source/destination IPs, ports, and protocols, useful for identifying network-based attacks.
*   **Application logs**: Record events specific to an application, such as user logins, failed authentication attempts, data access, errors, and application-level vulnerabilities.
*   **Endpoint logs**: Logs from individual workstations or servers, often collected by an EDR agent, including system events, process execution, file changes, and network connections.
*   **OS-specific security logs**: Operating system logs (e.g., Windows Event Logs, Linux `auth.log`, `syslog`) that record authentication events, system changes, and other security-relevant activities.
*   **IPS/IDS logs**: Records of events detected or blocked by Intrusion Prevention/Detection Systems, including signature matches and anomalous behavior.
*   **Network logs**: General network logs including DNS queries, DHCP assignments, router/switch logs, and proxy logs, providing insights into network activity.

#### Other Data Sources
*   **Metadata**: Data that provides information about other data (e.g., the creation date, modification date, author, and size of a file; header information in an email; timestamp of a log entry).
*   **Vulnerability scans**: Reports that show known vulnerabilities on systems, which can help investigators identify potential attack vectors or confirm if a known vulnerability was exploited.
*   **Automated reports**: Scheduled reports generated by security tools (e.g., SIEM, DLP, antivirus) that summarize security posture, detected threats, or compliance status.
*   **Dashboards**: Visual representations of security data from various sources, providing a high-level overview of security posture and trends.
*   **Packet captures (pcap)**: A file containing the actual raw network traffic (packets) captured over a period of time, allowing for deep analysis of an attack, communication patterns, and data exfiltration.
