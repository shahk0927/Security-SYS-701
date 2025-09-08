## Domain 4.0: Security Operations

### 4.1 Given a scenario, apply common security techniques to computing resources

#### Secure Baselines
*   **Establish:** Create a standardized, secure configuration for a system or device.
*   **Deploy:** Apply the secure baseline configuration to all new and existing systems.
*   **Maintain:** Monitor systems for any deviation from the baseline and update the baseline as needed.

#### Hardening Targets
*   **Hardening:** The process of reducing a system's attack surface by disabling unnecessary services, changing default passwords, and applying secure configurations. This applies to all devices, from mobile devices and workstations to servers and cloud infrastructure.

#### Mobile Solutions
*   **Mobile device management (MDM):** A centralized software solution for managing and securing mobile devices (phones, tablets) used by employees.
*   **Deployment models:**
    *   **BYOD (Bring your own device):** Employees use their personal devices for work. Hard to secure.
    *   **COPE (Corporate-owned, personally enabled):** The company owns the device, but allows personal use.
    *   **CYOD (Choose your own device):** Employees choose from a list of company-approved devices.

#### Wireless Security Settings
*   **WPA3:** The latest and most secure Wi-Fi security protocol.
*   **AAA/RADIUS:** A framework for Authentication, Authorization, and Accounting. RADIUS is a common protocol used to implement AAA for network access.

#### Application Security
*   **Input validation:** The practice of checking and sanitizing all data received from a user to prevent attacks like SQL injection.
*   **Secure cookies:** Using flags on web cookies, such as HttpOnly and Secure, to prevent them from being stolen or used maliciously.
*   **Static code analysis:** Analyzing an application's source code for vulnerabilities without actually running the program.
*   **Code signing:** Using a digital signature to verify the author of a piece of code and ensure it hasn't been tampered with.
*   **Sandboxing:** Running an application in an isolated environment with restricted access to system resources.

### 4.2 Explain the security implications of proper asset management

*   **Acquisition/procurement process:** The formal process for purchasing and introducing new hardware or software, including security reviews.
*   **Assignment/accounting:** Tracking who is responsible for an asset and what its purpose is.
*   **Inventory:** A complete list of all hardware and software assets an organization owns.
*   **Disposal/decommissioning:** The formal process for retiring an asset at the end of its life.
*   **Sanitization:** The process of securely and completely erasing data from a storage device.
*   **Destruction:** The physical destruction of a storage device to ensure data cannot be recovered. For example, shredding a hard drive.
*   **Data retention:** A policy that defines how long data must be kept and when it should be destroyed.

### 4.3 Explain various activities associated with vulnerability management

#### Identification Methods
*   **Vulnerability scan:** An automated tool that scans systems for known vulnerabilities.
*   **Threat feed:** A stream of real-time data about the latest threats, vulnerabilities, and attack indicators.
*   **OSINT (Open-source intelligence):** Information gathered from publicly available sources, such as social media or public websites.
*   **Penetration testing:** An authorized, simulated attack on a system to evaluate its security.
*   **Bug bounty program:** A program that rewards security researchers for finding and reporting vulnerabilities.

#### Analysis
*   **False positive:** A vulnerability scan incorrectly reports a vulnerability that does not actually exist.
*   **False negative:** A vulnerability scan fails to detect a vulnerability that does exist. This is the more dangerous of the two.
*   **CVSS (Common Vulnerability Scoring System):** A standardized scoring system (0-10) used to rate the severity of a vulnerability.
*   **CVE (Common Vulnerability Enumeration):** A list of publicly known information security vulnerabilities, each with a unique ID number.

#### Vulnerability Response and Remediation
*   **Patching:** Applying a vendor-supplied update to fix a known vulnerability.
*   **Compensating controls:** Implementing an alternative security measure when a primary control is not feasible. For example, using an IPS to protect an unpatched server.
*   **Exceptions and exemptions:** Formal approval to deviate from a security policy, often with a documented business justification and expiration date.

### 4.4 Explain security alerting and monitoring concepts and tools

#### Monitoring Activities
*   **Log aggregation:** Collecting logs from multiple sources (e.g., firewalls, servers, applications) into a single, centralized location.
*   **Alerting:** Automatically notifying personnel when a specific event or threshold is detected in the logs.
*   **Quarantine:** Isolating a system that is suspected of being compromised to prevent it from infecting other systems on the network.
*   **Alert tuning:** The process of adjusting alert rules to reduce the number of false positives.

#### Tools
*   **SIEM (Security information and event management):** A tool that collects, aggregates, and analyzes log data from across the network to provide real-time alerting and analysis.
*   **Antivirus:** Software designed to detect, prevent, and remove malware.
*   **DLP (Data loss prevention):** A set of tools and processes used to ensure that sensitive data is not lost, misused, or accessed by unauthorized users.
*   **NetFlow:** A network protocol used to collect IP traffic information and monitor network traffic flow.

### 4.5 Explain how to modify enterprise capabilities to enhance security

#### Firewall
*   **Rules:** A set of instructions that tells a firewall what traffic to allow or deny based on criteria like source/destination IP, port, and protocol.
*   **Screened subnets (DMZ):** A semi-trusted network segment that is isolated from the internal network, where public-facing servers (like web servers) are placed.

#### Operating System Security
*   **Group Policy:** A feature in Microsoft Windows that allows administrators to manage and configure operating systems, applications, and user settings across a network.
*   **SELinux (Security-Enhanced Linux):** A security module in the Linux kernel that provides a mechanism for supporting access control security policies.

#### Email Security
*   **SPF (Sender Policy Framework):** An email authentication method that specifies which mail servers are authorized to send email on behalf of a domain. Helps prevent spoofing.
*   **DKIM (DomainKeys Identified Mail):** Adds a digital signature to outgoing emails, allowing the receiving server to verify that the message was not tampered with.
*   **DMARC (Domain-based Message Authentication Reporting and Conformance):** A policy that tells a receiving mail server what to do if an email fails SPF or DKIM checks (e.g., quarantine or reject).

#### Other Tools
*   **File integrity monitoring (FIM):** A process that checks for and alerts on any unauthorized changes to critical system or configuration files.
*   **NAC (Network access control):** A security solution that enforces policies to control which devices can connect to the network.
*   **EDR (Endpoint detection and response):** A solution that continuously monitors endpoint devices (laptops, servers) to detect and respond to advanced threats.
*   **XDR (Extended detection and response):** An evolution of EDR that collects and correlates data from multiple security layers, including endpoints, email, and cloud.

### 4.6 Given a scenario, implement and maintain identity and access management (IAM)

*   **Provisioning/de-provisioning:** The process of creating user accounts and granting permissions (provisioning) and disabling or deleting them when a user leaves (de-provisioning).
*   **Federation:** An arrangement where two or more organizations trust each other's user authentication, allowing a user from one organization to access resources in another.
*   **SSO (Single sign-on):** An authentication scheme that allows a user to log in with a single ID and password to gain access to multiple systems.
*   **SAML (Security Assertions Markup Language):** An open standard used for exchanging authentication and authorization data between parties, often used to implement SSO.

#### Access Controls
*   **Mandatory (MAC):** Access is determined by security labels. The OS makes the decision, not the owner. Used in high-security environments.
*   **Discretionary (DAC):** The owner of a resource determines who has access to it.
*   **Role-based (RBAC):** Access is assigned based on a user's job role (e.g., "Accountant," "Manager"). The most common model.
*   **Attribute-based (ABAC):** Access is granted based on a set of attributes, such as user location, time of day, or device type.

#### Multifactor Authentication (MFA)
*   **Factors:**
    *   **Something you know:** A password or PIN.
    *   **Something you have:** A physical token or a smartphone app.
    *   **Something you are:** A biometric characteristic, like a fingerprint or facial scan.
    *   **Somewhere you are:** Geolocation.

#### Privileged Access Management (PAM)
*   **Just-in-time (JIT) permissions:** Granting a user elevated permissions for a limited time, only when they need it.
*   **Password vaulting:** A secure, centralized repository for storing and managing privileged account passwords.
*   **Ephemeral credentials:** Temporary credentials that are valid for only a single use or a very short period of time.

### 4.7 Explain the importance of automation and orchestration

#### Use Cases of Automation
*   **User provisioning:** Automatically creating new user accounts and assigning permissions when an employee is hired.
*   **Resource provisioning:** Automatically deploying new servers or cloud resources based on demand.
*   **Ticket creation:** Automatically generating a help desk ticket when a security alert is triggered.

#### Benefits
*   **Efficiency/time saving:** Automating repetitive tasks frees up security personnel for more important work.
*   **Enforcing baselines:** Automation ensures that all systems are configured consistently and securely according to the established baseline.
*   **Reaction time:** Automated responses to security incidents can happen much faster than manual responses.

### 4.8 Explain appropriate incident response activities

#### Incident Response Process
*   **Preparation:** Preparing the team and tools before an incident occurs.
*   **Detection and Analysis:** Identifying that an incident has occurred and determining its scope.
*   **Containment:** Isolating the affected systems to prevent the incident from spreading.
*   **Eradication:** Removing the threat and restoring systems from clean backups.
*   **Recovery:** Returning all systems to normal operation.
*   **Lessons learned:** Documenting the incident and identifying areas for improvement.

#### Digital Forensics
*   **Legal hold:** A process that ensures potentially relevant data is preserved for litigation.
*   **Chain of custody:** A detailed log that documents the collection, handling, and storage of evidence to ensure its integrity.
*   **Acquisition:** The process of creating a forensically sound copy of data from a system.

### 4.9 Given a scenario, use data sources to support an investigation

#### Log Data
*   **Firewall logs:** Show what traffic has been allowed or blocked by the firewall.
*   **Application logs:** Record events specific to an application, such as user logins or errors.
*   **Endpoint logs:** Logs from individual workstations or servers, often collected by an EDR agent.

#### Other Data Sources
*   **Metadata:** Data that provides information about other data. For example, the creation date and author of a file.
*   **Vulnerability scans:** Reports that show known vulnerabilities on systems, which can help identify the attack vector.
*   **Packet captures (pcap):** A file containing the actual network traffic captured over a period of time, allowing for deep analysis of an attack.
