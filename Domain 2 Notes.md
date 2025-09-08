## Domain 2.0: Threats, Vulnerabilities, and Mitigations

### 2.1 Compare and contrast common threat actors and motivations

#### Threat Actors
*   **Nation-state:** Government-sponsored attackers. Highly sophisticated, well-funded, and focused on espionage or sabotage.
*   **Unskilled attacker:** Often called a "script kiddie." Uses pre-made tools without understanding the underlying technology.
*   **Hacktivist:** An attacker motivated by a political or social cause. For example, defacing a website to spread a message.
*   **Insider threat:** A current or former employee, contractor, or partner with legitimate access who misuses it.
*   **Organized crime:** A group of cybercriminals motivated by financial gain. They operate like a business.
*   **Shadow IT:** Unauthorized systems or applications used by employees without IT department approval. For example, using a personal cloud storage account for work files.

#### Attributes of Actors
*   **Internal/external:** Whether the attacker is inside (e.g., employee) or outside the organization.
*   **Resources/funding:** The level of financial backing the actor has. A nation-state has vast resources; a script kiddie has almost none.
*   **Level of sophistication/capability:** The technical skill and knowledge of the attacker.

#### Motivations
*   **Data exfiltration:** Stealing and transferring data out of a network.
*   **Espionage:** Spying to obtain secret information (e.g., government or corporate secrets).
*   **Service disruption:** Making a service or network unavailable to legitimate users.
*   **Blackmail:** Demanding payment to prevent the release of sensitive data or to restore encrypted files.
*   **Financial gain:** Stealing money or financial information.
*   **Philosophical/political beliefs:** Motivation for hacktivists who want to advance a cause.
*   **Ethical:** A "white-hat" hacker who finds vulnerabilities to help an organization secure itself.
*   **Revenge:** A motivation for a disgruntled insider threat.
*   **Disruption/chaos:** Causing damage or disorder for its own sake.
*   **War:** Nation-state actors disrupting or destroying another nation's critical infrastructure.

### 2.2 Explain common threat vectors and attack surfaces

#### Threat Vectors
*   **Message-based:** Attacks delivered via email, SMS, or instant messaging. For example, a phishing link.
*   **Image-based:** Malicious code hidden within an image file.
*   **File-based:** Malicious code delivered in a file. For example, a macro in a Microsoft Word document.
*   **Voice call:** Attacks conducted over the phone. For example, vishing.
*   **Removable device:** Malware spread through a USB drive or external hard drive.
*   **Vulnerable software:** Exploiting a bug or flaw in software to gain access.
*   **Unsupported systems and applications:** Using software or hardware that no longer receives security updates.
*   **Unsecure networks:** Open or poorly configured Wi-Fi, wired, or Bluetooth networks that can be easily accessed.
*   **Open service ports:** Unnecessary network ports left open that can be exploited by an attacker.
*   **Default credentials:** Using factory-set usernames and passwords (e.g., "admin"/"password"), which are publicly known.
*   **Supply chain:** Compromising a less-secure vendor or partner to attack the primary target.

#### Human Vectors / Social Engineering
*   **Phishing:** A fraudulent email designed to trick a user into revealing sensitive information.
*   **Vishing:** Phishing conducted over a voice call.
*   **Smishing:** Phishing conducted via SMS (text message).
*   **Misinformation/disinformation:** Spreading false information (unintentionally/intentionally) to manipulate people.
*   **Impersonation:** Pretending to be someone else, such as a help desk technician or a CEO.
*   **Business email compromise (BEC):** An attacker impersonates a high-level executive to trick an employee into making a payment or sending data.
*   **Pretexting:** Creating a believable story or scenario (a pretext) to gain someone's trust.
*   **Watering hole:** Compromising a website that is frequently visited by a specific group of users.
*   **Brand impersonation:** Using the branding of a well-known company to make a phishing attack look legitimate.
*   **Typo squatting:** Registering a domain name that is a common misspelling of a legitimate site (e.g., "Gogle.com").

### 2.3 Explain various types of vulnerabilities

#### Application
*   **Memory injection:** Introducing malicious code into a running application's memory space.
*   **Buffer overflow:** Sending more data to a memory buffer than it can handle, causing it to overwrite adjacent memory.
*   **Race conditions:** An issue where the outcome of an operation depends on the timing of two or more tasks. An attacker can exploit this to alter results.
*   **Zero-day:** A vulnerability that has been discovered by attackers but is not yet known to the vendor, so no patch exists.

#### Web-based
*   **Structured Query Language injection (SQLi):** Injecting malicious SQL commands into a web form to manipulate a back-end database.
*   **Cross-site scripting (XSS):** Injecting malicious scripts into a trusted website, which then execute in the browsers of other users.

#### System and Hardware
*   **Operating system (OS)-based:** Vulnerabilities specific to an OS, such as unpatched security flaws.
*   **Hardware:** Vulnerabilities in physical components like firmware or CPUs.
*   **Virtualization (VM escape):** An attack where malware in a virtual machine can break out and access the host system.
*   **Cloud-specific:** Vulnerabilities related to cloud misconfigurations, such as public S3 buckets.
*   **Mobile device:** Vulnerabilities like sideloading (installing apps from untrusted sources) or jailbreaking (removing OS restrictions).

### 2.4 Given a scenario, analyze indicators of malicious activity

#### Malware Attacks
*   **Ransomware:** Encrypts a victim's files and demands a ransom payment to decrypt them.
*   **Trojan:** Malware disguised as legitimate software.
*   **Worm:** Self-replicating malware that spreads across a network without human interaction.
*   **Spyware:** Malware that secretly monitors and collects information about a user.
*   **Virus:** Malicious code that attaches itself to a legitimate program and requires human action to spread.
*   **Keylogger:** Malware that records every keystroke a user makes.
*   **Logic bomb:** Malicious code that is programmed to execute when a specific condition is met (e.g., a certain date).
*   **Rootkit:** Malware designed to gain administrative-level control over a system while hiding its presence.

#### Network Attacks
*   **Distributed denial-of-service (DDoS):** An attack that overwhelms a target with traffic from many different sources, making it unavailable.
*   **On-path attack:** An attacker secretly intercepts and relays communication between two parties (formerly man-in-the-middle).
*   **DNS attacks:** Manipulating the Domain Name System. For example, DNS poisoning redirects users to a malicious site.

#### Application and Password Attacks
*   **Privilege escalation:** An attack where a user with limited access gains administrative-level permissions.
*   **Directory traversal:** An attack that allows access to files and directories stored outside the web root folder.
*   **Password spraying:** Trying a few common passwords against many different user accounts.
*   **Brute force:** Trying every possible password combination for a single account.

#### Indicators of Malicious Activity
*   **Account lockout:** Numerous failed login attempts causing an account to be locked.
*   **Concurrent session usage:** A single user account being used from multiple locations simultaneously.
*   **Impossible travel:** A user account logging in from geographically distant locations in an impossibly short amount of time.
*   **Resource consumption:** Unusually high CPU, memory, or network bandwidth usage.
*   **Missing logs:** Gaps in log files, which could indicate an attacker is covering their tracks.

### 2.5 Explain the purpose of mitigation techniques used to secure the enterprise

#### Core Techniques
*   **Segmentation:** Dividing a network into smaller, isolated sub-networks to contain breaches.
*   **Access control:** Using rules, like an Access Control List (ACL), to define what users or systems can access.
*   **Application allow list:** A security policy that only allows pre-approved applications to run, blocking all others.
*   **Isolation:** Separating a system or network segment from the rest of the environment. For example, running a suspicious application in a sandbox.
*   **Patching:** Applying updates to fix known vulnerabilities in software and operating systems.
*   **Encryption:** Converting data into an unreadable format to protect its confidentiality.
*   **Monitoring:** Continuously observing systems and networks for signs of malicious activity.
*   **Least privilege:** Granting users only the minimum level of access and permissions they need to perform their jobs.
*   **Decommissioning:** The formal process of securely retiring an asset (e.g., a server or application).

#### Hardening Techniques
*   **Hardening:** The process of reducing a system's attack surface by eliminating unnecessary software, services, and configurations.
*   **Installation of endpoint protection:** Deploying antivirus, anti-malware, and EDR solutions on devices.
*   **Host-based firewall:** A firewall that runs on an individual computer or device to protect it.
*   **Disabling ports/protocols:** Closing network ports and turning off protocols that are not needed.
*   **Default password changes:** Immediately changing default credentials on all new devices and software.
*   **Removal of unnecessary software:** Uninstalling any applications that are not required for business functions.
