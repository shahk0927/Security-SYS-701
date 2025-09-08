## 2.1 Compare and Contrast Common Threat Actors and Motivations
Threat actors are individuals or groups who pose a security risk. Understanding who they are and what drives them is key to effective defense.

### Threat Actors

*   **Nation-state:** Governments using cyber capabilities for espionage or warfare.
*   **Unskilled attacker:** An individual with limited technical knowledge, often using pre-made tools (script kiddies).
*   **Hacktivist:** An individual or group driven by political or social beliefs, often using cyberattacks for protest.
*   **Insider threat:** A current or former employee, contractor, or partner who exploits their authorized access.
*   **Organized crime:** Criminal groups using cyberattacks for financial gain.
*   **Shadow IT:** Unauthorized systems or applications used within an organization, creating unmanaged vulnerabilities.

### Attributes of Actors

*   **Internal/External:** Is the threat actor from inside or outside the organization's perimeter?
*   **Resources/Funding:** The amount of money, equipment, and time available to the actor.
*   **Level of sophistication/capability:** The technical skills and knowledge of the actor.

### Motivations

*   **Data exfiltration:** Stealing sensitive data.
*   **Espionage:** Gaining confidential information, often for a government or competitor.
*   **Service disruption:** Causing a denial of service (DoS) or other interruptions.
*   **Blackmail:** Threatening to release data unless a ransom is paid.
*   **Financial gain:** Stealing money or financial information.
*   **Philosophical/political beliefs:** Attacking to make a statement or protest.
*   **Ethical:** An ethical hacker acting to expose vulnerabilities without malicious intent.
*   **Revenge:** Attacking an organization or person out of spite.
*   **Disruption/chaos:** Attacking simply to cause turmoil.
*   **War:** Attacks as part of a military conflict.

## 2.2 Explain Common Threat Vectors and Attack Surfaces
A threat vector is the path an attack takes, while the attack surface is the total area where an organization is vulnerable to attack.

### Supply Chain

*   **Managed service providers (MSPs):** Attackers may compromise an MSP to gain access to all its clients, as seen in the SolarWinds attack.
*   **Vendors & Suppliers:** A vendor or supplier can be a weak link, allowing an attacker to insert malicious code or hardware into the final product.

### Human Vectors/Social Engineering

*   **Phishing:** A fraudulent email sent to many people to trick them into revealing information or clicking a malicious link.
*   **Vishing (Voice phishing):** Phishing conducted over the phone.
*   **Smishing (SMS phishing):** Phishing via text message.
*   **Misinformation/Disinformation:** Sharing false or misleading information to cause confusion or influence decisions.
*   **Impersonation:** An attacker pretends to be someone else to gain trust.
*   **Business email compromise (BEC):** An attacker tricks an employee into transferring funds or sensitive data.
*   **Pretexting:** An attacker creates a fabricated scenario to obtain information.
*   **Watering hole:** An attacker compromises a website that a target group frequently visits to infect their computers.
*   **Brand impersonation:** An attacker creates a fake website or social media profile to mimic a legitimate brand.
*   **Typo squatting:** An attacker registers a domain name that is a common misspelling of a legitimate site.

### Other Threat Vectors / Attack Surfaces

*   **Message-based:** Attacks delivered via digital messages, including email, Short Message Service (SMS), and Instant messaging (IM).
*   **Image-based:** Malicious code hidden within an image file (steganography).
*   **File-based:** Malware hidden within a seemingly harmless file like a PDF or Word document.
*   **Voice call:** A social engineering attack via telephone (vishing).
*   **Removable device:** A thumb drive or external hard drive containing malware.
*   **Vulnerable software:** Exploiting a known weakness in an application, either with a client-based or agentless scanning approach.
*   **Unsupported systems and applications:** Software that no longer receives security patches, leaving it open to attack.
*   **Unsecure networks:** Networks that lack proper security controls, including wireless, wired, and Bluetooth networks.
*   **Open service ports:** Network ports that are open and exposed to the internet.
*   **Default credentials:** Accounts that use factory-set usernames and passwords.

## 2.3 Explain Various Types of Vulnerabilities
Vulnerabilities are weaknesses in a system that can be exploited by an attacker.

### Application Vulnerabilities

*   **Injection:** An attacker sends malicious code as data to a vulnerable application, causing the application to execute the code. This includes SQL injection.
*   **Buffer overflow:** Writing more data to a buffer than it can hold.
*   **Race conditions:** An outcome depends on the unpredictable sequence of events, which an attacker can exploit, like Time-of-check (TOC) to Time-of-use (TOU).
*   **Malicious update:** An attacker compromises an update server to distribute malware.

### Operating System (OS)-based Vulnerabilities

*   Flaws in the OS itself.

### Web-based Vulnerabilities

*   **Structured Query Language injection (SQLi):** An attacker uses malicious SQL code to manipulate a database.
*   **Cross-site scripting (XSS):** An attacker injects malicious scripts into a trusted website, which are then executed by other users' browsers.

### Hardware Vulnerabilities

*   **Firmware:** Vulnerabilities in a device's firmware.
*   **End-of-life:** Hardware no longer supported by the manufacturer.
*   **Legacy:** Older hardware that may have known vulnerabilities.

### Virtualization Vulnerabilities

*   **Virtual machine (VM) escape:** An attacker breaks out of a VM to access the host system.
*   **Resource reuse:** A VM retains data from a previous user, which a new user can access.

### Other Vulnerability Types

*   **Cloud-specific:** Misconfigured cloud services, such as public S3 buckets.
*   **Supply chain:** Vulnerabilities introduced via third-party hardware or software providers.
*   **Cryptographic:** Weak or outdated encryption algorithms or improper key management.
*   **Misconfiguration:** A system is not configured securely, leaving it exposed.
*   **Mobile device:**
    *   **Side loading:** Installing an application from an unofficial source.
    *   **Jailbreaking:** Modifying a mobile device's OS to bypass security restrictions.
*   **Zero-day:** A previously unknown vulnerability for which no patch exists.

## 2.4 Given a Scenario, Analyze Indicators of Malicious Activity
Indicators of malicious activity help identify a security incident.

### Malware Attacks

*   **Ransomware:** Encrypts files and demands a ransom.
*   **Trojan:** Malware disguised as legitimate software.
*   **Worm:** Self-replicating malware.
*   **Spyware:** Secretly monitors user activity.
*   **Bloatware:** Unwanted software.
*   **Virus:** Malicious code that attaches to other programs.
*   **Keylogger:** Records keystrokes.
*   **Logic bomb:** Malware that activates when a specific condition is met.
*   **Rootkit:** Malware that hides its presence and gives an attacker privileged access.

### Physical Attacks

*   **Brute force:** Physically forcing a lock or door open.
*   **Radio frequency identification (RFID) cloning:** Duplicating an RFID badge.
*   **Environmental:** Attacks that disrupt a data center's environment (e.g., cutting power).

### Network Attacks

*   **Distributed denial-of-service (DDoS):** A flood of traffic from multiple sources to overwhelm a server.
*   **Amplified:** A DDoS attack that uses a third-party service to increase the volume of traffic.
*   **Reflected:** A DDoS attack where the attacker spoofs the victim's IP address and sends requests to a third-party server.
*   **Domain Name System (DNS) attacks:** Attacks that manipulate DNS to redirect users to malicious websites.
*   **Wireless:** Attacks on Wi-Fi networks, such as rogue access points.
*   **On-path (Man-in-the-middle):** An attacker secretly intercepts communication between two parties.
*   **Credential replay:** An attacker captures valid login credentials and reuses them.
*   **Malicious code:** Code (like an exploit) sent over a network to target a vulnerability.

### Application Attacks

*   **Injection:** Sending malicious code as data to a vulnerable application.
*   **Buffer overflow:** Overwriting a buffer's memory.
*   **Replay:** Intercepting and retransmitting a valid data transmission.
*   **Privilege escalation:** Gaining a higher level of access.
*   **Forgery:** Creating a fake message or request.
*   **Directory traversal:** Accessing files outside of the intended directory.

### Cryptographic Attacks

*   **Downgrade:** Forcing a connection to use a less secure protocol.
*   **Collision:** Finding two different inputs that produce the same hash.
*   **Birthday:** A type of collision attack.

### Password Attacks

*   **Spraying:** Trying one password against many accounts.
*   **Brute force:** Systematically trying every possible password.

### Indicators of Malicious Activity

*   **Account lockout:** Indicates a brute-force or password-spraying attack.
*   **Concurrent session usage:** A single user logged in from multiple locations at the same time.
*   **Blocked content:** Unexpected attempts to access blocked content.
*   **Impossible travel:** A user logs in from two distant locations in a very short time.
*   **Resource consumption:** A spike in resource usage.
*   **Resource inaccessibility:** A resource becomes unavailable.
*   **Out-of-cycle logging:** Logs are missing or altered.
*   **Published/documented:** Malicious activity that has been publicly reported.
*   **Missing logs:** A gap in log files.

## 2.5 Explain the Purpose of Mitigation Techniques Used to Secure the Enterprise
Mitigation techniques are used to reduce or eliminate vulnerabilities and threats.

*   **Segmentation:** Dividing a network into smaller, isolated segments to limit an attacker's lateral movement.
*   **Access control:** Limiting access to resources based on a user's identity using an Access Control List (ACL) and permissions.
*   **Application allow list:** A list of approved applications that are permitted to run.
*   **Isolation:** Separating a compromised system from the network.
*   **Patching:** Applying software updates to fix vulnerabilities.
*   **Encryption:** Converting data into an unreadable format.
*   **Monitoring:** Continuously observing systems for malicious activity.
*   **Least privilege:** Granting users only the minimum permissions necessary.
*   **Configuration enforcement:** Using tools to ensure systems are configured securely.
*   **Decommissioning:** The secure removal of systems and data that are no longer in use.

### Hardening Techniques

*   **Encryption:** Encrypting data.
*   **Installation of endpoint protection:** Using security software on endpoints.
*   **Host-based firewall:** A firewall that protects a single host.
*   **Host-based intrusion prevention system (HIPS):** A system that monitors and blocks malicious activity on a host.
*   **Disabling ports/protocols:** Closing unnecessary network ports.
*   **Default password changes:** Immediately changing default credentials.
*   **Removal of unnecessary software:** Uninstalling unneeded programs.
