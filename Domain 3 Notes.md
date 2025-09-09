## Domain 3.0: Security Architecture

### 3.1 Compare and contrast security implications of different architecture models

#### Architecture and Infrastructure Concepts
*   **Cloud:** Using remote servers hosted on the internet to store, manage, and process data.
    *   **Responsibility matrix:** A chart showing who is responsible for securing different parts of a cloud environment (the cloud provider vs. the customer).
    *   **Hybrid considerations:** A mix of on-premises and cloud infrastructure. Security policies must be consistent across both environments.
    *   **Third-party vendors:** External organizations providing services or software, introducing supply chain risk.
*   **Infrastructure as code (IaC):** Managing and provisioning infrastructure through code and automation instead of manual processes. For example, using a script to deploy 100 servers.
*   **Serverless:** A cloud model where the cloud provider manages the servers, and developers just provide code that runs on-demand.
*   **Microservices:** An application is built as a collection of small, independent services. A failure in one service does not take down the entire application.
*   **Network infrastructure:**
    *   **Physical isolation:** Completely separating a network or system by physical means (e.g., separate cables, dedicated hardware) to prevent unauthorized access.
    *   **Air gapped:** A system or network that is completely physically isolated from any other network, having no direct connection.
    *   **Logical segmentation:** Dividing a network into smaller zones using software. For example, creating VLANs to separate the accounting department's network from marketing.
    *   **Software-defined networking (SDN):** Managing network services through a centralized software controller instead of configuring individual devices.
*   **On-premises:** Infrastructure is located within the organization's own physical data center.
*   **Centralized vs. decentralized:**
    *   **Centralized:** All resources and control points are in one location. Easier management, but a single point of failure.
    *   **Decentralized:** Resources and control points are distributed across multiple locations or systems. More resilient, but complex to secure consistently.
*   **Containerization:** A lightweight form of virtualization where applications run in isolated user spaces. For example, Docker.
*   **Virtualization:** Creating a virtual version of a server, storage device, or network. One physical server can host multiple virtual servers.
*   **IoT (Internet of Things):** A network of physical devices (e.g., smart thermostats, cameras) embedded with sensors and software. Often have weak security.
*   **Industrial control systems (ICS)/supervisory control and data acquisition (SCADA):** Systems used to control industrial processes like manufacturing plants or power grids.
*   **Real-time operating system (RTOS):** An OS used in systems where timing is critical. For example, car engines or medical devices. Often difficult or impossible to patch.
*   **Embedded systems:** A computer with a dedicated function within a larger device. For example, the computer in a smart TV.
*   **High availability:** A design approach that ensures a system is always operational and has very little downtime.

#### Considerations (for all architecture models)
*   **Availability:** Ensuring systems and data are accessible when needed.
*   **Resilience:** The ability of a system to recover from failures and maintain functionality.
*   **Cost:** Financial implications of implementing and maintaining security controls.
*   **Responsiveness:** How quickly a system or application responds to requests.
*   **Scalability:** The ability of a system to handle an increasing amount of work or users.
*   **Ease of deployment:** How simple or complex it is to set up and configure the architecture.
*   **Risk transference:** Shifting the financial burden of risk to another party (e.g., cyber insurance, outsourcing).
*   **Ease of recovery:** How quickly and efficiently systems and data can be restored after an incident.
*   **Patch availability:** The regularity and ease with which security updates are provided for systems.
*   **Inability to patch:** Systems (e.g., some embedded, ICS, RTOS) that cannot be easily updated, leaving them vulnerable.
*   **Power:** Ensuring a stable and redundant power supply for critical systems.
*   **Compute:** The processing power and resources available to run applications and security tools.

### 3.2 Given a scenario, apply security principles to secure enterprise infrastructure

#### Infrastructure Considerations
*   **Device placement:** The physical and logical location of a device in the network. For example, placing a web server in a DMZ.
*   **Security zones:** A segment of a network where all devices have a similar security posture. For example, a trusted internal zone and an untrusted external zone.
*   **Attack surface:** The total number of points through which an attacker could try to exploit a system. Hardening is used to reduce the attack surface.
*   **Connectivity:** How devices and networks communicate with each other, including protocols and allowed paths.
*   **Failure modes:**
    *   **Fail-open:** When a security control fails, it defaults to an open state, allowing all traffic. For example, a fire escape door that unlocks when the power fails. Prioritizes availability over security.
    *   **Fail-closed:** When a security control fails, it defaults to a closed state, blocking all traffic. This is the more secure option. Prioritizes security over availability.
*   **Device attribute:**
    *   **Active vs. passive:** Active devices (like an IPS) take action to block threats. Passive devices (like an IDS) only monitor and alert.
    *   **Inline vs. tap/monitor:** An inline device is placed directly in the path of network traffic. A tap (or monitor) receives a copy of the traffic for analysis without disrupting the flow.

#### Network Appliances
*   **Jump server:** A highly secured and monitored server used to access and manage devices in a separate security zone, enforcing administrative access control.
*   **Proxy server:** A server that acts as an intermediary between a client and another server, often used to filter content or hide the client's identity.
*   **Intrusion protection system (IPS)/Intrusion detection system (IDS):** An Intrusion Prevention System (IPS) is an active device that blocks attacks. An Intrusion Detection System (IDS) is a passive device that detects and alerts on attacks.
*   **Load balancer:** Distributes incoming network traffic across multiple servers to ensure no single server gets overloaded, enhancing availability.
*   **Sensors:** Devices or software agents that collect data (e.g., network traffic, logs) for security monitoring and threat detection.
*   **Port security (802.1X, Extensible Authentication Protocol [EAP]):**
    *   **802.1X:** A port-based network access control (PNAC) standard that authenticates a device before allowing it to connect to the network.
    *   **Extensible Authentication Protocol (EAP):** A framework for authentication often used with 802.1X, allowing various authentication methods.
*   **Firewall types:**
    *   **Web application firewall (WAF):** A firewall that protects web applications from attacks like SQL injection and cross-site scripting by inspecting HTTP traffic.
    *   **Unified threat management (UTM):** An all-in-one security appliance combining multiple security features (e.g., firewall, IDS/IPS, anti-virus, content filtering) into a single device.
    *   **Next-generation firewall (NGFW):** A modern firewall that can inspect application-layer traffic, has integrated IDS/IPS capabilities, and often includes deep packet inspection and threat intelligence.
    *   **Layer 4/Layer 7:** Refers to the OSI model layers at which the firewall operates. Layer 4 (Transport) filters based on ports and protocols. Layer 7 (Application) filters based on application content.

#### Secure Communication/Access
*   **Virtual private network (VPN):** Creates a secure, encrypted "tunnel" over an untrusted network like the internet, providing confidentiality and integrity.
*   **Remote access:** The ability to access internal network resources from an external location securely.
*   **Tunneling (Transport Layer Security [TLS], Internet Protocol Security [IPSec]):** Protocols used to create the secure tunnel for a VPN. IPSec operates at the Network Layer (Layer 3), while TLS operates at the Transport Layer (Layer 4).
*   **Software-defined wide area network (SD-WAN):** A centralized, software-based approach to managing and securing connections across multiple locations, optimizing traffic and applying policies.
*   **Secure access service edge (SASE):** A cloud-native model that combines network services (like SD-WAN) and security services (like a firewall, CASB, ZTNA) into a single, unified platform for distributed workforces.
*   **Selection of effective controls:** Choosing the right security measures based on risk assessment, cost, and organizational needs, following a risk-based approach.

### 3.3 Compare and contrast concepts and strategies to protect data

#### Data types
*   **Regulated:** Data subject to specific laws and regulations (e.g., HIPAA, GDPR, PCI DSS), requiring strict protection.
*   **Trade secret:** Confidential business information that provides a competitive edge (e.g., formulas, designs, practices).
*   **Intellectual property:** Creations of the mind (e.g., inventions, literary works, designs, symbols), legally protected.
*   **Legal information:** Data related to legal proceedings, contracts, or compliance.
*   **Financial information:** Data related to monetary transactions, accounts, and financial performance.
*   **Human- and non-human-readable:**
    *   **Human-readable:** Data easily understood by humans (e.g., text documents, images).
    *   **Non-human-readable:** Data in a format primarily for machines (e.g., binary code, encrypted files, database entries without context).

#### Data Classifications
*   **Sensitive:** Data that must be protected from unauthorized disclosure. A general term often encompassing other classifications.
*   **Confidential:** Data meant for internal use only. A breach would cause damage to the organization.
*   **Public:** Data that can be shared with anyone without risk to the organization.
*   **Restricted:** Data that is highly sensitive and access is severely limited, often with legal or regulatory protections (e.g., classified government data).
*   **Private:** Personal data about individuals (e.g., PII, PHI). Disclosure can harm individuals.
*   **Critical:** Data that is essential for the organization to function. Its loss would lead to immediate and severe operational disruption.

#### General Data Considerations
*   **Data states:**
    *   **Data at rest:** Data stored on a physical medium (e.g., hard drive, backup tape). Secure with encryption.
    *   **Data in transit:** Data being transmitted across a network (e.g., email, web traffic). Secure with TLS or IPSec.
    *   **Data in use:** Data being processed in memory (RAM) or by the CPU. Secure with methods like secure enclaves.
*   **Data sovereignty:** The concept that data is subject to the laws of the country where it is stored, dictating storage location.
*   **Geolocation:** The physical location where data is stored or processed, impacting data sovereignty and compliance.

#### Methods to Secure Data
*   **Geographic restrictions:** Limiting access to data based on a user's physical location or limiting data storage to specific regions.
*   **Encryption:** Converting data into an unreadable format using an algorithm and a key, primarily for confidentiality.
*   **Hashing:** Creating a unique, fixed-length "digital fingerprint" of data to verify integrity (one-way function, not for confidentiality).
*   **Masking:** Hiding parts of data with placeholder characters. For example, showing a credit card number as `************1234`.
*   **Tokenization:** Replacing sensitive data with a non-sensitive equivalent called a token, with the actual sensitive data stored separately.
*   **Obfuscation:** Making code or data intentionally difficult for humans to understand, often used to deter reverse engineering rather than provide strong security.
*   **Segmentation:** Isolating data stores or networks to prevent unauthorized access or limit the blast radius of a breach.
*   **Permission restrictions:** Implementing access control lists (ACLs) or role-based access control (RBAC) to limit who can access, modify, or delete data based on least privilege.

### 3.4 Explain the importance of resilience and recovery in security architecture

#### High Availability
*   **Load balancing vs. clustering:**
    *   **Load balancing:** Distributing incoming network traffic across multiple servers to ensure no single server gets overloaded, improving performance and availability.
    *   **Clustering:** Connecting multiple servers so they work as a single, highly available system. If one server fails, another takes over automatically (failover).
*   **Site considerations:** Strategies for disaster recovery sites.
    *   **Hot:** A fully operational duplicate data center ready for immediate failover with continuous data replication, offering minimal downtime.
    *   **Cold:** An empty data center with basic infrastructure (power, cooling) but no hardware or data. Low cost, long recovery time.
    *   **Warm:** A data center with hardware installed and some data replicated, but not fully configured or operational. Moderate cost and recovery time.
*   **Geographic dispersion:** Placing backup data centers in different geographic locations to protect against regional disasters like earthquakes or hurricanes.
*   **Platform diversity:** Using different operating systems, hardware vendors, or cloud providers for primary and backup systems to reduce single points of failure.
*   **Multi-cloud systems:** Utilizing services from multiple cloud providers to avoid vendor lock-in and increase resilience against a single cloud provider outage.

#### Continuity of Operations (Ensuring ongoing business functions during/after disruption)
*   **Capacity planning:** Ensuring that current and future infrastructure resources are sufficient to meet operational demands, especially during peak loads or disaster recovery.
    *   **People:** Having enough trained staff for recovery, cross-training.
    *   **Technology:** Sufficient servers, network devices, storage, and software.
    *   **Infrastructure:** Adequate power, cooling, physical space, and network connectivity.
*   **Testing:** Validating recovery plans and systems.
    *   **Tabletop exercises:** A discussion-based meeting where team members walk through a hypothetical disaster scenario to identify gaps in plans.
    *   **Fail over:** The process of switching from a primary system to a backup system in the event of a failure, a crucial test of recovery.
    *   **Simulation:** Running a mock disaster, actively testing systems and procedures without impacting production, more realistic than tabletop.
    *   **Parallel processing:** Running identical processes on multiple systems simultaneously to ensure consistency and immediate failover capability, often used for critical, real-time systems.
*   **Backups:** Copies of data taken at specific points in time.
    *   **On-site/off-site:** Keeping backups locally for quick recovery (on-site) and remotely (off-site) for disaster protection.
    *   **Frequency:** How often backups are performed (e.g., daily, hourly, continuous), determining the maximum data loss (RPO).
    *   **Encryption:** Encrypting backup data to protect its confidentiality if the backup media is stolen or compromised.
    *   **Snapshots:** A point-in-time copy of a virtual machine or file system, allowing for quick restoration to a previous state.
*   **Recovery:** The process of restoring systems and data after an incident.
    *   **Replication:** Continuously copying data or virtual machines from a primary system to a secondary one, often in real-time or near real-time, for minimal data loss.
    *   **Journaling:** A file system feature that records changes before they are actually made to the disk, allowing for faster and more consistent recovery after a crash.
*   **Power:** Essential for continuous operation.
    *   **Generators:** Provides long-term backup power using fuel like diesel or natural gas during prolonged outages.
    *   **UPS (Uninterruptible power supply):** A large battery that provides immediate, short-term power to allow systems to shut down gracefully or until a generator starts, protecting against power fluctuations.
