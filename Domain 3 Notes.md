## Domain 3.0: Security Architecture

### 3.1 Compare and contrast security implications of different architecture models

#### Architecture and Infrastructure Concepts
*   **Cloud:** Using remote servers hosted on the internet to store, manage, and process data.
*   **Responsibility matrix:** A chart showing who is responsible for securing different parts of a cloud environment (the cloud provider vs. the customer).
*   **Hybrid considerations:** A mix of on-premises and cloud infrastructure. Security policies must be consistent across both environments.
*   **Infrastructure as code (IaC):** Managing and provisioning infrastructure through code and automation instead of manual processes. For example, using a script to deploy 100 servers.
*   **Serverless:** A cloud model where the cloud provider manages the servers, and developers just provide code that runs on-demand.
*   **Microservices:** An application is built as a collection of small, independent services. A failure in one service does not take down the entire application.
*   **Network infrastructure:**
    *   **Air gapped:** A system or network that is completely physically isolated from any other network.
    *   **Logical segmentation:** Dividing a network into smaller zones using software. For example, creating VLANs to separate the accounting department's network from marketing.
    *   **Software-defined networking (SDN):** Managing network services through a centralized software controller instead of configuring individual devices.
*   **On-premises:** Infrastructure is located within the organization's own physical data center.
*   **Containerization:** A lightweight form of virtualization where applications run in isolated user spaces. For example, Docker.
*   **Virtualization:** Creating a virtual version of a server, storage device, or network. One physical server can host multiple virtual servers.
*   **IoT (Internet of Things):** A network of physical devices (e.g., smart thermostats, cameras) embedded with sensors and software. Often have weak security.
*   **ICS/SCADA:** Systems used to control industrial processes like manufacturing plants or power grids.
*   **RTOS (Real-time operating system):** An OS used in systems where timing is critical. For example, car engines or medical devices. Often difficult or impossible to patch.
*   **Embedded systems:** A computer with a dedicated function within a larger device. For example, the computer in a smart TV.
*   **High availability:** A design approach that ensures a system is always operational and has very little downtime.

### 3.2 Given a scenario, apply security principles to secure enterprise infrastructure

#### Infrastructure Considerations
*   **Device placement:** The physical and logical location of a device in the network. For example, placing a web server in a DMZ.
*   **Security zones:** A segment of a network where all devices have a similar security posture. For example, a trusted internal zone and an untrusted external zone.
*   **Attack surface:** The total number of points through which an attacker could try to exploit a system. Hardening is used to reduce the attack surface.
*   **Failure modes:**
    *   **Fail-open:** When a security control fails, it defaults to an open state, allowing all traffic. For example, a fire escape door that unlocks when the power fails.
    *   **Fail-closed:** When a security control fails, it defaults to a closed state, blocking all traffic. This is the more secure option.
*   **Device attribute:**
    *   **Active vs. passive:** Active devices (like an IPS) take action to block threats. Passive devices (like an IDS) only monitor and alert.
    *   **Inline vs. tap/monitor:** An inline device is placed directly in the path of network traffic. A tap (or monitor) receives a copy of the traffic.

#### Network Appliances
*   **Jump server:** A highly secured and monitored server used to access and manage devices in a separate security zone.
*   **Proxy server:** A server that acts as an intermediary between a client and another server, often used to filter content or hide the client's identity.
*   **IPS/IDS:** An Intrusion Prevention System (IPS) is an active device that blocks attacks. An Intrusion Detection System (IDS) is a passive device that detects and alerts on attacks.
*   **WAF (Web application firewall):** A firewall that protects web applications from attacks like SQL injection and cross-site scripting.
*   **NGFW (Next-generation firewall):** A modern firewall that can inspect application-layer traffic and has integrated IDS/IPS capabilities.
*   **802.1X:** A port-based network access control (PNAC) standard that authenticates a device before allowing it to connect to the network.

#### Secure Communication/Access
*   **VPN (Virtual private network):** Creates a secure, encrypted "tunnel" over an untrusted network like the internet.
*   **Tunneling (TLS, IPSec):** Protocols used to create the secure tunnel for a VPN. IPSec operates at the Network Layer (Layer 3), while TLS operates at the Transport Layer (Layer 4).
*   **SD-WAN (Software-defined wide area network):** A centralized, software-based approach to managing and securing connections across multiple locations.
*   **SASE (Secure access service edge):** A cloud-native model that combines network services (like SD-WAN) and security services (like a firewall) into a single, unified platform.

### 3.3 Compare and contrast concepts and strategies to protect data

#### Data Classifications
*   **Sensitive:** Data that must be protected from unauthorized disclosure. A general term.
*   **Confidential:** Data meant for internal use only. A breach would cause damage.
*   **Public:** Data that can be shared with anyone without risk.
*   **Private:** Personal data about individuals (e.g., PII, PHI).
*   **Critical:** Data that is essential for the organization to function.

#### General Data Considerations
*   **Data states:**
    *   **Data at rest:** Data stored on a physical medium. For example, a file on a hard drive. Secure with encryption.
    *   **Data in transit:** Data being transmitted across a network. For example, an email being sent. Secure with TLS or IPSec.
    *   **Data in use:** Data being processed in memory (RAM) or by the CPU. Secure with a secure enclave.
*   **Data sovereignty:** The concept that data is subject to the laws of the country where it is stored.

#### Methods to Secure Data
*   **Geographic restrictions:** Limiting access to data based on a user's physical location.
*   **Encryption:** Converting data into an unreadable format.
*   **Hashing:** Creating a unique, fixed-length "digital fingerprint" of data to verify integrity.
*   **Masking:** Hiding parts of data with placeholder characters. For example, showing a credit card number as `************1234`.
*   **Tokenization:** Replacing sensitive data with a non-sensitive equivalent called a token.
*   **Obfuscation:** Making code or data intentionally difficult for humans to understand.

### 3.4 Explain the importance of resilience and recovery in security architecture

#### High Availability
*   **Load balancing:** Distributing incoming network traffic across multiple servers to ensure no single server gets overloaded.
*   **Clustering:** Connecting multiple servers so they work as a single, highly available system. If one server fails, another takes over automatically.
*   **Site considerations:**
    *   **Hot:** A fully operational duplicate data center ready for immediate failover.
    *   **Cold:** An empty data center with power and cooling. Takes weeks or months to bring online.
    *   **Warm:** A data center with hardware installed, but not configured. Faster than cold, but still requires setup time.
*   **Geographic dispersion:** Placing backup data centers in different geographic locations to protect against regional disasters like earthquakes or hurricanes.

#### Continuity of Operations
*   **Testing:**
    *   **Tabletop exercises:** A discussion-based meeting where team members walk through a hypothetical disaster scenario.
    *   **Failover:** Testing the ability to switch from a primary system to a backup system.
*   **Backups:**
    *   **On-site/off-site:** Keeping backups locally for quick recovery and remotely for disaster protection.
    *   **Snapshots:** A point-in-time copy of a virtual machine or file system.
    *   **Replication:** Continuously copying data from a primary system to a secondary one in real-time.
*   **Power:**
    *   **Generators:** Provides long-term backup power using fuel like diesel or natural gas.
    *   **UPS (Uninterruptible power supply):** A large battery that provides immediate, short-term power to allow systems to shut down gracefully or until a generator starts.
