# 1.1 Compare and contrast various types of security controls

## Security Control Categories
- **Technical**: Controls that use technology. For example, a firewall or encryption.
- **Managerial**: Policies and rules created by management. For example, user access policies and security training.
- **Operational**: The daily processes that enforce security. For example, log monitoring and vulnerability scanning.
- **Physical**: Tangible controls you can touch. For example, locks, fences, and security guards.

## Security Control Types
- **Preventive**: Acts to stop a security event from happening.
- **Deterrent**: Discourages a potential attacker from even trying.
- **Detective**: Identifies a security event that is already in progress or has occurred.
- **Corrective**: Fixes damage and restores a system after an incident.
- **Compensating**: A substitute control when the primary one is not feasible.
- **Directive**: A policy or guideline that dictates security behavior.


# 1.2 Summarize Fundamental Security Concepts

- **Confidentiality, Integrity, and Availability (CIA)**: The core principles of information security. Confidentiality ensures data is private, Integrity ensures it has not been altered, and Availability ensures it is accessible when needed.

- **Non-repudiation**: The assurance that a party cannot deny an action.  This is often achieved with digital signatures.

- **Authentication, Authorization, and Accounting (AAA)**:
  - **Authentication**: Verifies a user's identity.
  - **Authorization**: Grants access to resources based on identity.
  - **Accounting**: Tracks and logs user actions for auditing.

- **Gap Analysis**: The process of comparing a current state to a desired future state to identify what is missing.

- **Zero Trust**: A security model based on the principle of "never trust, always verify." Every user and device must be authenticated and authorized before gaining access. It operates on a control plane (managing access) and a data plane (the network where data resides).

- **Physical Security**: Tangible measures to protect assets. This includes bollards to stop vehicles, access control vestibules (mantraps) to control entry, fences, video surveillance, security guards, access badges, and adequate lighting.

- **Deception and Disruption Technology**: Intentionally misleading attackers. A honeypot is a decoy system, a honeynet is a network of decoys, a honeyfile is a decoy file, and a honeytoken is a piece of data designed to be attractive to an attacker.


# 1.3 Explain the Importance of Change Management Processes

Change management is a formal process for managing all changes to an IT environment to minimize security risks.

## Business Processes:
- **Approval Process**: All changes must be formally approved by stakeholders and an owner.
- **Impact Analysis**: The potential effect of the change on security and business operations is assessed.
- **Test Results**: Changes are tested in a non-production environment before deployment.
- **Backout Plan**: A plan to reverse the change if it causes issues.
- **Maintenance Window**: A specific time frame for making the change to minimize disruption.
- **Standard Operating Procedure (SOP)**: A written guide to ensure consistent and secure execution of the change.

## Technical Implications:
- **Allow/Deny Lists**: Changes to these lists can inadvertently block legitimate traffic or allow malicious traffic.
- **Downtime/Restarts**: Changes to systems or applications often require planned downtime or service restarts, which can disrupt business operations.
- **Legacy Applications**: Older applications may be fragile and have unexpected issues with changes.
- **Dependencies**: Changes to one system can break others that depend on it.

## Documentation:
- **Updating Diagrams**: Network and system diagrams must be kept current to reflect changes.
- **Updating Policies/Procedures**: Security policies and standard operating procedures (SOPs) must be revised to include the new changes.
- **Version Control**: Using a version control system ensures that all changes to code or configurations are tracked, allowing for easy rollback if needed.


# 1.4 Cryptographic Solutions

- **Public Key Infrastructure (PKI)**: A system for creating, managing, and revoking digital certificates.
- **Public Key**: A key that can be shared openly to encrypt data or verify a digital signature.
- **Private Key**: A secret key that is kept confidential to decrypt data or create a digital signature.
- **Key Escrow**: A process where a copy of a private key is securely stored by a third party.
- **Encryption**: The process of converting data into an unreadable format.

## Types of Encryption:
- **Asymmetric**: Uses a public/private key pair. Slower but allows for secure key exchange.
- **Symmetric**: Uses a single shared secret key. Faster but requires a secure way to share the key.
- **Key Exchange**: The process of securely sharing cryptographic keys.
- **Algorithms**: The mathematical rules used for encryption (e.g., AES, RSA).

## Tools:
- **Trusted Platform Module (TPM)**: A chip on a motherboard that stores cryptographic keys and provides a hardware-based root of trust.
- **Hardware Security Module (HSM)**: A physical computing device that safeguards and manages digital keys.
- **Secure Enclave**: A secure, isolated area on a processor that protects data from the rest of the system.

## Techniques:
- **Obfuscation**: Techniques to intentionally make data difficult to understand or analyze.
- **Steganography**: Hiding data within another file (e.g., an image or audio file).
- **Tokenization**: Replacing sensitive data with a unique, non-sensitive identifier.
- **Data Masking**: Hiding or replacing sensitive data with realistic-looking, but false, data.
- **Hashing**: A one-way function that creates a unique, fixed-length value (hash) from data. It's used for integrity checking, as any change to the data will result in a different hash.
- **Salting**: Random data added to a password before it is hashed. This protects against rainbow table attacks.
- **Digital Signatures**: A cryptographic method used for non-repudiation and integrity. It proves the authenticity of a message or document and that it has not been altered.
- **Key Stretching**: Techniques used to make a weak password more difficult to crack by increasing the computational effort required to test each guess.

## Advanced Concepts:
- **Blockchain/Open Public Ledger**: A decentralized, distributed ledger that stores an immutable record of transactions. Used for security and transparency.
- **Certificates**: Electronic documents used to verify a user or server's identity.
- **Certificate Authorities (CAs)**: Trusted organizations that issue digital certificates.
- **Certificate Revocation Lists (CRLs)**: A list of certificates that have been revoked and should no longer be trusted.
- **Online Certificate Status Protocol (OCSP)**: A protocol for real-time validation of certificate status.
- **Root of Trust**: A public key trusted implicitly by a system. All certificates in a chain must link back to a trusted root.
- **Certificate Signing Request (CSR)**: A file generated by a server and sent to a CA to request a digital certificate.
- **Wildcard**: A certificate that secures multiple subdomains under a single domain.
