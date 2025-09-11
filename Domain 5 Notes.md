## Domain 5.0: Security Program Management and Oversight

### 5.1 Summarize Elements of Effective Security Governance

#### Document Hierarchy
*   **Policies:** High-level statements of management's intent. The "what" and "why."
    *   **Acceptable Use Policy (AUP):** Rules for how employees can use company IT resources. For example, "no personal streaming on the corporate network."
    *   **Information Security Policies:** Rules for protecting data confidentiality, integrity, and availability.
    *   **Business Continuity / Disaster Recovery:** Plans for how the business will operate during and after a major disruption.
    *   **Incident Response:** Policy outlining the organization's plan for reacting to and managing security breaches.
    *   **Software Development Lifecycle (SDLC):** Policy ensuring security is integrated into every phase of software development.
    *   **Change Management:** Policy outlining procedures for making controlled changes to IT systems to minimize risk.
*   **Standards:** Mandatory requirements that enforce policies. The "how specific." For example, "all passwords must be at least 14 characters and use MFA."
    *   **Password Standard:** Specific rules for password complexity, length, and management.
    *   **Access Control Standard:** Defines how access to resources is granted, managed, and revoked.
    *   **Physical Security Standard:** Requirements for protecting physical assets, suchs as server rooms and offices.
    *   **Encryption Standard:** Mandates the types and strengths of encryption to be used for data at rest and in transit.
*   **Guidelines:** Recommendations and best practices. Not mandatory but strongly advised. For example, "it is recommended to restart your computer weekly."
*   **Procedures:** Step-by-step instructions for a specific task. The "step-by-step how." For example, a procedure for onboarding a new employee.
    *   **Change Management Procedure:** Detailed steps for submitting, reviewing, approving, and implementing system changes.
    *   **Onboarding/Offboarding Procedure:** Step-by-step instructions for granting/revoking access and managing accounts for new/departing employees.
    *   **Playbooks:** A specific type of procedure designed for incident response, providing a checklist of actions.

#### External Considerations
*   **Regulatory:** Laws passed by a government body. For example, HIPAA for healthcare data.
*   **Legal:** Rules related to courts and lawsuits.
*   **Industry:** Standards required by a specific industry. For example, PCI-DSS for credit card processing.
*   **Geographic:** Rules specific to a location (Local, National, Global). For example, GDPR in Europe.
    *   **Local/Regional:** City or state-specific ordinances.
    *   **National:** Country-specific laws (e.g., CCPA in the US).
    *   **Global:** International laws or agreements (e.g., GDPR in Europe).

#### Monitoring and Revision
*   The ongoing process of reviewing and updating security governance documents to ensure they remain relevant, effective, and compliant with current threats and regulations.

#### Governance Structures and Roles
*   **Governance Structures:** How decisions are made.
    *   **Boards:** Executive-level bodies providing strategic direction and oversight for security.
    *   **Committees:** Groups formed to address specific security topics, make recommendations, or manage projects.
    *   **Government Entities:** Public sector organizations with specific mandates or regulatory powers influencing security.
    *   **Centralized:** One central team makes all security decisions.
    *   **Decentralized:** Local teams or departments have security authority.
*   **Roles and Responsibilities:** Who is responsible for the data.
    *   **Owner:** Ultimately accountable for the data. Usually a senior manager.
    *   **Controller:** Decides the purpose and means of processing personal data.
    *   **Processor:** Processes data on behalf of the controller. For example, a cloud provider.
    *   **Custodian/Steward:** Hands-on role that manages and protects the data day-to-day.

---

### 5.2 Explain Elements of the Risk Management Process

#### Risk Identification
*   The process of discovering, recognizing, and describing risks that could affect the organization's objectives.

#### Risk Assessment
*   The overall process of identifying, analyzing, and evaluating risks.
    *   **Ad hoc:** Assessments performed irregularly, usually in response to a specific event or need.
    *   **Recurring:** Assessments performed on a scheduled, periodic basis (e.g., quarterly or annually).
    *   **One-time:** A single assessment performed for a specific purpose, without intent for repetition.
    *   **Continuous:** Ongoing, real-time monitoring and assessment of risks and controls.

#### Risk Analysis
*   **Qualitative:** Based on opinion and categories. Uses labels like High, Medium, Low. It is subjective and fast.
*   **Quantitative:** Uses numbers and formulas to assign a monetary value to risk. It is objective and data-driven.
    *   **Single Loss Expectancy (SLE):** The cost of a single incident. SLE = Asset Value ($) * Exposure Factor (%)
    *   **Annualized Rate of Occurrence (ARO):** How many times an incident is expected to happen per year.
    *   **Annualized Loss Expectancy (ALE):** The expected cost per year from an incident. ALE = SLE * ARO
    *   **Probability:** The likelihood of a specific event occurring, expressed as a fraction or percentage.
    *   **Likelihood:** The qualitative or quantitative possibility of something happening (often used interchangeably with probability).
    *   **Exposure Factor (EF):** The percentage of an asset's value that would be lost if a specific incident occurred.
    *   **Impact:** The magnitude of harm that could result from a security breach or incident.

#### Risk Concepts
*   **Risk Register:** A central document that lists all identified risks, their severity, and their mitigation plans.
*   **Key Risk Indicators (KRIs):** Metrics used to provide an early signal of increasing risk exposure in a specific area.
*   **Risk Owners:** Individuals or departments responsible for managing specific risks assigned to them in the risk register.
*   **Risk Appetite:** The amount of risk an organization is willing to pursue for its objectives.
    *   **Expansionary:** High willingness to take risks for potential high returns.
    *   **Conservative:** Low willingness to take risks, prioritizing security and stability.
    *   **Neutral:** Balanced approach, willing to take moderate risks for moderate returns.
*   **Risk Tolerance:** The acceptable level of deviation from the risk appetite.
*   **Risk Threshold:** The specific point at which a risk becomes unacceptable.

#### Risk Management Strategies
*   **Transfer (or Share):** Make someone else responsible for the risk. For example, buying insurance.
*   **Accept:** Acknowledge the risk and do nothing. Done when the cost to fix is greater than the potential loss.
    *   **Exemption:** A formal declaration that a specific system or process is excluded from a security control, usually due to a unique circumstance.
    *   **Exception:** A temporary deviation from a security policy or standard, granted under specific conditions.
*   **Avoid:** Stop doing the activity that causes the risk.
*   **Mitigate (or Reduce):** Implement a control to reduce the likelihood or impact of the risk. For example, installing a firewall.

#### Risk Reporting
*   The process of communicating identified risks, their status, and mitigation efforts to relevant stakeholders and management.

#### Business Impact Analysis (BIA) Metrics
*   **Recovery Time Objective (RTO):** The maximum acceptable time to get a system back online after a failure. "How fast do we need to be back up?"
*   **Recovery Point Objective (RPO):** The maximum acceptable amount of data loss, measured in time. "How much data can we afford to lose?"
*   **Mean Time to Repair (MTTR):** The average time it takes to repair a failed system.
*   **Mean Time Between Failures (MTBF):** The average time a system operates before it fails.

---

### 5.3 Explain the processes associated with third-party risk assessment and management

#### Vendor Assessment
*   The review process itself, which may include:
    *   **Penetration Testing:** Allowing your team to test the vendor's security.
    *   **Right-to-audit clause:** A contract clause that gives you permission to audit the vendor's security controls.
    *   **Evidence of internal audits:** Reviewing reports from the vendor's own internal security audits.
    *   **Independent assessments:** Reviewing reports from third-party audits of the vendor (e.g., SOC reports).
    *   **Supply chain analysis:** Evaluating the risk from your vendor's vendors.

#### Vendor Selection
*   **Due diligence:** The process of investigating a vendor before signing a contract to ensure they meet your security requirements.
*   **Conflict of interest:** A situation where a vendor's interests might unfairly influence their services or decisions, potentially compromising security.

#### Agreement Types
*   **Service-level agreement (SLA):** Defines specific performance metrics, like uptime of 99.9%.
*   **Memorandum of agreement (MOA):** A more formal version of an MOU, often involving the exchange of services or funds.
*   **Memorandum of understanding (MOU):** A non-binding agreement that outlines a general understanding between two parties.
*   **Master service agreement (MSA):** A contract that defines the general terms and conditions that will govern all future agreements or work between the parties.
*   **Work order (WO)/statement of work (SOW):** Documents detailing specific tasks, deliverables, timelines, and costs for a particular project or service under an MSA.
*   **Non-disclosure agreement (NDA):** A legal contract to ensure confidentiality.
*   **Business partners agreement (BPA):** A legal document that defines the responsibilities and liabilities of each partner in a business relationship.

#### Vendor Monitoring
*   **Questionnaires:** Sending regular security questionnaires to vendors to verify their controls.
*   **Rules of engagement:** A document that defines the scope and limits of a security test (like a pen test) against a vendor.

---

### 5.4 Summarize elements of effective security compliance

#### Compliance reporting
*   **Internal:** Reports on compliance status generated for internal management and stakeholders.
*   **External:** Reports on compliance status provided to external regulatory bodies, auditors, or customers.

#### Consequences of non-compliance
*   The "why" we must be compliant.
    *   **Fines:** Financial penalties from regulators.
    *   **Sanctions:** Official penalties or prohibitions.
    *   **Reputational damage:** Loss of customer trust.
    *   **Loss of license:** Revocation of an operating license or certification required for business.
    *   **Contractual impacts:** Penalties or termination of contracts due to failure to meet agreed-upon security clauses.

#### Compliance monitoring
*   The ongoing process of ensuring adherence to security policies, standards, and regulatory requirements.
*   **Due diligence/care:** The continuous effort and investigation to ensure compliance and protect assets.
*   **Attestation and acknowledgement:** Formal confirmation of compliance or understanding of policies, often signed by employees or management.
    *   **Internal and external:** Attestations can be for internal policies or for external regulatory compliance.
*   **Automation:** Using tools and systems to automatically check for compliance with defined rules and configurations.

#### Privacy
*   **Legal implications:** The consequences stemming from laws related to privacy.
    *   **Local/regional:** Laws specific to a city or region regarding data privacy.
    *   **National:** Country-specific privacy laws (e.g., CCPA).
    *   **Global:** International privacy regulations (e.g., GDPR).
*   **Data subject:** The individual whose data is being collected (e.g., the customer).
*   **Controller vs. processor:** The controller decides what to do with data; the processor acts on the controller's instructions.
*   **Ownership:** The party responsible for the data and its protection, often the data controller.
*   **Data inventory and retention:** Knowing what data you have, where it is, and how long you are required to keep it.
*   **Right to be forgotten:** A principle that allows a data subject to request the deletion of their personal data.

---

### 5.5 Explain types and purposes of audits and assessments

#### Attestation
*   A formal declaration or certification that controls or processes are in place and operating effectively.
*   **Internal:** Attestations made by internal management or auditors.
*   **Compliance:** Attestations specifically related to adherence to regulatory or industry standards.
*   **Audit committee:** An oversight body that receives and reviews audit findings and attestations.
*   **Self-assessments:** An organization's internal evaluation of its own security posture against a set of criteria.

#### External
*   Performed by an independent third party.
*   **Regulatory:** An external audit required by law or a regulatory body.
*   **Examinations:** A thorough review or inspection of an organization's records, processes, or systems by an external party.

#### Assessment
*   A broad term for evaluating security, including audits, vulnerability scans, and penetration tests.
*   **Independent third-party audit:** A review conducted by an unbiased external entity to provide an objective opinion on security controls.

#### Penetration testing
*   **Physical:** Testing the physical security controls of a facility to identify weaknesses (e.g., tailgating, unauthorized entry).
*   **Offensive:** Simulating an attacker to find vulnerabilities (e.g., pen testing).
*   **Defensive:** Evaluating and improving security controls (e.g., security audits).
*   **Integrated:** A testing approach that combines offensive and defensive techniques to evaluate both attack and defense capabilities.
*   **Known environment (White-Box):** The tester has full knowledge of the network and systems.
*   **Partially known environment (Gray-Box):** The tester has some information, like user credentials.
*   **Unknown environment (Black-Box):** The tester has no prior knowledge and simulates an external attacker.

#### Reconnaissance
*   **Passive:** Gathering information from publicly available sources (e.g., Google searches, social media).
*   **Active:** Directly interacting with the target to gather information (e.g., port scanning).

---

### 5.6 Given a scenario, implement security awareness practices

#### Phishing
*   Training users to recognize and report suspicious emails.
*   **Campaigns:** Simulated phishing attacks sent to users to test their awareness.
*   **Recognizing a phishing attempt:** Specific training on identifying common indicators like suspicious sender, generic greetings, urgent requests, and bad grammar.
*   **Responding to reported suspicious messages:** Procedures for IT security teams to analyze reported phishing attempts and take appropriate action.

#### Anomalous behavior recognition
*   Training users to spot unusual activity on their accounts or systems.
*   **Risky:** Behavior that deviates from normal patterns and could indicate a security threat.
*   **Unexpected:** Activity that is out of the ordinary or not anticipated.
*   **Unintentional:** Actions that may unintentionally lead to security vulnerabilities.

#### User guidance training
*   **Policy/handbooks:** Educating users on the organization's security policies and procedures as documented in handbooks.
*   **Situational awareness:** Training users to understand their environment, identify potential threats, and react appropriately.

#### Insider threat
*   Awareness of threats that come from current or former employees.

#### Password management
*   Education on creating strong passwords and using password managers.

#### Removable media and cables
*   Policies on the use of USB drives and other external devices. Training on securing cables to prevent physical tampering or data interception.

#### Social engineering
*   Making users aware of psychological manipulation tactics (e.g., pretexting, baiting).

#### Operational security
*   The practices and procedures used to protect sensitive information from falling into the wrong hands.
*   **Hybrid/remote work environments:** Special training for securing home networks, using VPNs, and protecting physical devices outside the office.
*   **Reporting and monitoring:** Establishing a clear and easy process for users to report security incidents.
    *   **Initial:** Training for the first time users are exposed to security awareness topics.
    *   **Recurring:** Regular, ongoing training to reinforce security concepts and address new threats.
*   **Development:** Providing security training to developers (e.g., secure coding practices).
*   **Education:** Broad term encompassing all forms of security awareness and training provided to users.
