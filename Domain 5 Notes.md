## Domain 5.0: Security Program Management and Oversight

### 5.1 Summarize Elements of Effective Security Governance

#### Document Hierarchy
*   **Policies:** High-level statements of management's intent. The "what" and "why."
*   **Acceptable Use Policy (AUP):** Rules for how employees can use company IT resources. For example, "no personal streaming on the corporate network."
*   **Information Security Policies:** Rules for protecting data confidentiality, integrity, and availability.
*   **Business Continuity / Disaster Recovery:** Plans for how the business will operate during and after a major disruption.
*   **Standards:** Mandatory requirements that enforce policies. The "how specific." For example, "all passwords must be at least 14 characters and use MFA."
*   **Guidelines:** Recommendations and best practices. Not mandatory but strongly advised. For example, "it is recommended to restart your computer weekly."
*   **Procedures:** Step-by-step instructions for a specific task. The "step-by-step how." For example, a procedure for onboarding a new employee.
*   **Playbooks:** A specific type of procedure designed for incident response, providing a checklist of actions.

#### External Considerations
*   **Regulatory:** Laws passed by a government body. For example, HIPAA for healthcare data.
*   **Legal:** Rules related to courts and lawsuits.
*   **Industry:** Standards required by a specific industry. For example, PCI-DSS for credit card processing.
*   **Geographic:** Rules specific to a location (Local, National, Global). For example, GDPR in Europe.

#### Governance Structures and Roles
*   **Governance Structures:** How decisions are made.
    *   **Centralized:** One central team makes all security decisions.
    *   **Decentralized:** Local teams or departments have security authority.
*   **Roles and Responsibilities:** Who is responsible for the data.
    *   **Owner:** Ultimately accountable for the data. Usually a senior manager.
    *   **Controller:** Decides the purpose and means of processing personal data.
    *   **Processor:** Processes data on behalf of the controller. For example, a cloud provider.
    *   **Custodian/Steward:** Hands-on role that manages and protects the data day-to-day.

### 5.2 Explain Elements of the Risk Management Process

#### Risk Analysis
*   **Qualitative:** Based on opinion and categories. Uses labels like High, Medium, Low. It is subjective and fast.
*   **Quantitative:** Uses numbers and formulas to assign a monetary value to risk. It is objective and data-driven.
*   **Single Loss Expectancy (SLE):** The cost of a single incident. SLE = Asset Value ($) * Exposure Factor (%)
*   **Annualized Rate of Occurrence (ARO):** How many times an incident is expected to happen per year.
*   **Annualized Loss Expectancy (ALE):** The expected cost per year from an incident. ALE = SLE * ARO

#### Risk Concepts
*   **Risk Register:** A central document that lists all identified risks, their severity, and their mitigation plans.
*   **Risk Appetite:** The amount of risk an organization is willing to pursue for its objectives.
*   **Risk Tolerance:** The acceptable level of deviation from the risk appetite.
*   **Risk Threshold:** The specific point at which a risk becomes unacceptable.

#### Risk Management Strategies
*   **Transfer (or Share):** Make someone else responsible for the risk. For example, buying insurance.
*   **Accept:** Acknowledge the risk and do nothing. Done when the cost to fix is greater than the potential loss.
*   **Avoid:** Stop doing the activity that causes the risk.
*   **Mitigate (or Reduce):** Implement a control to reduce the likelihood or impact of the risk. For example, installing a firewall.

#### Business Impact Analysis (BIA) Metrics
*   **Recovery Time Objective (RTO):** The maximum acceptable time to get a system back online after a failure. "How fast do we need to be back up?"
*   **Recovery Point Objective (RPO):** The maximum acceptable amount of data loss, measured in time. "How much data can we afford to lose?"
*   **Mean Time to Repair (MTTR):** The average time it takes to repair a failed system.
*   **Mean Time Between Failures (MTBF):** The average time a system operates before it fails.

### 5.3 Explain Third-Party Risk Management

#### Vendor Assessment and Selection
*   **Due Diligence:** The process of investigating a vendor before signing a contract to ensure they meet your security requirements.
*   **Vendor Assessment:** The review process itself, which may include:
    *   **Penetration Testing:** Allowing your team to test the vendor's security.
    *   **Right-to-Audit Clause:** A contract clause that gives you permission to audit the vendor's security controls.
    *   **Supply Chain Analysis:** Evaluating the risk from your vendor's vendors.

#### Agreement Types
*   **Service-Level Agreement (SLA):** Defines specific performance metrics, like uptime of 99.9%.
*   **Memorandum of Understanding (MOU):** A non-binding agreement that outlines a general understanding between two parties.
*   **Memorandum of Agreement (MOA):** A more formal version of an MOU, often involving the exchange of services or funds.
*   **Non-Disclosure Agreement (NDA):** A legal contract to ensure confidentiality.

#### Vendor Monitoring
*   **Questionnaires:** Sending regular security questionnaires to vendors to verify their controls.
*   **Rules of Engagement:** A document that defines the scope and limits of a security test (like a pen test) against a vendor.

### 5.4 Summarize Elements of Effective Security Compliance

#### Compliance Drivers
*   **Consequences of Non-Compliance:** The "why" we must be compliant.
    *   **Fines:** Financial penalties from regulators.
    *   **Sanctions:** Official penalties or prohibitions.
    *   **Reputational Damage:** Loss of customer trust.
*   **Due Care / Due Diligence:**
    *   **Due Care:** Acting as a reasonable person would. The ongoing effort to protect assets.
    *   **Due Diligence:** The investigation and research done before an action.

#### Privacy Concepts
*   **Data Subject:** The individual whose data is being collected (e.g., the customer).
*   **Controller vs. Processor:** The controller decides what to do with data; the processor acts on the controller's instructions.
*   **Data Inventory and Retention:** Knowing what data you have, where it is, and how long you are required to keep it.
*   **Right to be Forgotten:** A principle that allows a data subject to request the deletion of their personal data.

### 5.5 Explain Types and Purposes of Audits and Assessments

#### Audit & Assessment Categories
*   **Internal:** Performed by your own organization (e.g., self-assessments).
*   **External:** Performed by an independent third party.
*   **Regulatory:** An external audit required by law or a regulatory body.

#### Penetration Testing (Pen Test)
*   **Testing Scope (Based on Knowledge):**
    *   **Known Environment (White-Box):** The tester has full knowledge of the network and systems.
    *   **Partially Known Environment (Gray-Box):** The tester has some information, like user credentials.
    *   **Unknown Environment (Black-Box):** The tester has no prior knowledge and simulates an external attacker.
*   **Testing Approaches:**
    *   **Offensive:** Simulating an attacker to find vulnerabilities (e.g., pen testing).
    *   **Defensive:** Evaluating and improving security controls (e.g., security audits).

#### Reconnaissance
*   **Passive:** Gathering information from publicly available sources (e.g., Google searches, social media).
*   **Active:** Directly interacting with the target to gather information (e.g., port scanning).

### 5.6 Given a Scenario, Implement Security Awareness Practices

#### Key Training Topics
*   **Phishing:** Training users to recognize and report suspicious emails.
*   **Campaigns:** Simulated phishing attacks sent to users to test their awareness.
*   **Anomalous Behavior Recognition:** Training users to spot unusual activity on their accounts or systems.
*   **Insider Threat:** Awareness of threats that come from current or former employees.
*   **Password Management:** Education on creating strong passwords and using password managers.
*   **Removable Media:** Policies on the use of USB drives and other external devices.
*   **Social Engineering:** Making users aware of psychological manipulation tactics (e.g., pretexting, baiting).

#### Operational Considerations
*   **Hybrid/Remote Work Environments:** Special training for securing home networks, using VPNs, and protecting physical devices outside the office.
*   **Reporting and Monitoring:** Establishing a clear and easy process for users to report security incidents.
*   **Development:** Providing security training to developers (e.g., secure coding practices).
