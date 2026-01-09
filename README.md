**Introduction**

The Security Operation Center has transformed in the contemporary cybersecurity landscape from a traditional reactive monitoring model where alerts were acted upon after a security breach had already taken place. Signature-based detection was majorly relied on by the early iterations. The SOC has currently transformed to proactive threat hunting which assumes that a breach might have already taken place thus focusing on the iterative search through networks. The Security Information and Event Management remain central to this evolution; this is evident through platforms like Splunk that ingest large data from different places with an aim of providing real-time visibility. In this report I will be making use of Search Processing Language to analyze and correlate disperse data points from Botsv3 to display the complex attack patterns.

**BOTSv3 Exercise: Investigating Frothly**

A realistic simulation of a modern network environment under attack has been provided through the Boss of The SOC dataset. In this (Inc, 2018)report the focus is placed on Frothly which is a fictious brewery which is on the process of digital transformation by migrating its digital infrastructure to the cloud hence bringing forth several security breaches.

In this case Frothly is targeted by a threat actor group that is sophisticated, this will be done a simulation referred to as Advanced Persistent Threat.

**Objectives**

The main aim of this investigation is to use Splunk in navigate the Frothly environment and neutralize the threat through the following ways:

Identification of the Hardware Specifications through the establishment of a performance baseline by enumerating the hardware details and server assets.

Detecting misconfigurations on the cloud by auditing AWS environment to find S3 buckets which have been exposed, privilege escalations on IAM, and how API calls are made without utilizing Multi Factor Authentication.

**Scope**

The BOTSv3 dataset will confine the scope of this analysis, this dataset is made up of the following:

- AWS Cloud Trail: This will be used to perform an audit on the activity of the API and how events are managed on the cloud.
- Access Logs: This will aid in tracking how data moves and the security events for the bucket-level.

**Assumptions**

- **Data Integrity:** The log entries are an accurate representation of the activity of the system and time.
- **Time Synchronization:** The dataset has a consistent timestamp that will ensure consistency for the correlation of the logs globally, it follows the UTC+0 format.

**SOC Roles and Incident Handling Reflection**

A high-fidelity simulation is served by the BOTSv3 exercise on how collaboration is made by tiers of SOC as they work together in the lifecycle of incident handling. A practical application of the NIST Incident Response Framework will be illustrated by navigating the Frothly breweries to the cloud.

**Roles of SOC in BOTSv3**

I will step into the role of different SOC levels during the investigation; this can be summarized as below:

- **Tier 1:** In this triage phase a major focus will be placed on how data will be ingested and filtered since it will be the early stage of the exercise. I will wear the shoe of a tier one analysts and validate initial alerts to reduce false positives.
- **Tier 2:** In this investigative stage I will dive deeper to shift my role and analyze the correlation of the leaked AWS keys with the subsequent events.
- **Tier 3:** This will be a threat hunting phase and I will pivot from those alerts which are known to the unknown ones, a simulation will be done on the expert-level hunting. This is needed to show the persistence mechanisms of the covert.

**Incident Handling**

A reflection on the effectiveness of the mentioned investigative phases will be done through the BOTSv3 dataset.

- **Prevention:** In this phase a failure in the prevention phase will be revealed by data, this will focus on the absence of multi factor authentication on the sensitive accounts of AWS. The main aim will be to show the effectiveness of tools like Splunk when they are merged with identity controls that are strict.
- **Detection:** A correlation of data across CloudTrail and WinHostMon has been done by Splunk. Automated alerts and manual SPL searches have been used to achieve detection; this helped in flagging those API calls which are not authorized.
- **Response:** A reactive response is showcased through the exercise; a good example is a support case being opened by AWS. In the real world, the SOAR playbooks will be utilized in Tier 2 by a SOC analyst to instantly reject those credentials which have been compromised.
- **Recovery:** This entails the identification and recovery of those S3 buckets which have been affected. Detailed logs have been used by the exercise to prove how backdoors can be closed.

**Installation and Data Preparation**

The first step in simulating a SOC Infrastructure that is professional entails setting up a big lab environment. In the BOTSv3 exercise I utilized Ubuntu that is within a virtual box which hosts the Splunk Enterprise. The enterprise-grade server deployments have been mirrored by this configuration that provides a stable Linux-base foundation.

**Steps on How to Install Splunk on Ubuntu**

This installation was done on Ubuntu Desktop 22.0.4 LTS, this was chosen to ensure that Splunk remains stable and compatible with its dependencies.

The first step entailed acquiring the Splunk Enterprise .deb package from the official website.

![Alt text](Picture1.png)
- I then used the Debian manager to execute the installation

- Initialization: This entailed starting Splunk, and agreeing to the set terms and conditions using the script: sudo /opt/splunk/bin/splunk start --accept-license

- Boot Persistence: Ensured Splunk could automatically initialize upon the reboot of the system, this was through the following script: sudo /opt/splunk/bin/splunk enable boot-start

**Setup Justification:** The installation on a virtualized environment reduces the attack surface and the utilization of resources of the Security Information and Management (SIEM) host. The internal adapters of the virtual environment protect the BOTSv3 dataset by isolating it from the public network hence ensuring a simulation that is air-gapped SOC environment and secured.

Data Ingestion

The dataset in BOTSv3 is provided as pre-indexed application, this is different from the standard log ingestion since the data has already been parsed into packets.

The following steps were followed during the process:

- **Preparation:** I downloaded the BOTSv3 data from the official GitHub account through the provided link. I then followed the stated steps while installing the additional packages that were critical to the application.

- **Deployment:** In this stage I extracted the dataset directly into the directory that contains Splunk using the following script: sudo tar -zxvf botsv3_data_set.tgz -C /opt/splunk/etc/apps/

- **Permission:** This step entails ensuring the splunk user has access to the newly added files, this helps to prevent errors from the database and lock file issues, this was achieved using the following command: sudo chown -R splunk:splunk /opt/splunk/etc/apps/botsv3_data_set

- **Splunk Restart:** This ensures that splunk has been initialized to the new index.

**Data Validation**

The following validation metrics were utilized during the process:

- **Source Confirmation:** To confirm the source I ran the following query to ensure that the presence of the events: **index=botsv3 earliest=0**

- **Source Integrity:** I verified the presence of critical source types like the AWS cloud trail. aws:cloudtrail, S3AccessLogs, and WinHostMon using: index=botsv3 | stats count by sourcetype

- **Time Synchronization:** I used the UTC+0 time zone to ensure that the events were correctly synchronized.

**Guided Questions: 200-Level SOC Analysis**

In this section I will explore a set of 200-level questions that are from the BOTSv3 dataset, my main focus would be on cloud security and asset inventory. The tasks of a Tier 2 SOC Analyst would be simulated in these questions; the main investigation would be on the potential misconfigurations and establishing an inventory baseline in the midst of an accident.

Case Set: Cloud Integrity and Asset Inventory

**Question: What field would you use to alert that AWS API activity has taken place without Multi Factor Authentication (MFA)?**

**Answer:** userIdentity.sessionContext.attributes.mfaAuthenticated

Splunk Query to Use: index=botsv3 sourcetype="aws:cloudtrail" | table userIdentity.sessionContext.attributes.mfaAuthenticated, eventName, username

Relevance to SOC: Monitoring for Multi Factor Authentication is an important priority for Detection. In the Frothly environment, the Taedonggang group took advantage of those accounts that did not have multi factor authentication. It is very important for a SOC to have a real-time alert for console logins or API calls that are high-privilege like when creating access keys.

**Question 202: Web Server Hardware Baseline**

**What is the processor number that has been used on the web servers?**

**Answer:** E5-2676 v3 @2.40 GHZ

**Relevance to SOC:** Asset Management and Anomaly Detection entail the ability to identify hardware specifications. An analyst is able to detect unauthorized resource usage once he is able to identify the baseline CPU. A good example is when a web server all of a sudden indicates a full 100% CPU utilization on a separate architecture, a container escape or the deployment of a crypto mining binary by an attacker could be indicated.

**Q203 and Q204: The S3 Public Exposure Incident**

**Question: Bud accidentally makes an S3 bucket publicly accessible. What is the Event ID of the API call, and what is the Bucket Name?**

**Answer (Event ID):** ab45689d-69cd-41e7-8705-5350402cf7a

**Answer (Bucket Name):** frothlywebcode

Relevance To SOC: This is a good example of a cloud misconfiguration investigation. A SOC analyst should be able to identify the leaked bucket name and also roll back to S3 Access Logs to see files have been accessed by malicious actors or in the event when the bucket has been exposed.

**Conclusion and SOC Strategy Implications**

A high-flexibility simulation of the challenges faced by modern enterprises as they migrate to the cloud has been provided by BOTSv3 exercise. This simulation has revealed that in as much as scalability is one of the benefits of migrating to the cloud, it increases the attack surface in a significant manner. This requires a change to identity-centric monitoring from the traditional perimeter monitoring.

**Summary of Findings**

This investigation has managed to successfully trace activities and uncover a multi-stage intrusion:

- **Initial Foothold:** The leaking of AWS access keys to a public repository was clear evidence of the critical failure in evidence management.
- **Escalation of Privileges:** API calls that include creating access key were performed by the adversary, this was done after the exploitation of multi-factor authentication.
- **Data Exposure:** The frothlywebcode was used to compromise the sensitive corporate data, this happened after the data was left accessible to the public because of an administrative misconfiguration by Bud Stoll.
- **Hijacking of Resources:** The deployment of crypto mining software is among the post-compromise activity that I identified through the anomalous hardware performance logs.

**Key SOC Lessons that I have Learned**

Visibility remains to be foundation: The ability of Splunk to correlate CloudTrail events with WinHostMon and the S3 Access Logs is what contributed majorly towards the reconstruction of a kill chain.

Identity is the new perimeter: Traditional network firewalls were bypassed by the breach since it makes use of legitimate credentials which are stolen. User Entity Behavior Analytics is one thing that must be prioritized by the modern SOCs.

Being Proactive is greater than being reactive. It was only possible to establish a hardware baseline. This is a clear indication that looking for patch holes and problems which are not known is more effective as compared to waiting for signature alerts.

**Recommended Improvements for Detection and Response**

I am recommending the following SOC strategy measures in order to pervert the recurrence of the Frothly breach.

- **Detection:** A real-time splunk alert should be implemented for any console login or a high-privilege call in the scenarios where multi factor authentication cannot be used.
- **Prevention:** Secret scanning tools like Gigaradian should be integrated into Continuous Integration and Continuous Deployment pipeline to prevent AWS keys from being pushed to public repos accidentally.
- **Response:** Security Orchestration, Automation, and Response should be put in place to automatically stop IAM permissions, they should further rotate keys each time an S3 Public Access event has been detected.
- **Recovery:** Monthly assumed breach exercises should be conducted to confirm that logging remains active across all the new cloud regions and ephemeral assets.

# References

Inc, S. (2018). _Boss of the SOC (BOTSv3) Dataset._
