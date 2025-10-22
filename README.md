# Elevate-Labs-_-Task-2
This project demonstrates the identification and analysis of phishing emails. The project guides users through analyzing suspicious emails using headers, URLs, and domain information.


# Phishing Email Analysis
 **Aim**

To identify phishing characteristics in suspicious email samples and understand the techniques used by attackers.


 **Tools and Resources Used**

* **Email Client** – Gmail, Outlook, or any client with access to full email headers
* **MXToolbox Email Header Analyzer** – [https://mxtoolbox.com/EmailHeaders.aspx](https://mxtoolbox.com/EmailHeaders.aspx)
* **VirusTotal** – [https://www.virustotal.com/](https://www.virustotal.com/) (for URL analysis)
* **DNS Lookup Tool** – MXToolbox DNS Lookup or any equivalent online to
 **Steps to Analyze a Phishing Email**

1. **Select a Suspicious Email**

   * Example: Email claiming to be from Vodafone Idea requesting urgent verification.
   * Look for phishing indicators like generic greetings, urgent language, and suspicious links.

2. **View Email Header**

   * Open the original email → “View Source” / “Show Original”.
   * Copy the entire header for analysis.

3. **Analyze Email Header**

   * Paste the header into MXToolbox Email Header Analyzer.
   * Check:

     * **Return-Path** and **From** address authenticity
     * SPF/DKIM/DMARC validation
     * IP of sending server

4. **Check Suspicious URL**

   * Copy the link from the email body.
   * Scan using VirusTotal for malicious or phishing activity.

5. **Verify Domain Information**

   * Use DNS Lookup to check domain registration date, IP location, and association with official organization.

6. **Document Findings**

   * Identify phishing characteristics such as:

     * Fake sender domain
     * Failed authentication (SPF/DKIM/DMARC)
     * Malicious URLs
     * Urgent or threatening tone
     * Recently registered or unrelated dom

**Observations Example**

| Aspect                   | Observation                                              |
| ------------------------ | -------------------------------------------------------- |
| From Address             | `support@vodafone-idea.com` (fake domain)                |
| SPF/DKIM/DMARC           | Fail                                                     |
| URL                      | Detected as malicious on VirusTotal                      |
| Domain                   | Recently registered, unrelated to official Vodafone Idea |
| Phishing Characteristics | Urgent language, generic greeting, mismatched headers    |



 **Conclusion**

The analyzed email exhibits multiple phishing indicators. Users should avoid clicking links or sharing personal information and report suspicious emails to their organization or email provider.


 **References**

* [MXToolbox Email Header Analyzer](https://mxtoolbox.com/EmailHeaders.aspx)
* [VirusTotal](https://www.virustotal.com/)
* [Cybersecurity & Infrastructure Security Agency – Phishing Guidance](https://www.cisa.gov/phishing)


