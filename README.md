# C2-Daily-Feed

This repository provides a daily updated list of IP addresses derived from Criminal IP (https://www.criminalip.io/) under the C2_TI license. Our goal is to offer a daily sample of 50 malicious IP addresses identified by the Criminal IP real-time threat hunting search engine, specializing in OSINT-based Cyber Threat Intelligence (CTI). This includes Command and Control (C2, C&C) IP addresses categorized under the C2_TI license.

Hosted on Criminal IP's official GitHub, this repository serves as a direct access point to our threat intelligence data. By showcasing a subset of our comprehensive data, we aim to raise awareness of potential threats and inspire users to delve deeper into our complete range of threat intelligence offerings.

For enhanced security response processes with broader threat intelligence insights, please contact us (https://www.criminalip.io/contact-us) to inquire about samples and API access for our complete dataset.

## Overview

The selection criteria for the IP addresses listed in this repository are based on various conditions such as Criminal IP's threat tags (https://www.criminalip.io/developer/filters-and-tags/tags) and honeypot detections. This ensures a diverse representation of threats within the C2_TI dataset. The repository updates daily with a sample of 50 IP addresses, providing insights into a subset of the extensive C2_TI data.

These IP addresses are intentionally chosen to reflect a broad spectrum of conditions, showcasing different types of threats identified by Criminal IP's real-time threat hunting capabilities.

## Criteria for IP Selection

- **Tags:** IPs with C2_xx tags.
- **Honeypot Detections:** IPs caught in honeypots.
- **Additional conditions** as specified by senior analysts.

## Data Fields

The data provided includes the following fields, identical to those in the C2_TI license:

| Field                  | Description                                           |
|------------------------|-------------------------------------------------------|
| **IP Address**         | The IP address.                                       |
| **Target C2**          | Type of Command and Control server.                   |
| **Open Ports**         | Ports open on the IP address (formatted as [80, 443]).|
| **Score (Inbound/Outbound)** | Threat score for inbound and outbound traffic.  |
| **Country**            | Country of origin.                                    |
| **Scan Time**          | Time when the scan was conducted.                     |


## Example of Daily IP Addresses List

Here is an example of the daily list format:

| IP Address     | Target C2      | Open Ports | Score (Inbound/Outbound) | Country | Scan Time             |
|----------------|----------------|------------|--------------------------|---------|-----------------------|
| [88.119.174.117](https://www.criminalip.io/asset/report/88.119.174.117)  | c2_covenant | 7443 | Low/Critical | US | 2024-07-02 15:16:16 |
| [20.51.184.161](https://www.criminalip.io/asset/report/20.51.184.161)  | c2_posh | 443 | Low/Critical | EG | 2024-06-24 01:41:57 |
| [143.198.40.134](https://www.criminalip.io/asset/report/143.198.40.134)  | c2_mythic | 80 | Low/Critical | CA | 2024-07-22 22:17:34 |
