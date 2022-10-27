---
title: "Encrypted Client Hello Deployment Considerations"
abbrev: "ECH Deployment Considerations"
docname: draft-campling-ech-deployment-considerations-latest
category: info

ipr: trust200902
cat: info
submissiontype: IETF
area: SEC
wg: secdispatch

stand_alone: yes
smart_quotes: no
pi: [toc, sortrefs, symrefs]

lang: en
kw:
  - ECH
  - Enterprises
  - Operational Security
author:
- role: editor
  ins: A.J. Campling
  name: Andrew Campling
  org: 419 Consulting Limited
  email: Andrew.Campling@419.Consulting
  uri: https://www.419.Consulting/
- role: editor
  ins: P. Vixie
  name: Paul Vixie
  org: Red Barn
  email: paul@redbarn.org
  uri: http://www.redbarn.org/
- role: editor
  ins: D. Wright
  name: David Wright
  org: UK Safer Internet Centre
  email: david.wright@swgfl.org.uk
  uri: https://saferinternet.org.uk/
- role: editor # remove if not true
  ins: A. Taddei
  name: Arnaud Taddei
  org: Broadcom
  street: 1320 Ridder Park Dr
  city: San Jose
  region: CA
  code: 95131
  country: US # use TLD (except UK) or country name
  phone: +41795061129
  email: Arnaud.Taddei@broadcom.com
  uri: https://www.linkedin.com/in/arnaudtaddei/
- role: editor # remove if not true
  ins: S. Edwards
  name: Simon Edwards
  org: Broadcom
  street: 1320 Ridder Park Dr
  city: San Jose
  region: CA
  code: 95131
  country: US # use TLD (except UK) or country name
  email: Simon.Edwards@broadcom.com
  uri: https://www.linkedin.com/in/simononsecurity/
contributor: # Same structure as author list, but goes into contributors
- name: Eric Chien
  org: Broadcom
  email: Eric.Chien@broadcom.com
  uri: https://www.linkedin.com/in/eric-chien-66b4b258/
  contribution: |
    Eric contributed to the analysis of the Man in the Browser attacks.
- name: Gianpaolo Scalone
  org: Vodafone
  email: gianpaolo-angelo.scalone@vodafone.com
  uri: https://www.linkedin.com/in/gianpaoloscalone/
  contribution: |
    Gianpaolo contributed the research on the Digital Markets Act (DMA) EU law conflict with ECH.
- name: Daniel Engberg
  org: Skandinaviska Enskilda Banken AB (SEB)
  email: daniel.engberg@seb.se
  uri: https://www.linkedin.com/in/daniel-engberg-1561aaa/
  contribution:
    Validate the issues for his organization.


normative:
  RFC8484:


informative:
  CIPA:
    title: Children's Internet Protection Act (CIPA)
    target: https://www.fcc.gov/consumers/guides/childrens-internet-protection-act/
    author:
    - org: FCC
    date: 2019-12-30
  Coroner:
    title: Prevention of future deaths report
    target: https://www.judiciary.uk/publications/frances-thomas-prevention-of-future-deaths-report/
    author:
    - name: Henderson
    date: 2021-11-26
  ECH_Roundtable:
    title: Encrypted Client Hello - Notes from an ECH Roundtable
    target: https://419.consulting/encrypted-client-hello/
    author:
    - org: 419 Consulting
    date: 2021-08-18
  KCSE:
    title: Keeping children safe in education 2021
    target: https://419.consulting/encrypted-client-hello/
    author:
    - org: DfE
    date: 2021-11-01
  Bloomberg:
    title: Wall Street's Record Fines Over WhatsApp Use Were Years in the Making
    target: https://www.bloomberg.com/news/articles/2022-08-16/wall-street-sticker-shock-whatsapp-fines-were-years-in-making
    author:
    - name: Stefania Spezzati
      org: Bloomberg
    - name: Matt Robinson
      org: Bloomberg
    - name: Lydia Beyoud
      org: Bloomberg
    date: 2022-08-16
  CLESS:
    title: Capabilities and Limitations of Endpoint Security Solutions
    target: https://www.ietf.org/archive/id/draft-taddei-smart-cless-introduction-03.txt
    author:
    - name: Arnaud Taddei
      org: Symantec
    - name: Candid Wueest
      org: Acronis
    - name: Kevin Roundy
      org: Norton Lifelock
    - name: Dominique Lazanski
      org: Last Press Label
    date: 2020-07-13
  MAGECART:
    target: https://en.wikipedia.org/wiki/Web_skimming#Magecart
    title: Magecart
    author:
    - org: Wikipedia
    date: 2022-04-03
  MALVERTISING:
    target: https://en.wikipedia.org/wiki/Malvertising
    title: Malvertising
    author:
    - org: Wikipedia
    date: 2022-06-02
  MITB:
    target: https://owasp.org/www-community/attacks/Man-in-the-browser_attack
    title: Man-in-the-browser attack
    author:
    - org: OWASP
    date:
  MITB-MITRE:
    target: https://attack.mitre.org/techniques/T1185/
    title: Browser Session Hijacking - T1185
    author:
    - org: MITRE
    date: 2022-02-25
  NIST-DID:
    target: https://csrc.nist.gov/glossary/term/defense_in_depth#:~:text=Definition(s)%3A,and%20missions%20of%20the%20organization.
    title: Glossary - defense-in-depth
    author:
    - org: NIST
    date:
  OPSECNSIMPACT:
    title: Impact of TLS 1.3 to Operational Network Security Practices
    target: https://datatracker.ietf.org/doc/html/draft-ietf-opsec-ns-impact-04
    author:
    - name: N. Cam-Winget
      org: Cisco Systems, Inc.
    - name: E. Wang
      org: Cisco Systems, Inc.
    - name: R. Danyliw
      org: Software Engineering Institute
    - name:  R. DuToit
      org: Broadcom
    date: 2021-01-26
  SMART:
    title: BCP72 - A Problem Statement
    target: https://datatracker.ietf.org/doc/draft-mcfadden-smart-threat-changes/
    author:
    - name: M. McFadden
      org: internet policy advisors
    date: 2022-01-21
  SOLARWIND:
    target: https://symantec.broadcom.com/en/solarwinds-sunburst-attacks
    title: SolarWinds (Sunburst) Attack What You Need to Know
    author:
    - org: Symantec, a Division of Broadcom Software Group
    date: 2020-12
  RFC8890:
  RFC7258:
  RFC8404:
  RFC8744:
  I-D.draft-ietf-tls-esni:
  I-D.draft-ietf-opsec-indicators-of-compromise:


--- abstract

This document is intended to inform the development of the proposed
Encrypted Client Hello (ECH) standard that encrypts Server Name
Indication (SNI) and other data.  Data encapsulated by ECH (ie data
included in the encrypted ClientHelloInner) is of legitimate interest
to on-path security actors including anti-virus software, parental
controls and consumer and enterprise network, endpoint, information mandatory security controls.


The document includes observations on current use cases for SNI data
in a variety of contexts.  It highlights how the use of that data is
important to the operators of private networks and shows how the loss
of access to SNI data will cause difficulties in the provision of a
range of services to many millions of end-users.


--- middle




# Introduction


As noted above, this document includes observations on current use
cases for SNI data in a variety of contexts.  It highlights how the
use of that data is important to the operators of private networks
and shows how the loss of access to SNI data will cause difficulties
in the provision of a range of services to many millions of end-
users.


The Internet was envisaged as a network of networks, each able to
determine what data to transmit and receive from their peers.
Developments like ECH mark a fundamental change in the architecture
of the Internet, allowing opaque paths to be established from
endpoints to commercial services, some potentially without the
knowledge or permission of the device owners.  This change should not
be undertaken lightly given both the architectural impact on the
Internet and potentially adverse security implications for end users.
Given these implications, it certainly should not be undertaken
without either the knowledge or consultation of end users, as
outlined in {{RFC8890}}.


NB Whilst it is reasonable to counter that VPNs also establish opaque
paths, a primary difference is that the use of a VPN is a deliberate
act by the user, rather than a choice made by client software,
potentially without either the knowledge and/or consent of the end-
user or device owner.


{{RFC7258}} discusses the critical need to protect users'
privacy when developing IETF specifications and also recognises that
making networks unmanageable to mitigate pervasive monitoring is not
an acceptable outcome.


{{RFC8404}} discusses current security and network operations
as well as management practices that may be impacted by the shift to
increased use of encryption to help guide protocol development in
support of manageable and secure networks.  As {{RFC8404}} notes, "the
implications for enterprises that own the data on their networks or
that have explicit agreements that permit the monitoring of user
traffic are very different from those for service providers who may
be accessing content in a way that violates privacy considerations".


This document considers the implications of ECH for private network
operators including enterprises and education establishments.  The
data encapsulated by ECH is of legitimate interest to on-path
security actors including anti-virus software, parental controls and
consumer and enterprise network, endpoint, information and mandatory
security controls.  This document will focus specifically on
the impact of encrypting the SNI data by ECH on private networks,
but it should be noted that other elements will be relevant for some
on-path security methods.


# Encrypted Server Name Indication


{{RFC8744}} describes the general problem of encrypting the
Server Name Identification (SNI) TLS extension.  The document
includes a brief description of what it characterises as
"unanticipated" usage of SNI information (section 2.1) as well as a
brief (two paragraph) assessment of alternative options in the event
that the SNI data is encrypted (section 2.3).


The text in {{RFC8744}} suggests that most of the unanticipated SNI
usage "could also be implemented by monitoring DNS traffic or
controlling DNS usage", although it does then acknowledge the
difficulties posed by encrypted DNS protocols.  It asserts, with
limited evidence, that "most of functions can, however, be realized
by other means", although without considering or quantifying the
affordability, operational complexity, technical capability of
affected parties or privacy implications that
might be involved.  It is unclear from the document whether any
stakeholders that may be impacted by the encryption of SNI data have
been consulted; it does not appear to be the case that any such
consultation has taken place.


The characterisation of "unanticipated usage" of SNI data could be
taken to imply that such usage was not approved and therefore
inappropriate in some manner.  The reality is that the development of
the Internet has many examples of permissionless innovation and so
these "unanticipated usages" should not be dismissed as lacking in
either importance or validity.


This document is intended to address the above limitations of {{RFC8744}}
by providing more information about the issues posed by the
introduction of ECH due to the loss of visibility of SNI data on
private networks.  To do so it considers the situation within schools
and enterprises, building on information previously documented in a
report from a roundtable discussion {{ECH_Roundtable}}.


# The Education Sector


## Context


Focusing specifically on the education sector, the primary issue
caused by ECH is that it is likely to circumvent the safeguards
applied to protect children through content filtering, whether in the
school or home environments, adding to adverse impacts already
introduced through the use of encrypted DNS protocols such as DNS
over HTTPS {{RFC8484}}.


Content filtering that leverages SNI information is used by education
establishments to protect children from exposure to malicious, adult,
extremist and other content that is deemed either age-inappropriate
or unsuitable for other reasons.  Any bypassing of content filtering
by client software on devices will be problematic and may compromise
duties placed on education establishments: for example, schools in
the England and Wales have obligations to provide "appropriate
filtering systems in place" {{KCSE}}; schools in the US use Internet
filters and implement other measures to protect children from harmful
online content as a condition for the receipt of certain federal
funding, especially E-rate funds {{CIPA}}.


## Why Content Filtering Matters to Schools


The impact that ineffective content filtering can have on an
educational institutions should not be underestimated.  For example, a
coroner in the UK in 2021 ruled that a school's failure to prevent a
pupil from accessing harmful material online on its equipment
contributed to her taking her own life {{Coroner}}.  In this particular
case, the filtering software installed at the school was either
faulty or incorrectly configured but it highlights the harmful risks
posed if the filtering is bypassed by client software using ECH.


## Mitigations


Whilst it may be possible for schools to overcome some of the issues
ECH raises by adopting similar controls to those used by enterprises,
it should be noted that most schools have a very different budget for
IT compared to enterprises and usually have very limited technical
support capabilities.  Therefore, even where technical solutions
exist that may allow them to continue to meet their compliance
obligations, affordability and operational expertise will present
them with significant difficulties.


Absent funding and technical expertise, schools will need to consider
the best way forward that allows them to remain compliant.  If client
software does not allow ECH to be disabled, any such software that
implements support for ECH may need to be removed from school devices
and replaced, assuming that suitable alternatives are available.
This will have a negative impact on budgets and maybe operationally
challenging if institutions have made a significant investment in the
deployment and use of particular applications and technologies.


There are instances where policies in education establishments allow
for the use of equipment not owned by the institution, including
personal devices and the devices of contractors and site visitors.
These devices are unlikely to be configured to use the institution's
proxy but can nevertheless connect to the school network using a
transparent proxy (see below).  Transparent proxies used for
filtering will typically use SNI data to understand whether a user is
accessing inappropriate data, so encrypting the SNI field will
disrupt the use of these transparent proxies.


In the event that transparent proxies are no longer effective,
institutions will either have to require more invasive software to be
installed on third party devices before they can be used along with
ensuring they have the capability to comprehend and adequately manage
these technologies or will have to prevent those devices from
operating.  Neither option is desirable.


# Transparent Proxies


A proxy server is a server application that acts as an intermediary
between a client requesting a resource and the server providing that
resource.  Instead of connecting directly, the client directs the
request to the proxy server which evaluates the request before
performing the required network activity.  Proxies are used for
various purposes including load balancing, privacy and security.


Traditionally, proxies are accessed by configuring a user's
application or network settings, with traffic diverted to the proxy
rather than the target destination.  With "transparent" proxying, the
proxy intercepts packets directed to the destination, making it seem
as though the request is handled by the target destination itself.


A key advantage of transparent proxies is that they work without
requiring the configuration of user devices or software.  They are
commonly used by organisations to provide content filtering for
devices that they don't own that are connected to their networks.
For example, some education environments use transparent proxies to
implement support for BYOD without needing to load software on third-
party devices.


Transparent proxies use SNI data to understand whether a user is
accessing inappropriate content without the need to inspect data
beyond the SNI field.  Because of this, encryption of the SNI field,
as is the case with ECH, will disrupt the use of transparent proxies.


# The need for Operational security by Enterprises and Other Organisations


## Threat landscape


The general threat landscape which was already very large (see {{SMART}}), has significantly increased since the
COVID crisis. Indeed as the crisis forced many enterprises and organizations to accelerate their digital
transformation, it increased the opportunity for the cyber criminals and nation states to launch more attacks,
leverage innovations to their advantages, better select their targets, increase their efficiency and increase their
rewards, in particular with Ransomware based attacks.


One implication from the COVID crisis is the acceleration of BYOD
with the current reliance on remote working, which is another area
where the use of transparent proxies can help.  Alternative solutions
are available but will require the use of more invasive software to
be installed onto the guest device.


Any restrictions on the use of BYOD will also affect contractors and
other third parties that need to connect to one or more enterprise
networks on a temporary basis.  In such circumstances, requiring
software or custom configurations to be installed on those devices
may be problematic, especially for contractors that work across
multiple organisations.  One solution could be for dedicated
equipment for each client, however this will have potentially
significant cost considerations.

## Implications to Enterprises and Organizations

Attacks are now damaging Enterprises and Organizations in increasing severity which

* Loss of revenue with an average between 11-24%
* Loss in capitalisation between 1-5%
* Degradation by credit notation agencies


Since the damage is so high, some cyber insurances companies in some countries prefer
to pay the ransom to mitigate the damage which has the unfortunate side effect of
funding and encouraging cybercriminals to increase their attacks!


## The main requirements


Enterprises and Organizations need to protect themselves for a vast number of reasons, mainly:


* Reduce their Risks. And in particular as part of any Cyber Resilience strategy.
* Protect their Reputation. The term Reputation includes many aspects way beyond the traditional enterprises and
organization assets (data, etc.).
* Comply to a growing diverse set of Policies, Regulations, Certifications, Labeling and Guidelines. This set of
artifacts is increasing by countries and regions in the world, by the nature of the object of the artifact (just
in the EU: NIS, EBAG, DORA, NIS2, etc.), by the changes of roles (e.g. the ENISA is now carrying a Certification
Mandate), etc.

Clear audit trails of any communications between parties are required
in the finance sector amongst others for compliance purposes.  If it
becomes possible for communications to take place without an audit
trail or any visibility to the enterprise, then there is increased
scope for abuse to take place, including insider trading or fraud.
The lack of a comprehensive audit trail can also have serious enforcement
consequences, at least in some sectors.  For example, although not
ECH-related, there are indications that US regulators are in the
process of levying fines of $200m each on number of institutions
because they were unable to track all communications by their
employees because some were encrypted though the use of WhatsApp
or Signal {{Bloomberg}}.


In addition to concerns about the loss of visibility of deliberate
activity by users, the loss of visibility of potential command and
control and other activity by malicious software is of concern to
enterprises.  In such cases, the lack of visibility from these
privacy protections could lead to negative impacts on security and
privacy for the enterprise, its employees, suppliers and customers.


## Defence in Depth reminders


The concept of Defence in Depth is not a new one {{NIST-DID}}, but it is still highly relevant today. Put simply
Defence in Depth is about creating multiple layers of defence to stop hackers.

Normal internet traffic relies first on the DNS resolution and as discussed this can be a simple and effective way to block known bad sites i.e. check the domain name against a list of bad sites, or analyse the age of the domain and return a zero value if the site is known bad or has only existed for a short period of time.


Next as the HTTPS connection is made, checking the SNI, decrypting the traffic, and analyzing its content will ensure nothing sensitive is being sent or anything malicious is being received. Again, if anything is detected as bad, then block the request/response. This therefore forms the first levels of defence, it should also be noted that this network analysis does not have to be done  on-premise or as a traditional boundary defence, but can also be routed through an online service in the model of SASE (Secure Access Service Edge) allowing for greater flexibility for remote users and users working from home.


On the endpoint, deployment of anti-malware and DLP agents allows the analysis of data and activity on the endpoint (remembering to make sure there are controls in place to stop the software from being deactivated!); this forms the final line of defence. And this really is the point, there will always be a need to deploy agents on the endpoint of devices managed by the organisation; but these should only be thought of as that last line of defence, and not the only line of defence! It is also worth considering the increase in devices that are not managed by the organisation through initiatives such as  Bring Your own Device (BYOD); how can an organisation protect these devices and ensure that data is not being leaked? The only way to really protect these devices relies again on network based analysis for malware and DLP etc.


## Evolution of defence approaches


Approaches to defence have evolved over recent decades with a number of notable milestones: several key formal works on security were developed in the 1970s and 80s, with X.800 being the last formal, international consensus-based security architecture. Then several works moved security from a purely on-premise perimeter defence model, to a tiered/layered defence, to defence in depth, to Jericho Forum, to Beyond corp, to Zero Trust and most recently to Secure Access Service Edge (SASE).


On the way, the community and the operational security practitioners across enterprises and organizations of all sizes and industry verticals, have recognized the following:


* Security cannot rely on just one solution. Just like in other areas, such as aircraft safety, an aircraft would have multiple alternative components, systems and methods to decrease the probability of hitting a unique point of failure. Several measures are used in conjunction with each other to provide defence in depth safety so if one layer fails a another layer can provide coverage
* Compartmentalising perimeters (regardless on how big or small their granularity is), like in a submarine, is a good approach to resiliency
* Not trusting anyone, anything, neither the device, nor the network, nor the service endpoints (servers, clouds, etc.), nor the application, nor the logs, etc. is a good practice
* The acceptance that breaches will occur; and that minimising the impact of such a breach (through developing a strong Cyber Resilience) and through the adoption of Zero Trust is best practice


## The need for Network based security


In general {{OPSECNSIMPACT}} covered several aspects of the impacts of pervasive encryption to Operational Network Security Practices.


Filtering is an important tool within many enterprises, with uses
including the prevention of accidental access to malicious content
due to phishing etc.  In the enterprise market, a number of vendors
use transparent proxy solutions, often combined with DNS filtering,
to give stronger protections, with the proxy capability requiring
unencrypted SNI information.

The history of network based attack detection is a long one, dating back to the mid-1990’s with the first Intrusion Detection Systems (IDS) and Proxies. These started off being fairly simple systems which would search network traffic for certain string types and raise alerts when these were identified. As such they tended to simply look at Layer 4 traffic and did not understand the behaviours of certain protocols, and so were highly prone to false positives.

Over time the technologies developed and became more protocol aware.  As accuracy improved so did the confidence to
actually block attacks before they reached the targeted endpoint; IDS became Intrusion Prevention. At a higher
protocol level, Proxies have fundamentally not changed much at all: in essence they look at the HTTP connection and
extract the Server Name Identification (SNI) and then check that against a list of known good or bad sites and then
block or allow as appropriate. But they have evolved to allow integration with other security products, such as
sandboxes, to extract the payload and analyse for malware embedded in that content.


In all cases these ‘boundary controls’ have been essential to organisations in trying to protect their users from
malicious attacks coming in from the Internet. But this only considers the inbound traffic, what about what users
are sending out of an organisation ? This is where Data Loss Prevention (DLP) controls come in; allowing
organisations to look for company confidential data, Personal Identifiable Information (PII), and financial data
(such as credit card data) to stop it egressing the organisation. Not only are these controls used to protect the
organisation, but they are also essential from a legal and compliance point of view due to legislation such as GDPR
and PCI.

Increasingly the need for network centric security controls has grown, but counter to this has been the ever
increasing use of encryption. In the 1990’s the amount of internet traffic that was encrypted was very small, which
easily allowed the traffic and its content to be checked. But today almost all communication is encrypted and so the
job of monitoring it has also become harder to achieve. From a Proxy perspective, simply looking at the SNI address
of the destination of traffic allows for malicious traffic (such as malware talking to a Command and Control (C&C)
server) to be blocked on the Proxy or Firewall. But, in order to read deeper into the traffic, Deep Packet
Inspection (DPI) relies on using a network intermediary to sit between the client and the server it is connecting
to, to decrypt the traffic, analyse it and then re-encrypt it before sending it on to the destination. Again, being
able to analyse the SNI allows these systems to only decrypt the traffic that the organisation is interested in,
which is called 'selective decryption'. So normal user activity such as connecting to a news site or social media
can be ignored while traffic destined for an online email system can be decrypted and inspected for malware and DLP
controls.

So why can all this essential analysis not be carried out on the endpoint? In theory it can, but there are several
problems and limitations with this approach. One problem is that this endpoint software can be turned off and
disabled. Even today, most endpoint security software (be it DLP or antimalware based) does not have Tamper Controls
built into it. And as can be seen from many high profile attacks, such as the recent Sunburst attack that targeted
the {{SOLARWIND}} supply chain, the first thing that malware did was disable the anti-malware system so that attack
would succeed. So, the need for network security as a Mandatory security control is much more effective than having
endpoint based controls which can be turned on and off (and as such can be seen as a Discretionary control). The
second problem arises because more and more organisations are moving applications and services to the cloud and the
web browser has become the ubiquitous method to connect to these applications. An increasing focus for security is
on protecting the web browser from being the initial attack vector; ensuring the content is clean and trusted by the
time it arrives at the browser adds a significant security benefit.  The third problem is that to truly run the full
set of defence in depth analysis on the endpoint will cripple many endpoints due to compute and memory required for
the full analysis. Adding security in the network mitigates all of these difficulties.

## Network Security deployment

To the knowledge of the authors, all Fortune 500, Fortune 2000, and likely the vast majority of enterprise customers
have deployed network security solutions for decades. This is both motivated by the nature of the attacks,
compliance requirements and also by costs as it is easier to manage security from the network vs the endpoint (see
below).

When considering the operational and cost implications for
enterprises, it should be remembered that the resources available
will vary significantly between a multinational organisation and a
small to medium-sized enterprise.  It should not be assumed that a
solution that can be absorbed financially and operationally by the
former is practical for the latter.  The needs of both need to be
taken into account when evaluating potential solutions.




# Threat Detection


{{RFC8404}} identifies a number of issues arising from increased
encryption of data, some of which apply to ECH.  For example, it
notes that an early trigger for DDoS mitigation involves
distinguishing attacker traffic from legitimate user traffic; this
become more difficult if traffic sources are obscured.


The various indicators of compromise (IoCs) are documented in {{I-D.draft-ietf-opsec-indicators-of-compromise}}, which also describes how they
are used effectively in cyber defence.  For example, section 4.1.1 of
the document describes the importance of IoCs as part of a defence-
in-depth strategy; in this context, SNI is just one of the range of
indicators that can be used to build up a resilient defence (see
section 3.1 in the same document on IoC types and the 'pyramid of
pain').


In the same Internet-Draft, section 6.1 expands on the importance of
the defence in depth strategy.  In particular, it explains the role
that domains and IP addresses can play, especially where end-point
defences are compromised or ineffective, or where endpoint security
isn't possible, such as in BYOD, IoT and legacy environments.  SNI
data plays a role here, in particular where DNS data is unavailable
because it has been encrypted; if SNI data is lost too, alongside
DNS, defences are weakened and the attack surface increased.


# Client Complications


## Devices are not trustable


As {{CLESS}} showed before its work was stopped, is that a strategy pushing security to only the two endpoints of a communication is doomed to a lot of trouble as the spectrum of limits affecting endpoint security solutions is a very big gap that has not been resolved in the past decades and won't be in any short term.


## Attacks targeting the web browser


As discussed, the web browser has now become the primary method used by users to access applications and services
on the internet. Hackers know this and so increasingly use attacks that aim to compromise the browser including by
performing and enabling a Man in the Browser {{MITB}} attack, codified at T1185 in MITRE ATT&CK framework
{{MITB-MITRE}}.

In the first instance we have Phishing attacks, which trick the user into clicking on a malicious link or opening a
malicious file. Hackers create domains that look like legitimate websites which often are related to delivery
companies or tax offices (and these can be blocked at the network level through analysing the SNI to understand the
age of a domain or whether it is known bad). To evade this hackers, have become more stealthy by using legitimate
domains (such as aws.amazon.com or other similar internet hosting sites) but then embedding the malware in the
website code itself (i.e. HTML or Java). In these cases, knowing the SNI is necessary but not sufficient (because it
is essentially legitimate), so proper analysis on the whole page itself is much more important. In this case the web
browser will not protect the user as it requires proper analysis, which can be done in transit from analysing the
network traffic.

Other attacks work by compromising the legitimate website itself. {{MALVERTISING}} (malicious advertising) attacks
work by creating fake adverts that then get displayed on legitimate websites. In many cases the user can get
infected by simply viewing the advert and again it is not always possible to stop these attacks with simply the SNI
data; The SNI is necessary but it is only when the specific code hidden in the advert is analysed that the attack is
detected and stopped. This, again, cannot be done in the browser alone.

{{MAGECART}}, or Web Skimming is a common form of attack which is intended to steal PII and credit card data.
Hackers compromise legitimate websites, typically ecommerce related, and add JavaScripts which skim the credit card
data used by a customer and send that data to the hacker. Other attacks will distribute the malware loaders to the
user so again they get compromised by simply viewing the otherwise legitimate website. In both cases simply looking
at the SNI server data is necessary but insufficient; and that the whole page needs to be analysed to detect the
malicious code.

Users themselves can also be targeted directly through Social Engineering. A common technique is to use legitimate
social networks, like LinkedIn, to lure targeted users to open malicious files or links. So the hacker would appear
to be a legitimate job recruiter with news of a new job opportunity, ‘please read this job description’ is the
lure, the user clicks on the link or opens the document and the host is compromised. These communications are almost
always encrypted and may use specific chat channels to send the malware through; the site itself is good and so it
is only through analysing every object being received on the host, can the malware be detected.

Finally the browser itself can be compromised by the user themselves, by installing what looks to be legitimate
plug-ins for the browser, but in fact they collect browsing habits or may log keyboard activity.


# Mitigations


## Need for clarification on the ECH proposal


The current ECH proposal shows a very complex setup requiring a new Hybrid Cryptography, a significant change in the
DNS with new Record Resources (RRs) and the introduction of splitting the backend servers into client facing server
and backend servers (in shared or split mode).


## DNS impact


The current mechanism of the ECH vector needs a way that the client can retrieve that vector and a choice was made to use the DNS for this purpose. Yet this requires adding new RRs with a substantial amount of new data. It seems like this proposal is definitely moving the DNS as it is today into a 'Directory Service for Domains'. What would be the consequences of making such a radical direction change into the DNS? Was there any study that shows potential impacts on the overall DNS service from various design criteria perspective?


## Client Facing vs Backend Servers need a lot of clarification


It is understood that ECH needs to establish the split of the targeted servers into a Client Facing and a Backend server (whether in shared or split architecture). However it is extremely unclear on how these should be setup and how they will communicate. Even if this is to be left to "implementation", this interaction requires clarification and at minimum a more pedagogic explanation and step by step approach in the different cases. Some additional questions:


* Are these Client Facing servers meant to be hosted only by CDNs?
* Are these Client Facing servers a new middlebox model where a number of auxiliary services (e.g. security
services) could be provided?
* How will these changes affect the way network security and monitoring is carried out by companies and
organisations today, to protect their own employees and data ?


## General approaches


Access to SNI data is sometimes necessary in order for institutions,
including those in the education and finance sectors, to discharge
their compliance obligations.  The introduction of ECH in client
software poses operational challenges that could be overcome on
devices owned by those institutions if policy settings are supported
within the software that allows the ECH functionality to be disabled.


Third-party devices pose an additional challenge, primarily because
the use of ECH will render transparent proxies inoperable.  The most
likely solution is that institutions will require the installation of
full proxies and certificates on those devices before they are
allowed to be connected to the host networks.  They may alternatively
determine that such an approach is impractical and instead withdraw
the ability for network access by third-party devices.


An additional option that warrants further consideration is the
development of a standard that allows a network to declare its policy
regarding ECH and other such developments.  Clients would then have
the option to continue in setting up a connection if they are happy
to accept those policies, or to disconnect and try alternative
network options if not.  Such a standard is outside of the scope of
this document but may provide a mechanism that allows the interests
and preferences of client software, end-users and network operators
to be balanced.


# Conclusions


This document reminds on the Enterprises and Organizations environments, constraints and requirements.
It shows too that the current ECH drafts will implicitly:

* Leave the security responsibility to the browser and the client facing server
* The browser cannot be judge and jury as if it is compromised, it cannot act properly to protect end users
* The client facing server is becoming a new middlebox which is creating a number of problems
* There is a need for a 3rd party security to add credentials to the solution


This leaves a few questions to the the current ECH drafts:

* Can the impacts of ECH on DNS and on the Client Facing vs Backend servers be clarified?
* Can the problems of enterprises and organizations be acknowledged?
* If not, then this will leave little choices to the defenders to use a protocol based clean solution
* If yes, then what could be the suggestions to include operational security in the ECH design


# Security Considerations


In addition to introducing new operational and financial issues, the
introduction of SNI encryption poses new challenges for threat
detection which this document outlines.  These do not appear to have
been considered within either {{RFC8744}} or the current ECH Internet-
Draft {{I-D.draft-ietf-tls-esni}} and should be addressed fully within
the latter's security considerations section.


This I-D should help improve Security Considerations for ECH.


# IANA Considerations


This document has no IANA actions.


# Acknowledgment


In addition to the authors, this document is the product of an
informal group of experts including the following people:
