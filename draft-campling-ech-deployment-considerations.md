---
title: "Encrypted Client Hello Deployment Considerations"
abbrev: "ECH Deployment Considerations"
docname: draft-campling-ech-deployment-considerations-latest

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
- name: Celine Leroy
  org: Eight Advisory
  email: celine.leroy@8advisory.com
  uri: https://www.linkedin.com/in/celine-leroy-1a534252/
  contribution: |
    Thank you to Céline for her work on cybersecurity financial impacts on enterprises.
- name: Daniel Engberg
  org: Skandinaviska Enskilda Banken AB (SEB)
  email: daniel.engberg@seb.se
  uri: https://www.linkedin.com/in/daniel-engberg-1561aaa/
  contribution: |
    Validate the issues for his organization.
- name: Gianpiero Tavano
  org: Broadcom
  email: Gianpiero.Tavano@broadcom.com
  uri: https://www.linkedin.com/in/gianpiero-tavano-5b975383/
  contribution: |
    Review the text, provided feedback and reminded us on the budgetary issues
- name: Roelof duToit
  org: Broadcom
  email: roelof.dutoit@broadcom.com
  uri: https://www.linkedin.com/in/roelof-du-toit-a66831/
  contribution: |
    Roelof contributed many things including research, former I-D, text, the newly setup github, etc.
- name: Diego Lopez
  org: Telefonica
  email: diego.r.lopez@telefonica.com
  uri: https://www.linkedin.com/in/dr2lopez/
  contribution: |
    Diego contributed in several aspects including MCPs.
- name: Gary Tomic
  org: Broadcom
  email: gary.tomic@broadcom.com
  uri: https://www.linkedin.com/in/garytomic/
  contribution: |
    Gary contributed many things including research, keep us on scope, critique for when issues where not impacted by ECH as we initially thought.

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
  SOLARWIND:
    target: https://symantec.broadcom.com/en/solarwinds-sunburst-attacks
    title: SolarWinds (Sunburst) Attack What You Need to Know
    author:
    - org: Symantec, a Division of Broadcom Software Group
    date: 2020-12
  LOSSINCAP:
    target: https://www.amf-france.org/sites/default/files/2020-02/etude-sur-la-cybercriminalite-boursiere-_-definition-cas-et-perspectives.pdf
    author:
    - name: Alexandre Neyret
    - org:  Autorité des Marchés Financiers
    title: La cybercriminalité boursière – définition, cas et perspectives
    date: 2019-10-10
  LOSSINCREDITSCORE:
    author:
    - org: Deloitte
    title: Beneath the surface of a cyberattack – A deeper look at business impacts
    date: 2016
    target: https://www2.deloitte.com/content/dam/Deloitte/global/Documents/Risk/gx-risk-gra-beneath-the-surface.pdf
  LOSSINREVENUE:
    author:
    - org: ANOZR WAY
    date: 2022-09-04
    title: BAROMÈTRE ANOZR WAY DU RANSOMWARE
    target: https://anozrway.com/wp-content/uploads/dlm_uploads/2022/09/ANOZR-WAY_Barometre-Ransomware_edition-septembre-2022.pdf

  RFC8890:
  RFC7258:
  RFC8404:
  RFC8744:
  I-D.draft-ietf-tls-esni:
  I-D.draft-ietf-opsec-indicators-of-compromise:
  I-D.draft-mcfadden-smart-threat-changes:
  I-D.draft-ietf-opsec-ns-impact:
  I-D.draft-taddei-smart-cless-introduction:



--- abstract

This document is intended to inform the community about the impact of the deployment of the proposed
Encrypted Client Hello (ECH) standard that encrypts Server Name
Indication (SNI) and other data.  Data encapsulated by ECH (ie data
included in the encrypted ClientHelloInner) is of legitimate interest
to on-path security actors including those providing inline malware detection, parental
controls, content filtering to prevent access to malware and other risky traffic, mandatory security controls etc.

The document includes observations on current use cases for SNI data
in a variety of contexts.  It highlights how the use of that data is
important to the operators of both public and private networks and shows how the loss
of access to SNI data will cause difficulties in the provision of a
range of services to end-users.  Some mitigations are
identified that may be useful for inclusion by those considering the adoption
of support for ECH in their software.

--- middle




# Introduction


As noted above, this document includes observations on current use
cases for SNI data in a variety of contexts.  It highlights how the
use of that data is important to the operators of both public and private networks
and shows how the loss of access to SNI data will cause difficulties
in the provision of a range of services to end-users.
Some mitigations are identified that may be useful for inclusion by those considering the adoption of support for ECH in their software.


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

Whilst it is reasonable to counter that VPNs also establish opaque
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
operators including enterprises and education establishments. The
data encapsulated by ECH is of legitimate interest to on-path
security actors including those providing inline malware detection,
firewalls, parental controls, content filtering to prevent access to malware
and other risky traffic, mandatory security controls (e.g. Data Loss Prevention) etc.

This document will focus specifically on
the impact of encrypting the SNI data by ECH on public and private networks,
but it should be noted that other elements in the client hello may be relevant for some
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
limited evidence, that "most of 'the unanticipated usage' functions
can, however, be realized by other means", although without
considering or quantifying the affordability, operational complexity,
technical capability of affected parties or privacy implications that
might be involved.  It is unclear from the document whether any
stakeholders that may be impacted by the encryption of SNI data have
been consulted; it certainly does not appear to be the case that any such
consultation has taken place.

The characterisation of "unanticipated usage" of SNI data could be
taken to imply that such usage was not approved and therefore
inappropriate in some manner.  The reality is that the development of
the Internet has many examples of permissionless innovation and so
this "unanticipated usage" of SNI data should not be dismissed as lacking in
either importance or validity.

This document is intended to address the above limitations of {{RFC8744}}
by providing more information about the issues posed by the
introduction of ECH due to the loss of visibility of SNI data on
private networks.  To do so it considers the situation within schools,
enterprises and public service providers, building on information previously documented in a
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
duties placed on education establishments.  For example: schools in
England and Wales have obligations to provide "appropriate
filtering systems" {{KCSE}}; schools in the US use Internet
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
This will have a negative impact on budgets and may be operationally
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
implement support for “bring your own device” (BYOD) without needing to load software on third-
party devices.

Transparent proxies use SNI data to understand whether a user is
accessing inappropriate content without the need to inspect data
beyond the SNI field.  Because of this, encryption of the SNI field,
as is the case with ECH, will disrupt the use of transparent proxies, requiring far more intrusive data inspection to be undertaken instead.

# Impact of ECH on Enterprises and Organizations

## The main requirements

Enterprises and Organizations need to protect themselves for a vast number of reasons, mainly:

* Reduce their Risks. And in particular as part of any Cyber Resilience strategy.
* Protect their Reputation. The term Reputation includes many aspects way beyond the traditional enterprises and organization assets (data, etc.).
* Comply to a growing diverse set of Policies, Regulations, Certifications, Labeling and Guidelines. This set of artifacts is increasing by countries and regions in the world, by the nature of the object of the artifact

## A degrading threat landscape

In addition, the general threat landscape which was already very large (see {{I-D.draft-mcfadden-smart-threat-changes}}), has significantly increased in three ways:

* COVID crisis generally accelerated the overall attack landscape. Indeed as the crisis forced many enterprises and organizations to accelerate their digital transformation, it increased the opportunity for cyber criminals and nation states to launch more attacks, leverage innovations to their advantages, better select their targets, increase their efficiency and increase their rewards, in particular with Ransomware based attacks.
* The Supply Chain is under stress as per the {{SOLARWIND}} attack
* Nation State attacks are getting more visibility, among other things, through the Ukraine crisis.

Attacks are now damaging Enterprises and Organizations (with ransomware being the number 1 issue by large) in increasing severity which materialises and started to be measured at macroscopic level in some countries:

* €1B loss of revenue for French organizations from January to August 2022 {{LOSSINREVENUE}}
* Loss in capitalisation between 1-5% {{LOSSINCAP}}
* Degradation by credit notation agencies {{LOSSINCREDITSCORE}}

Another implication from the COVID crisis is the acceleration of BYOD
with the current reliance on remote working which created two types of side effects for remote employees, contractors and third parties that need to connect to one or more enterprise
networks on a temporary basis:

* need to use a VPN access to the corporate network, which brings all the risks that VPN may open
* need to access a cloud proxy which requires an agent to be installed on the device to steer the traffic to the right place.

In such circumstances, requiring
software or custom configurations to be installed on those devices
may be problematic (see {{I-D.draft-taddei-smart-cless-introduction}}.

This is why network security solutions are required and this is why ECH preventing the access to the SNI makes it impossible for blue teams to defend (see the next sections for details).

Finally there is a major lack of manpower in cybersecurity with a lack of professionalization which is not compensated anymore by the vocational aspect of cybersecurity so far.

All the above conditions are weighing on capabilities to defend, both:

* Directly: a lack of visibility on a key meta data like the SNI will cause significant issues to enterprises and organizations
* Indirectly: should ECH happen and should alternative be provided, managing migrations to any alternative not requiring access to the SNI, in these conditions, is undesirable from a timing, resources, capacities and risks perspectives.


## Examples of regulatory implications

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
employees because some were encrypted through the use of WhatsApp
or Signal {{Bloomberg}}.

In addition to concerns about the loss of visibility of deliberate
activity by users, the loss of visibility of potential command and
control and other activity by malicious software is of concern to
enterprises.  In such cases, the lack of visibility from these
privacy protections could lead to negative impacts on security and
privacy for the enterprise, its employees, suppliers and customers.

## Impact of ECH deployment on Network Security Operations

### Reminders on Network Security

Network Security is a set of security capabilities which is articulated as part of a defense strategy, e.g. Defense In Depth {{NIST-DID}}, Zero Trust, SASE/SSE, etc. and can trigger and enable other security capabilities such as sandboxing, Data Loss Prevention, Cloud Access Service Broker (CASB), etc. One constituency is a Web Proxy, combining both a TLS proxy and an application level (HTTP) proxy.

In the same way that {{I-D.draft-ietf-opsec-ns-impact}} showed the impact of TLS1.3 on operational security, a loss of visibility of the SNI as indicator of compromise (see {{I-D.draft-ietf-opsec-indicators-of-compromise}}) will have mostly two types of implications

### Implications from loss of Meta Data

The loss of visibility of the SNI, at TLS level, will prevent transparent proxies from applying corporate policies to manage risk and compliancy. Typical examples:

* categories of compromised sites cannot be applied anymore, leading employees to potential cybersecurity risk for them and for their organization and alternative approaches to block access to theses sites need to be found
* corporate lists of excluded sites for compliancy reasons need alternatives ways to be blocked.

### Implications from loss of Selective Decrypt

TLS proxies also have the ability to selectively intercept, avoiding any visibility into or modification of the original application protocol payload - but such selective intercept relies heavily on knowledge of the origin content server hostname, which can be extracted in plaintext from the TLS ClientHello SNI (server name) field.

This capabilities allows the application proxy, in particular an HTTPS proxy to engage efficiently specific security controls, e.g. Data Loss Prevention, Sandboxing, etc.

The loss of SNI visibility will make it more difficult for corporate user flows to be intercepted and impossible when this is BYOD use cases.

This will create inefficiencies, require more resources, and increase security risks themselves. It will also be counter productive for privacy itself as it may require the proxy to decrypt the whole TLS connection.

# Specific implications for SMBs

Small and Medium Business (SMBs) form a particular vulnerable subset of enterprises and organizations and span from Small Office Home Office (SOHO, sometimes a one person business) to Medium Business with strong variations depending on the country (a 50 employee company is considered the upper range of SMB business in developing countries while it is up to 25’000 in some developed countries).

Yet it leaves a large range of organizations with very limited capabilities to defend themselves, a security which is often outsourced to Managed Security Service Providers (Among which many Operators, mid range and small service providers).

For them, the above ‘education’ use case would apply in similar ways, opening, by ripple effect, the same issues found by major service providers and in particular by smaller ones (see next section).

# Public Network Service Providers

In Public Networks the legislator has to balance between freedom of access to the information on the one hand, and safety of the internet and the protection of other fundamental rights on the other hand.

There are mainly 2 different approaches:

* First, there are countries which do not have any specific legislation on the issue of blocking, filtering and takedown of illegal internet content: there is no legislative or other regulatory system put in place by the state with a view to defining the conditions and the procedures to be respected by those who engage in the blocking, filtering or takedown of online material. In the absence of a specific or targeted legal framework, several countries rely on an existing “general” legal framework that is not specific to the internet to conduct – what is, generally speaking - limited blocking or takedown of unlawful online material. here the approach has been differentiated in relying on self regulation from the private sector or limit the political or legislative intervention to specific areas.

* The other approach has been to set up a legal framework specifically aimed at the regulation of the internet and other digital media, including the blocking, filtering and removal of internet content. Such legislation typically provides for the legal grounds on which blocking or removal may be warranted, the administrative or judicial authority which has competence to take appropriate action and the procedures to be followed.

In relation to specific areas where the public interest has to be protected more strongly, such as Child abuse crimes, terrorism, criminality and national security many states have a framework for the urgent removal of internet content regarding the above materials without the need of a court order: Administrative authorities, police authorities or public prosecutors are given specific powers to order internet access providers to block access without advance judicial authority. It is common to see such orders requiring action on the part of the internet access provider within 24 hours, and without any notice being given to the content provider or host themselves.

Particularly in relation to material concerning child abuse and other serious crimes, many countries adopt a “list” system, whereby a central list of blocked URLs or domain names are maintained and updated by the relevant administrative authority. This is notified to the relevant internet access providers, who are required to ensure that blocking is enforced.
Additionally in some states the authorities can request the removal of content that infringes intellectual property, privacy or defamation rights. In this case the removal need to be requested by a court order.

Generally speaking, the grounds relied on broadly correspond to the interests protected under Article 10(2) of the European Convention of Human Rights (ECHR), namely: the protection of national security, territorial integrity or public safety, the prevention of disorder or crime, the protection of health or morals, the protection of the reputation or rights of others, and the prevention of the disclosure of information received in confidence.
From the methodology we have to distinguish between blocking or takedown of content.

* The blocking, filtering or prevention of access to internet content are generally technical measures intended to restrict access to information or resources typically hosted in another jurisdiction. Such action is normally taken by the internet access provider through hardware or software products that block specific targeted content from being received or displayed on the devices of customers of the internet access provider.

* Takedown or removal of internet content, on the other hand, will instead broadly refer to demands or measures aimed at the website operator (or “host”) to remove or delete the offending website content or sub content.

In these considerations we will refer to blocking only.

This can be achieved through a number of techniques, including the blocking of the Domain Name System (DNS), the analysis of the SNI field or the Uniform Resource Locator (URL).
Given the increasing adoption of encryption techniques often a mixture of the above techniques is needed.

In particular for the most serious crimes such as Child abuse or National Security many countries adopt a “list” methodology, where a central list of blocked Domains or URLs is maintained by the authorities and updated on a regular basis (daily or even hourly) and shared with Public Network Operators that have to enforce the blocking.

In many jurisdictions there are legal consequences for the Operator not complying with the blocking order.

Technically the blocking can be implemented using some techniques that have been adapted during time based on the new technologies introduced.

Historically  depending on the content of the list the technique have been based on DNS or Proxy blocking.

DNS is effective on Domains (the whole domain is blocked), while proxy is effective either on Domain (for encrypted traffic) or URL (for unencrypted traffic).

Given that nowadays the vast majority of traffic is encrypted, the capability of blocking based on URL is limited to a small portion of traffic and proxy is as effective as DNS.

Theoretically for an operator DNS would be the element of choice given the more limited investments necessary to implement blocking of the Domains, but given the increased usage of external encrypted DNS services DNS is becoming less effective and Operators need to use also SNI analysis to fulfil legal obligations.

In this case the adoption of ECH will cause additional problems and limit the possibility of implementing the legal blocking requirements, exposing the population to illegal content related to crimes such as Child Sex Abuse Material (CSAM), Cyber Crimes or National Security.

Given the current international situation where Network Operators implements blocks requested by the jurisdiction that protect the populations against several Cyber Attacks today this is even more important.


# Threat Detection

{{RFC8404}} identifies a number of issues arising from increased
encryption of data, some of which apply to ECH.  For example, it
notes that an early trigger for DDoS mitigation involves
distinguishing attacker traffic from legitimate user traffic; this
become more difficult if traffic sources are obscured.

The various indicators of compromise (IoCs) are documented in {{I-D.draft-ietf-opsec-indicators-of-compromise}}, which also describes how they
are used effectively in cyber defence. For example, section 4.1.1 of
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


# Potential further development of this work

This work could consider several potential developments:

* If ECH is enforced what are the solutions to all the above problems and what are the migration paths?

* Elaborate on endpoint security complications as {{I-D.draft-taddei-smart-cless-introduction}} as well as {{MAGECART}} {{MITB}} {{MITB-MITRE}} {{MALVERTISING}} showed that in some cases, the only way to detect an attack is coming from Network Security. So losing the visibility on the SNI will make it much harder to detect attacks. The endpoints components (Operating System, Applications, Browsers) cannot be judge and party.

*  There are need for further clarifications from the ECH draft, e.g. The link between the Client Facing and the backend servers are not clear enough and need further description. It can’t be just ‘left to the implementation’

* Will there be any impact to the DNS by adding so many new RRs?

* What happens if Client Facing servers are controlled by malicious actors?

* The Client Facing servers are acting as a new category of middleboxes. In this shift left movement, until the attack surface is minimal and complexities are removed, you have to rely on third parties for inspection. In these conditions, on which basis can they be more trusted than any other middleboxes? Is this creating a concentration problem?

* What prevents a Client Facing server providing security solutions to protect the data path?


# Conclusion

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

# Security Considerations

In addition to introducing new operational and financial issues, the
introduction of SNI encryption poses new challenges for threat
detection which this document outlines.  These do not appear to have
been considered within either {{RFC8744}} or the current ECH Internet-
Draft {{I-D.draft-ietf-tls-esni}} and should be addressed fully within
the latter's security considerations section.

This I-D should help improve improve security in deployments of ECH.

# IANA Considerations

This document has no IANA actions.

# Acknowledgment

In addition to the authors, this document is the product of an
informal group of experts including the following people:
