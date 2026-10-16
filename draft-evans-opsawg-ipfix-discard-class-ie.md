---
title: Information Element for Flow Discard Classification
abbrev: IE for Flow Discard Classification
docname: draft-evans-opsawg-ipfix-discard-class-ie-latest
date: 2026-10-16
category: info
stream: IETF
ipr: trust200902
area: Operations and Management Area
workgroup: OPSAWG
keyword: Internet-Draft

stand_alone: yes
pi: [toc, sortrefs, symrefs]

author:
 -
    ins: J. Evans
    name: John Evans
    org: Individual
    country: UK
    email: john@nopacketleftbehind.net

 -
    ins: O. Pylypenko
    name: Oleksandr Pylypenko
    org: NVIDIA
    street: 2788 San Tomas Expy
    city: Santa Clara
    region: CA
    code: 95051
    country: US
    email: opylypenko@nvidia.com

 -
    ins: K. Cheaito
    name: Karim Cheaito
    org: Amazon
    street: 410 Terry Ave N
    city: Seattle
    region: WA
    code: 98109
    country: US
    email: kcheaito@amazon.com

normative:
  IANA-IPFIX:
    title: IP Flow Information Export (IPFIX) Entities
    author:
      org: IANA
    target: https://www.iana.org/assignments/ipfix/

--- abstract

This document defines an IPFIX flowDiscardClass Information Element for classifying flow-level packet discards using the discard classes defined in {{!I-D.ietf-opsawg-discardmodel}}. The Information Element provides consistent classification of packet discards across IPFIX implementations, enabling correlation between device, interface and control-plane discards and the flows affected by those discards.

--- middle

Introduction        {#introduction}
============

For network operators, understanding both where and why packet loss occurs within a network is essential for effective operation. While certain types of packet loss, such as policy-based discards, are intentional and part of normal network operation, unintended packet loss can impact customer services. To automate network operations, operators must be able to detect customer-impacting packet loss, determine its root cause, and apply appropriate mitigation actions.

{{!I-D.ietf-opsawg-discardmodel}} defines an information model for classifying packet discards. Its YANG data model provides device, interface, and control-plane discard counters, while its information model also defines flow-level discard classification. Reporting those classes in IPFIX allows aggregate discard counters to be correlated with affected flows. For example, when mitigating congestion, operators may need to identify and trace the sources of elephant flows. This requires the ability to correlate device and interface-level discard classes with the specific flows being dropped.

{{?RFC7270}} defines the forwardingStatus Information Element for reporting packet forwarding outcomes in IPFIX, including various reasons for packet drops. Its drop reason codes do not provide the classification defined by {{!I-D.ietf-opsawg-discardmodel}}, however. They lack the granularity and clarity needed for automated root cause analysis and impact mitigation. For instance, the "For us" reason code provides insufficient context to determine appropriate mitigation actions. 

This document addresses these limitations by defining the flowDiscardClass Information Element to carry the {{!I-D.ietf-opsawg-discardmodel}} classification in IPFIX Flow Records, together with the semantics and context needed to correlate flow-level discards with aggregate discard counters.  This enables:

1. Precise detection of unintended packet loss through clear distinction between intended and unintended discards

2. Accurate root cause analysis through detailed classification of discard reasons

3. Automated selection of mitigation actions based on discard type, rate, and duration

4. Consistent reporting across vendor implementations in both YANG and IPFIX data models

By providing this mapping between YANG and IPFIX implementations, this document enables operators to correlate device-level statistics with flow-level impacts, facilitating more effective automated network operations.

Terminology {#terminology}
===========

{::boilerplate bcp14-tagged}

This document uses the terms "packet discard", "intended discards", and "unintended discards" as defined in {{!I-D.ietf-opsawg-discardmodel}}:

Packet discard:
: It accounts for any instance where a packet is dropped by a device, regardless of whether the discard was intentional or unintentional.

Intended packet discards (Intended discards, for short):
: Are packets dropped due to deliberate network policies or configurations designed to enforce security or Quality of Service (QoS). For example, packets dropped because they match an Access Control List (ACL) denying certain traffic types.

Unintended packet discards (Unintended discards, for short):
: Are packets that were dropped, which the network operator otherwise intended to deliver, i.e. which indicates an error state.  There are many possible reasons for unintended packet loss, including: erroring links may corrupt packets in transit; incorrect routing tables may result in packets being dropped because they do not match a valid route; configuration errors may result in a valid packet incorrectly matching an ACL and being dropped.

This document uses the IPFIX terminology defined in Section 2 of {{!RFC7011}}, including Flow Record, Template, Exporter, Collector, Observation Point, Observation Domain, and Metering Process. The terms Biflow and Biflow Record are defined in {{!RFC5103}}.

Information Element   {#informationelement}
===================

This Information Element has been specified in accordance with the guidelines in {{!RFC7013}}.

Design Rationale {#rationale}
----------------

The mapping between {{!I-D.ietf-opsawg-discardmodel}} and the IPFIX flowDiscardClass Information Element follows these principles, maintaining consistency with the YANG model while allowing self-contained decoding from a single IE:

1. Scope. flowDiscardClass reports flow-level discard reasons, and therefore only represents the flow subtree from {{!I-D.ietf-opsawg-discardmodel}}. The component is implicitly "flow" and the type is implicitly "discards".  Device, interface, and control-plane counters are not represented by this IE.

2. Hierarchy preserved, causes only. The enumeration covers the causal subtrees errors, policy, and no-buffer. Both specific classes and their aggregates are assigned values, including layer-qualified causal aggregates such as errors/l3. Standalone layer, address-family, and cast accounting dimensions are excluded because they describe traffic rather than discard causes and that context is already available in companion IPFIX Information Elements.

3. Self-contained decoding. The value alone carries the discard class. Exporters and collectors can still use other IEs (e.g., flowDirection, ipVersion, addresses, ipDiffServCodePoint) for correlation, but they are not required to decode the class. 

4. Implementation-friendly ordering. Initial codes are assigned in preorder traversal, with each parent preceding its children. Future registrations need not preserve this ordering. Hierarchy is therefore determined from the registry Name field rather than from numeric ranges (see {{impl-collector}}).


flowDiscardClass Definition  {#flowDiscardClass-definition}
---------------------------

   Name: flowDiscardClass

   Description: Classifies the reason a packet was discarded in a flow, using the hierarchical classification scheme defined in {{!I-D.ietf-opsawg-discardmodel}}.

   Abstract Data Type: unsigned8

   Data Type Semantics: identifier

   Units: none

   Additional Information: Assigned values are listed in the IANA "flowDiscardClass (Value TBD)" subregistry ({{subregistry}}). Unassigned values are treated as unknown ({{impl-semantics}}).

   Reversibility: reversible, as defined in {{!RFC5103}}.

   Status: current

   ElementId: TBD

   References: {{!I-D.ietf-opsawg-discardmodel}}



flowDiscardClass Values  {#flowDiscardClass-values}
-----------------------

The initial values are taken from draft-ietf-opsawg-discardmodel-16. [RFC Editor: please update this sentence to refer to the published RFC.]

{{flowDiscardClass-table}} defines the initial values for the flowDiscardClass Information Element mapped from the corresponding {{!I-D.ietf-opsawg-discardmodel}} Discard Class.  Codes are assigned in preorder traversal to reflect the hierarchy.

The code points for flowDiscardClass are maintained by IANA in the "flowDiscardClass (Value TBD)" subregistry of the IPFIX registry.  Future additions or changes are managed via Expert Review as described in {{iana}}.

| Discard Class                                                | flowDiscardClass Value |
|:-------------------------------------------------------------|:-----------------------|
| errors                                                       |   0    |
| errors/l2                                                    |   1    |
| errors/l2/rx                                                 |   2    |
| errors/l2/rx/crc-error                                       |   3    |
| errors/l2/rx/invalid-mac                                     |   4    |
| errors/l2/rx/invalid-vlan                                    |   5    |
| errors/l2/rx/invalid-frame                                   |   6    |
| errors/l2/tx                                                 |   7    |
| errors/l3                                                    |   8    |
| errors/l3/rx                                                 |   9    |
| errors/l3/rx/checksum-error                                  |  10    |
| errors/l3/rx/invalid-packet                                  |  11    |
| errors/l3/mtu-exceeded                                       |  12    |
| errors/l3/mtu-exceeded/fragmentation-not-permitted           |  13    |
| errors/l3/mtu-exceeded/fragmentation-permitted-not-performed |  14    |
| errors/l3/ttl-expired                                        |  15    |
| errors/l3/no-route                                           |  16    |
| errors/l3/neighbor-resolution-failure                        |  17    |
| errors/l3/invalid-sid                                        |  18    |
| errors/l3/invalid-label                                      |  19    |
| errors/l3/tx                                                 |  20    |
| errors/internal                                              |  21    |
| errors/internal/parity-error                                 |  22    |
| policy                                                       |  23    |
| policy/l2                                                    |  24    |
| policy/l2/acl                                                |  25    |
| policy/l3                                                    |  26    |
| policy/l3/acl                                                |  27    |
| policy/l3/policer                                            |  28    |
| policy/l3/null-route                                         |  29    |
| policy/l3/rpf                                                |  30    |
| policy/l3/dos                                                |  31    |
| no-buffer                                                    |  32    |
| unassigned                                                   |  33-254 |
| unknown                                                      | 255    |
{: #flowDiscardClass-table title="Flow discard classification values and corresponding discard classes"}

Implementation Requirements {#implreq}
---------------------------

### Semantics and Scope {#impl-semantics}

1. Scope. flowDiscardClass MUST identify a flow-level discard class under flow/discards in {{!I-D.ietf-opsawg-discardmodel}}. It MUST NOT represent an interface, device, or control-plane counter.
2. Code points. Exporters MUST use only assigned values. Collectors MUST treat unrecognized or unassigned values as unknown without rejecting a Flow Record solely for that reason.
3. Direction. flowDiscardClass is reversible under {{!RFC5103}}. Forward and reverse instances in a Biflow Record MAY have different values, each associated with dropped counters for the same direction. For uniflow reporting, the discard direction MUST be unambiguous, for example through flowDirection {{IANA-IPFIX}} or the observation context.

### Exporter Requirements {#impl-exporter}

1. Cardinality. A Flow Record MUST contain at most one flowDiscardClass instance. A Biflow Record MAY additionally contain at most one reverse flowDiscardClass instance, as defined in {{!RFC5103}}.
2. Attribution. Each discarded packet counted under flowDiscardClass MUST be attributed to only one reported discard class for a given observation point and reporting interval. An exporter MUST NOT count the same packet under both an aggregate and a descendant class. When more than one discard class applies to a packet, the exporter SHOULD select the class using the same precedence as the device's discard counters defined in {{!I-D.ietf-opsawg-discardmodel}}.
3. Multiple classes. Exporters MAY use separate Flow Records to report different discard classes for the same flow and interval. Each record's dropped counters MUST quantify only the discarded traffic attributed to its flowDiscardClass value. Records for the same flow and interval can be correlated using consistent flow keys and time bounds. Reporting one discard class does not imply that all discards for the flow have been classified or reported.
4. Specificity. Exporters SHOULD report the most specific known class. If only a broader causal class is known, they SHOULD report the corresponding aggregate. If the cause is unknown, they MUST use unknown (255). Layer knowledge alone does not establish a causal class.
5. Counts and interval. When flowDiscardClass is present, the Flow Record MUST include an applicable dropped-count IE for that class and direction, such as droppedPacketDeltaCount, droppedOctetDeltaCount, or droppedLayer2OctetDeltaCount. For an interval record, the class and its dropped counts describe the discards observed in that interval. A record reporting the occurrence of discards for a class MUST have a non-zero associated dropped count.
6. Correlation context. Exporters supporting correlation with discard counters defined in {{!I-D.ietf-opsawg-discardmodel}} MUST provide, or make unambiguously recoverable, the reporting interval, the relevant device/Observation Domain and observation location, and the discard direction. Interface identification (such as ingressInterface or egressInterface) is necessary when correlating with interface counters; observationPointId can distinguish observation points within a domain. When an aggregate counter is qualified by traffic class, the traffic class used for the discard decision MUST also be identifiable for per-class correlation (e.g., using ipDiffServCodePoint for L3, dot1qPriority for L2, or mplsTopLabelExp for the MPLS Traffic Class field). These details MAY be provided using existing IPFIX IEs or associated observation context; this document does not prescribe a particular record layout.

### Collector Requirements {#impl-collector}
1. Classification. Collectors MUST accept aggregate, leaf, and unknown values. An aggregate class MUST NOT be interpreted as one specific descendant class.
2. Multiple classes. Flow Records with the same flow keys and time bounds but different flowDiscardClass values report different discard classes for the same flow. Collectors MUST NOT treat such records as duplicates.
3. Hierarchy. Collectors MUST resolve parent/child relationships using the registry Name paths, not numeric adjacency or ranges.
4. Correlation. When comparing flow-level dropped counts with aggregate discard counters, collectors MUST account for the observation location, direction, time interval, and classification scope. Where the aggregate counter represents a parent class, a collector can include the matching descendant classes, provided that the reported packet populations do not overlap. Traffic-class-qualified counters require matching traffic-class context. The absence of suitable context or flow-level coverage prevents reliable numerical reconciliation.

### Interoperability with Existing IPFIX IEs {#impl-interop}

1. flowDiscardClass identifies the discard reason independently of other IEs. Existing IEs describe the flow, its direction and observation context, and the quantity of discarded traffic.
2. Exporters MAY also export forwardingStatus {{?RFC7270}}. When both are present, flowDiscardClass provides the discard classification defined here, while forwardingStatus retains its forwarding-outcome semantics. Where the two indicate different discard reasons, collectors SHOULD use flowDiscardClass for discard classification as defined in this document.

Security Considerations {#security}
=======================

This document defines a new Information Element and does not introduce any new protocol mechanism; the security considerations of {{!RFC7011}} and {{!RFC7012}} apply.

The information exported via flowDiscardClass can, however, be sensitive. Per-flow discard classification reveals aspects of a network's operational and security posture: policy values (e.g., policy/l3/acl, policy/l3/rpf, policy/l3/dos, policy/l3/null-route) expose which traffic is being filtered and by what mechanism, no-buffer values reveal congestion conditions, and errors/internal values may indicate device health problems. An attacker able to observe this data could use it to map filtering policies or to assess the effectiveness of an ongoing attack. An attacker able to inject packets and observe the resulting flow records could probe filtering behaviour with per-flow precision, which is finer-grained than the aggregate counters of {{!I-D.ietf-opsawg-discardmodel}}.

Accordingly, IPFIX Transport Sessions carrying this Information Element should be protected consistently with the transport security guidance of {{!RFC7011}} (e.g., TLS or DTLS), and access to collected records should be restricted, consistent with the considerations described in Section 8 of {{!I-D.ietf-opsawg-discardmodel}} for the equivalent counter data.

IANA Considerations {#iana}
===================
IANA is requested to make the following changes under the IP Flow Information Export (IPFIX) Information Elements registry.

## New IPFIX Information Element: flowDiscardClass

IANA is requested to register a new Information Element as follows:

* Name: flowDiscardClass
* ElementId: TBD (to be assigned by IANA)
* Description: Classifies the reason a packet was discarded in a flow, using the hierarchical classification scheme defined in {{!I-D.ietf-opsawg-discardmodel}}.
* Abstract Data Type: unsigned8
* Data Type Semantics: identifier
* Units: none
* Additional Information: Assigned values are listed in the IANA "flowDiscardClass (Value TBD)" subregistry ({{subregistry}}). Unassigned values are treated as unknown ({{impl-semantics}}).
* Reversibility: reversible, as defined in {{!RFC5103}}
* Status: current
* Reference: This document; {{!RFC7013}}

## New Subregistry: "flowDiscardClass (Value TBD)" {#subregistry}

IANA is requested to create a new subregistry titled "flowDiscardClass (Value TBD)" under the IPFIX Information Elements registry, where TBD is the ElementId assigned in {{iana}}, following the naming convention of existing IE value subregistries.

* Registration Procedure: Expert Review {{!RFC8126}}
* Reference: This document; {{!RFC7013}}
* Fields:
  - Value (integer)
  - Name (causal-class path under flow/discards/..., or unknown)
  - Description (optional)
  - Reference

The initial contents of the subregistry are the assigned values listed in {{flowDiscardClass-table}}: values 0-32 and 255. Values 33-254 are unassigned.

Designated Expert guidance: Existing code points MUST NOT be repurposed. Experts SHOULD maintain the hierarchical structure by ensuring each new value's Name is a well-formed path under an existing aggregate (registering the parent aggregate first if absent). New values are assigned from the lowest unassigned code point; preorder numbering is not preserved across additions and implementations do not rely on it.

--- back


Correlating Flow Discards with Interface/Device/Control-Plane Discards {#correlating}
======================================================================

This appendix is non-normative. It illustrates how the classification defined here can relate aggregate discard counters to the flows affected by a discard condition, and how the same flow data can help investigate contributing traffic.

## Correlation Keys {#correlation-keys}

A collector correlates aggregate discard counters with IPFIX Flow Records using:

1. Time: align the counter observation interval with the reporting interval of the flow-level dropped counts, allowing for clock skew and differing interval boundaries.
2. Location: identify the device and Observation Domain, and match ingressInterface or egressInterface and observationPointId where applicable. The relevant observation point must see the packets that are being counted as discarded.
3. Direction: match ingress and egress discards, including the appropriate forward or reverse counters in biflow reporting.
4. Discard class: match the same class, or map a specific class to its registered ancestor when comparing against an aggregate class. A parent class and its descendants must not be counted twice.
5. Traffic class, where applicable: match the traffic class used by the discard mechanism, for example DSCP, 802.1Q PCP, or MPLS Traffic Class. A DSCP-to-queue or other local mapping may be needed when the interface counter is keyed by queue rather than packet marking. Where packets are remarked, the relevant marking is the one used by the discard mechanism. For egress queue discards, this is typically the post-remark value (for example, postIpDiffServCodePoint) rather than the marking received at ingress.

These keys support correlation, not necessarily equality of counters. Observation coverage, sampling, encapsulation, and differences between measurement points can prevent exact reconciliation.

## Analysis Strategies {#analysis-strategies}

Two analyses are useful:

* Impacted flows: identify flows whose dropped counters are attributed to the discard class observed in the aggregate counter.
* Contributing flows: for conditions such as congestion, examine all flows using the affected resource, including those with no discards of their own. High volume or rate makes a flow a candidate contributor; it does not by itself establish causation.

## Operational Example: Congestion Drops {#congestion-example}

Suppose an egress interface reports an increase in no-buffer discards in its Best Effort queue. The operator wants to identify the affected flows and investigate which traffic contributed to the congestion.

The aggregate signal is:

* Time: 2026-10-15 10:00:00 to 10:01:00
* Observation Domain: 1234
* Interface: Ethernet1/0 (ifIndex 10), egress
* Discard class: no-buffer (flowDiscardClass value 32)
* Traffic class: Best Effort (DSCP 0). No remarking is assumed, so ipDiffServCodePoint reflects the marking used for queue selection.

Flow records are selected from the same observation context and reporting interval. Dropped counters associated with flowDiscardClass 32 identify no-buffer loss. Traffic-volume counters from all flows on the affected resource are also considered, including those without no-buffer discards.

The following illustrative results show the two different views:

| Flow                                 |    Traffic volume | No-buffer dropped packets |
|:-------------------------------------|------------------:|--------------------------:|
| 10.0.0.5 to 192.0.2.200, UDP 50000   | 850,000,000 bytes |                         0 |
| 192.0.2.10 to 198.51.100.55, TCP 443 |  15,000,000 bytes |                    15,400 |
| 192.0.2.12 to 198.51.100.80, TCP 80  |   4,200,000 bytes |                     2,100 |

The TCP flow to 198.51.100.55 is the most affected in this example. The large UDP flow has no reported no-buffer loss but is a candidate contributor because it uses the same congested queue. Establishing whether it caused the congestion would require further evidence, such as queue occupancy, timing, and traffic bursts.

An implementation might perform this analysis with a query such as the following. The query assumes a storage model in which each traffic-volume counter is accounted for once and class-attributed dropped counts are held separately. If the same traffic counters appear in several stored records, for example in separate class-attributed records for one flow, summing them as shown overstates traffic volume. The query is illustrative and does not prescribe an exporter record layout.

~~~ sql
SELECT src_addr, dst_addr, l4_dst_port, protocol,
       SUM(COALESCE(octetDeltaCount, 0)) AS total_bytes,
       SUM(CASE WHEN flowDiscardClass = 32
                THEN COALESCE(droppedPacketDeltaCount, 0)
                ELSE 0 END) AS nobuf_pkt_discards
FROM   flow_records
WHERE  observationDomainId = 1234
  AND  egressInterface = 10
  AND  flowEnd >= '2026-10-15 10:00:00'
  AND  flowStart <= '2026-10-15 10:01:00'
  AND  ipDiffServCodePoint = 0
GROUP BY src_addr, dst_addr, l4_dst_port, protocol;
~~~

The query does not filter out flows without matching discards, because those flows may have contributed to the congestion.

## Implementation Note on Sampling {#sampling}

When the Metering Process samples packets, the reported dropped counts may describe only sampled observations. A sampling-rate multiplier can estimate unsampled totals only when discarded packets are included in the sampling population with a known inclusion probability.

For uniform independent sampling with probability p, an illustrative estimate is:

* estimated dropped packets = sampled dropped packets / p
* estimated dropped octets = sampled dropped octets / p

For 1-in-100 sampling, the multiplier is 100. The result is an estimate, not an exact count; uncertainty can be substantial for low-volume classes. If the observation or sampling process excludes discarded packets, this method cannot recover their counts. Sampling parameters may be exported using existing PSAMP Information Elements {{?RFC5477}}.
