---
title: Information Element for Flow Discard Classification
abbrev: IE for Flow Discard Classification
docname: draft-evans-opsawg-ipfix-discard-class-ie-latest
date: 2026-07-09
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
    role: editor
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

informative:

--- abstract

This document defines the IPFIX flowDiscardClass Information Element for classifying flow-level packet discards using the discard classes defined in {{!I-D.ietf-opsawg-discardmodel}}. The Information Element enables correlation between device, interface, and control-plane discard counters and the flows affected by those discards.

--- middle

Introduction        {#introduction}
============

Network operators need to know where packet loss occurs and why packets are dropped. Some packet loss, such as policy-based discards, is intentional and part of normal operation. Unintended packet loss can impact customer services. Automated operations require discard signals that support detection, diagnosis, and mitigation.

{{!I-D.ietf-opsawg-discardmodel}} defines an information model for classifying packet discards. Its YANG data model provides device, interface, and control-plane discard counters. Operators also need the same discard classification at flow level, so that aggregate discard counters can be correlated with affected flows. For example, when mitigating congestion, operators may need to identify and trace the sources of elephant flows.

{{!RFC7270}} defines the forwardingStatus Information Element for reporting forwarding outcomes in IPFIX, including packet drops. Those drop reason codes do not provide the discard classes defined by {{!I-D.ietf-opsawg-discardmodel}}.

This document defines the flowDiscardClass Information Element. The value identifies the discard class for packets dropped within a Flow Record, using the classification paths defined by {{!I-D.ietf-opsawg-discardmodel}}. Using the same discard classes in IPFIX and the YANG model allows collectors to correlate flow-level loss with device, interface, and control-plane discard counters.

Terminology {#terminology}
===========

{::boilerplate bcp14-tagged}

This document uses the terms "packet discard", "intended discards", and "unintended discards" as defined in {{!I-D.ietf-opsawg-discardmodel}}, which also discusses (Section 6.1) why discard counters do not by themselves establish operator intent. Determining intent for policy discards is out of scope for this specification.

Information Element   {#informationelement}
===================

This Information Element has been specified in accordance with the guidelines in {{!RFC7013}}.

Design Rationale {#rationale}
----------------

The mapping follows these principles:

1. Scope. flowDiscardClass reports flow-level discard reasons from the flow subtree of {{!I-D.ietf-opsawg-discardmodel}}. The component is implicitly "flow/discards". Interface, device, and control-plane counters are out of scope.

2. Hierarchy preserved, causes only. The enumeration mirrors the causal subtrees of the model: errors, policy, and no-buffer. Both leaf classes and aggregate classes are assigned values. Layer-qualified nodes within a causal subtree, such as errors/l3 and policy/l2, are assigned values because they are causal aggregates. Standalone layer, address-family, and cast accounting dimensions, such as l2 or l3/address-family-stat/unicast, are not assigned values because they are accounting dimensions, not discard causes. In IPFIX, this context is recoverable from existing IEs in the same Flow Record, such as ipVersion, source and destination addresses, and dataLinkFrameType. This keeps flowDiscardClass values mutually exclusive: distinct values for the same flow and interval identify distinct discarded packets, provided each packet is attributed to exactly one value ({{impl-exporter}}).

3. Self-contained decoding. The value alone carries the discard class ({{impl-interop}}).

4. Implementation-friendly ordering. Initial codes use preorder traversal, with each parent numbered before its children. This is a property of the initial assignment only; future registrations are appended and need not preserve it, so hierarchy is determined from the registry's Name field ({{impl-collector}}).

flowDiscardClass Definition  {#flowDiscardClass-definition}
---------------------------

   Name: flowDiscardClass

   Description: Classifies the reason a packet was discarded in a flow, using the hierarchical classification scheme defined in {{!I-D.ietf-opsawg-discardmodel}}.

   Abstract Data Type: unsigned8

   Data Type Semantics: identifier

   Units: none

   Range: 0..255. Assigned values are maintained in the IANA "flowDiscardClass (Value TBD)" subregistry ({{subregistry}}); unassigned values MUST be treated as unknown ({{impl-semantics}}).

   Reversibility: reversible (value does not change under flow reversal as per {{!RFC5103}})

   Status: current

   ElementId: TBD

   References: {{!I-D.ietf-opsawg-discardmodel}}

flowDiscardClass Values  {#flowDiscardClass-values}
-----------------------

{{flowDiscardClass-table}} defines the initial values, mapped from the corresponding {{!I-D.ietf-opsawg-discardmodel}} discard classes. Values are maintained in the IANA "flowDiscardClass (Value TBD)" subregistry ({{subregistry}}).

| Discard Class                  | flowDiscardClass Value |
|:-------------------------------|:-----------------------|
| errors                         |   0    |
| errors/l2                      |   1    |
| errors/l2/rx                   |   2    |
| errors/l2/rx/crc-error         |   3    |
| errors/l2/rx/invalid-mac       |   4    |
| errors/l2/rx/invalid-vlan      |   5    |
| errors/l2/rx/invalid-frame     |   6    |
| errors/l2/tx                   |   7    |
| errors/l3                      |   8    |
| errors/l3/rx                   |   9    |
| errors/l3/rx/checksum-error    |  10    |
| errors/l3/rx/mtu-exceeded      |  11    |
| errors/l3/rx/invalid-packet    |  12    |
| errors/l3/ttl-expired          |  13    |
| errors/l3/no-route             |  14    |
| errors/l3/invalid-sid          |  15    |
| errors/l3/invalid-label        |  16    |
| errors/l3/tx                   |  17    |
| errors/internal                |  18    |
| errors/internal/parity-error   |  19    |
| policy                         |  20    |
| policy/l2                      |  21    |
| policy/l2/acl                  |  22    |
| policy/l3                      |  23    |
| policy/l3/acl                  |  24    |
| policy/l3/policer              |  25    |
| policy/l3/null-route           |  26    |
| policy/l3/rpf                  |  27    |
| policy/l3/ddos                 |  28    |
| no-buffer                      |  29    |
| unknown                        | 255    |
{: #flowDiscardClass-table title="Flow discard classification values and corresponding discard classes"}

Values 30-254 are unassigned.

For discard classes where per-traffic-class granularity is operationally significant (e.g., no-buffer, policy/l3/policer), the traffic class SHOULD be conveyed via companion IEs in the same Flow Record (e.g., ipDiffServCodePoint for L3, dot1qPriority for L2, mplsTopLabelExp for the MPLS Traffic Class field). This enables correlation with per-class interface counters from {{!I-D.ietf-opsawg-discardmodel}}.

Implementation Requirements {#implreq}
---------------------------

### Semantics and Scope {#impl-semantics}

1. Scope. flowDiscardClass MUST report only flow-level discard classes under flow/discards in {{!I-D.ietf-opsawg-discardmodel}}. It MUST NOT be used for interface, device, or control-plane discard counters.
2. Enumeration. Exporters MUST encode only values from the IANA "flowDiscardClass (Value TBD)" subregistry for this IE, and MUST NOT transmit unassigned values.
3. Direction and reversibility. The value of flowDiscardClass MUST NOT change under biflow reversal as defined by {{!RFC5103}}. In a Biflow Record, flowDiscardClass does not by itself identify the discard direction; direction is indicated by the forward or reverse dropped-count IEs. The flow structure in {{!I-D.ietf-opsawg-discardmodel}} is keyed by direction; exporters MUST include flowDirection {{IANA-IPFIX}} or otherwise make the direction of the classified discards unambiguous (e.g., by exporting separate per-direction Flow Records).

### Exporter Requirements {#impl-exporter}

1. Cardinality. A Flow Record MUST contain at most one instance of flowDiscardClass.
2. Attribution. Each discarded packet reported using flowDiscardClass MUST be attributed to exactly one flowDiscardClass value. An exporter MUST NOT report the same discarded packet against both an aggregate class and one of its descendant classes.
3. Multiplicity. When multiple discard reasons apply to the same flow interval, exporters SHOULD export one Flow Record per discard reason, using the same flow keys and timestamps and a distinct flowDiscardClass value. Exporters that can report only one reason per flow entry MUST report the reason accounting for the most discarded packets in the interval, or the nearest common aggregate class. When exporting multiple records for the same flow interval, exporters MUST NOT duplicate non-discard traffic counters (e.g., octetDeltaCount, packetDeltaCount) across the reason-specific records; they SHOULD be exported on at most one record for the flow interval.
4. Specificity. Exporters SHOULD report the most specific known class (a leaf). If only a broader causal class is known, exporters SHOULD report the nearest known aggregate (e.g., errors/l3 for a Layer 3 error whose specific reason is unknown, or policy for a policy discard of unknown type). If the causal class is unknown, exporters MUST report unknown; knowledge of the layer alone does not identify a causal class.
5. Dropped counts. In an interval Flow Record, the presence of flowDiscardClass indicates that at least one packet in the interval matched that class. Exporters MUST include droppedPacketDeltaCount, droppedOctetDeltaCount, or another applicable dropped-count IE in the same record to quantify the volume attributed to that discard class. Note that droppedOctetDeltaCount counts IP header and payload octets; for Layer 2 byte accounting, exporters SHOULD use droppedLayer2OctetDeltaCount.
6. Traffic class context. Where per-class correlation is operationally significant (e.g., no-buffer, policy/l3/policer), exporters SHOULD include a traffic-class IE in the same record (e.g., ipDiffServCodePoint or ipClassOfService for L3, dot1qPriority for L2, mplsTopLabelExp for the MPLS Traffic Class field). If classification occurs after remarking, exporters SHOULD report the class used for the discard decision, or provide a queue-to-class mapping via IPFIX Options data.
7. Context. For correlation with interface/device/control-plane counters, exporters SHOULD include time bounds (flowStart/flowEnd or an observation-time IE), ingressInterface/egressInterface as applicable, and observationPointId when multiple pipeline stages/taps exist.

### Collector Requirements {#impl-collector}

1. Multiple records per flow. When multiple Flow Records carry different flowDiscardClass values for the same flow keys and overlapping time intervals, collectors MUST treat them as indicating distinct discard reasons affecting the same flow. Collectors SHOULD aggregate these records when computing per-flow total discards, while preserving per-reason breakdowns.
2. Aggregate handling. Collectors MUST accept both aggregate and leaf values; an aggregate class is a coarse classification that is a semantic superset of its descendants and MUST NOT be interpreted as any specific descendant class.
3. Traffic class correlation. When a traffic-class IE is present alongside no-buffer or policy/l3/policer, collectors SHOULD use it to correlate with per-class interface counters. If absent, collectors MAY apply local device mappings if available.
4. Unknown values. Collectors MUST handle unknown or unassigned values gracefully (e.g., categorize as unknown) without rejecting the record, and MUST NOT remap them to another code.
5. Hierarchy resolution. Collectors MUST resolve parent/child relationships between values using the classification path in the Name field of the "flowDiscardClass (Value TBD)" subregistry. Collectors MUST NOT infer hierarchy from numeric adjacency or value ranges.

### Interoperability with Existing IPFIX IEs {#impl-interop}

1. flowDiscardClass alone MUST be sufficient to recover the discard classification.
2. Exporters MAY export forwardingStatus {{!RFC7270}} in parallel. When both are present, flowDiscardClass MUST be considered authoritative for discard classification only; forwardingStatus remains authoritative for the forwarding outcome itself (forwarded, dropped, consumed) and its own reason-code space is unaffected by this document.
3. When flow sampling is active, the presence of flowDiscardClass indicates at least one sampled packet matched that class.

Security Considerations {#security}
=======================

This document defines a new Information Element and does not introduce a new protocol mechanism. The security considerations of {{!RFC7011}} and {{!RFC7012}} apply.

flowDiscardClass can expose sensitive operational information: it can reveal filtering policy, congestion conditions, attack mitigation, and device-health information. An attacker able to observe this data could use it to map filtering policies or assess the effectiveness of an ongoing attack. Per-flow reporting can also make such probing more precise than the aggregate counters of {{!I-D.ietf-opsawg-discardmodel}}.

IPFIX Transport Sessions carrying this Information Element should be protected consistently with the transport security guidance of {{!RFC7011}}, and access to collected records should be restricted, consistent with the considerations of Section 8 of {{!I-D.ietf-opsawg-discardmodel}} for the equivalent counter data.

IANA Considerations {#iana}
===================

IANA is requested to make the following changes under the IP Flow Information Export (IPFIX) Information Elements registry.

## New IPFIX Information Element: flowDiscardClass

IANA is requested to register the flowDiscardClass Information Element as defined in {{flowDiscardClass-definition}}, with the ElementId assigned by IANA.

## New Subregistry: "flowDiscardClass (Value TBD)" {#subregistry}

IANA is requested to create a new subregistry titled "flowDiscardClass (Value TBD)" under the IPFIX Information Elements registry, where TBD is the ElementId assigned in {{iana}}, following the naming convention of existing IE value subregistries.

* Registration Procedure: Expert Review {{!RFC8126}}
* Reference: This document; {{!RFC7013}}
* Fields:
  - Value (integer)
  - Name (path under flow/discards/..., or the special value unknown)
  - Description (optional)
  - Reference

The initial contents of the subregistry are the assigned values listed in {{flowDiscardClass-table}}: values 0-29 and 255. Values 30-254 are unassigned. This document is the Reference for each assigned value.

Designated Expert guidance: Existing code points MUST NOT be repurposed; backwards-compatible additions are preferred. Experts SHOULD maintain the hierarchy by requiring each new Name to be a well-formed path under an existing aggregate (registering the parent aggregate first if absent). New values are assigned from the lowest unassigned code point; preorder numbering is not preserved across additions.

--- back

Correlating Flow Discards with Interface/Device/Control-Plane Discards {#correlating}
======================================================================

This non-normative appendix describes how collectors can correlate aggregate discard counters (from {{!I-D.ietf-opsawg-discardmodel}}) with affected flows.

Correlation Keys {#correlation-keys}
----------------

Collectors correlate discard counters with flow records using:

1. Time: Align the counter collection interval with the Flow Record start and end times, allowing for small clock skew.

2. Location: Match the Observation Domain and interface.
   * For ingress discards: match ingressInterface.
   * For egress discards: match egressInterface.

3. Direction: Match flowDirection against the direction of the discard counter (ingress or egress).

4. Discard Class: Match the YANG discard-class leaf with the IPFIX flowDiscardClass value.
   * If the drop is traffic-class specific (e.g., no-buffer), also match the traffic-class identifier (e.g., ipDiffServCodePoint) to the specific queue experiencing loss.

Analysis Strategies {#analysis-strategies}
-------------------

Once flow records are correlated with discard counters, two analyses are possible over the same result set: impacted analysis (which flows suffered loss of the given class) and, for congestive discards, causal analysis (which flows likely drove the condition, ranked by volume — including flows that suffered no loss themselves). {{congestion-example}} demonstrates both.

Operational Example: Congestion Drops {#congestion-example}
-------------------------------------

Scenario: an anomaly is detected in no-buffer discards on Ethernet1/0 (ifIndex 10) in the egress direction. The drops are occurring in the Best Effort queue (DSCP 0). The operator wants to identify affected flows and likely contributors.

1. Signal: Interface discard counter

   * Time: 2025-09-18 10:00:00 to 10:01:00
   * Observation Domain: 1234
   * Interface: 10 (egress)
   * Class: no-buffer (value 29; see {{flowDiscardClass-table}})
   * Queue/DSCP: 0

2. Correlation: SQL Query

   The query selects all flows sharing the congested resource — matching the observation domain, egress interface, time window, and traffic class per {{correlation-keys}} — and uses conditional aggregation to attribute loss per flow only to no-buffer discards. Under the multi-record export model ({{impl-exporter}}), a flow may carry discard records for several distinct reasons in the same interval; an unscoped sum of dropped counts would conflate unrelated discards with the congestion event.

~~~ sql
SELECT src_addr, dst_addr, l4_dst_port, protocol,
       SUM(octetDeltaCount)  AS total_bytes,
       SUM(packetDeltaCount) AS total_pkts,
       SUM(CASE WHEN flowDiscardClass = 29
                THEN droppedPacketDeltaCount
                ELSE 0 END)  AS nobuf_pkt_discards
FROM   flow_records
WHERE
       -- 0. Match Observation Domain
       observationDomainId = 1234
       -- 1. Match Location (egress interface)
  AND  egressInterface = 10
       -- 2. Match Time Window (any overlap with counter interval)
  AND  flowEnd   >= '2025-09-18 10:00:00'
  AND  flowStart <= '2025-09-18 10:01:00'
       -- 3. Match Traffic Class context (Best Effort queue)
  AND  ipDiffServCodePoint = 0
GROUP  BY src_addr, dst_addr, l4_dst_port, protocol;
~~~

   The query deliberately does not filter on flowDiscardClass — doing so would exclude flows with no discard records of the matching class, which (as the results show) can include the flows most responsible for the congestion. The summation of octetDeltaCount and packetDeltaCount relies on the non-duplication requirement of {{impl-exporter}}; stores fed by non-compliant exporters require de-duplication of traffic counters per flow interval first.

3. Results: two readings of one result set

   Ordering by nobuf_pkt_discards descending identifies flows affected by the loss:

| src_addr   | dst_addr      | l4_dst_port | protocol | total_bytes | total_pkts | nobuf_pkt_discards |
| :---       | :---          | :---        | :---     | ---:        | ---:       | ---:               |
| 192.0.2.10 | 198.51.100.55 | 443         | 6 (TCP)  |  15,000,000 |     21,000 |             15,400 |
| 192.0.2.12 | 198.51.100.80 | 80          | 6 (TCP)  |   4,200,000 |      5,900 |              2,100 |

   Ordering the same result set by total_bytes descending identifies flows that likely contributed to the congested queue:

| src_addr   | dst_addr      | l4_dst_port | protocol | total_bytes | total_pkts | nobuf_pkt_discards |
| :---       | :---          | :---        | :---     | ---:        | ---:       | ---:               |
| 10.0.0.5   | 192.0.2.200   | 4791        | 17 (UDP) | 850,000,000 |  1,214,285 |                  0 |
| 192.0.2.10 | 198.51.100.55 | 443         | 6 (TCP)  |  15,000,000 |     21,000 |             15,400 |

   The two readings surface different flows. The flow from 10.0.0.5 transferred 850 MB through the congested queue while suffering no no-buffer loss of its own — its bursts fill the buffer, with the losses landing on competing traffic. It is the primary causal candidate, yet it is invisible to any analysis that considers only flows carrying the discard class. Conversely, the flow from 192.0.2.10 is the most heavily impacted but, at 15 MB, too small to be the primary cause.

Implementation Note on Sampling {#sampling}
-------------------------------

When flow sampling is active, flowDiscardClass indicates that a sampled packet was dropped. To estimate unsampled flow-level impact and compare it with interface counters (which are typically unsampled), operators can apply a sampling-rate multiplier to the dropped counters.

Let:

* p = the sampling probability (e.g., 0.01 for 1-in-100 sampling)
* N = 1 / p be the corresponding "1-in-N" sampling interval

The sampling-rate multiplier is N:

* estimated_total_dropped_packets = droppedPacketDeltaCount * N
* estimated_total_dropped_octets = droppedOctetDeltaCount * N

Exporters typically report their sampling configuration via IPFIX using samplingProbability, or the applicable PSAMP selector parameters such as samplingPacketInterval and samplingPacketSpace.
