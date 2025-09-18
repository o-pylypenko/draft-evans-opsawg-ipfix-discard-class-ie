---
title: Information Element for Flow Discard Classification
abbrev: IE for Flow Discard Classification
docname: draft-evans-opsawg-ipfix-discard-class-ie
date: 2025-09-18
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
    org: Amazon
    street: 1 Principal Place, Worship Street
    city: London
    code: EC2A 2FA
    country: UK
    email: jevanamz@amazon.co.uk
    
 -
    ins: O. Pylypenko
    name: Oleksandr Pylypenko
    org: Amazon
    street: 410 Terry Ave N
    city: Seattle
    region: WA
    code: 98109
    country: US
    email: opyl@amazon.com

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


informative:
     RFC7270:
     I-D.ietf-opsawg-discardmodel:
          target: https://datatracker.ietf.org/doc/draft-ietf-opsawg-discardmodel/
          title: "Information and Data Models for Packet Discard Reporting"
     RFC9710:
     RFC7012:
     RFC7013:
     RFC7011:
     RFC6313:
     RFC8126:
     RFC5103:

     
--- abstract

This document defines a new IPFIX Information Element for classifying flow-level discards which aligns with the information model defined in {{?I-D.ietf-opsawg-discardmodel}}. The flowDiscardClass Information Element provides consistent classification of packet discards across IPFIX implementations, enabling correlation between device and interface-level statistics and impacted flows.

--- middle

Introduction        {#introduction}
============

For network operators, understanding both where and why packet loss occurs within a network is essential for effective operation. While certain types of packet loss, such as policy-based discards, are intentional and part of normal network operation, unintended packet loss can impact customer services. To automate network operations, operators must be able to detect customer-impacting packet loss, determine its root cause, and apply appropriate mitigation actions.

{{?I-D.ietf-opsawg-discardmodel}} addresses this need by defining an information model that provides precise classification of packet loss, enabling accurate automated mitigation. While its YANG data model implementation provides device, interface and control-plane discards, effective automated triage often requires understanding which specific flows are impacted. For example, when mitigating congestion, operators may need to identify and trace the sources of elephant flows. This requires the ability to correlate device and interface-level discard classes with the specific flows being dropped.

Currently, {{?RFC7270}} defines the forwardingStatus Information Element for reporting packet forwarding outcomes in IPFIX, including various reasons for packet drops. The defined drop reason codes lack the granularity and clarity needed for automated root cause analysis and impact mitigation, however. For instance, the "For us" reason code provides insufficient context to determine appropriate mitigation actions.

This document addresses these limitations by introducing a new Information Element, flowDiscardClass, to provide a consistent classification scheme for packet discards across IPFIX implementations. This new element aligns with the classification scheme defined in {{?I-D.ietf-opsawg-discardmodel}} and enables:

1. Precise detection of unintended packet loss through clear distinction between intended and unintended discards

2. Accurate root cause analysis through detailed classification of discard reasons

3. Automated selection of mitigation actions based on discard type, rate, and duration

4. Consistent reporting across vendor implementations in both YANG and IPFIX data models

By providing this mapping between YANG and IPFIX implementations, this document enables operators to correlate device-level statistics with flow-level impacts, facilitating more effective automated network operations.

Terminology {#terminology}
===========

{::boilerplate bcp14-tagged}

A packet discard accounts for any instance where a packet is dropped by a device, regardless of whether the discard was intentional or unintentional.

Intended discards are packets dropped due to deliberate network policies or configurations designed to enforce security or quality of service. For example, packets dropped because they match an Access Control List (ACL) denying certain traffic types.

Unintended discards are packets that were dropped, which the network operator otherwise intended to deliver, i.e. which indicates an error state.  There are many possible reasons for unintended packet loss, including: erroring links may corrupt packets in transit; incorrect routing tables may result in packets being dropped because they do not match a valid route; configuration errors may result in a valid packet incorrectly matching an ACL and being dropped.

Device discard counters do not by themselves establish operator intent. Discards reported under policy (e.g., ACL/policer) indicate only that traffic matched a configured rule; such discards may still be unintended if the configuration is in error. Determining intent for policy discards requires external context (e.g., configuration validation and change history) which is out of scope for this specification.

Information Element   {#informationelement}
===================

This Information Element has been specified in accordance with the guidelines in {{?RFC7013}}.

Design Rationale {#rationale}
----------------

The mapping between {{?I-D.ietf-opsawg-discardmodel}} and the IPFIX flowDiscardClass Information Element follows these principles, maintaining consistency with the YANG model while allowing self-contained decoding from a single IE

1. The flowDiscardClass Information Element is specifically for reporting flow-level discard reasons, and therefore only represents the flow subtree from {{?I-D.ietf-opsawg-discardmodel}}. The component is implicitly "flow" and the type is implicitly "discards"; interface, device, and control-plane components are out of scope for this IE.

2. All leaves under flow/discards are assigned codes, and aggregate (parent) nodes are also assigned codes to enable coarse-grained rollups.

3. To preserve the information model’s hierarchy, the code space includes structural aggregates under flow/discards/l2 and flow/discards/l3, and for L3 the address-family and cast aggregates l3/{v4,v6}/{unicast,multicast}.

4. Exporters and collectors MAY continue to use existing IPFIX IEs (e.g., flowDirection, ipVersion, addresses, ipDiffServCodePoint) for filtering, correlation, or redundancy, but flowDiscardClass alone suffices to recover the discard classification.


flowDiscardClass Definition  {#flowDiscardClass-definition}
---------------------------

   Name: flowDiscardClass

   Description: Classifies the reason a packet was discarded in a flow, using the hierarchical classification scheme defined in {{?I-D.ietf-opsawg-discardmodel}}.

   Abstract Data Type: unsigned8

   Data Type Semantics: identifier

   Units: none

   Range: 0..38 (values from {{flowDiscardClass-table}}; other values are unassigned and MUST be treated as unknown)

   Reversibility: reversible (value does not change under flow reversal as per {{?RFC5103}})

   Status: current

   ElementId: TBD

   References: {{?I-D.ietf-opsawg-discardmodel}}



flowDiscardClass Values  {#flowDiscardClass-values}
----------------------- 
   
{{flowDiscardClass-table}} defines the values for the flowDiscardClass Information Element mapped from the corresponding {{?I-D.ietf-opsawg-discardmodel}} Discard Class.  The codepoints for flowDiscardClass are maintained by IANA in the "flowDiscardClass Values" subregistry of the IPFIX registry.  Future additions or changes are managed via Expert Review as described in {{iana}}.


| Discard Class                  | flowDiscardClass Value |
|:-------------------------------|:-----------------------|
| l2                                    |  0     |
| l3                                    |  1     |
| l3/v4                                 |  2     |
| l3/v4/unicast                         |  3     |
| l3/v4/multicast                       |  4     |
| l3/v6                                 |  5     |
| l3/v6/unicast                         |  6     |
| l3/v6/multicast                       |  7     |
| errors                                |  8     |
| errors/l2                             |  9     |
| errors/l2/rx                          |  10     |
| errors/l2/rx/crc-error                |  11     |
| errors/l2/rx/invalid-mac              |  12     |
| errors/l2/rx/invalid-vlan             |  13     |
| errors/l2/rx/invalid-frame            |  14     |
| errors/l2/tx                          |  15     |
| errors/l3                             |  16     |
| errors/l3/rx                          |  17     |
| errors/l3/rx/checksum-error           |  18     |
| errors/l3/rx/mtu-exceeded             |  19     |
| errors/l3/rx/invalid-packet           |  20     |
| errors/l3/ttl-expired                 |  21     |
| errors/l3/no-route                    |  22     |
| errors/l3/invalid-sid                 |  23     |
| errors/l3/invalid-label               |  24     |
| errors/l3/tx                          |  25     |
| errors/internal                       |  26     |
| errors/internal/parity-error          |  27     |
| policy                                |  28     |
| policy/l2                             |  29     |
| policy/l2/acl                         |  30     |
| policy/l3                             |  31     |
| policy/l3/acl                         |  32     |
| policy/l3/policer                     |  33     |
| policy/l3/null-route                  |  34     |
| policy/l3/rpf                         |  35     |
| policy/l3/ddos                        |  36     |
| no-buffer                             |  37     |
| no-buffer/class                       |  38      |
{: #flowDiscardClass-table title="Flow discard classification values and corresponding discard classes"}

Codes are assigned in preorder (depth-first) tree order to reflect the model’s hierarchy. no-buffer/class conveys per-QoS class congestion loss; the specific class (e.g., DSCP/class index, or L2 PCP) SHOULD be exported via the appropriate companion IE in the same record.


Usage with Existing Information Elements {#ExistingInformationElements}
----------------------------------------

flowDiscardClass enumerates all leaf and aggregate nodes under flow/discards so that a collector can recover the full classification from this IE alone, with the exception of traffic class.

Per-class congestive loss (no-buffer/class): When reporting no-buffer/class, the specific traffic class (e.g., DSCP or L2 PCP) SHOULD be carried in a companion IE (e.g., ipDiffServCodePoint, ipClassOfService, or dot1qPriority) in the same record; flowDiscardClass itself remains an identifier only, consistent with {{?RFC7013}} separation of condition vs. parameters.

Multiplicity: Exporters MUST NOT encode multiple discard reasons in a single instance of flowDiscardClass. If multiple reasons apply, export multiple records (one per reason) or use IPFIX Structured Data (e.g., a basicList of flowDiscardClass values) per {{?RFC6313}} and {{?RFC7013}}.


Security Considerations {#security}
=======================

This document defines a new Information Element for flow-level discard classification to align with the information model defined in {{?I-D.ietf-opsawg-discardmodel}}.  As such, there are no  security issues related to this document, which are additional to those discussed in {{?RFC7011}}, {{?RFC7012}}.


IANA Considerations {#iana}
===================
      
This document requests IANA to register the flowDiscardClass Information Element in the IANA IPFIX Information Elements registry.

IANA is requested to make the following actions in the IP Flow Information Export (IPFIX) Entities registry:

1. Register the flowDiscardClass Information Element.

2. Create a new subregistry: "flowDiscardClass Values":

   Registry: under IP Flow Information Export (IPFIX) Entities

   Registration Procedure: Expert Review {{RFC8126}}

   Reference: this document; {{RFC7013}}

   Fields:

   * Value (integer)
   * Name (path under flow/discards/...)
   * Description (optional)
   * Reference

   Initial contents: the values in {{flowDiscardClass-table}} (codes 0..38).

   Allocation policy guidance to the Designated Expert(s): New values should reflect additions to or clarifications of the discard reasons in {{I-D.ietf-opsawg-discardmodel}} (or its successor) and must not repurpose existing codepoints. Backwards-compatible additions are preferred; revisions to existing entries should follow {{RFC7013}}.

   
--- back

Correlating Flow Discards with Interface/Device Discards {#correlating}
========================================================

This section gives non-normative guidance for correlating flow-level discard 
reporting (this document) with interface and device discard aggregates exported
via {{?I-D.ietf-opsawg-discardmodel}}. The goal is to enable operators to correlate device and interface-level discard classes with the specific flows being dropped.

Correlation Keys {#correlation-keys}
----------------

Collectors SHOULD correlate records along the following axes:

### Device / Observation Domain {#device-observation-domain}

The observationDomainId (IPFIX message header) binds Flow Records to the same 
Exporter/Observation Domain as the device-level or interface-level counters.

The observationPointId (IE 138) can disambiguate between multiple observation 
points on a device (e.g., line card/port pipeline). Exporters MAY also include
lineCardId (IE 141) and portId (IE 142) to improve stability across interface
renumbering.

### Interface Context {#interface-context}

Exporters SHOULD include ingressInterface (IE 10) and/or egressInterface (IE 14)
in Flow Records carrying discard information, so that flow-level drops can be
grouped to the same interface hierarchy used by the discardmodel. Note that
values correspond to ifIndex semantics and may be reassigned on reboot.

### Time Alignment {#time-alignment}

When Flow Records represent an interval, use IPFIX time IEs to align with the
window of the discardmodel counters:

* flowStart/flowEnd timestamps (e.g., millisecond-precision variants) and/or
* observationTime{Seconds,Milliseconds,Microseconds,Nanoseconds} for event-style
  exports

Collectors SHOULD perform windowed joins (e.g., within the Flow's start/end 
bounds) when aggregating flows to interface/device counters.

### Discard Class {#discard-class}

This draft's flowDiscardClass values index the leaf and aggregate classes 
defined by the discardmodel, including L2 and L3 aggregates. Correlation is
therefore a direct match on the class identifier.

Recommended Exporter Behaviour {#recommended-exporter-behaviour}
------------------------------

To facilitate accurate correlation, an Exporter that sets flowDiscardClass for
a Flow Record:

* SHOULD also export ingressInterface/egressInterface and observationPointId in
  the same record/template.

* SHOULD export time bounds (flowStart/flowEnd) or an observationTime* timestamp
  appropriate to the reporting model.

* SHOULD include counters that quantify the drop, such as droppedOctetDeltaCount
  (IE 132) and droppedPacketDeltaCount (IE 133), when available, alongside this
  draft's class indicator, so that the per-class volume can be rolled up to the
  interface/device aggregates. (For L2 counters, the corresponding IEs such as
  droppedLayer2OctetDeltaCount (IE 424) apply.)

* MAY include lineCardId/portId when interface renumbering is common in the
  deployment.

These recommendations follow {{?RFC7013}} guidance to keep identifiers and semantics
precise, avoid ambiguity about scope, and provide sufficient context to interpret
counters correctly.

Correlating to Discardmodel Components {#correlating-to-discardmodel-components}
--------------------------------------

The discardmodel organizes counters under three components: interface, device,
and control-plane, with traffic and discards subtrees, per direction and class.
A collector can:

### Interface-level Correlation {#interface-level-correlation}

Group Flow Records by (observationDomainId, observationPointId?, 
ingressInterface/egressInterface, flowDiscardClass) over the chosen time window
and sum dropped-packet/byte deltas. Compare to the discardmodel's per-interface,
per-direction, per-class counters in the corresponding time bucket.

### Device-level Correlation {#device-level-correlation}

Repeat the above grouping without the interface keys (sum over all interfaces),
and compare to device-level aggregates in the discardmodel.

### Control-plane Correlation {#control-plane-correlation}

Where applicable, correlate Flow Records whose flowDiscardClass indicates
control-plane policy/actions with the discardmodel's control-plane subtree.
(Exporters may additionally use forwarding status IEs when relevant; see {{?RFC9710}} updates to the IPFIX registry.)

Handling Expected Discrepancies {#handling-expected-discrepancies}
-------------------------------

Differences between summed flow-level drops and interface/device aggregates are
expected when:

* Different observation points (e.g., pre- vs post-feature stages) are used;
  observationPointId and observationPointType can explain such gaps.

* Sampling or filtering is applied to flows but not to device counters.

* Clock skew / windowing causes boundary effects; prefer aligning to
  observationTime* if flows are very short.

Exporters SHOULD document (or export via Options) any sampling, filtering, or
pipeline placement that affects visibility, per {{?RFC7011}}/{{?RFC7012}} operational
guidance.
