---
layout: default
---

<!--The Florida Institute for Cybersecurity Research (FICS Research)-->

## Research

#### [RANsacked](/ransacked) - Domain-Informed LTE/5G RAN-Core Fuzzing

Cellular networks have become critical to daily communication and emergency services. At the same
time, the internals of cellular protocols have increased in complexity through successive
generations. This increased complexity raises the likelihood of bugs and vulnerabilities in
cellular deployments, and adversaries have more access to these networks than ever before:

![RAN-Core Threats](/assets/images/ransacked-threats.png)

**RANsacked** leverages open-source testbed setups to inform the innovation and application of
fuzzing techniques to the cellular domain. Our advances enable hundreds of millions of unique inputs
to be tested on the core per CPU-day; each testcase is intelligently formed to appear to be valid
and pass decoding requirements, thereby allowing deeper exploration into the protocol. Our research
uncovers **119 vulnerabililties** across 7 LTE cores and 3 5G cores, with **93 CVEs** assigned.

A detailed report on the vulnerability disclosure can be found [here](/ransacked); read more about
how we designed and evaluated the fuzzer in [our paper](https://nathanielbennett.com/publications/ransacked.pdf).
