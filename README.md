# Explainer: Private Proof API

This proposal is an early design sketch by Privacy Sandbox to describe the problem below and solicit feedback on the proposed solution.
It has not been approved to ship in Chrome.

* [Discussion](https://github.com/explainers-by-googlers/private-proof/issues)

## Introduction

Protecting users from online fraud and abuse is a shared responsibility between websites and user agents.
Historically, unpartitioned storage and third-party cookies (3PC) enabled services to recall when a client was first seen (as well as tracking subsequent events for examining “normal” behavior).
This helped established users distinguish themselves from novel clients during Sybil attacks (multiple fake identities) or other spammy behavior, granting established users frictionless access to online services.
However, the reduced availability of 3PC and limitations on unpartitioned local storage necessitate a paradigm shift in anti-fraud mechanisms.

Without a viable client-side alternative to provide anti-fraud capabilities, organizations may resort to less precise and potentially less private solutions like device fingerprinting, or compromising user experience through added user friction, such as requests to log in or excessive CAPTCHA puzzles.
The proposed Private Proof API offers a privacy-centric solution, ensuring that users are not unduly burdened while websites implement effective fraud prevention capabilities.

This API uses Zero-Knowledge Proofs (ZKPs) to allow analysis of potentially identifiable signals while providing only a limited verdict output.
For example, it empowers anti-fraud services to verify whether a user possesses an unmodified stored timestamp older than some provided timestamp without disclosing any additional user data.
This approach strikes a balance between user privacy and anti-fraud capabilities by enabling websites to request a reputation signal (such as [profile age](https://github.com/antifraudcg/proposals/issues/9)) on which the user agent can enforce meaningful privacy constraints, while making the signal useful enough to remove the need for other burdensome or invasive checks, and allow the user to clear said signal at will.

## Goals

* Reduce challenge friction for likely-benign users
* Offer a verifiable, low-bit function evaluation on state kept within the browser
* Allow data to be targeted for clearing, and clear the data automatically alongside other site data
* Allow to run on arbitrary hardware and browsers

## Non-Goals

* Increase challenge friction for novel users
* Provide a new mechanism for cross-site tracking
* Provide a non-clearable reputation score

## Use Cases

While the client is usually considered untrusted, anti-fraud vendors often use client side signals and storage as an important complement to server-side or offline fraud analysis and detection.
Many fraud and spam fighting organizations across a wide range of verticals look for discrepancies and anomalies between expected and observed client signals and behavior.

### Bot detection: finding anomalies in client or cookie age

Since user storage is easily cleared, spammers tend to clear their state in an attempt to look like a new user, say to boost views or alter billable stats.
While websites do not want to discourage new users, they need to limit fraud and spam, and can do so in aggregate by looking for anomalies in “new” users compared to baseline distributions.

We already see this use case with the SelectURL Shared Storage API, which can be used to build a client age distribution and warn of discrepancies in access patterns. However, an implementation based on those APIs lacks verification and is vulnerable to tampering. See [example 1](https://docs.google.com/presentation/d/1XXgpwQLmfh87oQ3q5I3mzocUjLdjtTQMqLMLGb2nIMY/edit#slide=id.g2c78a183f9f_7_530)  and  [example 2](https://docs.google.com/presentation/d/1-VjSchD47FoLK1e_Iv4b6DGsUb70JE5No3VG_zLptbY/edit#slide=id.g3041befa8d0_6_325).

### Payment protection: prior successful transactions

Payment providers often do per-card verifications for online transactions to mitigate the risk of theft.
While payment providers know many details about the cardholder and their identity is not private at checkout, it can be useful for payment providers to verify a checkout has been completed on the client previously.
[Future work](https://docs.google.com/document/d/1SmdxtvIcCY8q7NB_rDkDa0NeuHukEJ6NT_GcGp-HoPY/edit?tab=t.0#heading=h.q8ytx891vfg1) may also unlock additional functionality for this use case.

## Proposed Solution

Our solution seeks to provide a JavaScript context with a way to make a request to store a signed integer token from its own site.
Contexts on that same site could then make a request for proof to be sent back to the site, that the token is less than or equal to some bound (without disclosing the value of the integer stored itself).

For example: a site requests that a token be stored, which represents a current timestamp.
The site then makes a request for proofs to be sent back which demonstrate that the user account is at least one month old, as a trust signal.

See the following sequence diagram for an overview of the API flow:

![](./images/sequence-diagram.png)
