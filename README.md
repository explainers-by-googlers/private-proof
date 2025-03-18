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
This approach strikes a balance between user privacy and anti-fraud capabilities by enabling websites to request a reputation signal (such as profile age) on which the user agent can enforce meaningful privacy constraints, while making the signal useful enough to remove the need for other burdensome or invasive checks, and allow the user to clear said signal at will.

## Goals

* Reduce challenge friction for likely-benign users
* Offer a verifiable, low-bit function evaluation on state kept within the browser
* Allow data to be targeted for clearing, and clear the data automatically alongside other site data
* Allow to run on arbitrary hardware and browsers

## Non-Goals

* Increase challenge friction for novel users
* Provide a new mechanism for cross-site tracking
* Provide a non-clearable reputation score
