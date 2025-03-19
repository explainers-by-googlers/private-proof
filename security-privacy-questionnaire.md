# [TAG Security & Privacy Questionnaire](https://www.w3.org/TR/security-privacy-questionnaire/#questions) Answers

## What information does this feature expose, and for what purposes?

This API exposes the capacity to store a cryptographic token representing an integer in per-origin storage. This token can then be used to generate zero-knowledge proofs that this token is less than or equal to some threshold and send that proof back to that same origin.

## Do features in your specification expose the minimum amount of information necessary to implement the intended functionality?

Yes, we do not expose the underlying token value when generating proofs and limit API usage to prevent identification of user agents.

## Do the features in your specification expose personal information, personally-identifiable information (PII), or information derived from either?

The token stored could represent an integer that contained PII if the origin setting the token already had that.

## How do the features in your specification deal with sensitive information?

See answer 3.

## Does data exposed by your specification carry related but distinct information that may not be obvious to users?

See answer 3.

## Do the features in your specification introduce state that persists across browsing sessions?

Yes, we allow up to a single token to be stored per-origin that persists across browsing sessions. Additional information may be required to properly implement rate limiting as well.

## Do the features in your specification expose information about the underlying platform to origins?

No.

## Does this specification allow an origin to send data to the underlying platform?

No.

## Do features in this specification enable access to device sensors?

No.

## Do features in this specification enable new script execution/loading mechanisms?

No.

## Do features in this specification allow an origin to access other devices?

No.

## Do features in this specification allow an origin some measure of control over a user agent’s native UI?

No.

## What temporary identifiers do the features in this specification create or expose to the web?

The generated proofs are only sent to and usable by the origin that originally set the token they were generated from.

## How does this specification distinguish between behavior in first-party and third-party contexts?

It does not, the same token is shared per-origin between first and third party contexts.

## How do the features in this specification work in the context of a browser’s Private Browsing or Incognito mode?

The token storage is unique per-origin and per-profile, so an incognito browsing profile would have different tokens.

## Does this specification have both "Security Considerations" and "Privacy Considerations" sections?

Yes.

## Do features in your specification enable origins to downgrade default security protections?

No.

## What happens when a document that uses your feature is kept alive in BFCache (instead of getting destroyed) after navigation, and potentially gets reused on future navigations back to the document?

Not applicable.

## What happens when a document that uses your feature gets disconnected?

Not applicable.

## Does your spec define when and how new kinds of errors should be raised?

Yes.

## Does your feature allow sites to learn about the user’s use of assistive technology?

See answer 3.

## What should this questionnaire have asked?

What novel technical context would be helpful to understand this feature? [Anonymous Credentials with Range Proofs and Rate Limiting](https://github.com/SamuelSchlesinger/authenticated-pseudonyms/blob/dev/design/Range.pdf)
