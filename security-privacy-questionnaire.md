# [TAG Security & Privacy Questionnaire](https://www.w3.org/TR/security-privacy-questionnaire/#questions) Answers

## 1. What information does this feature expose, and for what purposes?

This API exposes the capacity to store a cryptographic token representing an integer in per-origin storage. This token can then be used to generate zero-knowledge proofs that this token is less than or equal to some threshold and send that proof back to that same origin.

## 2. Do features in your specification expose the minimum amount of information necessary to implement the intended functionality?

Yes, we do not expose the underlying token value when generating proofs and limit API usage to prevent identification of user agents.

## 3. Do the features in your specification expose personal information, personally-identifiable information (PII), or information derived from either?

The token stored could represent an integer that contained PII if the origin setting the token already had that.

## 4. How do the features in your specification deal with sensitive information?

See answer 3.

## 5. Does data exposed by your specification carry related but distinct information that may not be obvious to users?

See answer 3.

## 6. Do the features in your specification introduce state that persists across browsing sessions?

Yes, we allow up to a single token to be stored per-origin that persists across browsing sessions. Additional information may be required to properly implement rate limiting as well.

## 7. Do the features in your specification expose information about the underlying platform to origins?

No.

## 8. Does this specification allow an origin to send data to the underlying platform?

No.

## 9. Do features in this specification enable access to device sensors?

No.

## 10. Do features in this specification enable new script execution/loading mechanisms?

No.

## 11. Do features in this specification allow an origin to access other devices?

No.

## 12. Do features in this specification allow an origin some measure of control over a user agent’s native UI?

No.

## 13. What temporary identifiers do the features in this specification create or expose to the web?

The generated proofs are only sent to and usable by the origin that originally set the token they were generated from.

## 14. How does this specification distinguish between behavior in first-party and third-party contexts?

It does not, the same token is shared per-origin between first and third party contexts.

## 15. How do the features in this specification work in the context of a browser’s Private Browsing or Incognito mode?

The token storage is unique per-origin and per-profile, so an incognito browsing profile would have different tokens.

## 16. Does this specification have both "Security Considerations" and "Privacy Considerations" sections?

Yes.

## 17. Do features in your specification enable origins to downgrade default security protections?

No.

## 18. What happens when a document that uses your feature is kept alive in BFCache (instead of getting destroyed) after navigation, and potentially gets reused on future navigations back to the document?

Not applicable.

## 19. What happens when a document that uses your feature gets disconnected?

Not applicable.

## 20. Does your spec define when and how new kinds of errors should be raised?

Yes.

## 21. Does your feature allow sites to learn about the user’s use of assistive technology?

See answer 3.

## 22. What should this questionnaire have asked?

What novel technical context would be helpful to understand this feature? [Anonymous Credentials with Range Proofs and Rate Limiting](https://github.com/SamuelSchlesinger/authenticated-pseudonyms/blob/dev/design/Range.pdf)
