Analyze this repository for insecure direct object references, broken object-level
authorization and closely related authorization failures.

For every reported issue, identify:

1. The externally reachable endpoint, GraphQL resolver or mutation.
2. The attacker-controlled object identifier or target identity.
3. The authenticated principal, if any.
4. The resource read or state-changing operation.
5. The authorization or ownership check that is absent, bypassed or overwritten.
6. The exact file and line where the vulnerable resource operation or missing
   authorization decision is visible.
7. A concrete explanation of how one user can read, modify, create as or delete
   another user's resource.

Do not report a vulnerability merely because an endpoint accepts an object ID.
Suppress the finding when the resource is constrained to the authenticated user,
tenant, permitted role, sender, receiver or owner.

Do not report generic authentication hardening, missing rate limiting, weak
passwords, SQL injection, XSS, CSRF or cryptographic issues unless they directly
create the authorization failure being reported.

Report your findings as a single JSON object of the form
{"findings": [ ... ]}, where each finding has exactly these fields:

  repository            string  - repository slug
  endpoint              string  - route, GraphQL field, or handler entry point
  method_or_operation   string  - GET|POST|PUT|DELETE|query|mutation
  handler               string  - dotted handler / resolver name
  file                  string  - repo-relative path
  start_line            integer
  end_line              integer
  cwe                   string  - e.g. "CWE-639"
  object_identifier     string  - the attacker-controlled key/identity
  authenticated_principal string- the authenticated identity, or "" if none
  resource_operation    string  - the read/update/delete/create operation
  missing_or_bypassed_check string - the absent/bypassed/overwritten check
  attack_scenario       string  - how one user reaches another user's resource
  confidence            number  - 0.0 to 1.0

Report an empty findings array if there are no real authorization vulnerabilities.
