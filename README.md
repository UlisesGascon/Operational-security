# SecOps checklist

This repo is a personal security list that will change on the time. It is heavily based on Web App and Nodejs, but most of the items can be extended to other environments.

## Attribution

Forked from mozilla-services/websec-check and based/mixed from:

- [Mozilla Websec-check](https://github.com/mozilla-services/websec-check)
- [mozilla-services/GitHub-Audit](https://github.com/mozilla-services/GitHub-Audit/blob/master/docs/checklist.md)
- [Threat model for GitHub repositories](https://github.com/mozilla-services/GitHub-Audit/blob/master/docs/threat.md)
- [Threat model for GitHub repositories (Threats)](https://github.com/mozilla-services/GitHub-Audit/blob/master/docs/graph.md)
- [Mozilla Security Guidelines](https://infosec.mozilla.org/guidelines/web_security)
- [Shieldfy blog | API Security Checklist](https://shieldfy.io/blog/api-security-checklist/)

## Developer Operational Security

- [ ] Use MFA/2FA in all the places that you can. But [avoid SMS/Phone](https://blog.sucuri.net/2020/01/why-2fa-sms-is-a-bad-idea.html)
- [ ] Use a password manager and autogenerate passwords
- [ ] Generate Public keys and use them
- [ ] If you expose sensitive information. Revoke tokens and alert the team or relevant people

## Organization Operational Security

- [ ] Remove non-relevant users from communication channels (Slack, Telegram groups, etc...)
- [ ] Remove non-relevant users from operational stuff (Source control, CI, Registries, etc..)
- [ ] Store organization members Public Keys for emergencies and recovery
- [ ] Create a Matrix role to have clear picture of roles and permissions
- [ ] Store exceptions in a safe place for audit propuses
- [ ] Store logs in a safe place for audit propuses
- [ ] Scan and review organization resources (emails, Source controls, CIs, permissions) in daily/weekly/monthy bases

## Infrastructure

- [ ] Access and application logs must be archived for a minimum of 90 days
- [ ] Use TLS
- [ ] Set HSTS to 31536000 (1 year) `strict-transport-security: max-age=31536000`
- [ ] If service has an admin panels, it must:
  - [ ] only be available behind VPN (which provides 2FA/MFA)
  - [ ] require MFA authentication
- [ ] Build and deploy alpine or -slim variants of official language-specific base docker images
- [ ] Anchor Docker versions, avoid generics like `node:10` or latests versions `node:latest`
- [ ] Correctly set client IP
  - [ ] Confirm client ip is in the proper location in [X-Forwarded-For](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Forwarded-For), modifying what is sent from the client if needed. AWS and GCP's load balancers will do this automatically.
  - [ ] [ ] Make sure the web server and the application get the true client IP by configuring trusted IP's within [Nginx (ngx_http_realip_module)](https://nginx.org/en/docs/http/ngx_http_realip_module.html) or [Apache (mod_remoteip)](https://httpd.apache.org/docs/2.4/mod/mod_remoteip.html)
  - [ ] If you have a service-oriented architecture, you must always be able to find the IP of the client that sent the initial request. Recommendation: pass along the `X-Forwarded-For` to all back-end services.
- [ ] Use an API Gateway service to enable caching, Rate Limit policies and deploy APIs resources dynamically.
- [ ] Do not forget to turn the DEBUG mode OFF.
- [ ] Use feature flags.
- [ ] Remove fingerprinting headers (`X-Powered-By`, etc...)
- [ ] Design a rollback solution for deployments.
- [ ] When managing permissions, make sure access controls are enforced server-side
- [ ] If an authenticated user accesses protected resource, make sure the pages with those resource arent cached and served up to unauthenticated users (like via a CDN).
- [ ] If handling cryptographic keys, must have a mechanism to handle quarterly key rotations
  - Keys used to sign sessions don't need a rotation mechanism if destroying all sessions is acceptable in case of emergency.
- [ ] Do not proxy requests from users without strong limitations and filtering (see [Pocket UserData vulnerability](https://www.gnu.gl/blog/Posts/multiple-vulnerabilities-in-pocket/)). Don't proxy requests to [link local, loopback, or private networks](https://en.wikipedia.org/wiki/Reserved_IP_addresses#IPv4) or DNS that resolves to addresses in those ranges (i.e. 169.254.0.0/16, 127.0.0.0/8, 10.0.0.0/8, 100.64.0.0/10, 172.16.0.0/12, 192.168.0.0/16, 198.18.0.0/15).
- [ ] Do not use `target="_blank"` in external links unless you also use `rel="noopener noreferrer"` (to prevent [Reverse Tabnabbing](https://www.owasp.org/index.php/Reverse_Tabnabbing))

## Development

### Source Control (Github, Gitlab, bitbucket...)

- [ ] All accounts must use 2FA
- [ ] All accounts with elevated permissions must have phone numbers removed. (This protects against 2FA bypass using SMS reset.)
- [ ] The branching structure of the repository should be documented.
- [ ] Committing (or merging) to a production branch should be limited to the smallest reasonable set of people.
- [ ] Branch protection should be enabled for production branches. [see](https://help.github.com/articles/configuring-protected-branches/)
- [ ] Branch protections should always apply to administrators as well. [see](https://help.github.com/articles/configuring-protected-branches/)
- [ ] Commits (including merges) to the production branch should be GPG signed. [See](https://help.github.com/articles/about-required-commit-signing)
- [ ] Important milestones, such as releases, should be marked by a signed tag. [See](https://help.github.com/articles/about-required-commit-signing)
- [ ] Important milestone achievement criteria should include an audit all relevant verified commits.
- [ ] Elevated permissions should be granted to teams, not individual accounts, whenever possible. (Only org members can be part of a team.)
- [ ] Sensitive repositories should be monitored for vulnerabilities in their supply chain.
- [ ] Automatic PRs to remediate vulnerable packages should be enabled whenever available ([Snyk](https://snyk.io/), [dependabot](https://dependabot.com/), [WhiteSource](https://renovate.whitesourcesoftware.com/), [GreenKeeper](https://greenkeeper.io/)...).
- [ ] A developer should be designated to triage all reported dependency vulnerability alerts.
- [ ] Project release criteria should include verifying no outstanding vulnerabilities are unresolved.
- [ ] Integrate static code analysis in CI and Husky, and avoid merging code with issues like [Eslint](https://eslint.org/)
- [ ] 3rd Parties software (plugins, marketplace, etc..) must be validated by two adminstrators
- [ ] Never include secrets or sensitive information in plain text. Please encrypt data if you nee to.
- [ ] If you expose sensitive information the leaked data still in the git history after removal [See](https://help.github.com/en/github/authenticating-to-github/removing-sensitive-data-from-a-repository)

## Logging

- [ ] Use whitelisting/blacklisting mechanisms to prevent publication of sensitive information about Business logic (pass, emails, etc..)
- [ ] Add a login platform to the project
- [ ] Access control failures must be logged at WARN level
- [ ] Access and application logs must be archived for a minimum of 90 days

## Alerts/subscriptions

- [ ] Add alerts to platforms (emails, slack...) for new Open Source Projects (issues, releases, etc...) and registry (NPM, DockerHub...)
- [ ] Add alerts to running projects for live environment in the platforms (for Warn and Error level)

## Deployment

### Public Registry (NPM, etc...)

- [ ] All accounts must use 2FA
- [ ] All accounts with elevated permissions must have phone numbers removed. (This protects against 2FA bypass using SMS reset.)
- [ ] Only tagged versions from Source Control must be deployed in the registry
- [ ] Checksums must be added to tag version in Source control

## Common

### NPM Dependencies (devDependencies and Dependencies)

- [ ] Anchor versions in package.json
- [ ] Add NPM Scripts to handle:
  - [ ] Dependencies outdated `npm outdated`
  - [ ] Security checks from Snyk `snyk test`
  - [ ] Auto-upgrade dependencies with `npm-check-updates`
  - [ ] Lock package-lock.json using (?????)
  - [ ] Avoid risky dependencies (non-updated for years, few downloads per week, weird dependencies, etc...)
- [ ] Add Husky to add dependencies check as `pre-pull`

## Web Applications

### Common for Web Applications

- [ ] Websites must redirect to HTTPS, API endpoints should disable HTTP entirely
- [ ] Sites should use HTTPS (or other secure protocols) for all communications
- [ ] Both passive and active resources should be loaded through protocols using TLS, such as HTTPS
- [ ] Strict Transport Security (STS): Minimum allowed time period of six months
- [ ] Cross-origin Resource Sharing: Origin sharing headers and files should not be present, except for specific use cases
- [ ] Cross-site Request Forgery Tokenization (CRFT): Mandatory for websites that allow destructive changes
- [ ] Referrer Policy: Improves privacy for users, prevents the leaking of internal URLs via Referer header
- [ ] X-Content-Type-Options: Websites should verify that they are setting the proper MIME types for all resources
- [ ] X-Frame-Options: Websites that don't use DENY or SAMEORIGIN must employ clickjacking defenses
- [ ] Cookies set as restrictively as possible
  - [ ] Set the Secure and HTTPOnly flags
  - [ ] Use a sensible Expiration
  - [ ] Use the prefix `__Host-` for the cookie name
- [ ] Make sure your application gets an A+ on the [Mozilla Observatory](https://observatory.mozilla.org/)
- [ ] Confirm your application doesn't fail the [ZAP Security Baseline](https://github.com/zaproxy/zaproxy/wiki/ZAP-Baseline-Scan):
- [ ] Don’t use any sensitive data in the URL, but use standard Authorization header (Barrer Tokens).
- [ ] Use a CDN for file uploads.
- [ ] When using cookies for session management, make sure you have CSRF protections in place, which in 99% of cases is [SameSite cookies](https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies#SameSite_cookies). If you can't use SameSite, use anti CSRF tokens. There are two exceptions to implementing CSRF protection:
  - [ ] Forms that don't change state (e.g. search forms) don't need CSRF protection and can indicate that by setting the 'data-no-csrf' form attribute (this tells our ZAP scanner to ignore those forms when testing for CSRF).
  - [ ] Sites that don't use cookies for anything sensitive can ignore CSRF protection. A lot of modern sites prefer to use local-storage JWTs for session management, which aren't vulnerable to CSRF (but must have a rock solid CSP).

### Frontend

- [ ] Must have a CSP with:
  - [ ] a report-uri endpoint `/__cspreport__`
  - [ ] web API responses should return `default-src 'none'; frame-ancestors 'none'; base-uri 'none'; report-uri /__cspreport__` to disallowing all content rendering, framing, and report violation
  - [ ] if default-src is not `none`, frame-src, and object-src should be `none` or only allow specific origins
  - [ ] no use of unsafe-inline or unsafe-eval in script-src, style-src, and img-src
- [ ] Third-party javascript must be pinned to specific versions
- [ ] Subresource Integrity: Only for websites that load JavaScript or stylesheets from foreign origins
- [ ] X-XSS-Protection: Manual testing should be done for existing websites, prior to implementation
- [ ] Validate user input
- [ ] User own resource ID should be avoided. Use `/me/orders` instead of `/user/654321/orders`.
- [ ] Don’t auto-increment IDs. Use UUID instead.
- [ ] User data must be [escaped for the right context](https://www.owasp.org/index.php/XSS_(Cross_Site_Scripting)_Prevention_Cheat_Sheet#XSS_Prevention_Rules_Summary) prior to reflecting it.
- [ ] When allowing users to upload or generate content, make sure to host that content on a separate domain (eg. githubusercontent.com, etc.). This will prevent malicious content from having access to storage and cookies from the origin. Also use this technique to host rich content you can't protect with a CSP, such as metrics reports, wiki pages, etc.
- [ ] Do not use `target="_blank"` in external links unless you also use `rel="noopener noreferrer"` (to prevent [Reverse Tabnabbing](https://www.owasp.org/index.php/Reverse_Tabnabbing))

### Backend

- [ ] Web APIs must set a non-HTML content-type on all responses, including 300s, 400s and 500s
- [ ] Web APIs should export an OpenAPI (Swagger) to facilitate automated vulnerability tests
- [ ] Don’t use Basic Auth. Use standard authentication (e.g. JWT, OAuth).
- [ ] Don’t reinvent the wheel in Authentication, token generation, password storage. Use the standards.
- [ ] Use Max Retries (login, reuqests) and jail features in Login.
- [ ] Use limit in API requests (maximum api calls per day/hour...) 
- [ ] Use encryption on all sensitive data.
- [ ] Validate `content-type` on request Accept header to allow only your supported format (`application/json`, etc.) and respond with `406 Not Acceptable response` if not matched.
- [ ] Return the proper status code according to the operation completed
- [ ] All the 5xx errors must be 500 code only without error payload in the response.
- [ ] Validate request data (params and body)
- [ ] Check if all the endpoints are protected behind authentication to avoid broken authentication process.
- [ ] If you are parsing XML files, make sure entity expansion is not enabled to avoid `Billion Laughs/XML bomb` via exponential entity expansion attack.
- [ ] Validate POST body size should be small (<500kB) unless explicitly needed

#### JWT

- [ ] Use a random complicated key (JWT Secret) to make brute forcing the token very hard.
- [ ] Don’t extract the algorithm from the payload. Force the algorithm in the backend (HS256 or RS256).
- [ ] Make token expiration (TTL, RTTL) as short as possible.
- [ ] Don’t store sensitive data in the JWT payload, it can be decoded easily.

## Databases

- [ ] All SQL queries must be parameterized, not concatenated
- [ ] Applications must use accounts with limited GRANTS when connecting to databases
- [ ] Applications **must not use admin or owner accounts**, to decrease the impact of a sql injection vulnerability.
- [ ] Databases must be under a VPN
- [ ] Databases must be under a Firewall
- [ ] Encrypt all the sensitive data
- [ ] Never dump production data to staging or development environment
- [ ] Audit and Monitor Database Activity
- [ ] Add alerts for critical cases and warnings
