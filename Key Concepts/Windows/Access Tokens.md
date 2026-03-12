## 1. What Access Tokens Are

* **Access tokens** are **temporary credentials used to authenticate and authorize requests** to services or APIs after a user or application has successfully logged in.
* They are commonly issued by identity providers such as Microsoft Entra ID, AWS Security Token Service, or systems implementing OAuth 2.0.
* Typically formatted as **JWTs (JSON Web Tokens)** or opaque tokens that contain claims about the identity and permissions of the requester.
* Used heavily in **cloud platforms (AWS, Azure), enterprise identity systems, web applications, APIs, and microservices architectures**.
* Tokens are **short-lived and scoped**, meaning they grant limited access for a defined time and purpose.
* Often paired with **refresh tokens** that allow obtaining new access tokens without re-authentication.

---

# 2. Legitimate Use

* **API Authentication** – Applications authenticate to APIs using access tokens instead of storing user credentials.
* **Single Sign-On (SSO)** – Identity providers like Microsoft Entra ID issue tokens to allow access across multiple enterprise applications.
* **Cloud Service Authorization** – Temporary credentials from AWS Security Token Service allow secure access to AWS resources.
* **Delegated Access** – OAuth-based applications obtain tokens to act on behalf of users.
* **Microservice Communication** – Internal services validate tokens to authorize requests between services.
* **Mobile & Web Apps** – Tokens allow stateless authentication without sending passwords repeatedly.

---

# 3. Attacker Abuse

* **Token Theft / Session Hijacking**

  * Attackers steal tokens from browser storage, memory, logs, or endpoint compromise.
  * Mapped to **Token Impersonation/Theft – T1528** in MITRE ATT&CK.

* **Pass-the-Token Attacks**

  * Stolen tokens are replayed to access APIs or cloud resources without needing credentials.

* **Token Forgery**

  * Weak JWT signing keys allow attackers to forge tokens with elevated privileges.

* **Cloud Token Abuse**

  * Compromised cloud workloads expose temporary credentials (e.g., STS tokens).

* **Refresh Token Abuse**

  * Attackers maintain persistence by repeatedly generating new access tokens.

* **Privilege Escalation via Token Manipulation**

  * Tokens containing roles/scopes can be abused if validation is weak.

---

# 4. SIEM Detection Opportunities

### Alert 1 – Access Token Used from Multiple Geographic Locations

**Suspicious Behavior**

* Same token or session used from geographically distant IP addresses within a short time window.

**Detection Logic**

```
same token_id OR session_id
AND distinct source_country > 1
AND time_difference < 1 hour
```

**Log Sources**

* Azure AD Sign-in Logs
* Cloud Identity logs
* API Gateway logs
* EDR telemetry

---

### Alert 2 – Suspicious Token Use After Privileged Role Assignment

**Suspicious Behavior**

* Access token used shortly after a role/permission change granting elevated privileges.

**Detection Logic**

```
RoleAssignmentEvent
FOLLOWED BY
API call using access_token
WHERE time_diff < 10 minutes
```

**Log Sources**

* Azure Activity Logs
* AWS CloudTrail
* Identity provider logs

---

### Alert 3 – Abnormal API Activity Using Access Token

**Suspicious Behavior**

* Token used to perform an unusually high volume of API calls.

**Detection Logic**

```
count(API_calls by token_id) > baseline * 5
within 5 minutes
```

**Log Sources**

* AWS CloudTrail
* API Gateway logs
* Application logs

---

### Alert 4 – Access Token Used from Untrusted Device

**Suspicious Behavior**

* Token issued to a trusted device but later used from a different or unmanaged device.

**Detection Logic**

```
token_device_id != login_device_id
```

**Log Sources**

* Azure AD Conditional Access logs
* Endpoint management telemetry
* EDR logs

---

### Alert 5 – Token Used After User Logout

**Suspicious Behavior**

* Token continues being used after the user session was terminated.

**Detection Logic**

```
Logout event
FOLLOWED BY
API request using same token_id
```

**Log Sources**

* Identity provider logs
* Application logs
* API access logs

---

# 5. Investigation Indicators

* **Source IP changes**

  * Sudden location changes (impossible travel).

* **Token issuance metadata**

  * Check **issuer, scopes, expiration, audience, client ID**.

* **User-agent anomalies**

  * Token issued to browser but used by curl/script.

* **Unusual API patterns**

  * Accessing resources outside normal usage scope.

* **Token lifetime anomalies**

  * Tokens being used close to expiration repeatedly.

* **Correlation with endpoint compromise**

  * Malware or credential theft activity on the user device.

---

# 6. Mitigations / Security Best Practices

* **Short Token Lifetimes**

  * Reduce exposure window for stolen tokens.

* **Implement Conditional Access**

  * Enforce device compliance and location restrictions.

* **Token Binding / Device Binding**

  * Bind tokens to specific devices or sessions.

* **Secure Storage**

  * Avoid storing tokens in browser local storage where possible.

* **Rotate Signing Keys**

  * Regularly rotate JWT signing keys and secrets.

* **Enhanced Monitoring**

  * Track token issuance, refresh activity, and abnormal API usage.

---