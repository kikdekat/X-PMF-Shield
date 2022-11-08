
# The X-PMF-Shield
### Build An Efficient Transport Rule Set



## Table of Contents

[**1. Know the limitations of MS Exchange Online Mail Flow (formerly Transport Rules)**](#1-know-the-limitations-of-ms-exchange-online-mail-flow-formerly-transport-rules)

 * [***1.1 The maximum number of Transport Rules***](#11-the-maximum-number-of-transport-rules)

 * [***1.2 Transport Rules conditions and logic***](#12-transport-rules-conditions-and-logic)

 * [***1.3 RegEx***](#13-regex)

   * [**(*) Common mistakes**](#-common-mistakes)

 * [***1.4 MS Exchange Online Protection (EOP) Architecture***](#14-ms-exchange-online-protection-eop-architecture)

[**2. Ingredients of malicious emails**](#2-ingredients-of-malicious-emails)

 * [***2.1 Common combinations of indicators of a generic phishing email***](#21-common-combinations-of-indicators-of-a-generic-phishing-email)

[**3. Building your ruleset**](#3-building-your-ruleset)

 * [***3.1. Phase 1***](#31-phase-1)

   * [**3.1.1 Blocking known threats**](#311-blocking-known-threats)

   * [**3.1.2 Clear X-PMF headers (\*\*)**](#312-clear-x-pmf-headers--will-explain-this-later-after-section-34)

   * [**3.1.3 Classify incoming emails**](#313-classify-incoming-emails)

 * [***3.2. Phase 2: Tags for Blocking***](#32-phase-2-tags-for-blocking)

   * [**3.2.1 Commercial Spam**](#321-commercial-spam)

   * [**3.2.2. External Phishing/Scam**](#322-external-phishingscam)

     * [**3.2.2.1 Common types**](#3221-common-types)

     * [**3.2.2.2. Generic Scams/Phishing**](#3222-generic-scamsphishing)

       * [**3.2.2.2.1 Generic Tagging**](#32221-generic-tagging)

       * [**3.2.2.2.2 Generic Blocking**](#32222-generic-blocking)

   * [**3.2.3 Internal Phishing**](#323-internal-phishing)

   * [**3.2.4 Spoofing/Impersonating**](#324-spoofingimpersonating)

   * [**3.2.5 Quarantined Senders**](#325-quarantined-senders)

 * [***3.3 Phase 3: Blocking***](#33-phase-3-blocking)

 * [***3.4 Block Mail Rejection Notifications***](#34-block-mail-rejection-notifications)

 * [**(*) 3.1.2 Clear X-PMF headers - IMPORTANT**](#-312-clear-x-pmf-headers---important)

[**4. Tips to tune your rule set**](#4-tips-to-tune-your-rule-set)

 * [***4.1 Mail headers***](#41-mail-headers)

 * [***4.2. Threat Explorer***](#42-threat-explorer)

 * [**4.2.1 Email Analyzing**](#421-email-analyzing)

 * [**4.2.2 Tracking Rule’s Performance**](#422-tracking-rules-performance)



**Disclaimer:** I am not an Exchange nor RegEx expert. This rule set is the result of my RegEx practices and is completely designed for Transport Rules, not including any ATP settings.




## **1. Know the limitations of MS Exchange Online Mail Flow (formerly Transport Rules)**
To build the Transport Rules effectively, it is important to understand what we can do and cannot. The following limitations are what I encountered, some are documented, and some are not.

### ***1.1 The maximum number of Transport Rules:***
Generally, you can have up to 300 rules to play with. It also has limits on the size of a rule, an attachment, etc. More about the limits can be found here: <https://docs.microsoft.com/en-us/office365/servicedescriptions/exchange-online-service-description/exchange-online-limits#journal-transport-and-inbox-rule-limits-1>

### ***1.2 Transport Rules conditions and logic:***
You can have one or multiple conditions/exceptions in one rule. However, the logic for those is quite limited. For example, you can only do keywords match on body or subject twice at most in a single rule and the same condition cannot be repeated.

- Multiple conditions: Logic = AND
- One condition with multiple values: Logic = OR
- Multiple exceptions: Logic = OR
- Multiple actions: Logic = AND

More details: <https://docs.microsoft.com/en-us/exchange/security-and-compliance/mail-flow-rules/mail-flow-rules#multiple-conditions-exceptions-and-actions>

### ***1.3 RegEx:***
Transport Rule’s RegEx is based on the .NET RegEx engine (I believe the Exchange DLP RegEx is using the same engine) and poorly documented. It’s more of a broken version of the .NET RegEx. Here are why:

- The max length for a RegEx pattern is 128 characters.
- The max length for ALL of the RegEx patterns for ALL rules is 20480 characters (or 20kB, let’s call it the *“**RegEx balance**”*) (\*). The “*backreference”* plays an important role to help us save up characters in a pattern.
- Complexity should be concerned, if a pattern takes too long to run, it will not work.
- Inline Modifier and Flags (?ismx): will NOT work as all of the input will be treated as case-insensitive.
- Anchors: ^ and $ at the beginning and end of the line will NOT work. Workaround: use \A and \Z instead.
- Quantifier: you can NOT use the common “greedy” (i.e.: .+/.\*) or “lazy” (i.e.: .+?/.\*?)  quantifier at the beginning, or the end of a RegEx pattern. You can NOT use them more than TWICE in a pattern. 
  For example, the patterns *“.\*keyword.\*”* or *“match1.\*match2.\*match3.\*match4”* will NOT work.
  Workaround: use *“[^\0]\*keyword[^\0]\*”* or *“[\s\S]\*keyword[\s\S]\*”* and “*match1[^\0]\* match2[^\0]\*match3[^\0]\*match4”*  will work. I know it uses more characters; But hey, at least it works, and those are the only way I can make it works so far.
- Backreference works differently: you must name the capture group and then refer to it using its reference order (a number), that’s the ONLY way to do backreference from what I observed. Example: *(?<d>pattern)[other\_matches]**\1*** (whereas “*\1”* will matches “*pattern”*. *<d>* is a named group, as short as possible).

##### **(\*) Common mistakes:**
From what I’ve seen, if a condition contains “includes” or “matches” (red), that will count toward the “RegEx balance”; on the other hand, if the condition says something with “is” (green), it does not (it does count toward the 8kB limit for a single rule, still).


![Screen Shot 2022-10-27 at 11 59 44 PM](https://user-images.githubusercontent.com/66635269/200206531-52f7b4d3-51db-41f9-8065-6040737c8038.png)


I have seen many people use the “includes/matches” condition to block a specific email address, which is a waste in my opinion. Please don’t do that, you will regret it when the RegEx balance ran out.

![Screen Shot 2022-10-28 at 12 00 00 AM](https://user-images.githubusercontent.com/66635269/200212331-92228562-2df2-48f4-b4fc-a254691dc027.png)

Example: <https://github.com/MicrosoftDocs/OfficeDocs-O365ServiceDescriptions/issues/365>


### ***1.4 MS Exchange Online Protection (EOP) Architecture:***
It is better to understand when Transport Rules hit the email, that will help us tune the rules more efficiently. Especially when you don’t have higher-tier licenses which have ATP and extras, a good Transport Rule set is crucial to fight malicious emails.

Without ATP:
![Screen Shot 2022-10-28 at 12 00 46 AM](https://user-images.githubusercontent.com/66635269/200212378-0fd85bcf-b8ff-4169-8a79-f146103d0b77.png)

With MS Defender for Office 365:
![Screen Shot 2022-10-28 at 12 00 57 AM](https://user-images.githubusercontent.com/66635269/200212396-83196e59-8286-4cc7-92fa-4501938df8ca.png)

#####
## **2. Ingredients of malicious emails**
After reviewing thousands of emails, I’m confident to say here are the common indicators of a malicious email:

- Keywords
- BCC
- Free email providers
- Compromised senders
- Bad *Authentication-Results* headers
- Spoofing
- The content is too short (usually 500-600 characters or less)
- Abnormal URLs
- Malicious attachment (.html, .xlsm, .docx, .docm, .msg, .eml and so on)

Of course, a single indicator is insufficient to determine if an email is malicious, it must be a combination of those indicators. Except if it is a solid known threat, we’ll talk about that a bit later.

### ***2.1 Common combinations of indicators of a generic phishing email:***
- Keywords (set #1) + Keywords (set #2) + abnormal URLs
- Keywords + short content + abnormal URLs
- Keywords + BCC + abnormal URLs
- Keywords + malicious attachments
- Short content/Free email + BCC
- Short content/Free email + abnormal URLs
- Short content/Free email + malicious attachments
- BCC + malicious attachments
- Free email + short content
- Etc.

## **3. Building your ruleset**
As mentioned earlier, we need to use multiple indicators to identify malicious emails. The approach is using *custom mail header(s) to tag suspicious emails* (including SPF check, keyword check, etc.) and then using those **tags** to process the email.

The benefits of this approach are: 

- Getting around the Transport Rule’s conditions’ restraints.
- Reusing RegEx patterns: For example, we use “tag” resulting from patterns of rule “x” in other rules “y” and “z” instead of repeating the patterns themselves. This will help us cut down the “RegEx balance” usage.
- Centralized managing: when we made changes on a RegEx pattern of a “tagging” rule (say, it generated “#tag1”), it will have effects on other rules that use that “#tag1” as the condition. Or we can apply a single action to all the tagged suspicious emails from multiple rules.


Please keep in mind that Exchange processes rule by order, from top to bottom. The following sections can be used as a framework to build your rule set and it was built in an appropriate order to make sure everything works as it should.



The rule set should do the following things:

- **Phase 1: Simple blocking and tagging**
- **Blocking known threats.**
- **Classify (tagging) emails as best as you can**: Doing just keyword filtering to find suspicious emails is not enough, we need to classify the email even before applying keyword filtering, based on its attribute such as authentication headers (passed or failed); sending from a commercial/free providers address or not; is it a mail thread of conversation; etc. The more fine-grained classifications, the better result. Remember that blocking using keywords is easy, the goal is to reduce the false positives and keep the malicious emails out at the same time. 
- **Define a Trusted/Allow list**: this could be IP, the sender addresses, etc. for both internal and external senders. It will be easier to manage a trusted list and exclude them from the filter to reduce the false positives. Make sure you trust those before adding them. **This list should be updated occasionally.**
- **Phase 2: Identify malicious emails and tagging for action**
- **External phishing/scam:**
  - Common types: should have rules with specific keywords targeting common malicious emails such as monetary/gift card/favor/billing/payroll, malicious SharePoint emails, etc. then tag them accordingly.
  - Generic phishing: a set of keywords found in common phishing/scam emails (account lockout, homograph, job scam, attachment, etc.) combine with other indicators (BCC, short content, attachment’s content, etc.) to tag suspicious emails. *This is the hardest part so far as phishing/scam emails change every day and sometimes it will catch legit emails (about 15% false positives for the X-PMF-Shield example). You will need to monitor the result closely and update the rules and/or add the sender to the “Allow list” to reduce the false positives.*
- **Internal phishing:** Scammers love BCC! This will reuse tags generated from the “Generic phishing”, target internal senders, and BCC. In general, a normal user would rarely use such keywords found in the “generic phishing” thus internal phishing emails are easier to deal with. We could block internal BCC, if possible; If not, creating a rule to restrict BCC only during business hours would reduce a great chance of an internal phishing outbreak.
- **Spoofing/Impersonate:** basically, just a simple Authentication-Results header checking and/or Sender Name checking to compare to some pre-defined VIP names that could be impersonated.
- **Phase 3: Actions based on tags**
- Using the tags generated from Phase 2, we could use a single rule to decide the action on tagged emails. Actions could vary from aggressive: **block**, moderate: **approval** to less aggressive: **move to junk**. I would suggest using the approval method to review the results and tune the rules until they have the best results.

The following sections explain the Phases in detail as well as reference tags; It also acts as brief introductions of what the reference “X-PMF-Shield” rule set does. Please refer to the “X-PMF-Shield/Samples” folder for examples.
&nbsp;

### **3.1. Phase 1**
#### ***3.1.1 Blocking known threats:***
It is essential to have basic blocking rules based on known threats such as:

- Block by IP
- Block by sender domains
- Block by sender address

Those are easy blocking as we don’t care about the content of the emails.

#### ***3.1.2 Clear X-PMF headers \*\*:*** Will explain this later (after section 3.4)

#### ***3.1.3 Classify incoming emails:***
\- `X-PMF-Tag: Exceptions`: there is always someone who is not happy with the Transport Rules we set, use this rule to opt them out of the rule set we made. We will use this tag as one of the exceptions for other rules, they’re at their own risk.

Assigned tag (X-PMF-Tag header): “**Exceptions**”

![Screen Shot 2022-10-28 at 12 01 14 AM](https://user-images.githubusercontent.com/66635269/200212461-aafd92be-c30b-4df8-83dc-db0798c63d36.png)
Powershell:
```
New-TransportRule -Name 'X-PMF-Tag: Exceptions' -Mode Enforce -SentTo 'someone@yourdomain.com' -SetHeaderName 'X-PMF-Tag' -SetHeaderValue 'Exceptions'
```
&nbsp;


\- `X-PMF-Tag: Free email providers`: define a list of common free email services (Gmail, Yahoo, etc.) using the “sender's address domain portion belongs to any of these domains” condition. Assigned tag (X-PMF-Tag header): “**Free-Mail**”

![Screen Shot 2022-10-28 at 12 01 30 AM](https://user-images.githubusercontent.com/66635269/200212534-80030385-6e00-4975-addf-977b11dcd002.png)
Powershell:
```
New-TransportRule -Name 'X-PMF-Tag: Free email providers' -Comments 'Tag free email domains to exclude from Commercial tags. Add more when needed.' -Mode Enforce -SenderAddressLocation Envelope -SentToScope InOrganization -SenderDomainIs 'protonmail.com', 'gmail.com', 'outlook.com', 'hotmail.co.uk', 'hotmail.com', 'live.com', 'aol.com', 'yahoo.co.uk', 'yahoo.com', 'ymail.com', 'inbox.com', 'icloud.com', 'mail.com', 'comcast.net' -ExceptIfHeaderContainsMessageHeader 'X-PMF-Tag' -ExceptIfHeaderContainsWords 'Exceptions' -ExceptIfSenderDomainIs 'alerts.comcast.net' -SetHeaderName 'X-PMF-Tag' -SetHeaderValue 'Free-Mail'
```
&nbsp;


\- `X-PMF-Tag: Auth-Passed`: contains RegEx patterns to determine if an email has a “good” Authentication-Results header. The best/good Authentication-Results header is where “spf=pass”, “dkim=pass”, “dmarc=pass”, AND the values of “smtp.mailfrom” = “header.d” = “header.from” IS the sender’s domain.

An “acceptable” Authentication-Results header is where: “spf=pass” AND “smtp.mailfrom” = “header.from” IS the sender’s domain. Or “dkim=pass” AND “header.d” = “header.from” IS the sender’s domain. The reason we can tell they’re “acceptable” is that only the domain’s owner can change the SPF/DMARC record or have the DKIM private key. This is also the same approach that Microsoft used to set their “CompAuth” value in the Authentication-Results header. More detail here: <https://docs.microsoft.com/en-us/microsoft-365/security/office-365-security/anti-spam-message-headers?view=o365-worldwide#authentication-results-message-header>

Assigned tag (X-PMF-Tag header): “**Auth-Passed**”, except if X-PMF-Tag is “Free-Mail” as emails from free providers will have the perfect Authentication-Results header.

![Screen Shot 2022-10-28 at 12 01 47 AM](https://user-images.githubusercontent.com/66635269/200212566-ef7b6d20-3423-43d0-bcc1-7956791841bd.png)
Powershell:
```
New-TransportRule -Name 'X-PMF-Tag: Auth-Passed' -Comments 'Tag if Authentication-Results are all pass and everything matches up (Best).
Or either of the following (similar to CompAuth which is OK-ish):
SPF=pass AND smtp.mailfrom=header.mailfrom
DKIM=pass AND smtp.mailfrom=header.mailfrom
' -Mode Enforce -SentToScope InOrganization -HeaderMatchesMessageHeader 'Authentication-Results' -HeaderMatchesPatterns 'spf=pa[^\0]+lfrom=(?:[\S.]+\.)?(?<d>\S+\.\S+);[^\0]+dkim=pa[^\0]+\.d=(?:[\S.]+\.)onmicrosoft\.com[^\0]+from=(?:[\S.]+\.)?\1', 'dkim=(pass|test)[^\0]+\.d=(?:[\S.]+\.)?(?<d>\S+\.\S+);[\s\S]+\.from=(?:[\S.]+\.)?\1', 'spf=(?:pass|temperror)[\s\S]+\.mailfrom=(?:[\S.]+\.)?(?<d>\S+\.\S+);[^\0]+\.from=(?:[\S.]+\.)?\1', 'spf=pass[^\0]+\.mailfrom=(?:[\S.]+\.)?(?<d>\S+\.\S+);[^\0]+dkim=pass[^\0]+\.d=(?:[\S.]+\.)?\1[^\0]+\.from=(?:[\S.]+\.)?\1', 'spf=pass[^\0]+dkim=pass[^\0]+dmarc=pass' -ExceptIfHeaderContainsMessageHeader 'X-PMF-Tag' -ExceptIfHeaderContainsWords 'Free-mail' -ExceptIfAttachmentNameMatchesPatterns '\.(xlsm?|cmd|bat|ps1|vbs|js|html?|eml|msg)$' -SetHeaderName 'X-PMF-Tag' -SetHeaderValue 'Auth-Passed'
```
&nbsp;


\- `X-PMF-Tag: ARC-Auth-Passed`: this is very similar to the “Auth-Passed” tag but applies to the ARC-Authentication-Results header instead. As the email might go through multiple “hops”, the ARC-Authentication-Results headers will retain the Authentication-Results headers from the previous hop. We only need to target the “i=1” hop, which is the very first hop it went through.

Assigned tag (X-PMF-Tag header): “**ARC-Auth-Passed**”, except if X-PMF-Tag is “Free-Mail” or “Auth-Passed”.

![Screen Shot 2022-10-28 at 12 02 11 AM](https://user-images.githubusercontent.com/66635269/200215053-dbd92706-ec06-4f6b-8c9c-50cccf17b6ec.png)
Powershell:
```
New-TransportRule -Name 'X-PMF-Tag: ARC-Auth-Passed' -Comments 'Tag if ARC-Auth are all pass.' -Mode Enforce -SentToScope InOrganization -HeaderMatchesMessageHeader 'ARC-Authentication-Results' -HeaderMatchesPatterns 'i=1[^\0]+?spf=pass[^\0]+\.mailfrom=(?:[\S.]+\.)?(?<d>\S+\.\S+); dmarc=pass[^\0]+\.from=(?:[\S.]+\.)?\1;[^\0]+dkim=pass' -ExceptIfHeaderContainsMessageHeader 'X-PMF-Tag' -ExceptIfHeaderContainsWords 'Auth-Passed', 'Free-mail' -ExceptIfAttachmentNameMatchesPatterns '\.(xlsm?|cmd|bat|ps1|vbs|js|html?|eml|msg)$' -SetHeaderName 'X-PMF-Tag' -SetHeaderValue 'ARC-Auth-Passed'
```
&nbsp;


\- `X-PMF-Tag: Auth-Failed`: this rule will tag any emails with a “bad” Authentication-Results header (either SPF, DKIM, or DMARC is failed).  

Assigned tag (X-PMF-Tag header): “**Auth-Failed**”, except if X-PMF-Tag is “Free-Mail” or “Auth-Passed”. 

![Screen Shot 2022-10-28 at 12 02 22 AM](https://user-images.githubusercontent.com/66635269/200215082-e851ab75-65de-42f5-b32c-ca2e464ec519.png)
Powershel:
```
New-TransportRule -Name 'X-PMF-Tag: Auth-Failed' -Comments 'Tag emails that failed Auth headers.' -Mode Enforce -SenderAddressLocation Envelope -SentToScope InOrganization -HeaderMatchesMessageHeader 'Authentication-Results' -HeaderMatchesPatterns '(spf|dkim|dmarc)=(?!pass)' -FromScope NotInOrganization -ExceptIfHeaderContainsMessageHeader 'X-PMF-Tag' -ExceptIfHeaderContainsWords 'Auth-Passed', 'Free-Mail' -ExceptIfFromScope InOrganization -SetHeaderName 'X-PMF-Tag' -SetHeaderValue 'Auth-Failed'
```
&nbsp;


\- `X-PMF-Tag: Commercial-3rd-SPOOFED`: this rule targets spoofed emails from 3rd party services (MailChimp, SendGrid, etc.) with improper email settings and got tagged with the “Auth-Failed” tag. Treating this as “Auth-Failed” or otherwise is up to your decision. The example in the X-PMF-Shield treats this like “Auth-Passed”.

\*Please note that this is a high-risk option as the attackers could use any of those mail services to send spoofed emails.

Assigned tag (X-PMF-Tag header): “**Commercial-3rd-SPOOFED**”. 

![Screen Shot 2022-10-28 at 12 02 41 AM](https://user-images.githubusercontent.com/66635269/200215098-593d2e71-ce4d-4153-b571-9711bce432b2.png)
Powershell:
```
New-TransportRule -Name 'X-PMF-Tag: Commercial-3rd-SPOOFED' -Comments 'Spoofed emails from 3rd party services (MailChimp, SendGrid, etc.)' -Mode Enforce -SentToScope InOrganization -HeaderContainsMessageHeader 'X-PMF-Tag' -HeaderContainsWords 'Auth-Failed' -HeaderMatchesMessageHeader 'Authentication-Results' -HeaderMatchesPatterns 'spf=pass[^\0]+\.mailfrom=(?:[\S.]+\.)?((mc|rsg)(sv|dlv)\.net|mandrillapp\.com); dkim=pass[^\0]+\.d=mailchimpapp\.net', 'spf=(?:pass|temperror)[^\0]+\.mailfrom=(?:[\S.]+\.)?(?<d>\S+\.\S+); dkim=pass[^\0]+\.d=(?:[\S.]+\.)?\1[^\0]+\.from=(?!ur_domain)' -ExceptIfHeaderMatchesMessageHeader 'Authentication-Results' -ExceptIfHeaderMatchesPatterns '\.mailfrom=(?!\w+\.shopifyemail\.com)\S+;[^\0]+dmarc=fail[^\0]+compauth=(?!pass)' -SetHeaderName 'X-PMF-Tag' -SetHeaderValue 'Commercial-3rd-SPOOFED'
```
&nbsp;


\- `X-PMF-Auth: Auth-Failed`: As we will override the X-PMF-Tag with other values in later rules, it’s better to save the current “Auth-Failed” result to a secondary tag to reuse it later.

Assigned tag (**X-PMF-Auth** header): “**Auth-Failed**”. 

![Screen Shot 2022-10-28 at 12 02 55 AM](https://user-images.githubusercontent.com/66635269/200215269-3e396a4e-7ebd-4996-8249-2bdcdd8dd39c.png)
Powershell:
```
New-TransportRule -Name 'X-PMF-Auth: Auth-Failed' -Comments 'Clone Auth-Failed to another tag.' -Mode Enforce -SenderAddressLocation Envelope -HeaderMatchesMessageHeader 'X-PMF-Tag' -HeaderMatchesPatterns 'Auth-Failed' -SetHeaderName 'X-PMF-Auth' -SetHeaderValue 'Auth-Failed'
```
&nbsp;


\- `X-PMF-Tag: Commercial-Content`: this rule would tag emails as “commercial” based on their content using common keywords found in legit commercial emails, except if they failed the Authentication-Results header or from free mail providers.

Assigned tag (**X-PMF-Tag** header): “**Commercial-Content**”, except if X-PMF-Tag is “Free-Mail”, “Auth-Failed” or “Exceptions”.

![Screen Shot 2022-10-28 at 12 03 15 AM](https://user-images.githubusercontent.com/66635269/200220407-1427f3f7-bf96-4023-8b21-c49fedb11d67.png)
Powershell:
```
New-TransportRule -Name 'X-PMF-Tag: Commercial-Content' -Mode Enforce -SenderAddressLocation Envelope -SentToScope InOrganization -HeaderMatchesMessageHeader 'Authentication-Results' -HeaderMatchesPatterns '\.(mailfrom|from)=[^;]+?\.(\w{3,6}|us|ca);' -SubjectOrBodyMatchesPatterns 'deal|cleara|s[ei]\w+.?up', 'no longer w(ant|wish)', '(do.?)?n[o''‘‘’’]?t?.re(ply|spond)', 'https?:\/\/([^''"<>\s]+)?(unsubs?|subscri|opt.?out|pref(s|er)?|remove)', '\bship(ping|ped|ment)', 'mail((ing)? )?list', 'Terms of Use|Copyright|All Rights Reserved', '(fu(ture|rther)|commercial) (email|mess|comm)\S*?', '(Security|Return|Privacy)( (and|&) \w+?)? (Policy|Notice|Statement)', '(modify|change|update|manage|choose|edit)s? (to )?(my |your )?(\b\S+\b )?(prefere|e-?mails?|alert|notific|subscri)\S*?', 'term(s)?[\S ]+(condition|privac\w+)s?', 'trademarks?', 'opt.?out', 'webinar|marketing|personalized', 'automated', 'survey' -FromScope NotInOrganization -ExceptIfHeaderContainsMessageHeader 'X-PMF-Tag' -ExceptIfHeaderContainsWords 'Exceptions', 'Auth-Failed', 'Free-Mail' -ExceptIfHeaderMatchesMessageHeader 'X-PMF-Auth' -ExceptIfHeaderMatchesPatterns 'Auth-Failed' -SetHeaderName 'X-PMF-Tag' -SetHeaderValue 'Commercial-Content'
```
&nbsp;


\- `X-PMF-Tag: Commercial-Address`: this rule is very similar to the “Commercial-Content” but matches the sender address with common commercial generic sending addresses instead. The “**Match sender address in message**” should be set to “**Header or envelop**”.

Assigned tag (**X-PMF-Tag** header): “**Commercial-Address**”, except if X-PMF-Tag is “Commercial-Content”, “Free-Mail”, “Auth-Failed” or “Exceptions”.

![Screen Shot 2022-10-28 at 12 03 26 AM](https://user-images.githubusercontent.com/66635269/200220908-5f1394b8-98c7-4185-856d-3d2dc30fc0e5.png)
Powershell:
```
New-TransportRule -Name 'X-PMF-Tag: Commercial-Address' -Mode Enforce -SenderAddressLocation HeaderOrEnvelope -SentToScope InOrganization -HeaderMatchesMessageHeader 'Authentication-Results' -HeaderMatchesPatterns '\.(mailfrom|from)=[^;]+?\.(\w{3,5}|us|ca);' -FromAddressMatchesPatterns '^(e?mail(er)?|noti((ce|fication)|fy)|newsletter|lists?(erv)?|alert|info(rmation)?)s?@', '^(post|web|system).?(master)?@', 'MAILER.?DAEMON@', '^(customer.?)?(services?|support|security|help|care|reports?)@', '(un)?subscri(\w+)?', 'promotion(\w+)?', 'advertis(\w+)?', 'marketing', '(do.?)?(no?|auto).{0,2}repl\S+?', 'bounce' -FromScope NotInOrganization -ExceptIfHeaderContainsMessageHeader 'X-PMF-Tag' -ExceptIfHeaderContainsWords 'Exceptions', 'Commercial-Content', 'Auth-Failed', 'Free-Mail' -ExceptIfHeaderMatchesMessageHeader 'X-PMF-Auth' -ExceptIfHeaderMatchesPatterns 'Auth-Failed' -SetHeaderName 'X-PMF-Tag' -SetHeaderValue 'Commercial-Address'
```
&nbsp;


\- `X-PMF-Tag: Commercial-List`: this rule will check if the email was sent to a mailing list subscriber regardless of the email’s content or sender address. *Please keep in mind that the attackers could fake a “List-Unsubscribe” header, we caught a bunch of LinkedIn phishing with a fake “List-Unsubscribe” header in January 2022.*

Assigned tag (**X-PMF-Tag** header): “**Commercial-List**”, except if X-PMF-Tag is “Commercial” (as you can see, we only use “Commercial” here and it will cover both “Commercial-Content” and “Commercial-Address”), “Free-Mail”, “Auth-Failed” or “Exceptions”.

![Screen Shot 2022-10-28 at 12 03 39 AM](https://user-images.githubusercontent.com/66635269/200220993-36617820-4d5f-4575-bf3c-bb1c2914ea35.png)
Powershell:
```
New-TransportRule -Name 'X-PMF-Tag: Commercial-List' -Mode Enforce -SenderAddressLocation HeaderOrEnvelope -SentToScope InOrganization -HeaderMatchesMessageHeader 'List-Unsubscribe' -HeaderMatchesPatterns '[^\0]+' -FromScope NotInOrganization -ExceptIfHeaderMatchesMessageHeader 'X-PMF-Tag' -ExceptIfHeaderMatchesPatterns 'Auth-Failed', 'Free-Mail', 'Exceptions', 'Commercial' -SetHeaderName 'X-PMF-Tag' -SetHeaderValue 'Commercial-List'
```
&nbsp;


\- `X-PMF-Tag: Mail-Thread`: this rule will tag incoming email that was a part of a prior “conversation” (which means the internal might already reply to the previous email).

Many phishing/scam emails put “RE:” or “FW:” in the subject to fake a mail-thread email, which will be caught by this rule as it didn’t use Subject as a condition but the “In-Reply-To” header instead. Remember to change <your\_domain> to your actual domain.

Assigned tag (**X-PMF-Tag** header): “**Mail-Thread**”, except if X-PMF-Tag is “Auth-Failed” or “Exceptions”.

![Screen Shot 2022-10-28 at 12 03 53 AM](https://user-images.githubusercontent.com/66635269/200221070-1e76be3f-5ebe-4a51-859f-1be0b613f224.png)
Powerhsell:
```
New-TransportRule -Name 'X-PMF-Tag: Mail-Thread' -Comments 'Tagging for mail threads, conversations.' -Mode Enforce -SentToScope InOrganization -HeaderMatchesMessageHeader 'In-Reply-To' -HeaderMatchesPatterns '[^\0]*' -AnyOfRecipientAddressMatchesPatterns '@yourdomain\.com' -SubjectOrBodyMatchesPatterns 'On[\S ]{1,120}(\b[\w._-]+@[\w.-]+\.[a-z]{2,}\b)[^\0]+?wrote:', '(From|CC|Subject|To): ((?!@)[\S ]+)(\r)?\n(Sent|Date):' -ExceptIfHeaderContainsMessageHeader 'X-PMF-Tag' -ExceptIfHeaderContainsWords 'Auth-Failed', 'Exceptions' -SetHeaderName 'X-PMF-Tag' -SetHeaderValue 'Mail-thread'
```
&nbsp;


\- `X-PMF-Tag: Trusted Sending IP`: define your trusted sending IPs here (either internal or external), emails sent from those IPs will bypass all PMF rules.

Assigned tag (**X-PMF-Tag** header): “**Trusted-IPs**”.

![Screen Shot 2022-10-28 at 12 04 05 AM](https://user-images.githubusercontent.com/66635269/200221312-0013ffbf-6170-4644-8d50-6dd83235e324.png)
Powershell:
```
New-TransportRule -Name 'X-PMF-Tag: Trusted Sending IP' -Comments 'Trusted IPs, could be either Internal or External.' -Mode Enforce -SenderIpRanges <your IP ranges> -SetHeaderName 'X-PMF-Tag' -SetHeaderValue 'Trusted-IPs'
```
&nbsp;


\- `X-PMF-Tag: Internal Services`: define your trusted sending **internal** addresses here, emails sent from those addresses will bypass all PMF rules. Except if they failed the Authentication-Results header (Auth-Failed).

Assigned tag (**X-PMF-Tag** header): “**Internal-Services**”.

![Screen Shot 2022-10-28 at 12 04 18 AM](https://user-images.githubusercontent.com/66635269/200223042-7c6310f5-9abd-4028-8556-541e484657cd.png)
Powershell:
```
New-TransportRule -Name 'X-PMF-Tag: Internal Services' -Mode Enforce -SenderAddressLocation HeaderOrEnvelope -From 'sender@yourdomain.com' -ExceptIfHeaderContainsMessageHeader 'X-PMF-Auth' -ExceptIfHeaderContainsWords 'Auth-Failed' -SetHeaderName 'X-PMF-Tag' -SetHeaderValue 'Internal-Services'
```
&nbsp;


\- `X-PMF-Tag: External Services`: define your trusted sending **external** addresses here, emails sent from those addresses will bypass all PMF rules. Except if they failed the Authentication-Results header (Auth-Failed).

Assigned tag (**X-PMF-Tag** header): “**EXT-Services**”.

![Screen Shot 2022-10-28 at 12 04 29 AM](https://user-images.githubusercontent.com/66635269/200223141-c7e65895-a04c-4639-944a-70c69274c04e.png)
Powershell:
```
New-TransportRule -Name 'X-PMF-Tag: External Services' -Comments 'Assign tag for common/well-known external service emails which users use them frequently. (i.e Canvas, Square, eBay, Amazon, Netflix, etc.)' -Mode Enforce -SenderAddressLocation HeaderOrEnvelope -From 'sender@extdomain.com' -ExceptIfHeaderMatchesMessageHeader 'X-PMF-Auth' -ExceptIfHeaderMatchesPatterns 'Auth-Failed' -SetHeaderName 'X-PMF-Tag' -SetHeaderValue 'EXT-Services'
```
&nbsp;


\- `X-PMF-Tag: External Service Domains`: define your trusted sending **external** **domains** here, emails sent from those domains will bypass all PMF rules. Except if they failed the Authentication-Results header (Auth-Failed).

Assigned tag (**X-PMF-Tag** header): “**EXT-Services**”.

![Screen Shot 2022-10-28 at 12 04 43 AM](https://user-images.githubusercontent.com/66635269/200223877-cfc887df-2050-40f8-a79d-9cd5b500ba58.png)
Powershell:
```
New-TransportRule -Name 'X-PMF-Tag: External Service Domains' -Comments 'Assign tag for common/well-known external service domains which users use them frequently. (i.e Canvas, Square, eBay, Amazon, Netflix, etc.)' -Mode Enforce -SenderDomainIs 'any-ext-domain.com' -ExceptIfHeaderMatchesMessageHeader 'X-PMF-Auth' -ExceptIfHeaderMatchesPatterns 'Auth-Failed' -SetHeaderName 'X-PMF-Tag' -SetHeaderValue 'EXT-Services'
```
&nbsp;


### **3.2. Phase 2: Tags for Blocking**
#### ***3.2.1 Commercial Spam:***
\- `X-PMF-Shield: Commercial-Trash (Auth-Failed)`: If an email contains the keyword “unsubscribe” and failed the Authentication-Results header or from a free email provider, it’s most likely spam.

Action: you can either delete or set the email SCL level to 9 to send them to the users’ Junk folder.

Exceptions: external service addresses defined in the “*X-PMF-Tag: External/Internal Services”* or exception recipients defined in the “*X-PMF-Tag: Exceptions*”.

![Screen Shot 2022-10-28 at 12 04 54 AM](https://user-images.githubusercontent.com/66635269/200225516-fe6fb454-764f-44b6-a3f0-3db3fa42e15b.png)
Powershell:
```
New-TransportRule -Name 'X-PMF-Tag: Commercial-Trash (Auth-Failed)' -Comments 'Set SCL = 9 (highest) for the "commercial"-like emails with failed Auth headers, or just delete them.' -Mode Enforce -SenderAddressLocation HeaderOrEnvelope -SentToScope InOrganization -HeaderContainsMessageHeader 'X-PMF-Tag' -HeaderContainsWords 'Free-Mail', 'Auth-Failed' -SubjectOrBodyContainsWords 'unsubscribe' -FromScope NotInOrganization -ExceptIfHeaderContainsMessageHeader 'X-PMF-Tag' -ExceptIfHeaderContainsWords 'Exceptions', 'Services' -SetSCL 9 -SetHeaderName 'X-PMF-Tag' -SetHeaderValue 'Commercial-Trash'
```
&nbsp;


\- `X-PMF-Shield: Commercial Emoji`: If an email is from a commercial sender (tagged by any of the “*X-PMF-Tag: Commercial”* rules) or from a free provider or failed the Authentication-Results header and has any “emoji” in the subject, it’s spam most of the time. It is rare to have a legit business email from vendors that have emojis in the subject (except some well-known as eBay, Walmart, etc.) in such cases, you could add those senders to the “*X-PMF-Tag: External Services”* if you trust them.

![Screen Shot 2022-10-28 at 12 05 09 AM](https://user-images.githubusercontent.com/66635269/200225581-747eae37-94cd-44d0-b1ed-d4633ae3aa49.png)

The RegEx in the example ***([^\w\d\s -”]***) was designed to catch any emojis in the subject. 

Action: you can either delete or set the email SCL level to 9 to send them to the users’ Junk folder.

Exceptions: external service addresses defined in the “*X-PMF-Tag: External/Internal Services”* or exception recipients defined in the “*X-PMF-Tag: Exceptions*”.

![Screen Shot 2022-10-28 at 12 05 22 AM](https://user-images.githubusercontent.com/66635269/200225597-b1d92d7f-8438-4303-bbee-32e9ea3bb0ab.png)
Powershell:
```
New-TransportRule -Name 'X-PMF-Tag: Commercial Emoji' -Mode Enforce -SenderAddressLocation HeaderOrEnvelope -SentToScope InOrganization -HeaderContainsMessageHeader 'X-PMF-Tag' -HeaderContainsWords 'Auth-Failed', 'Free-Mail', 'Commercial' -SubjectMatchesPatterns '[^\w\d\s -”]' -FromScope NotInOrganization -ExceptIfHeaderContainsMessageHeader 'X-PMF-Tag' -ExceptIfHeaderContainsWords 'Exceptions', 'Services' -RejectMessageReasonText 'Stop spamming us!' -RejectMessageEnhancedStatusCode '5.7.1'
```
&nbsp;


#### ***3.2.2. External Phishing/Scam:***
##### **3.2.2.1 Common types:**
\- `X-PMF-Shield: #MONETARY`: This rule will block most of the common Nigerian Prince, inheritance types of scams.

![Screen Shot 2022-10-28 at 12 05 34 AM](https://user-images.githubusercontent.com/66635269/200226056-efbdda42-208c-445e-b66a-78239a8f6015.png)

Exceptions: external service addresses defined in the “*X-PMF-Tag: External/Internal Services”* or commercial emails, or a mail thread (conversations).

Assigned tag (**X-PMF-Shield** header): “**#MONETARY**”. Note that we have the “#” sign in front of the “tag”, this will differentiate between the “tag for classifications” and “tag for actions”. Whatever emails got tagged with the **X-PMF-Shield** header and a “#” will have an action applied to them later. 

![Screen Shot 2022-10-28 at 12 06 01 AM](https://user-images.githubusercontent.com/66635269/200226085-76c00214-7202-463e-bd3a-64ba80755d01.png)
Powershell:
```
New-TransportRule -Name 'X-PMF-Shield: #MONETARY' -Comments 'Keywords: for inheritance/free money scam. No one is gonna give you millions of dollar.' -Mode Enforce -SenderAddressLocation HeaderOrEnvelope -SentToScope InOrganization -SubjectOrBodyContainsWords 'fund', 'overseas', 'donate', 'mutual benefit', 'consignment', 'kindly', 'compensation', 'victim', 'funds', 'next of kin', 'charity', 'donation', 'beneficiary', 'bank', 'ATM' -SubjectOrBodyMatchesPatterns '(?:(\$|USD)[^\n]*?)?\d?(?:(?(?=million)|[\S ]{0,3}?(\d{3}\b[,.]\d{3}\b(?!.\d{4}))[\S ]{0,10}?)|hundred([^\n]+)?thousand)', '(\$|U.?S.?D(ollar)?)[\S ]{0,5}?(\d{3}\b[,.]\d{3}\b(?!.\d{4}))', '(\d{3}\b[,.]\d{3}\b(?!.\d{4}))[\S ]{0,10}?(\$|U.?S.?D(ollar))', '\$?\d+?([.,]\d+?)? ?M(?!a|e|o|u|in|ill?e)(illion)?\b' -FromScope NotInOrganization -ExceptIfHeaderContainsMessageHeader 'X-PMF-Tag' -ExceptIfHeaderContainsWords 'Mail-thread', 'Services', 'Commercial' -ExceptIfSubjectOrBodyMatchesPatterns '[^\0]{3500,}' -SetHeaderName 'X-PMF-Shield' -SetHeaderValue '#MONETARY'
```
&nbsp;


\- `X-PMF-Shield: #GIFTCARD-Scam`: This rule will block most of the “*can you do me a favor?*”, and impersonating scams, which eventually ask the victims to get out and buy gift cards for them.

Exceptions: external service addresses defined in the “*X-PMF-Tag: External/Internal Services”* or commercial emails. The scam usually will happen AFTER the victim replies to the initial emails; therefore, we don’t use the mail thread as an exception here.

Assigned tag (**X-PMF-Shield** header): “**#GIFTCARD-Scam**”.

![Screen Shot 2022-10-28 at 12 06 13 AM](https://user-images.githubusercontent.com/66635269/200226199-5c6a703d-cd86-4ff2-a714-f9e1f1703845.png)
Powershell:
```
New-TransportRule -Name 'X-PMF-Shield: #GIFTCARD-Scam' -Comments 'Keywords: for gift card scam.Scammers usually ask for gift card purchasing after the user has replied.  So, don''t use the "Mail-thread" tag as exception here.' -Mode Enforce -SenderAddressLocation HeaderOrEnvelope -SentToScope InOrganization -SubjectOrBodyContainsWords 'not able', 'not available', 'occupied', 'soon as possible', 'reimburse', 'currently', 'traveling', 'kindly', 'errand', 'in a meeting', 'urgent', 'asap', 'right now', 'scratch', 'favor', 'task' -SubjectOrBodyMatchesPatterns '(gift|prepaid).?cards?' -FromScope NotInOrganization -ExceptIfHeaderContainsMessageHeader 'X-PMF-Tag' -ExceptIfHeaderContainsWords 'Commercial', 'Services' -SetHeaderName 'X-PMF-Shield' -SetHeaderValue '#GIFTCARD-Scam'
```
&nbsp;


\- `X-PMF-Shield: #BILLING-Scam`: This rule will block most of the fake billing (McAfee, Norton, PayPal, Geek Squad, etc.) scams a.k.a. “tech support/refund scams”.

![Screen Shot 2022-10-28 at 12 06 32 AM](https://user-images.githubusercontent.com/66635269/200226261-e41947e8-baab-4944-bb02-1e1337a738a1.png)

Exceptions: external service addresses defined in the “*X-PMF-Tag: External/Internal Services”*, commercial emails, or from a mail thread.

Assigned tag (**X-PMF-Shield** header): “**#BILLING-Scam**”.

![Screen Shot 2022-10-28 at 12 06 43 AM](https://user-images.githubusercontent.com/66635269/200226304-5b733d1f-f2ee-47ab-9446-8d8448c45df2.png)
Powershell:
```
New-TransportRule -Name 'X-PMF-Shield: #BILLING-Scam' -Comments 'Fake billing/invoice/tech-support scam.' -Mode Enforce -SubjectOrBodyContainsWords 'billing', 'refund', 'renewed', 'amount', 'charge', 'purchase', 'renewal', 'subscription', 'invoice', 'transaction' -SubjectOrBodyMatchesPatterns '(?=[\s\S]*(norton|mcafee|\bamazon\b|\bbtc\b|crypto|dispu|cancel))\A[\s\S]*(?>[\dIlO]{3}[^\r\n]*[\dIlO]{3,4}[^\r\n]*[\dIlO]{3,4})', '(supp|\sus\b|desk|immed|help|phone|reach|service|call)[^\0]{0,50}(?>[\dIlO]{3}[^\r\n]*[\dIlO]{3,4}[^\r\n]*[\dIlO]{3,4})' -FromScope NotInOrganization -ExceptIfHeaderContainsMessageHeader 'X-PMF-Tag' -ExceptIfHeaderContainsWords 'Mail-thread', 'Exceptions', 'Commercial', 'Services' -ExceptIfSubjectOrBodyContainsWords '<your location/state>' -ExceptIfHeaderMatchesMessageHeader 'X-PMF-URL' -ExceptIfHeaderMatchesPatterns 'Exception-URLs' -ExceptIfSubjectOrBodyMatchesPatterns '\A(?=[^\0]{150,})((?!\$|USD)[\s\S]){0,}\Z', '[^\0]{3000,}' -SetHeaderName 'X-PMF-Shield' -SetHeaderValue '#BILLING-Scam'
```
&nbsp;


\- `X-PMF-Shield: #Payroll`: This rule will block emails that impersonate internal users requesting paycheck direct deposit change. These scams are sent from the outside and are usually short, under 350 characters.

![Screen Shot 2022-10-28 at 12 06 53 AM](https://user-images.githubusercontent.com/66635269/200226363-4770522a-f870-4e7e-8430-212384a9d114.png)

Exceptions: external service addresses defined in the “*X-PMF-Tag: External/Internal Services”* OR email with more than 350 characters in the body/subject. However, **Microsoft does NOT support “email’s length” as a condition**. This RegEx pattern (***[\s\S]{350,}***) is a cool trick to check for the length of an email.

Assigned tag (**X-PMF-Shield** header): “**#Payroll**”.

![Screen Shot 2022-10-28 at 12 07 06 AM](https://user-images.githubusercontent.com/66635269/200226386-f8885c94-d2c7-42f0-85dc-2a3f936a1ec5.png)
Powershell:
```
New-TransportRule -Name 'X-PMF-Shield: #Payroll' -Mode Enforce -SenderAddressLocation HeaderOrEnvelope -SentToScope InOrganization -SubjectOrBodyContainsWords 'pay date', 'direct deposit', 'paycheck', 'payroll' -SubjectOrBodyMatchesPatterns 'void\w*\b', '(chang|updat|modif|new)\w+' -FromScope NotInOrganization -ExceptIfHeaderContainsMessageHeader 'X-PMF-Tag' -ExceptIfHeaderContainsWords 'Services' -ExceptIfSubjectOrBodyMatchesPatterns '[\s\S]{350,}' -SetHeaderName 'X-PMF-Shield' -SetHeaderValue '#Payroll'
```
&nbsp;


\- `X-PMF-Shield: #Favor-Scam`: This rule will block emails that impersonate internal users asking for “a favor/quick task” which will usually end up with buying/sending gift cards. These scams are sent from the outside and are usually short, under 300 characters.

![Screen Shot 2022-10-28 at 12 07 14 AM](https://user-images.githubusercontent.com/66635269/200227148-583b6880-7633-4905-90ff-010260508fe2.png)

Exceptions: external service addresses defined in the “*X-PMF-Tag: External/Internal Services”* OR email with more than 300 characters in the body/subject.

Assigned tag (**X-PMF-Shield** header): “**#Favor-Scam**”.

![Screen Shot 2022-10-28 at 12 07 28 AM](https://user-images.githubusercontent.com/66635269/200227175-66c8cf94-6909-4ace-a1b4-e7575770e874.png)
Powershell:
```
New-TransportRule -Name 'X-PMF-Shield: #Favor-Scam' -Comments 'Block external scam asking for quick task, cell number, etc.' -Mode Enforce -SubjectOrBodyContainsWords 'request', 'free', 'response', 'handle', 'personal', 'confidentiality', 'cellphone', 'asap', 'text', 'your number', 'favor', 'cell', 'task', 'available' -FromScope NotInOrganization -ExceptIfHeaderContainsMessageHeader 'X-PMF-Tag' -ExceptIfHeaderContainsWords 'Commercial', 'Services' -ExceptIfSubjectOrBodyMatchesPatterns '[\s\S]{400,}' -SetHeaderName 'X-PMF-Shield' -SetHeaderValue '#Favor-Scam'
```
&nbsp;


\- `X-PMF-Shield: #Toxic-SharePoint`: This rule will block shared content from external compromised or impersonating accounts via SharePoint to internal users. Blocking SharePoint shared contents might sound not feasible as it may have a lot of false positives, but this rule worked well. Remember to change “*yourdomain\_com*” to your actual domain name.

![Screen Shot 2022-10-28 at 12 07 53 AM](https://user-images.githubusercontent.com/66635269/200227299-9f1a8ab9-6e80-456d-8789-9c3821adbcc4.png)
![Screen Shot 2022-10-28 at 12 08 02 AM](https://user-images.githubusercontent.com/66635269/200227300-a89ea16a-0d92-4d59-ac25-18a49e3be3f6.png)

Assigned tag (**X-PMF-Shield** header): “**#Toxic-SharePoint**”.

![Screen Shot 2022-10-28 at 12 08 28 AM](https://user-images.githubusercontent.com/66635269/200227329-0c09d098-e230-4840-ad5b-5e66810a9221.png)
Powershell:
```
New-TransportRule -Name 'X-PMF-Shield: #Toxic-SharePoint' -Comments 'This will catch external SharePoint accounts trying to impersonate an internal user and toxic contents.' -Mode Enforce -SentToScope InOrganization -From 'no-reply@sharepointonline.com' -SubjectOrBodyMatchesPatterns 'https?:\/\/(?!([\w.-]+\.)?outlook\.com)', '[^\w\d\s -”]', 'https?:\/\/[^\s]+(?!_yourdomain_com)', '(?<k>shared a)[^\0]+?\1(?![^\0]+_yourdomain_com)' -SetHeaderName 'X-PMF-Shield' -SetHeaderValue '#Toxic-SharePoint'
```
&nbsp;


##### **3.2.2.2. Generic Scams/Phishing:**
For generic phishing and scam emails, it is very hard to have “one rule catches them all” because the attackers are very creative, and their contents keep changing/updating every day. However, their fundamental goals are harvesting credentials, spreading malware/exploits via attachments, or job scams end up with monetary favor; and that helps us to narrow down the criteria (keywords) for the rules.

As mentioned earlier, we need multiple indicators to determine if an email is malicious. For that reason, another stage of tagging for those indicators is essential. The tags in this stage are different from the tags we created in the earlier rules. You can think of those as “good tags” and we will use them as exceptions in this stage to reduce false positives and to create “bad tags” for indicators in this stage.

The sample rules in this section were built with a set of RegEx patterns that cover multiple generic phishing scenarios, including but not limited to: account lockout/upgrade, cryptocurrency, COVID, well-known vendors (FedEx/DHL/Walmart/etc.) scams, shared documents, homographic attacks, etc.

Those are absolutely not perfect, but after spending over a year monitoring thousands of phishing emails, 15% of false positives is somewhat reasonable to me (I’m still trying to improve that anyway). You will be surprised by how this will work out; it sometimes will catch novel phishing attempts that no one has reported yet.

*\*There is one thing we could do to improve the simplicity of this framework: using the prefix “GOOD” and “BAD” for tagging, which will simplify the exceptions. I might update the tags’ names in future revisions\**.

###### **3.2.2.2.1 Generic Tagging:**
\- `X-PMF-URL: Exception-URLs`: This is the third tag that we use to reduce the false positive. The idea is based on how the URLs appear in the email’s body, regardless of their content. If an email address (say sender@domain.com) appeared in the email’s body and there is an URL to that email’s domain (e.g. https://www.domain.com/zxy) OR multiple URLs from the same domain name (e.g. https://www.domain.com/zxy and https://www.domain.com/abc, etc.), that’s probably not a malicious one. It sure has false negatives, but it should work most of the time. The RegExes in the example were designed to do such tasks. Please change “yourdomain.com” to your actual domain name.

Except for URLs to uncommon domain LTDs (2 letters top LTD, etc.)

Other 3rd email security services may have the option to apply RegEx on the raw email, which means the sender address and the email’s body are in the same context. You could check if the URLs in the email’s body match the sender’s domain, if it does, then it’s probably a safe URL. I believe you could do so with Proofpoint.

Assigned tag (**X-PMF-URL** header): “**Exception-URLs**”.

![Screen Shot 2022-10-28 at 12 08 37 AM](https://user-images.githubusercontent.com/66635269/200228293-52321c3b-914f-400c-8e81-acfaa8a17c99.png)
Powershell:
```
New-TransportRule -Name 'X-PMF-URL: Exception-URLs' -Mode Enforce -SentToScope InOrganization -SubjectOrBodyMatchesPatterns '(?>\w+@(?!yourdomain\.com)(?<e>\S+\.[a-z]+))(?=[^\0]*(?>https?:..(?:[\w\.]*\.)?\1[^\w\.]))', '(?>https?:..(?:[\w\.]*\.)?(?!yourdomain\.com)(?<d>(?>[^\s>\/]+\.[a-z]+)))(?=[^\0]*@\1\b(?!\.\w))', '(?<f>(?>https?:..(?:[^\/]*\.)?(?<d>(?!yourdomain\.com)(?>[^\/\s]+\.\w+))\/?[^\s"''<>]*))(?!(?>[^\0]*?\1))(?>[^\0]*?\2(?!\.\w)){4}' -ExceptIfSubjectOrBodyMatchesPatterns 'https?:..(?!([^\s>\/]*\.)?[^\s>\/]*\b(\.(gov|edu|mil|org|com|net|us|ca|tv|mp)|youtu\.be|cash\.app|(aka|svc|1drv)\.ms)(?!\.\b))' -SetHeaderName 'X-PMF-URL' -SetHeaderValue 'Exception-URLs'
```
&nbsp;


\- `X-PMF-Tag: Abnormal URLs`: The idea is similar to “*X-PMF-URL: Exception-URLs*” but the RegExes were designed to catch suspicious URLs. For example:

`	`+ The same URL is repeated multiple times (4 times) as the attackers are greedy and they usually replace all URLs in the email body with a single URL to ensure the victim will land on the malicious page.

	`+ An URL contains another URL in it (except well-known sites)

	`+ An URL with any email@yourdomain.com address in it.

	`+ So on.

Assigned tag (**X-PMF-Tag** header): “**Abnormal-URLs**”.

![Screen Shot 2022-10-28 at 12 08 49 AM](https://user-images.githubusercontent.com/66635269/200228373-439996ac-bdf8-49ce-b0dc-7bdce83f1d4b.png)
Powershell:
```
New-TransportRule -Name 'X-PMF-URL: Abnormal URLs' -Mode Enforce -SentToScope InOrganization -SubjectOrBodyMatchesPatterns 'https?:\/\/([^\s?=>]+\/){4}(?![^\s>]+(?:jpe?g|gif|png|svg|tiff?))', 'https?:\/\/([^\s>\/]{12,}\.)[\w-]+\.[a-z]{2,}(?<!yourdomain\.com|awstrack\.me)\b(?!\.\w)(?![^\s>]+(?:jpe?g|gif|png|svg|tiff?))', 'https?:..(?!([^\s>\/]*\.)?[^\s>\/]*\b(\.(gov|edu|mil|org|com|net|us|ca|tv|mp)|youtu\.be|cash\.app|(aka|svc|1drv)\.ms)(?!\.\b))', 'https?:\/\/[^\s"''>]+\.(php|html?)\b', 'https?:\/\/(?!([\w.-]+\.)?(yourdomain\.com|(sharepoint|outlook)\.com|svc\.ms)\b)[^\s>]+(\?|#|=)[^\s>]+(@|%40)yourdomain.?com', 'https?:\/\/\d+\.\d+\.\d+\.\d+', '(?>https?:..(?:[^\/]+\.)?(?<d>[^\/]+\.[^\/\b\s]+))(?<!(?:svc\.ms|awstrack\.me))[^\s>]*(?::|%3a)(?:\/\/|%2f%2f)(?![^\s>]*\b\1\b)', '(?<u>https?:\/\/(?!(?:[^\.]+\.)?(?:[^\.]+\.\w{3,5}\/?[\b\s]))(?>[^\b\s"''<>]+))(?>[^\0]+?\1[\b\s\"''<>]){2}' -ExceptIfHeaderContainsMessageHeader 'X-PMF-Tag' -ExceptIfHeaderContainsWords 'Services', 'Mail-Thread', 'Exceptions', 'Trusted-IPs' -ExceptIfHeaderMatchesMessageHeader 'X-PMF-URL' -ExceptIfHeaderMatchesPatterns 'Exception-URLs' -SetHeaderName 'X-PMF-Tag' -SetHeaderValue 'Abnormal-URLs'
```
&nbsp;


\- `X-PMF-Tag: Suspicious-Keywords`: This rule will tag various generic suspicious keywords found in common phishing emails, including COVID grants, account suspension/deactivation, shipping scams, fax/voicemail phishing, homographic attack, cryptocurrency wallet, and so on.

Exceptions: external service addresses defined in the “*X-PMF-Tag: External/Internal Services”*, emails from trusted IPs, or a mail thread.

Assigned tag (**X-PMF-Tag** header): “**Suspicious-Keywords**”.

![Screen Shot 2022-10-28 at 12 09 00 AM](https://user-images.githubusercontent.com/66635269/200228487-dac081ac-cc4d-4df2-9d0f-7fde4e599084.png)
Powershell:
```
New-TransportRule -Name 'X-PMF-Tag: Suspicious-Keywords' -Mode Enforce -SenderAddressLocation HeaderOrEnvelope -SentToScope InOrganization -SubjectOrBodyMatchesPatterns '(?=[^\0]*\bcovid)\A[^\0]*\b(grant|benefit|relief)', 'Dear (value.? )?(user|customer).?', '\A(?![^\0]*\b(order|shipped))[^\0]*[\b\s](DHL\s|US?PS\b(.com)?|FedEx|parce)', '\A(?=[^\0]*?\b(?<!to )(maintain|keep|re(store|.?activate)) your)(?![^\0]*?\b(code|reset))[^\0]*?\b(accounts?\b|passw|access\b)', '(?=[^\0]{100,})(?![^\0]{1500,})\A(?=[^\0]*?\b(doc[xu]|fax))[^\0]*?(view|expire|deleted|cancel(l?ed)?\b)', '(?=[^\0]{99,})\A(?![^\0]*(statem|code|regi|creat|reset|trans|forg.t|b[ai]l|depos|s[ei]\w+.?up|paym))[^\0]*(accounts?\b|passw)', '\b(MetaMask|KYC|NFT|your wallet|kindly|shortly|urgent(?!.?care))\b', '(?<!a |the )(system).?(up(gra)?d(at)?e|maintenance)', 'storage limit', '\b(LinkedIn\s|Whatsapp|Walmart)', '\A(?![^\0]*?\b(Español|Français))[^\0]*?\b\w*[^®©�נ\u0000-\u007F\u2009-\u204F]\w*\b', '(re[lt]\w+e|un(re[ca]|del)\w*d|(secu|sha)red?|((?<!accept )incom|pend)ing|voice) (\w+ )?(messa|\w*?.?mails?|fax|docum|link|call)', 'remittance', 'blacklist.*?\b', '(?<!to )disabl.+?\b', '\s(suspend|hack)ed\b' -ExceptIfFrom 'events@attend.com' -ExceptIfHeaderContainsMessageHeader 'X-PMF-Tag' -ExceptIfHeaderContainsWords 'Trusted-IPs', 'Mail-thread', 'Exceptions', 'Services' -ExceptIfSubjectOrBodyMatchesPatterns '[^\0]{3500,}', '\A(?=[^\0]{150,})((?!https?:\/\/)[^\0]){0,}\Z' -SetHeaderName 'X-PMF-Tag' -SetHeaderValue 'Suspicious-Keywords'
```
&nbsp;


\- `X-PMF-Tag: Suspicious-Content-Job`: This rule will tag most job scam emails. The ingredients of a typical job scam are job descriptions and external emails/external URLs (not commercial). Remember to change “yourdomain.com” to your actual domain name.

Exceptions: external service addresses defined in the “*X-PMF-Tag: External/Internal Services”*, emails from trusted IPs, commercial emails, or from a mail thread. Note that we have the “Keywords” as an exception here because we don’t want this rule to conflict with the “*X-PMF-Tag: Suspicious-Keywords*” above.

Assigned tag (**X-PMF-Tag** header): “**Suspicious-Content-Job**”.

![Screen Shot 2022-10-28 at 12 09 14 AM](https://user-images.githubusercontent.com/66635269/200228585-ccc5b51e-eda6-474c-b8ea-c091537ef46d.png)
Powershell:
```
New-TransportRule -Name 'X-PMF-Tag: Suspicious-Content-Job' -Comments 'Keywords: for part-time job scam, keywords + ext email/url.' -Mode Enforce -SenderAddressLocation HeaderOrEnvelope -SentToScope InOrganization -SubjectOrBodyContainsWords 'Home based position', 'evaluating', 'remote', 'alternative email', 'no work', 'employment offer', 'great opportunity', 'per week', 'this opportunity', 'hiring', 'honest', 'kindly', 'personal assistant', 'this position', 'trustworthy', 'vacancy', 'virtual assistant' -SubjectOrBodyMatchesPatterns '(\b[\w._-]+@(?!yourdomain\.com)[\w.-]+\.[a-z]{2,}\b)', '(https?:\/\/(?!([\w.-]+\.)?(yourdomain\.com|zoom\.us|calendly\.com|aka\.ms)\b)[^"''\s]+)', '(?=(week(ly)?|part.?time|offer\w{0,}\b|personal|private)\b)[\S\s]+(\b[\w._-]+@(?!yourdomain\.com)[\w.-]+\.[a-z]{2,}\b)' -ExceptIfHeaderContainsMessageHeader 'X-PMF-Tag' -ExceptIfHeaderContainsWords 'Keywords', 'Trusted-IPs', 'Mail-thread', 'Exceptions', 'Commercial', 'Services' -ExceptIfSubjectOrBodyContainsWords 'next step', 'hiring process', 'no longer', 'Unfortunately', 'Unsubscribe', 'teams.microsoft.com', 'zoom.us', 'calendly.com' -ExceptIfSubjectOrBodyMatchesPatterns 'onboard', '\breview', 'consider', 'decided', 'letter', 'regret', 'talent', 'drug', 'contigent', 'coach', 'background', 'approv\w+', 'inter(view|n)\w*', '[^\0]{3000,}' -SetHeaderName 'X-PMF-Tag' -SetHeaderValue 'Suspicious-Content-Job'
```
&nbsp;


\- `X-PMF-Tag: Suspicious-Content-X-FILE (Attachment)`: This rule will tag emails with suspicious attachments, including executable files, office documents with macro, HTML, emojis, and so on.

Exceptions: external service addresses defined in the “*X-PMF-Tag: External/Internal Services”*, emails from trusted IPs, or a mail thread. 

Assigned tag (**X-PMF-Tag** header): “**Suspicious-Content-X-FILE**”.

![Screen Shot 2022-10-28 at 12 09 25 AM](https://user-images.githubusercontent.com/66635269/200228686-9fe2f0b3-7ed8-483f-a24d-24f01e99a9c4.png)
Powershell:
```
New-TransportRule -Name 'X-PMF-Tag: Suspicious-Content-X-FILE (Attachment)' -Mode Enforce -SenderAddressLocation HeaderOrEnvelope -SentToScope InOrganization -FromScope NotInOrganization -AttachmentNameMatchesPatterns '2E.?HTML?=2E', 'utf-8', '\.do.x?m?$', '\..?html?\.', '\.mmp$', '\.xlsm?$', '[^\w\d\s -”]', '\.exe$', '\.cmd$', '\.ps1$', '\.bat$', '\.7z$', '\.zip$', '\..ar$', '\.msg$', '\.eml$', '\.js$', '\.vbs$', '\..?html?$' -ExceptIfHeaderContainsMessageHeader 'X-PMF-Tag' -ExceptIfHeaderContainsWords 'Trusted-IPs', 'Mail-thread', 'Services' -ExceptIfFromAddressMatchesPatterns 'postmaster@', 'MAILER.?DAEMON@' -SetHeaderName 'X-PMF-Tag' -SetHeaderValue 'Suspicious-Content-X-FILE'
```
&nbsp;


\- `X-PMF-Tag: Suspicious-Content-Too-Short`: This rule will tag emails that either failed the Authentication-Results header, from free providers, have suspicious keywords/abnormal URLs, or any “suspicious” tags from previous rules AND have a short email body (under 700 characters). The RegEx patterns were designed to calculate the email’s length excluding the email’s footer (i.e. Disclaimer/Confidential Notice), this would improve the rule a bit as those footers are usually long, thus not reflecting the emails’ content length accurately.

Exceptions: external service addresses defined in the “*X-PMF-Tag: External/Internal Services”*, emails from trusted IPs, or a mail thread. 

Assigned tag (**X-PMF-Tag** header): “**Suspicious-Content-Too-Short**”.

![Screen Shot 2022-10-28 at 12 09 36 AM](https://user-images.githubusercontent.com/66635269/200475345-09b36f90-d1a8-47b4-83e4-a7457b6eceb6.png)
Powershell:
```
New-TransportRule -Name 'X-PMF-Tag: Suspicious-Content-Too-Short' -Mode Enforce -SenderAddressLocation HeaderOrEnvelope -SentToScope InOrganization -HeaderContainsMessageHeader 'X-PMF-Tag' -HeaderContainsWords 'Auth-Failed', 'Free-Mail', 'Keywords', 'Abnormal-URLs', 'Suspicious' -FromScope NotInOrganization -ExceptIfHeaderContainsMessageHeader 'X-PMF-Tag' -ExceptIfHeaderContainsWords 'X-FILE', 'Commercial', 'Trusted-IPs', 'Exceptions', 'Services' -ExceptIfSubjectOrBodyMatchesPatterns '(?![^\0]{600,})(?=[^\0]*(code|regis|creat|reset|forg.t|s[ei]\w+.?up))\A[^\0]*(account\b|passw)', '(?(?=[^\0]*(?<k>(?>Confid\w+ (?:Not|State)|Disclaimer|©)))[^\0]{700,}\1|\A[^\0]{700,})' -SetHeaderName 'X-PMF-Tag' -SetHeaderValue 'Suspicious-Content-Too-Short'
```
&nbsp;


\- `X-PMF-Tag: Suspicious-Content (Keywords #2)`: This rule consists of another set of suspicious keywords and combining those with emails got tagged from the “Too-Short” or “Suspicious-Keywords” to generate the “*Suspicious-Content”* tag.

You might notice most of the rules in this section had the “*Suspicious-Content*” prefix for their tags except for the first set of keywords (“*Suspicious-Keywords”*). The reason (again) because a single set of keywords is not enough to identify malicious emails. Two sets of keywords? Should be good. We could use the “Suspicious-Content” prefix (including Keywords, Too-Short, and X-File) as a condition in later rules. 

Exceptions: external service addresses defined in the “*X-PMF-Tag: External/Internal Services”*, emails from trusted IPs, or a mail thread.

Assigned tag (**X-PMF-Tag** header): “**Suspicious-Content**”.

![Screen Shot 2022-10-28 at 12 09 46 AM](https://user-images.githubusercontent.com/66635269/200475494-006af0cd-d151-4a82-b0f6-e909a23abe30.png)
Powershell:
```
New-TransportRule -Name 'X-PMF-Tag: Suspicious-Content (Keywords #2)' -Mode Enforce -SenderAddressLocation HeaderOrEnvelope -SentToScope InOrganization -HeaderContainsMessageHeader 'X-PMF-Tag' -HeaderContainsWords 'Too-Short', 'Keywords' -SubjectOrBodyMatchesPatterns '\A(?=[^\0]*\b(authen|valida|restor|storag|.e.?activat.ed?))(?![^\0]*?\b(code|reset))[^\0]*\b(accounts?|w?e?.?mail(box)?)\b', '。', '(?=risk|compromise|wrong|incorrect|(un|n.t( be)? )able|undeliver)([^\0]*\b(now\b|immediately|until|avoid))', '\b([bhiaswvern]{2,4}) (temp\w+ )?\b(shar|noti|hac|stol|leak|requi|affe|sus)\w*e[dsn]\b', '[a-z]+( [,.] ?|,)[a-z]+?', '(?=[^\0]{500,})\A[^\0]+(@|.?at.?)?yourdomain\.com\b', '\A(?![^\0]*?\b(code|reset))[^\0]*?\b(with)?in (\d\d.?h(ou)?r|0?\d.?day)s?\b', '\b(we|y?our) [^\.\n]{0,40}( [bhiaswvern]{2,4})? (not|lim|sus|fro|d(isa|e[ltcn])|u?n?[vt]er|res?[tmqa]|b?lock|expi)\w*e[dsn]?\b' -ExceptIfHeaderContainsMessageHeader 'X-PMF-Tag' -ExceptIfHeaderContainsWords 'Trusted-IPs', 'Mail-thread', 'Exceptions', 'Commercial', 'Services' -ExceptIfSubjectOrBodyMatchesPatterns '\A(?=[^\0]{150,})((?!https?:\/\/)[^\0]){1,}\Z', '[^\0]{3500,}' -SetHeaderName 'X-PMF-Tag' -SetHeaderValue 'Suspicious-Content'
```
&nbsp;


###### **3.2.2.2.2 Generic Blocking:**
\- `X-PMF-Shield: #EXT-Phishing-File`: This rule will block emails with common suspicious payload in the attachments’ content. Could be a fake login form, browser exploits, Folina exploits, macros, etc.

![Screen Shot 2022-10-28 at 12 10 06 AM](https://user-images.githubusercontent.com/66635269/200475904-338c218e-a5e2-4c22-ba63-b6f4bd32726d.png)


Exceptions: external service addresses defined in the “*X-PMF-Tag: External/Internal Services”*, trusted IPs, or a mail thread.

Assigned tag (**X-PMF-Shield** header): “**#EXT-Phishing-File**”.

![Screen Shot 2022-10-28 at 12 10 15 AM](https://user-images.githubusercontent.com/66635269/200475940-a8f42b03-5f3d-43fa-9aa8-18e0e0b135f3.png)
Powershell:
```
New-TransportRule -Name 'X-PMF-Shield: #EXT-Phishing-File' -Mode Enforce -SenderAddressLocation HeaderOrEnvelope -HeaderContainsMessageHeader 'X-PMF-Tag' -HeaderContainsWords 'Too-Short', 'X-FILE' -FromScope NotInOrganization -AttachmentMatchesPatterns 'ms-msdt:', 'SMTP:', 'iframe', 'parseInt', 'document\.write', 'decodeURI', 'window\.location', 'base64', 'form action=', 'C:\\', 'Download', '\.exe', 'bitcoin', '\.dll', 'atob\(', '\.vbs', 'VBA(_PROJECT)?', 'eval\(', '<.?script', 'javascript', 'location\.href', 'log.?in', 'unescape\(', '(\w+@)?yourdomain\.com' -ExceptIfHeaderContainsMessageHeader 'X-PMF-Tag' -ExceptIfHeaderContainsWords 'Trusted-IPs', 'Services', 'Mail-Thread' -ExceptIfHeaderMatchesMessageHeader 'X-PMF-URL' -ExceptIfHeaderMatchesPatterns 'Exception-URLs' -SetHeaderName 'X-PMF-Shield' -SetHeaderValue '#EXT-Phishing-File'
```
&nbsp;


\- `X-PMF-Shield: #EXT-Phishing`: This rule is the last stop for all of the “*Suspicious-Content”* rules above. It is your decision to leave it as is with just the “*Suspicious-Content”* tag for blocking or customizing this rule with an additional set of keywords. The example simply checks if the “*Suspicious-Content”* emails have any external URLs/emails or job scams in them.

Exceptions: emails with the tag “Exception-URLs” or already tagged by other blocking rules.

Assigned tag (**X-PMF-Shield** header): “**#EXT-Phishing**”.

![Screen Shot 2022-10-28 at 12 10 26 AM](https://user-images.githubusercontent.com/66635269/200476078-b1985262-d81c-4fdc-bb99-4aa2ff4776fa.png)
Powershell:
```
New-TransportRule -Name 'X-PMF-Shield: #EXT-Phishing' -Mode Enforce -SenderAddressLocation HeaderOrEnvelope -SentToScope InOrganization -HeaderContainsMessageHeader 'X-PMF-Tag' -HeaderContainsWords 'Suspicious-Content' -SubjectOrBodyMatchesPatterns '\A(?![^\0]*https?:\/\/\S+)(?=[^\0]*\b(I.a?m|my name)\b)(?=[^\0]*(re(ply|spond)))', '(?<!(Confid\w+ (Not|Sta)|Discl|©)[^\0]*)https?:..(?![^\s\/>]*(\byourdomain\.com)\b(?!\.\w))[^\s\/>]+(?!\S+(jpe?g|gif|png|svg|tiff?))', '(?=(part.?time|offer\w{0,}\b|personal|private)\b)[\S\s]+(\b[\w._-]+@(?!yourdomain\.com)[\w.-]+\.[a-z]{2,}\b)' -FromScope NotInOrganization -ExceptIfHeaderContainsMessageHeader 'X-PMF-URL' -ExceptIfHeaderContainsWords 'Exception-URLs' -ExceptIfHeaderMatchesMessageHeader 'X-PMF-Shield' -ExceptIfHeaderMatchesPatterns '^#' -SetHeaderName 'X-PMF-Shield' -SetHeaderValue '#EXT-Phishing'
```
&nbsp;


\- `X-PMF-Shield: #Suspicious-EXT-BCC`: This rule will block any suspicious emails that got tagged from previous rules and are sent via BCC. It is the most common method that attackers used to send scams and phishing emails. BCC is bad.

Exception: this rule is a bit different as we must use both header options (for “To:” and “CC:”) in the exceptions to determine if the email is BCC. As the result, we cannot reuse the “tags” (X-PMF-Tag header) as exceptions. Please modify the exceptions to fit your needs.

Assigned tag (**X-PMF-Shield** header): “**#Suspicious-EXT-BCC**”.

![Screen Shot 2022-10-28 at 12 10 40 AM](https://user-images.githubusercontent.com/66635269/200476200-510b4ab1-1a59-44e4-94b8-6ad3a1289557.png)
Powershell:
```
New-TransportRule -Name 'X-PMF-Shield: #Suspicious-EXT-BCC' -Mode Enforce -SenderAddressLocation HeaderOrEnvelope -SentToScope InOrganization -HeaderContainsMessageHeader 'X-PMF-Tag' -HeaderContainsWords 'Free-Mail', 'Abnormal-URLs', 'Keywords', 'Suspicious' -FromScope NotInOrganization -ExceptIfSenderIpRanges 1.2.3.4/16 -ExceptIfHeaderContainsMessageHeader 'CC' -ExceptIfHeaderContainsWords 'yourdomain.com' -ExceptIfSenderDomainIs 'privaterelay.appleid.com' -ExceptIfHeaderMatchesMessageHeader 'To' -ExceptIfHeaderMatchesPatterns 'yourdomain\.com' -SetHeaderName 'X-PMF-Shield' -SetHeaderValue '#Suspicious-EXT-BCC'
```
&nbsp;


\- `X-PMF-Shield: #Crypto-Address`: This rule will block any suspicious emails that got tagged from previous rules and contain cryptocurrency addresses in them, most likely those are extortion or scam emails.

Special thanks to MBrassey @ <https://gist.github.com/MBrassey/623f7b8d02766fa2d826bf9eca3fe005> for the RegEx patterns.

![Screen Shot 2022-10-28 at 12 10 59 AM](https://user-images.githubusercontent.com/66635269/200476280-098ec84d-32b7-4270-b448-641cfd8a9dfa.png)

Exceptions: service addresses defined in the “*X-PMF-Tag: External/Internal Services”*, trusted IPs, or commercial emails.

Assigned tag (**X-PMF-Shield** header): “**#Crypto-Address**”.

![Screen Shot 2022-10-28 at 12 11 13 AM](https://user-images.githubusercontent.com/66635269/200476322-19d58db6-0c28-4341-b6a2-06e7459443f7.png)
Powershell:
```
New-TransportRule -Name 'X-PMF-Shield: #Crypto-Address' -Comments 'Credit to MBrassey @ https://gist.github.com/MBrassey/623f7b8d02766fa2d826bf9eca3fe005' -Mode Enforce -SenderAddressLocation HeaderOrEnvelope -SentToScope InOrganization -HeaderContainsMessageHeader 'X-PMF-Tag' -HeaderContainsWords 'Suspicious' -SubjectOrBodyMatchesPatterns '\sbc1[\d\D]{39,59}\s', '\s4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}', '\s[LM3][a-km-zA-HJ-NP-Z1-9]{26,33}', '\s0x[a-fA-F0-9]{40}', '\sX[1-9A-HJ-NP-Za-km-z]{33}', '\s[13][a-km-zA-HJ-NP-Z1-9]{33}', '\s[13][a-km-zA-HJ-NP-Z0-9]{26,33}' -ExceptIfHeaderContainsMessageHeader 'X-PMF-Tag' -ExceptIfHeaderContainsWords 'Trusted-IPs', Commercial', 'Services', 'Exceptions' -ExceptIfHeaderMatchesMessageHeader 'X-PMF-Shield' -ExceptIfHeaderMatchesPatterns '^#' -SetHeaderName 'X-PMF-Shield' -SetHeaderValue '#Crypto-Address'
```
&nbsp;


#### ***3.2.3 Internal Phishing:***
What is “internal phishing”? When an account was compromised and the attackers used that account to send scams/phishing emails to internal users, that’s what we call “internal phishing”.

Preventing internal phishing ***was*** not hard because the attackers used to use BCC to send mass emails to everyone. So, blocking internal BCC entirely would be an easy solution but it is not the case most of the time. And it “was” easy until they figured out that we are blocking BCC and changed the sending method.

\- `X-PMF-Shield: #Suspicious-BCC`: This rule is similar to the “*#Suspicious-EXT-BCC”* rule but targets internal BCC instead. The MS Exchange uses an internal header name “X-MS-Exchange-Organization-BCC” for BCC email, which will be filtered out when the email reached the recipient but still have effects when Transport rules kick in.

Exception: service addresses defined in the “*X-PMF-Tag: External/Internal Services”*, trusted IPs, or an email thread.

Assigned tag (**X-PMF-Shield** header): “**#Suspicious-BCC**”.

![Screen Shot 2022-10-28 at 12 11 23 AM](https://user-images.githubusercontent.com/66635269/200476456-fce75ee5-4561-4f81-81e7-3ba68324a146.png)
Powershell:
```
New-TransportRule -Name 'X-PMF-Shield: #Suspicious-BCC' -Mode Enforce -SenderAddressLocation HeaderOrEnvelope -SentToScope InOrganization -HeaderContainsMessageHeader 'X-PMF-Tag' -HeaderContainsWords 'Suspicious-Content' -SenderDomainIs 'yourdomain.com' -HeaderMatchesMessageHeader 'X-MS-Exchange-Organization-BCC' -HeaderMatchesPatterns 'yourdomain.com' -ExceptIfHeaderContainsMessageHeader 'X-PMF-Tag' -ExceptIfHeaderContainsWords 'Services', 'Mail-thread', 'Trusted-IPs' -SetHeaderName 'X-PMF-Shield' -SetHeaderValue '#Suspicious-BCC'
```
&nbsp;


\- `X-PMF-Shield: Internal Off-hours BCC (#OffHours-BCC)`: This rule will block all BCC emails being sent off-hours (not 8 AM to 5 PM, based on the Date header) regardless of the email content. We are using the EST time; you might need to modify the RegEx patterns to fit your time zone.

Exception: service addresses defined in the “*X-PMF-Tag: External/Internal Services”*, or trusted IPs.

Assigned tag (**X-PMF-Shield** header): “***#OffHours-BCC***”.

![Screen Shot 2022-10-28 at 12 11 33 AM](https://user-images.githubusercontent.com/66635269/200476583-9cf1b11f-cd8a-4b91-970f-888e8ddb9775.png)
Powershell:
```
New-TransportRule -Name 'X-PMF-Shield: Internal Off-hours BCC (#OffHours-BCC)' -Mode Enforce -SenderAddressLocation HeaderOrEnvelope -HeaderContainsMessageHeader 'X-MS-Exchange-Organization-BCC' -HeaderContainsWords 'yourdomain.com' -HeaderMatchesMessageHeader 'Date' -HeaderMatchesPatterns 'Sun|Sat', '(?<!(Sun|Sat).{14})(0[0-9]|1[0-2]|2[2-4]):\d{2}:\d{2} \+\d{4}' -FromScope InOrganization -ExceptIfHeaderContainsMessageHeader 'X-PMF-Tag' -ExceptIfHeaderContainsWords 'Trusted-IPs', 'Services' -ExceptIfHeaderMatchesMessageHeader 'X-PMF-Shield' -ExceptIfHeaderMatchesPatterns '^#' -SetHeaderName 'X-PMF-Shield' -SetHeaderValue '#OffHours-BCC'
```
&nbsp;


#### ***3.2.4 Spoofing/Impersonating:***
\- `X-PMF-Shield: Block Spoofing (#SPOOFING)`: This rule will block spoofed emails. Remember to change “yourdomain\.com” to your actual domain name.

Exceptions: the exceptions might vary depending on your needs. For example, if a 3rd vendor did a poor job with the email settings, and messed up the Authentication-Results headers, you might want to add their IPs as the exceptions.

Assigned tag (**X-PMF-Shield** header): “**#SPOOFING**”.

![Screen Shot 2022-10-28 at 12 11 54 AM](https://user-images.githubusercontent.com/66635269/200476691-ee8b0dc1-9026-40ef-b349-982e7147c494.png)
Powershell:
```
New-TransportRule -Name 'X-PMF-Shield: Block Spoofing (#SPOOFING)' -Mode Enforce -HeaderMatchesMessageHeader 'X-PMF-Auth' -HeaderMatchesPatterns 'Auth-Failed' -FromAddressMatchesPatterns '[^\s]+@yourdomain\.com' -FromScope NotInOrganization -ExceptIfHeaderContainsMessageHeader 'X-PMF-Tag' -ExceptIfHeaderContainsWords 'Exceptions', 'Trusted-IPs' -SetHeaderName 'X-PMF-Shield' -SetHeaderValue '#SPOOFING'
```
&nbsp;


\- `X-PMF-Shield: Block Impersonate (#IMPERSONATE)`: This rule will block impersonating emails. For example, an email with the “From:” address is “*admin@contoso.com <badguy@outside.com>*" OR “Contoso Admin <badguy@outside.com>" (whereas “Contoso” is your company name). Remember to change “yourdomain\.com” to your actual domain name and “yourcompanyname” to yours.

![Screen Shot 2022-10-28 at 12 12 07 AM](https://user-images.githubusercontent.com/66635269/200476801-c17f7d9a-d71a-4201-83ed-63ae6959a066.png)

Exceptions: the exceptions might vary, customize them to fit your needs.

Assigned tag (**X-PMF-Shield** header): “**#IMPERSONATE**”.

![Screen Shot 2022-10-28 at 12 12 20 AM](https://user-images.githubusercontent.com/66635269/200476833-af659d9d-3175-4d3a-bd99-b58b353d7349.png)
Powershell:
```
New-TransportRule -Name 'X-PMF-Shield: Block Impersonate (#IMPERSONATE)' -Mode Enforce -HeaderMatchesMessageHeader 'From' -HeaderMatchesPatterns '@(?<d>[\w.-]+)[^\0]*@(?!\1)', 'yourcompanyname[\S ]+@(?!yourdomain\.com)' -FromScope NotInOrganization -ExceptIfHeaderContainsMessageHeader 'X-PMF-Tag' -ExceptIfHeaderContainsWords 'Mail-Thread', 'Commercial', 'Services', 'Exceptions' -SetHeaderName 'X-PMF-Shield' -SetHeaderValue '#IMPERSONATE'
```
&nbsp;


#### ***3.2.5 Quarantined Senders:***
\- `X-PMF-Shield: #QUARANTINED`: During an internal phishing outbreak, besides resetting the user’s password, and blocking IPs. It is a good idea to quarantine the compromised user from sending more malicious emails. You could prevent them from sending BCC or even more aggressively: don’t allow them to send anything.

Assigned tag (**X-PMF-Shield** header): “***#QUARANTINED***”.

![Screen Shot 2022-10-28 at 12 12 30 AM](https://user-images.githubusercontent.com/66635269/200476923-4aa058a8-1206-46bd-a826-87d1345335e4.png)
Powershell:
```
New-TransportRule -Name 'X-PMF-Shield: Quarantined Senders' -Comments 'Use this rule to quarantine internal compromised accounts. Remember to remove the email from the list after done Incident Response/Clean Up.' -Mode Enforce -SenderAddressLocation HeaderOrEnvelope -From 'compromised@yourdomain.com' -HeaderMatchesMessageHeader 'X-MS-Exchange-Organization-BCC' -HeaderMatchesPatterns 'yourdomain.com' -SetHeaderName 'X-PMF-Shield' -SetHeaderValue '#QUARANTINED'
```
&nbsp;


### **3.3 Phase 3: Blocking**
\- `X-PMF-Shield: Mail Approval`: This is the final phase where you decide the action on suspicious emails that got tagged from previous rules. You can either reject/block, move to the junk folder, or redirect the emails to the moderator(s) for review as in the example.

This single action will apply to all emails which have the X-PMF-Shield header starting with “#”. You can also customize/create multiple actions based on the tags’ prefixes or a partial keyword in a tag.

The Exceptions are to exclude the forwarded emails to internal in case the user forwards their personal emails to your domain, this is optional.

![Screen Shot 2022-10-28 at 12 12 44 AM](https://user-images.githubusercontent.com/66635269/200477036-f8e4710f-b189-493c-993f-1e7e206d6442.png)
Powershell:
```
New-TransportRule -Name 'X-PMF-Shield: Mail Approval' -Mode Enforce -SenderAddressLocation HeaderOrEnvelope -HeaderMatchesMessageHeader 'X-PMF-Shield' -HeaderMatchesPatterns '\A#' -ExceptIfHeaderContainsMessageHeader 'X-Forwarded-To' -ExceptIfHeaderContainsWords 'yourdomain.com' -ExceptIfHeaderMatchesMessageHeader 'Resent-From' -ExceptIfHeaderMatchesPatterns '@' -ModerateMessageByUser 'phishing@yourdomain.com'
```
&nbsp;


### **3.4 Block Mail Rejection Notifications:**
\- `X-PMF-Shield: Block Mail Rejection Notifications`: Set this rule up if you went with the mail approval route because the MS Exchange will send a notification to the sender if an email is rejected/expired, and we don’t want the attackers to know that their emails got blocked. Also, if an email was not approved, it will be expired after 48 hours.

![Screen Shot 2022-10-28 at 12 12 56 AM](https://user-images.githubusercontent.com/66635269/200477125-34b78dc4-6451-46bd-92ee-edf696ffcdcb.png)
Powershell:
```
New-TransportRule -Name 'X-PMF-Shield: Block Mail Rejection Notifications' -Mode Enforce -SenderDomainIs 'yourdomain.onmicrosoft.com' -SubjectMatchesPatterns '\A(Rejected|Expired):' -DeleteMessage $true
```
&nbsp;


#### ***(\*\*) 3.1.2 Clear X-PMF headers - IMPORTANT:***
\- The following rules must be on the very top of the rule set. The reason I moved the explanations here is that at this point you might have a better understanding of what those “tags” do.

Those tags are custom tags, so if the attackers knew about this rule set, they could spoof the tags easily and bypass the rule set by set the X-PMF-Tag to “Services” or something similar. We need to purge any spoofed tags from the emails when they come in to prevent that.

![Screen Shot 2022-10-28 at 12 13 07 AM](https://user-images.githubusercontent.com/66635269/200477335-962f3d9d-3444-43a1-8c6a-e0a82d1215e8.png)
![Screen Shot 2022-10-28 at 12 13 16 AM](https://user-images.githubusercontent.com/66635269/200477338-448423ab-83a3-470e-a157-c0fc1fff740d.png)

## **4. Tips to tune your rule set**
For the initial setup, going with the mail approval for **Phase 3** is highly recommended. It will take you a couple of weeks to months to build a baseline of which services (“*X-PMF-Tag: External/Internal Services*”, “*X-PMF-Tag: Trusted-IPs*”, etc.) are frequently used by the users and got caught (false positives). Once you have the baseline, it’s time to tune the individual rule.

### **4.1 Mail headers**
Inspecting the captured email headers will give you a brief idea of the last rules that hit the email and why it got caught. In this example, we can tell the email got caught because it was too short and sent via BCC. However, those were not all the rules that hit the email, to see that, please use the “Threat Explorer”.

By the way, this example is a common fake billing/invoice scam with almost no content in the email body, the fake invoice will be in an attachment, either an image or a PDF/HTML/DOC file. A typical keyword filter would not work on this one.

![Screen Shot 2022-11-07 at 11 47 24 PM](https://user-images.githubusercontent.com/66635269/200477715-534068b2-1aa0-4d19-b8f5-9f09d4681fc4.png)


***\* Note**: the “X-FTag” and “X-FShield” are the former names of “X-PMF-Tag” and “X-PMF-Shield” respectively.*

###

### **4.2. Threat Explorer**
#### ***4.2.1 Email Analyzing***
Threat Explorer (<https://security.microsoft.com/threatexplorer>) is a great tool to monitor and analyze email traffic. It will give you overview information about the email, including attachments, URLs, ATP detections, transport rules applied, email headers, etc.

![Screen Shot 2022-11-07 at 11 47 45 PM](https://user-images.githubusercontent.com/66635269/200477803-e5d2cd12-08a5-4012-8b89-e88d40f0a5e1.png)


As you can see the example in section 4.1 got tagged with the “Free email providers” then “Suspicious-Content-Too-Short” and tagged for blocking with “#Suspicious-EXT-BCC”, finally got blocked by the “Mail approval”


#### ***4.2.2 Tracking Rule’s Performance***
You can use Threat Explorer to track the performance of the rule(s), i.e. how many emails got tagged, what rules were applied to those, and so on. This is extremely useful especially if you went with the aggressive route – blocking every tagged email. 

![Screen Shot 2022-11-07 at 11 48 19 PM](https://user-images.githubusercontent.com/66635269/200477839-972ce4e2-b90b-4c04-8d97-157e462c40d7.png)
![Screen Shot 2022-11-07 at 11 48 31 PM](https://user-images.githubusercontent.com/66635269/200477842-0243e82b-979e-4715-bffe-2e49312739dd.png)

