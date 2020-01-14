
GSuite Security Best Practicies

Administrator 
Protect admin accounts


Require 2-Step Verification for admin accounts
Because super admins control access to all business and employee data in the organization, it's especially important for their accounts to be protected by an additional authentication factor.
Protect your business with 2-Step Verification | Deploy 2-Step verification


Use security keys for 2-Step Verification
Security keys help to resist phishing threats and are the most phishing-resistant form of 2-Step Verification.
Protect your business with 2-Step Verification


Don't use a super admin account for daily activities
Super admins should use a separate user account for daily activities. They should sign in to their super administrator account only when they need to perform specific super administrator duties.
Administrator privilege definitions | Security best practices for administrator accounts


Don't remain signed in to an idle super admin account
Super admins should sign in to perform specific super admin tasks and then sign out.
Security best practices for administrator accounts 
Manage super admin accounts

Set up multiple super admin accounts
A business should have more than one super admin account, each managed by a separate person. If one account is lost or compromised, another super admin can perform critical tasks while the other account is recovered.
Assign administrator roles to a user 

Create per-user super admin role accounts
Each super admin should have an identifiable admin account so it's clear which admin is responsible for activities in the audit log.
Security best practices for administrator accounts

Delegate daily admin tasks to user accounts
Use the super admin account only when needed and delegate daily tasks to user accounts. Use the model of least privilege, in which each user has access to only the resources and tools needed for their typical tasks.
Assign administrator roles to a user | Security best practices for administrator accounts 
Manage activity on admin accounts

Set up admin email alerts
Monitor admin activity and track potential security risks by setting up admin email alerts for certain events, such as suspicious sign-in attempts, compromised mobile devices, or changes by another admin.
Administrator email alerts

Review the Admin audit log
Use the Admin audit log to see a history of every task performed in the Google Admin console, which admin performed the task, the date, and the IP address from which the admin signed in.
Admin audit log
Prepare for admin account recovery

Add recovery options to admin accounts
Add a recovery phone number and email address to admin accounts so Google can send a new password via phone, text, or email. 
Add account recovery information to your administrator account

Keep information on hand for super admin password reset
If a super admin can’t reset their password using email or phone recovery options, and another super admin isn’t available to reset the password, they can contact Google Support.

To verify identity, Google asks questions about the organization’s account. The admin also needs to verify DNS ownership of the domain. You should keep account information and DNS credentials in a secure place in case they’re needed.
Security best practices for administrator accounts

Enroll a spare security key
Admins should enroll more than one security key for their admin account and store it in a safe place. If their primary security key is lost or stolen, they can still sign in to their account.
Add a security key to your account

Save backup codes ahead of time
If an admin loses their security key or phone (where they receive a 2-Step Verification code or Google prompt), they can use a backup code to sign in.
Generate and print backup codes
Accounts 
Enforce multifactor authentication


Require 2-Step Verification (2SV) for users
2-Step Verification helps protect a user account from unauthorized access should someone manage to obtain their password.
Protect your business with 2-Step Verification | Deploy 2-Step verification


Enforce security keys, at least for admins and other high-value accounts.
Security keys are small hardware devices used when signing in that provide second factor authentication that resists phishing.
Deploy 2-Step verification
Protect passwords


Help prevent password reuse with Password Alert
Use Password Alert to make sure users don't use their corporate credentials on other sites.
Prevent password reuse


Use unique passwords
A good password is the first line of defense to protect user and admin accounts. Unique passwords aren’t easily guessed. Also discourage password reuse across different accounts, such as email and online banking.
Create a strong password & a more secure account
Help prevent and remediate compromised accounts


Regularly review activity reports and alerts
See activity reports for account status, admin status, and 2-Step Verification enrollment details.
Account activity reports


Set up admin email alerts
Set up email alerts for potentially risky events, such as suspicious sign-in attempts, compromised mobile devices, or setting changes by another admin.
Admin email alerts


Add user login challenges 
Set up login challenges for suspicious login attempts. Users must enter a verification code that Google sends to their recovery phone number or recovery email address or they must answer a challenge that only the account owner can solve.
Verify a user’s identity with a login challenge |  Add employee ID as a login challenge


Identify and secure compromised accounts
If you suspect an account may be compromised, suspend the account, investigate for malicious activity, and take action if necessary.
Review mobile devices associated with the account
Use the Email log search to review delivery logs for your domains
Use the Security report to evaluate the exposure of the domain to data security risks.
Verify if any malicious settings were created
Identify and secure compromised accounts


Disable the ability to download data if circumstances warrant it
Prevent user account data from being downloaded if the account is compromised or the user leaves the company.
Turn Takeout on or off for user
Apps (G Suite only) 


Review third-party access to core services
Know and approve which third-party apps can access G Suite core services such as Gmail and Drive. 
Whitelist connected apps


Create a whitelist of trusted apps
Create a whitelist that specifies which third-party apps can access core G Suite services.
Whitelist connected apps
Calendar (G Suite only) 


Limit external calendar sharing
Restrict external calendar sharing to free/busy information only. This reduces the risk of data leaks.
Set calendar visibility and sharing options

















Classic Hangouts (G Suite only) 

Warn users when chatting outside their domain
Show users a warning when they chat with people outside their domain. When enabled, group chat conversations are split when the first person from outside the domain is added to the discussion. This prevents external users from seeing previous internal discussions and reduces the risk of data leaks.
Classic Hangouts Chat settings

Set a chat invitation policy
Use this setting to set a chat invitation policy based on your organization’s policy on collaboration.
Classic Hangouts Chat settings
Contacts (G Suite only) 

Don’t automatically share contact information
Disable the option to automatically share contact information.
Turn the global Directory on or off
Drive  
Limit sharing and collaboration outside your domain

Set sharing options for your domain
Confine file sharing within the boundary of your domains by turning sharing options off. This reduces data leak and data exfiltration risks. If sharing is required outside of a domain because of business needs, you can define how sharing is done for organizational units, or you can designate whitelisted domains.
Set Drive users' sharing permissions

Set the default for link sharing
Turn off link sharing for newly created files. Only the file owner should have access until they share the file.
Set Drive users' sharing permissions

Warn users when they share a file outside the domain
If you allow users to share files outside the domain, enable a warning when a user does so. This allows users to confirm whether this action is the intended one, and reduces the risk of data leaks.
Set Drive users' sharing permissions

Limit file access to recipients only
When a user shares a file via a Google product other than Docs or Drive (for example, by pasting a link in Gmail), Access Checker can check that the recipients can access the file. Configure Access Checker for Recipients only. This gives you control over the accessibility of links shared by your users, and reduces the risk of data leaks.
Set Drive users' sharing permissions

Prevent users from publishing on the web
Disable file publishing on the web. This reduces the risk of data leaks.
Set Drive users' sharing permissions

Require Google sign-in for external collaborators
Require external collaborators to sign in with a Google account. If they don't have a Google account, they can create one at no cost. This reduces the risk of data leaks.
Set Drive users' sharing permissions

Control files stored on shared drives​
Allow only users in your organization to move files from their shared drives to a Drive location in a different organization.
Set Drive users' sharing permissions

Control content sharing in new shared drives
Restrict sharing in new shared drives using the shared drive creation settings.

Control sharing in shared drives
Limit local copies of Drive data

Disable access to offline docs
To reduce the risk of data leaks, consider disabling access to offline docs. When docs are accessible offline, a copy of the document is stored locally. If you have a business reason to enable access to offline docs, enable this feature per organizational unit to minimize risk.
Control offline use of Docs editors

Disable desktop access to Drive
You can enable desktop access to Drive by deploying the Backup and Sync client or Drive File Stream. The Backup and sync client lets users sync files between their computers and Google Drive. Drive File Stream syncs files from the cloud to a user's local computer.
To reduce the risk of data leaks, consider disabling desktop access to Drive. If you decide to enable desktop access, be sure that you enable it only for users with a critical business need.
Deploy Backup and Sync | Turn on sync for your organization |
Compare Backup and Sync and Drive File Stream
Control access to your data by third-party apps

Don't allow Drive add-ons
To reduce the risk of data leaks, consider not allowing users to install add-ons for Google Docs from the add-on store. To support a specific business need, you can deploy specific add-ons for Google Docs that are aligned with your organizational policy.
Enable add-ons in Google Docs editors
Gmail (G Suite only) 
Set up authentication and infrastructure

Validate email with SPF, DKIM, and DMARC
SPF, DKIM, and DMARC establish an email validation system that uses DNS settings to authenticate, digitally sign, and help prevent spoofing of your domain.
Attackers sometimes forge the "From" address on email messages so they appear to come from a user in your domain. To prevent this, you can configure SPF and DKIM on all outbound email streams. 
Once SPF and DKIM are in place, you can configure a DMARC record to define how Google and other receivers should treat unauthenticated emails purporting to come from your domain.
Enhance security for outgoing email (DKIM) | Authorize email senders with SPF | 
Enhance security for forged spam (DMARC)

Set up inbound email gateways to work with SPF
If you use an email gateway to route incoming email, make sure it’s configured properly for Sender Policy Framework (SPF). This avoids negatively impacting spam handling.
Set up an inbound mail gateway

Enforce TLS with your partner domains
Require that mail be transmitted using TLS to ensure a secure connection. Configure the TLS setting to require a secure connection for email to (or from) partner domains.
Require mail to be transmitted via a secure (TLS) connection

Require sender authentication for all approved senders​
Enable the Require sender authentication setting for spam policies. Not requiring sender authentication bypasses the spam folder for approved senders that don't have authentication enabled (such as SPF or DKIM). Disabling this setting reduces the risk of spoofing and phishing/whaling. Learn more about sender authentication. 
Customize spam filter settings

Configure MX records for correct mail flow
Configure the MX records to point to Google’s mail servers as the highest priority record to ensure correct mail flow to your G Suite domain users. This reduces the risk of data deletion(through lost email) and malware threats.
Set up MX records for G Suite Gmail | G Suite MX records values
Protect users and organizations

Disable IMAP/POP access
IMAP and POP desktop clients let users access Gmail through third-party email clients. Disable POP and IMAP access for any users who don't explicitly need this access. This reduces data leak, data deletion, and data exfiltration risks. It also can reduce the threat of attacks because IMAP clients might not have similar protections to first-party clients.
Turn IMAP and POP on and off for users

Disable automatic forwarding
Prevent users from automatically forwarding incoming mail to another address. This reduces the risk of data exfiltration through email forwarding, which is a common technique employed by attackers.
Disable automatic forwarding

Enable comprehensive mail storage
The comprehensive mail storage setting ensures that a copy of all sent and received mail in your domain—including mail sent or received by non-Gmail mailboxes—is stored in the associated users' Gmail mailboxes. Enable this setting to ensure mail is stored in Google Vault for all users who enable SMTP relay.
This reduces the risk of data deletion by ensuring that a copy of all sent or received messages in your domain—including messages sent or received by non-Gmail mailboxes—is stored in the associated users' Gmail mailboxes.
Set up comprehensive mail storage

Don't bypass spam filters for internal senders
Turn off Bypass spam filters for internal senders, because any external addresses added to groups are treated as internal addresses. By turning this setting off, you can make sure all user email is filtered for spam, including mail from internal senders. This reduces the risk of spoofing and phishing/whaling.
Customize spam filter settings

Add spam headers setting to all default routing rules
Adding the spam headers setting to all default routing rules helps maximize the filtering capacity of email servers downstream to reduce the risks of spoofing and phishing/whaling. While Gmail  automatically filters messages for spam and phishing, checking the Add X-Gm-Spam and X-Gm-Phishy headers box adds these headers to indicate the spam and phishing status of the message.
For example, an administrator at a downstream server can use this information to set up rules that handle spam and phishing differently from clean mail.
Configure default routing

Enable enhanced pre-delivery message scanning
When Gmail identifies that an email message may be phishing, this setting enables Gmail to perform additional checks on the message.
Use enhanced pre-delivery message scanning

Enable external recipient warnings 
Gmail detects if an external recipient in an email response is not someone a user interacts with regularly, or isn't present in a user’s Contacts. When you configure this setting, your users receive a warning and an option to dismiss.
Configure an external recipient warning

Enable additional attachment protection
Google scans incoming messages to protect against malware, even if the additional malicious attachment protections settings aren't enabled. Turning on additional attachment protection can catch email that previously wasn't identified as malicious.
Enhance phishing and malware protection

Enable additional link and external content protection
Google scans incoming messages to protect against malware, even if the additional malicious link and content protections settings aren't enabled. Turning on additional links and external images protection can catch email that previously wasn't identified as phishing.
Enhance phishing and malware protection

Enable additional spoofing protection​
Google scans incoming messages to protect against spoofing even if additional spoofing protections settings aren't enabled. Turning on additional spoofing and authentication protection can, for example, reduce the risk of spoofing based on similar domain names or employee names.
Enhance phishing and malware protection
Security considerations for daily Gmail tasks

Take care when overriding spam filters
Advanced Gmail settings provide detailed control of message delivery and filtering. To avoid an increase in spam, exercise thought and care if you use these settings to override Gmail’s default spam filters. 
If you add a domain or an email address to the approved senders list, use caution with the “Do not require sender authentication” option, as this may result in bypassing Gmail’s spam filters for senders with no authentication.
You can bypass the spam filters for messages sent from specific IP addresses by adding these IP addresses to the email whitelist. Be cautious while whitelisting IP addresses, particularly if you whitelist large ranges of IP addresses via CIDR notation.
If you're forwarding messages to your G Suite domain via an inbound gateway, add the IP addresses of your inbound gateway to the inbound gateway settings and not the email whitelist.
Monitor and tune compliance rules to help prevent spam and phishing.
Tailor Gmail settings for an organization

Don't include domains in the approved senders list
You can include domains in your approved senders list. If you configured approved senders, and if you checked Bypass spam filters for messages received from addresses or domains within these approved senders lists, remove any domains from your approved sender list. Excluding domains from the approved senders list reduces the risk of spoofing and phishing/whaling.  
Customize spam filter settings

Don't whitelist IP addresses
In general, mail sent from whitelisted IP addresses isn't marked as spam. To take full advantage of the Gmail spam filtering service and for best spam classification results, IP addresses of your mail servers  and partner mail servers that are forwarding email to Gmail should be added to an Inbound mail gateway, and not an IP whitelist.
Whitelist IP addresses in Gmail | Set up an inbound mail gateway
Google+ (G Suite only) 

Restrict new posts by default
Make new posts restricted to your domain by default. Users can change a post to restricted or unrestricted before sharing.
Set a default sharing restriction for Google+ content

Disable profile visibility
Disable the ability to find user profiles from public searches.
Set the default for profile discoverability

Automatically create Google+ profiles
Disable automatic creation of public Google+ profiles for users in your organization.
Manage Google+ profiles
(See Create Google+ profiles for all users in an organizational unit.)

Consider allowing apps to access Google+ APIs
Third-party apps can use Google+ APIs to act on behalf of users, performing actions such as reading posts, writing restricted posts, or managing circles. Enable this setting if you plan to programmatically access the Google+ APIs. Otherwise, disable it.
Enable or disable Google+ APIs
Groups 

Set up private access to your groups
Select the Private setting to limit access to members of your domain. (Group members can still receive email from outside the domain.) This reduces the risk of data leaks.
Set Groups for Business sharing options

Limit group creation to admins
Allow only admins to create groups. This reduces the risk of data leaks.
Set Groups for Business sharing options

Customize your group access settings
Recommendations:
Allow or disable  members and messages from outside your domain.
Set up message moderation.
Set visibility of groups.
Perform other actions, according to your company policies.
Set who can view, post, and moderate

Disable some access settings for internal groups
The following settings allow anyone on the Internet to join the group, send messages, and view the discussion archives. Disable these settings for internal groups:
Public access
Also grant this access to anyone on the Internet
Also allow anyone on the Internet to post messages 
Assign access levels to a group

Enable spam moderation for your groups
You can have messages sent to the moderation queue with or without notifying moderators, immediately reject spam messages, or allow the messages to be posted without moderation.
Approve or block new posts
Mobile 
Sites (G Suite only) 

Block sharing sites outside the domain
Block users from sharing sites outside the domain to reduce the risk of data leaks. To support a critical business need, you could enable sharing outside the domain. If you do so, display a warning when users share sites outside the domain.
Set Google Sites sharing options | Set sharing options: classic Sites
Vault (Vault only) 

Control, audit, and secure Vault accounts
Make sure accounts with Vault access are carefully controlled and audited.
Understand audits

Treat accounts with Vault access as sensitive
Vault accounts should be treated as elevated access accounts, similar to super admin accounts. Accounts with Vault access should be carefully controlled and audited, and should have 2-Step Verification enforced.
Protect your business with 2-Step Verification | Deploy 2-Step verification


