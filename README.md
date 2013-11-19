Overview
========
This repository is a proof of concept for the protocol which enables password-less authentication and
authorization of user access via mobile devices. The proof of concept is implemented using Erlang and demonstrates
the message exchange and the security features which guard the exchange.

In essence, the protocol enables the participating *targets* (e.g. websites) to authenticate and authorize the accessing users
without requiring them to enter their password. For the users, this allows the user to access the remote targets
without the need to enter password but without a risk of unauthorized access via their logins.

Example by analogy
------------------
The protocol works in a similar fashion to how some banks notify the user about account transactions. They send an SMS
to the verified mobile number letting the user to confirm the transaction. If the user is the one who initiated
the transaction it is easy for them to confirm. On the other hand, if they did not initiate it, they can easily deny
transaction by simply ignoring the message.

Another similar implementation is the Facebook authorization on mobiles. When you click on a link "Login with Facebook"
you may get your mobile Facebook app popup asking you whether you would allow the other party access to you Facebook
profile. The problem with that though is that you are releasing your private information from your Facebook profile
which is not what most people want (but the websites do seek that as it helps them in marketing).

**In contrast**, this solution focuses on authorization in particular - it does not release any information but merely
 confirms your will to access the target.

Protocol
========
The protocol recognises 4 active parties:
- the user (usually represented by a user agent such as a browser)
- the target (what the user is trying to access)
- the trust server (the server that is mediating the communication and has the trust relationship with either party)
- the authenticator (the dedicated agent capable of communicating back to the user for confirmations)

Protocol sequence
-----------------
The protocol consists of a sequence of messages exchanges by the parties in the following order:
<pre>User --1-> Target --2-> Trust server --3-> Authenticator
     &lt;-6-- Target &lt;-5-- Trust server &lt;-4--
</pre>
1. The protocol is initiated by the user who accesses a compliant target via a user's agent (usually a browser).
   The user provides only his user ID (e.g. username, email) - no password is required.
2. The target requests confirmation from the trust server for access for the specified user.
3. The trust server communicates this request to the dedicated authenticator (e.g. a mobile app on user's mobile device)
4. The user receives UI prompt to confirm access with simple Yes/No
5. If the user chooses Yes within certain timeout the access to the target is then granted.
   The reply is communicated back to the trust server, and then to the target
6. The user's agent is granted or denied access to the target

**Note**: Nowhere in this exchange the user is required to enter password, or expose his private information such as email or name.

Running the test
----------------
Execute "app:test_app()" from Erlang shell. The only parameter is either "Y" or "N" (a string) which represent user's reply to the UI prompt:

    app:test_app("Y").

Discussion
==========
The key aspect of the protocol is the usage of trust relationships between involved parties.

Similar to OAuth, there is a trust triangle between the user, the target he accesses, and the federating authority.
Instead of web redirect from target to federating authority, this protocol introduces another leg which relies on the trust between the federating authority
and the mobile application. In turn, this also relies on the trust between the user and the mobile application.

While complicating the design, the last two steps allow to avoid web redirects (which require login and session cache somewhere in a browser)
which is replaced with a "mobile redirect". The callback from the redirect (which in OAuth is usually a call back into the target) is a message
back to the trust authority, and then back to the target.

License
=======
GPL v3