![image alt text](/images/biid_logo.png)

# Biid Authentication Node

The Biid Authentication Node allows ForgeRock users to integrate their AM instance to the Biid platform.
This document assumes that you already have an AM 5.5+ instance running with users configured.

## Installation

Follow this steps in order to install the node:

1. Download the jar file from [here](biidAuthNode-1.0.0-no-deps.jar).
2. Copy the **biidAuthNode-1.0.0-no-deps.jar** file on your server: `/path/to/tomcat/webapps/openam/WEB-INF/lib`
3. Restart AM.
4. Login into Biid Back Office and open your `Entity` details. Copy the **Entity Key** value save it for later.

![image alt text](/images/biid_entity_key.png)

5. Stay in Biid Back Office and open `Entity App` that is going to be used. Copy the **App API Key** value save it for later.

![image alt text](/images/biid_app_key.png)

6. Login into AM console as an administrator and go to `Realms > Top Level Real > Authentication > Trees`.
7. Click on **Add Tree** button. Name the tree `biid` and click **Create**.

![image](/images/create_tree.png)

8. Add 3 tree nodes: Start, Username Collector, Biid Authentication Initiator.
9. Connect them as shown in the image below.

![image](/images/biid_auth_init.png)

10. Select the **Biid Authentication Initiator** node and set the **Entity Key** from step 4, **App API Key** from step 5. Set **Biid API Server URL** based on your biid server location - it should be like `https://api.integration-biid.com`. Set **Attribute** that should be taken from Forgerock user as biid user, default is same username `sn`.
11. Add 5 nodes: Polling Wait Node, Biid Authentication Decision, Retry Decision Limit, Failure and Success.
12. Select the Polling Wait Node and set **Seconds To Wait** to 15.
13. Select the Retry Decision Limit and set the **Retry Limit** to 4.

![image](/images/biid_auth_flow.png)

14. Save changes.
15. You can test the Biid authentication tree by accessing this URL in your browser `https://YOUR_AM_SERVER HERE/openam/XUI/?realm=/#login/&service=biid`.</br>
16. Enter your username and hit enter. An authentication request will be send to biid app through the AM authentication tree. Biid will verify you username and keys. If everything is correct you should get an authentication request on your phone.

![image](/images/demo_auth.png)
