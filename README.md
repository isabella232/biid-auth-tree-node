![image alt text](/images/biid_logo.png)

# Biid Authentication Node

The Biid Authentication Node allows ForgeRock users to integrate their AM instance with the Biid platform.

NB These instructions assume that an AM 5.5+ instance is already running with users configured.

## Installation

The following steps detail how to install the node:

1. Download the jar file from [here](biidAuthNode-1.0.0-no-deps.jar).
2. Copy the **biidAuthNode-1.0.0-no-deps.jar** file to the following path on the server: `/path/to/tomcat/webapps/openam/WEB-INF/lib`
3. Restart AM.
4. Login to the Biid Back Office, select the `Entity` and click Edit to view it's details. Copy the **Entity Key** value and save it for Step 10.

![image alt text](/images/biid_entity_key.png)

5. Still in the Biid back office, select and edit the `Entity App` to be used. Copy the **App API Key** value and again save it for Step 10.

![image alt text](/images/biid_app_key.png)

6. Login into AM console as an administrator and go to `Realms > Top Level Real > Authentication > Trees`.
7. Click on **Add Tree** button. Name the tree `biid` and click **Create**.

![image](/images/create_tree.png)

8. Add 3 tree nodes: Start, Username Collector, and Biid Authentication Initiator.
9. Connect them as shown in the image below.

![image](/images/biid_auth_init.png)

10. Select the **Biid Authentication Initiator** node. Enter values for the **Entity Key** (saved in Step 4) and the **App API Key** (saved in step 5). Set the **Biid API Server URL** to your biid server location NB the URL should be similar to the following `https://api.test-biid.com`. Set the **Attribute** to be used for the Biid username. Setting it to the default value of `sn` will mean that the Forgerock username will be used. 
11. Add 5 nodes: Polling Wait Node, Biid Authentication Decision, Retry Decision Limit, Failure and Success. Connect them as shown in the image below. 
12. Select the Polling Wait Node and set **Seconds To Wait** to 15.
13. Select the Retry Decision Limit and set the **Retry Limit** to 4.

![image](/images/biid_auth_flow.png)

14. Save changes.
15. You can now test the Biid authentication tree by accessing the following URL in your browser : `https://YOUR_AM_SERVER HERE/openam/XUI/?realm=/#login/&service=biid`.</br>
16. When prompted enter the username and hit return. An authentication request will be sent to the biid app through the AM authentication tree. Biid will then verify the username and keys and if everything is correctly configured, an authentication request will appear on the device.

![image](/images/demo_auth.png)
