/*
 * The contents of this file are subject to the terms of the Common Development and
 * Distribution License (the License). You may not use this file except in compliance with the
 * License.
 *
 * You can obtain a copy of the License at legal/CDDLv1.0.txt. See the License for the
 * specific language governing permission and limitations under the License.
 *
 * When distributing Covered Software, include this CDDL Header Notice in each file and include
 * the License file at legal/CDDLv1.0.txt. If applicable, add the following below the CDDL
 * Header, with the fields enclosed by brackets [] replaced by your own identifying
 * information: "Portions copyright [year] [name of copyright owner]".
 *
 * Copyright 2017 ForgeRock AS.
 */


package com.biid.biidAuthNode;

import com.google.inject.assistedinject.Assisted;
import com.iplanet.sso.SSOException;
import com.sun.identity.idm.AMIdentity;
import com.sun.identity.idm.IdRepoException;
import com.sun.identity.shared.debug.Debug;
import org.apache.commons.lang.StringUtils;
import org.forgerock.openam.annotations.sm.Attribute;
import org.forgerock.openam.auth.node.api.*;
import org.forgerock.openam.core.CoreWrapper;

import javax.inject.Inject;

import java.util.Set;

import static org.forgerock.openam.auth.node.api.SharedStateConstants.REALM;
import static org.forgerock.openam.auth.node.api.SharedStateConstants.USERNAME;

/**
 * A node that checks to see if zero-page login headers have specified username and shared key
 * for this request.
 */
@Node.Metadata(outcomeProvider = SingleOutcomeNode.OutcomeProvider.class,
        configClass = BiidAuthNodeInitiator.Config.class)
public class BiidAuthNodeInitiator extends SingleOutcomeNode {

    private final Config config;
    private BiidTransactionService biidTransactionService;
    private final CoreWrapper coreWrapper;
    private final static String DEBUG_FILE = "BiidAuthNodeInitiator";
    protected Debug debug = Debug.getInstance(DEBUG_FILE);

    /**
     * Configuration for the node.
     */
    public interface Config {
        @Attribute(order = 100)
        default String entityKey() {
            return "entityKey";
        }

        @Attribute(order = 200)
        default String appKey() {
            return "appKey";
        }

        @Attribute(order = 300)
        String biidSiteUrl();

        @Attribute(order = 400)
        default String attribute() {
            return "username";
        }
    }


    /**
     * Create the node.
     *
     * @param config The service config.
     * @throws NodeProcessException If the configuration was not valid.
     */
    @Inject
    public BiidAuthNodeInitiator(@Assisted Config config, CoreWrapper coreWrapper) throws NodeProcessException {
        this.config = config;
        this.coreWrapper = coreWrapper;
        try {
            this.biidTransactionService = new BiidTransactionService(config.biidSiteUrl(), config.entityKey(), config.appKey());
        } catch (Exception e) {
            debug.error("[" + DEBUG_FILE + "]: " + "Error setting configs: " + e.getMessage(), e);
        }
    }

    @Override
    public Action process(TreeContext context) throws NodeProcessException {
        AMIdentity userIdentity = coreWrapper.getIdentity(context.sharedState.get(USERNAME).asString(),
                context.sharedState.get(REALM).asString());
        String biidUsername = getUsername(userIdentity);

        debug.message("Starting biid node...");

        if (StringUtils.isEmpty(biidUsername)) {
            throw new NodeProcessException("Username is required for Biid Authentication");
        }
        String idOfTransaction = null;
        try {
            idOfTransaction = biidTransactionService.sendAuthTransaction(biidUsername);
        } catch (Exception e) {
            debug.error("[" + DEBUG_FILE + "]: " + "Error sending transaction for user '" + biidUsername + "': "
                    + e.getMessage(), e);
        }
        return goToNext().replaceSharedState(context.sharedState.copy()
                .add("biid_transaction_id", idOfTransaction)
                .add("biid_entity_key", config.entityKey())
                .add("biid_app_key", config.appKey())
                .add("biid_site_url", config.biidSiteUrl())
        ).build();

    }

    private String getUsername(AMIdentity userIdentity) {
        String username = null;
        try {
            Set idAttrs = userIdentity.getAttribute(config.attribute());
            if (idAttrs == null || idAttrs.isEmpty()) {
                debug.error("[" + DEBUG_FILE + "]: " + "Unable to find iProov user attribute: " + config.attribute());
            } else {
                username = (String) idAttrs.iterator().next();
            }
        } catch (IdRepoException | SSOException e) {
            debug.error("[" + DEBUG_FILE + "]: " + "Error getting attribute " + e.getMessage(), e);
        }
        return username;
    }
}