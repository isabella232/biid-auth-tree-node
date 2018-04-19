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

import com.biid.api.service.integrator.model.IdentityTransactionItem;
import com.google.inject.assistedinject.Assisted;
import com.sun.identity.shared.debug.Debug;
import org.apache.commons.lang.StringUtils;
import org.forgerock.openam.annotations.sm.Attribute;
import org.forgerock.openam.auth.node.api.*;
import org.forgerock.openam.core.CoreWrapper;

import javax.inject.Inject;

import static java.lang.Thread.sleep;
import static org.forgerock.openam.auth.node.api.SharedStateConstants.USERNAME;

/**
 * A node that checks to see if zero-page login headers have specified username and shared key
 * for this request.
 */
@Node.Metadata(outcomeProvider = AbstractDecisionNode.OutcomeProvider.class,
        configClass = BiidAuthNode.Config.class)
public class BiidAuthNode extends AbstractDecisionNode {

    private final Config config;
    private final BiidTransactionService biidTransactionService = new BiidTransactionService();
    private final CoreWrapper coreWrapper;
    private final static String DEBUG_FILE = "BiidAuthNode";
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

    }


    /**
     * Create the node.
     *
     * @param config The service config.
     * @throws NodeProcessException If the configuration was not valid.
     */
    @Inject
    public BiidAuthNode(@Assisted Config config, CoreWrapper coreWrapper) throws NodeProcessException {
        this.config = config;
        this.coreWrapper = coreWrapper;
    }

    @Override
    public Action process(TreeContext context) throws NodeProcessException {
        String username = context.sharedState.get(USERNAME).asString();
        if (StringUtils.isEmpty(username)) {
            return goTo(false).build();
        }
        String entityKey = config.entityKey();
        String appKey = config.appKey();

        try {
            String idOfTransaction = biidTransactionService.sendAuthTransaction(username, entityKey, appKey);
            int counter = 0;
            String status = biidTransactionService.getTransactionStatusById(idOfTransaction, entityKey, appKey);
            //2 minutres to verify
            while (status.equals(IdentityTransactionItem.StatusEnum.PENDING.getValue()) && counter < 12) {
                sleep(10_000);
                counter++;
                status = biidTransactionService.getTransactionStatusById(idOfTransaction, entityKey, appKey);
            }
            if (status.equals(IdentityTransactionItem.StatusEnum.SUCCESSFUL.getValue())) {
                goTo(true).build();
            }
        } catch (Exception e) {
            debug.error("[" + DEBUG_FILE + "]: " + "Error locating user '{}' ", e);
        }
        return goTo(false).build();
    }
}