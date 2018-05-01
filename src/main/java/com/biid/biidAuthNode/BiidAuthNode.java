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
import com.sun.identity.shared.debug.Debug;
import org.apache.commons.lang.StringUtils;
import org.forgerock.guava.common.collect.ImmutableList;
import org.forgerock.json.JsonValue;
import org.forgerock.openam.annotations.sm.Attribute;
import org.forgerock.openam.auth.node.api.*;
import org.forgerock.openam.authentication.callbacks.PollingWaitCallback;
import org.forgerock.openam.core.CoreWrapper;
import org.forgerock.openam.utils.Time;
import org.forgerock.util.i18n.PreferredLocales;

import javax.inject.Inject;

import java.util.List;
import java.util.Optional;
import java.util.ResourceBundle;

import static java.lang.Thread.sleep;
import static org.forgerock.openam.auth.node.api.Action.send;
import static org.forgerock.openam.auth.node.api.SharedStateConstants.USERNAME;

/**
 * A node that checks to see if zero-page login headers have specified username and shared key
 * for this request.
 */
@Node.Metadata(outcomeProvider = BiidAuthNode.OutcomeProvider.class,
        configClass = BiidAuthNode.Config.class)
public class BiidAuthNode implements Node {

    private final Config config;
    private BiidTransactionService biidTransactionService;
    private final CoreWrapper coreWrapper;
    private final static String DEBUG_FILE = "BiidAuthNode";
    protected Debug debug = Debug.getInstance(DEBUG_FILE);
    private final static String TRUE_OUTCOME_ID = "true";
    private final static String FALSE_OUTCOME_ID = "false";
    private final static String POLLING_TIME = "5000";//in millisec


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
        default int timeout() {
            return 120_000;
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
        try {
            this.biidTransactionService = new BiidTransactionService(config.biidSiteUrl(), config.entityKey(), config.appKey());
        } catch (Exception e) {
            debug.error("[" + DEBUG_FILE + "]: " + "Error setting configs: " + e.getMessage(), e);
        }
    }

    @Override
    public Action process(TreeContext context) throws NodeProcessException {
        String username = context.sharedState.get(USERNAME).asString();
        // Either initial call to this node, or a revisit from a polling callback?
        if (!context.hasCallbacks()) {
            debug.message("Starting biid node...");

            if (StringUtils.isEmpty(username)) {
                return goTo(false).build();
            }

            try {
                String idOfTransaction = biidTransactionService.sendAuthTransaction(username);
                return send(new PollingWaitCallback(POLLING_TIME)).replaceSharedState(context.sharedState.copy()
                        .add("biid_start", Time.currentTimeMillis())
                        .add("biid_transaction_id", idOfTransaction)).build();
            } catch (Exception e) {
                debug.error("[" + DEBUG_FILE + "]: " + "Error locating user '{}' ", e);
            }
        } else {
            Optional<PollingWaitCallback> answer = context.getCallback(PollingWaitCallback.class);
            if (answer.isPresent()) {
                String idOfTransaction = context.sharedState.get("biid_transaction_id").asString();
                // Check status of biid transaction
                String status = null;
                try {
                    status = biidTransactionService.getTransactionStatusById(idOfTransaction, username);
                } catch (Exception e) {
                    debug.error("[" + DEBUG_FILE + "]: " + "Error locating user '{}' ", e);
                    return goTo(false).build();
                }
                if (status.equals("SUCCESSFUL")) {
                    goTo(true).build();
                } else if (status.equals("PENDING") &&
                        (Time.currentTimeMillis() - context.sharedState.get("biid_start").asLong()) < config.timeout()) {
                    return send(new PollingWaitCallback(POLLING_TIME)).build();
                }
            }
        }
        return goTo(false).build();
    }

    private Action.ActionBuilder goTo(boolean outcome) {
        return Action.goTo(outcome ? TRUE_OUTCOME_ID : FALSE_OUTCOME_ID);
    }

    static final class OutcomeProvider implements org.forgerock.openam.auth.node.api.OutcomeProvider {
        private static final String BUNDLE = BiidAuthNode.class.getName().replace(".", "/");

        @Override
        public List<Outcome> getOutcomes(PreferredLocales locales, JsonValue nodeAttributes) {
            ResourceBundle bundle = locales.getBundleInPreferredLocale(BUNDLE, OutcomeProvider.class.getClassLoader());
            return ImmutableList.of(
                    new Outcome(TRUE_OUTCOME_ID, bundle.getString("trueOutcome")),
                    new Outcome(FALSE_OUTCOME_ID, bundle.getString("falseOutcome")));
        }
    }
}