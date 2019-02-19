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

import com.google.common.collect.ImmutableList;
import com.google.inject.assistedinject.Assisted;
import com.sun.identity.shared.debug.Debug;
import org.forgerock.json.JsonValue;
import org.forgerock.openam.auth.node.api.*;
import org.forgerock.openam.core.CoreWrapper;
import org.forgerock.util.i18n.PreferredLocales;

import javax.inject.Inject;

import java.util.List;
import java.util.ResourceBundle;

/**
 * A node that checks to see if zero-page login headers have specified username and shared key
 * for this request.
 */
@Node.Metadata(outcomeProvider = BiidAuthNodeDecision.OutcomeProvider.class,
        configClass = BiidAuthNodeDecision.Config.class)
public class BiidAuthNodeDecision implements Node {

    private final Config config;
    private final CoreWrapper coreWrapper;
    private final static String DEBUG_FILE = "BiidAuthNodeDecision";
    protected Debug debug = Debug.getInstance(DEBUG_FILE);
    private final static String TRUE_OUTCOME_ID = "true";
    private final static String FALSE_OUTCOME_ID = "false";
    private final static String UNANSWERED_OUTCOME_ID = "none";


    /**
     * Configuration for the node.
     */
    public interface Config {
    }


    /**
     * Create the node.
     *
     * @param config The service config.
     * @throws NodeProcessException If the configuration was not valid.
     */
    @Inject
    public BiidAuthNodeDecision(@Assisted Config config, CoreWrapper coreWrapper) throws NodeProcessException {
        this.config = config;
        this.coreWrapper = coreWrapper;
    }

    @Override
    public Action process(TreeContext context) throws NodeProcessException {
        // Either initial call to this node, or a revisit from a polling callback?
        debug.message("Starting biid decision node...");

        String idOfTransaction = context.sharedState.get("biid_transaction_id").asString();
        String biidSiteUrl = context.sharedState.get("biid_site_url").asString();
        String entityKey = context.sharedState.get("biid_entity_key").asString();
        String appKey = context.sharedState.get("biid_app_key").asString();

        // Check status of biid transaction
        String status = null;
        try {
            status = new BiidTransactionService(biidSiteUrl, entityKey, appKey).getTransactionStatusById(idOfTransaction);
        } catch (Exception e) {
            debug.error("[" + DEBUG_FILE + "]: " + "Error getting status for transaction '" +
                    idOfTransaction + "': " + e.getMessage(), e);
            return goTo(FALSE_OUTCOME_ID).build();
        }
        if (status.equals("SUCCESSFUL")) {
            return goTo(TRUE_OUTCOME_ID).build();
        } else if (status.equals("REJECTED")) {
            return goTo(FALSE_OUTCOME_ID).build();
        }
        return goTo(UNANSWERED_OUTCOME_ID).build();
    }

    private Action.ActionBuilder goTo(String outcome) {
        return Action.goTo(outcome);
    }

    static final class OutcomeProvider implements org.forgerock.openam.auth.node.api.OutcomeProvider {
        private static final String BUNDLE = BiidAuthNodeDecision.class.getName().replace(".", "/");

        @Override
        public List<Outcome> getOutcomes(PreferredLocales locales, JsonValue nodeAttributes) {
            ResourceBundle bundle = locales.getBundleInPreferredLocale(BUNDLE, OutcomeProvider.class.getClassLoader());
            return ImmutableList.of(
                    new Outcome(TRUE_OUTCOME_ID, bundle.getString("trueOutcome")),
                    new Outcome(FALSE_OUTCOME_ID, bundle.getString("falseOutcome")),
                    new Outcome(UNANSWERED_OUTCOME_ID, bundle.getString("noneOutcome")));
        }
    }
}