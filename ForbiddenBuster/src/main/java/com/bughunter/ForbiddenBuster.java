package com.bughunter;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;

import javax.swing.*;
import java.awt.*;
import java.util.ArrayList;
import java.util.List;

/**
 * 403 Forbidden Buster — Burp Suite Extension
 * Entry point: registers UI, context menu, and unload handler.
 */
public class ForbiddenBuster implements BurpExtension, ContextMenuItemsProvider {

    private MontoyaApi api;
    private BusterUI ui;

    @Override
    public void initialize(MontoyaApi api) {
        this.api = api;
        ActiveMethodsRegistry.reset();
        api.extension().setName("403 Forbidden Buster");

        SwingUtilities.invokeLater(() -> {
            ui = new BusterUI(api);
            api.userInterface().registerSuiteTab("403 Buster", ui.getUI());
        });

        api.userInterface().registerContextMenuItemsProvider(this);

        // Proper unload handler — shuts down all threads and clears active mode.
        api.extension().registerUnloadingHandler(() -> {
            ActiveMethodsRegistry.reset();
            if (ui != null) {
                ui.getEngine().stop();
                ui.saveSettings();
            }
        });

        api.logging().logToOutput("403 Forbidden Buster v8 Loaded — Safe Mode is the default.");
    }

    @Override
    public List<Component> provideMenuItems(ContextMenuEvent event) {
        List<HttpRequestResponse> selected = event.selectedRequestResponses();
        if (selected == null || selected.isEmpty()) return null;

        HttpRequestResponse target = selected.get(0);

        JMenuItem safeItem = new JMenuItem("Bypass 403 Forbidden (Safe Mode)");
        safeItem.addActionListener(e -> {
            ActiveMethodsRegistry.configure(false, target.request().method());
            if (ui != null) {
                ui.setTarget(target);
            }
            api.logging().logToOutput(
                    "[403 Buster] Safe Mode selected for " + target.request().method()
                            + " " + target.request().path()
                            + ". Automatic requests are limited to GET/HEAD/OPTIONS families; "
                            + "Method Tampering and mixed Header Injection are gated."
            );
        });

        JMenuItem activeItem = new JMenuItem("Bypass 403 Forbidden (Active Methods...)");
        activeItem.addActionListener(e -> {
            int answer = JOptionPane.showConfirmDialog(
                    null,
                    "Active Methods can transmit non-GET/HEAD/OPTIONS requests, including "
                            + "POST, PUT, PATCH, DELETE, TRACE, CONNECT, and method-override payloads.\n\n"
                            + "These requests may change server-side state. Continue only on an authorized target "
                            + "where you understand the possible side effects.",
                    "Enable Active Methods for this target?",
                    JOptionPane.YES_NO_OPTION,
                    JOptionPane.WARNING_MESSAGE
            );

            if (answer != JOptionPane.YES_OPTION) {
                ActiveMethodsRegistry.configure(false, target.request().method());
                api.logging().logToOutput("[403 Buster] Active Methods opt-in cancelled; Safe Mode retained.");
                return;
            }

            ActiveMethodsRegistry.configure(true, target.request().method());
            if (ui != null) {
                ui.setTarget(target);
            }
            api.logging().logToOutput(
                    "[403 Buster] ACTIVE METHODS enabled for this target only: "
                            + target.request().method() + " " + target.request().path()
            );
        });

        List<Component> menuList = new ArrayList<>();
        menuList.add(safeItem);
        menuList.add(activeItem);
        return menuList;
    }
}
