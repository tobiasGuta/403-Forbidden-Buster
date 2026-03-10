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
        api.extension().setName("403 Forbidden Buster");

        SwingUtilities.invokeLater(() -> {
            ui = new BusterUI(api);
            api.userInterface().registerSuiteTab("403 Buster", ui.getUI());
        });

        api.userInterface().registerContextMenuItemsProvider(this);

        // Proper unload handler — shuts down all threads
        api.extension().registerUnloadingHandler(() -> {
            if (ui != null) {
                ui.getEngine().stop();
                ui.saveSettings();
            }
        });

        api.logging().logToOutput("403 Forbidden Buster (Modular v7.0) Loaded.");
    }

    @Override
    public List<Component> provideMenuItems(ContextMenuEvent event) {
        List<HttpRequestResponse> selected = event.selectedRequestResponses();
        if (selected == null || selected.isEmpty()) return null;

        JMenuItem bypassItem = new JMenuItem("Bypass 403 Forbidden");
        bypassItem.addActionListener(e -> {
            if (ui != null) {
                ui.setTarget(selected.get(0));
            }
        });

        List<Component> menuList = new ArrayList<>();
        menuList.add(bypassItem);
        return menuList;
    }
}
