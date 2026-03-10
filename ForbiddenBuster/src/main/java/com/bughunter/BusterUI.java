package com.bughunter;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.persistence.Preferences;
import burp.api.montoya.ui.editor.EditorOptions;
import burp.api.montoya.ui.editor.HttpRequestEditor;
import burp.api.montoya.ui.editor.HttpResponseEditor;

import javax.swing.*;
import javax.swing.border.TitledBorder;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.DefaultTableCellRenderer;
import java.awt.*;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * Complete Swing UI for 403 Forbidden Buster.
 * Three tabs: Monitor, Configuration, About.
 * Color-coded results, native Burp editors, CSV export, attack controls.
 */
public class BusterUI implements AttackEngine.AttackListener {

    // --- Color Constants ---
    private static final Color BYPASS_GREEN = new Color(144, 238, 144);
    private static final Color REDIRECT_ORANGE = new Color(255, 218, 185);
    private static final Color ERROR_RED = new Color(255, 182, 193);
    private static final Color ANOMALY_YELLOW = new Color(255, 255, 200);
    private static final Color INTERESTING_BOLD_GREEN = new Color(76, 175, 80);
    private static final Color ACCENT = new Color(0xFF, 0x66, 0x33);
    private static final Font SECTION_TITLE = new Font("SansSerif", Font.BOLD, 11);

    // --- Persistence Keys ---
    private static final String KEY_IPS = "buster.ips";
    private static final String KEY_PATHS = "buster.paths";
    private static final String KEY_DELAY = "buster.delay";
    private static final String KEY_THREADS = "buster.threads";
    private static final String KEY_PREFIX = "buster.chk.";

    // --- Defaults ---
    static final String DEFAULT_IPS =
            "127.0.0.1\nlocalhost\n0.0.0.0\n192.168.0.1\n10.0.0.1\n::1\n127.0.0.2\n" +
            "192.168.1.1\n172.16.0.1\n10.10.10.1\n2130706433\n0x7f000001\n017700000001";
    static final String DEFAULT_PATHS =
            "/admin\n/dashboard\n/login\n/panel\n/console\n/manager\n/administrator\n" +
            "/private\n/internal\n/sysadmin\n/auth\n/api\n/swagger\n/graphql\n/debug\n" +
            "/actuator\n/health\n/status\n/config\n/settings\n/backup";
    private static final int DEFAULT_DELAY = 50;
    private static final int DEFAULT_THREADS = 5;

    private final MontoyaApi api;
    private final Preferences preferences;
    private final AttackEngine engine;
    private final ResultTableModel tableModel = new ResultTableModel();

    // UI Root
    private JTabbedPane mainTabs;

    // Monitor tab
    private HttpRequestEditor requestViewer;
    private HttpResponseEditor responseViewer;
    private JButton runBtn, pauseBtn, stopBtn, clearBtn, exportBtn;
    private JProgressBar progressBar;
    private JLabel statusLabel;
    private JLabel targetLabel;

    // Configuration tab
    private JTextArea ipConfigArea;
    private JTextArea pathConfigArea;
    private JSlider delaySlider;
    private JLabel delayLabel;
    private JSpinner threadSpinner;

    // Toggles (attack techniques)
    private JCheckBox chkIpSpoofing, chkPathSwapping, chkHopByHop, chkPathObf;
    private JCheckBox chkMethods, chkProtocolDowngrade, chkSuffixes;
    private JCheckBox chkHide404, chkHide403;
    private JCheckBox chkCaseSwitch, chkUnicode, chkBackslash, chkHeaderInjection;

    // State
    private volatile HttpRequestResponse targetRequest;

    public BusterUI(MontoyaApi api) {
        this.api = api;
        this.preferences = api.persistence().preferences();
        this.engine = new AttackEngine(api, this);
        buildUI();
        loadSettings();
    }

    public JComponent getUI() { return mainTabs; }
    public AttackEngine getEngine() { return engine; }

    public void setTarget(HttpRequestResponse target) {
        this.targetRequest = target;
        String host = target.httpService().host();
        String path = target.request().path();
        short status = target.response().statusCode();
        SwingUtilities.invokeLater(() -> {
            targetLabel.setText("Target: " + host + path + " [" + status + "]");
            targetLabel.setForeground(ACCENT);
            runBtn.setEnabled(!engine.isRunning());
        });
        api.logging().logToOutput("[403 Buster] Target set: " + host + path);
    }

    public void saveSettings() {
        preferences.setString(KEY_IPS, ipConfigArea.getText());
        preferences.setString(KEY_PATHS, pathConfigArea.getText());
        preferences.setString(KEY_DELAY, String.valueOf(delaySlider.getValue()));
        preferences.setString(KEY_THREADS, String.valueOf(threadSpinner.getValue()));

        preferences.setBoolean(KEY_PREFIX + "ipSpoofing", chkIpSpoofing.isSelected());
        preferences.setBoolean(KEY_PREFIX + "pathSwapping", chkPathSwapping.isSelected());
        preferences.setBoolean(KEY_PREFIX + "hopByHop", chkHopByHop.isSelected());
        preferences.setBoolean(KEY_PREFIX + "pathObf", chkPathObf.isSelected());
        preferences.setBoolean(KEY_PREFIX + "methods", chkMethods.isSelected());
        preferences.setBoolean(KEY_PREFIX + "protocol", chkProtocolDowngrade.isSelected());
        preferences.setBoolean(KEY_PREFIX + "suffixes", chkSuffixes.isSelected());
        preferences.setBoolean(KEY_PREFIX + "hide404", chkHide404.isSelected());
        preferences.setBoolean(KEY_PREFIX + "hide403", chkHide403.isSelected());
        preferences.setBoolean(KEY_PREFIX + "caseSwitch", chkCaseSwitch.isSelected());
        preferences.setBoolean(KEY_PREFIX + "unicode", chkUnicode.isSelected());
        preferences.setBoolean(KEY_PREFIX + "backslash", chkBackslash.isSelected());
        preferences.setBoolean(KEY_PREFIX + "headerInj", chkHeaderInjection.isSelected());
    }

    // =========================================================================
    //  UI Construction
    // =========================================================================

    private void buildUI() {
        mainTabs = new JTabbedPane();
        mainTabs.addTab("Monitor", buildMonitorTab());
        mainTabs.addTab("Configuration", buildConfigTab());
    }

    // -------------------------------------------------------------------------
    //  Tab 1: Monitor
    // -------------------------------------------------------------------------
    private JComponent buildMonitorTab() {
        JPanel panel = new JPanel(new BorderLayout(0, 4));
        panel.setBorder(BorderFactory.createEmptyBorder(6, 6, 6, 6));

        // Top: Target + Controls
        panel.add(buildControlBar(), BorderLayout.NORTH);

        // Center: Table + Editors split
        JTable table = new JTable(tableModel);
        table.setFont(new Font("SansSerif", Font.PLAIN, 12));
        table.setRowHeight(22);
        table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        table.setAutoCreateRowSorter(true);
        table.setShowHorizontalLines(true);
        table.setShowVerticalLines(false);
        table.setGridColor(new Color(230, 230, 230));

        // Column widths
        int[] widths = {40, 60, 200, 250, 140, 55, 60};
        for (int i = 0; i < widths.length && i < table.getColumnCount(); i++) {
            table.getColumnModel().getColumn(i).setPreferredWidth(widths[i]);
        }
        table.getColumnModel().getColumn(0).setMaxWidth(50);  // ID
        table.getColumnModel().getColumn(1).setMaxWidth(80);  // Method
        table.getColumnModel().getColumn(5).setMaxWidth(70);  // Status
        table.getColumnModel().getColumn(6).setMaxWidth(80);  // Length

        // Color renderer
        StatusColorRenderer renderer = new StatusColorRenderer();
        for (int i = 0; i < table.getColumnCount(); i++) {
            table.getColumnModel().getColumn(i).setCellRenderer(renderer);
        }

        // Native Burp editors
        requestViewer = api.userInterface().createHttpRequestEditor(EditorOptions.READ_ONLY);
        responseViewer = api.userInterface().createHttpResponseEditor(EditorOptions.READ_ONLY);

        table.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                int row = table.getSelectedRow();
                if (row != -1) {
                    int modelRow = table.convertRowIndexToModel(row);
                    BypassResult result = tableModel.getResult(modelRow);
                    requestViewer.setRequest(result.getRequestResponse().request());
                    responseViewer.setResponse(result.getRequestResponse().response());
                } else {
                    requestViewer.setRequest(null);
                    responseViewer.setResponse(null);
                }
            }
        });

        // Context menu on table
        JPopupMenu popup = new JPopupMenu();
        JMenuItem deleteItem = new JMenuItem("Delete Row");
        JMenuItem clearItem = new JMenuItem("Clear All Results");
        deleteItem.addActionListener(e -> {
            int row = table.getSelectedRow();
            if (row != -1) tableModel.removeRow(table.convertRowIndexToModel(row));
        });
        clearItem.addActionListener(e -> clearResults());
        popup.add(deleteItem);
        popup.addSeparator();
        popup.add(clearItem);
        table.setComponentPopupMenu(popup);

        JScrollPane tableScroll = new JScrollPane(table);
        tableScroll.setBorder(BorderFactory.createTitledBorder(
                BorderFactory.createLineBorder(new Color(180, 180, 180)),
                " Results ", TitledBorder.LEFT, TitledBorder.TOP, SECTION_TITLE));

        JTabbedPane reqTabs = new JTabbedPane();
        reqTabs.addTab("Request", requestViewer.uiComponent());
        JTabbedPane resTabs = new JTabbedPane();
        resTabs.addTab("Response", responseViewer.uiComponent());

        JSplitPane editorSplit = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT,
                reqTabs, resTabs);
        editorSplit.setResizeWeight(0.5);

        JSplitPane mainSplit = new JSplitPane(JSplitPane.VERTICAL_SPLIT,
                tableScroll, editorSplit);
        mainSplit.setResizeWeight(0.4);

        panel.add(mainSplit, BorderLayout.CENTER);
        return panel;
    }

    private JPanel buildControlBar() {
        JPanel bar = new JPanel(new BorderLayout(0, 4));

        // Row 1: Target label
        targetLabel = new JLabel("No target set — right-click a request and choose \"Bypass 403 Forbidden\"");
        targetLabel.setFont(new Font("SansSerif", Font.BOLD, 12));
        targetLabel.setForeground(Color.GRAY);
        targetLabel.setBorder(BorderFactory.createEmptyBorder(2, 4, 4, 0));

        // Row 2: Buttons
        JPanel btnPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 2));

        runBtn = styledButton("Run Attack", new Color(46, 125, 50));
        runBtn.setEnabled(false);
        runBtn.addActionListener(e -> startAttack());

        pauseBtn = styledButton("Pause", new Color(245, 124, 0));
        pauseBtn.setEnabled(false);
        pauseBtn.addActionListener(e -> togglePause());

        stopBtn = styledButton("Stop", new Color(198, 40, 40));
        stopBtn.setEnabled(false);
        stopBtn.addActionListener(e -> stopAttack());

        clearBtn = new JButton("Clear Results");
        clearBtn.addActionListener(e -> clearResults());

        exportBtn = new JButton("Export CSV");
        exportBtn.addActionListener(e -> exportCSV());

        statusLabel = new JLabel("Ready");
        statusLabel.setFont(new Font("SansSerif", Font.ITALIC, 11));
        statusLabel.setForeground(Color.GRAY);

        btnPanel.add(runBtn);
        btnPanel.add(pauseBtn);
        btnPanel.add(stopBtn);
        btnPanel.add(Box.createHorizontalStrut(16));
        btnPanel.add(clearBtn);
        btnPanel.add(exportBtn);
        btnPanel.add(Box.createHorizontalStrut(16));
        btnPanel.add(statusLabel);

        // Row 3: Progress bar
        progressBar = new JProgressBar(0, 100);
        progressBar.setStringPainted(true);
        progressBar.setString("Ready");
        progressBar.setPreferredSize(new Dimension(0, 20));

        bar.add(targetLabel, BorderLayout.NORTH);
        bar.add(btnPanel, BorderLayout.CENTER);
        bar.add(progressBar, BorderLayout.SOUTH);
        return bar;
    }

    private JButton styledButton(String text, Color bg) {
        JButton btn = new JButton(text);
        btn.setBackground(bg);
        btn.setForeground(Color.WHITE);
        btn.setFocusPainted(false);
        btn.setFont(new Font("SansSerif", Font.BOLD, 11));
        btn.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(bg.darker(), 1),
                BorderFactory.createEmptyBorder(4, 12, 4, 12)
        ));
        btn.setOpaque(true);
        return btn;
    }

    // -------------------------------------------------------------------------
    //  Tab 2: Configuration
    // -------------------------------------------------------------------------
    private JComponent buildConfigTab() {
        JPanel panel = new JPanel(new BorderLayout(8, 8));
        panel.setBorder(BorderFactory.createEmptyBorder(8, 8, 8, 8));

        // Left side: Toggles + Settings
        JPanel leftPanel = new JPanel();
        leftPanel.setLayout(new BoxLayout(leftPanel, BoxLayout.Y_AXIS));
        leftPanel.add(buildTogglesPanel());
        leftPanel.add(Box.createVerticalStrut(8));
        leftPanel.add(buildScanSettingsPanel());
        leftPanel.add(Box.createVerticalGlue());

        // Right side: IP List + Path List
        JPanel rightPanel = new JPanel();
        rightPanel.setLayout(new BoxLayout(rightPanel, BoxLayout.Y_AXIS));
        rightPanel.add(buildIPPanel());
        rightPanel.add(Box.createVerticalStrut(6));
        rightPanel.add(buildPathPanel());

        JSplitPane configSplit = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, leftPanel, rightPanel);
        configSplit.setResizeWeight(0.4);

        // Save button at the bottom
        JButton saveBtn = new JButton("Save Configuration");
        saveBtn.setFont(new Font("SansSerif", Font.BOLD, 12));
        saveBtn.addActionListener(e -> {
            saveSettings();
            JOptionPane.showMessageDialog(panel, "Configuration saved.",
                    "403 Buster", JOptionPane.INFORMATION_MESSAGE);
        });

        JPanel bottomBar = new JPanel(new FlowLayout(FlowLayout.CENTER));
        bottomBar.add(saveBtn);

        panel.add(configSplit, BorderLayout.CENTER);
        panel.add(bottomBar, BorderLayout.SOUTH);
        return panel;
    }

    private JPanel buildTogglesPanel() {
        JPanel panel = new JPanel(new GridBagLayout());
        panel.setBorder(BorderFactory.createTitledBorder(
                BorderFactory.createLineBorder(ACCENT),
                " Attack Techniques ", TitledBorder.LEFT, TitledBorder.TOP, SECTION_TITLE, ACCENT));

        GridBagConstraints g = new GridBagConstraints();
        g.anchor = GridBagConstraints.WEST;
        g.insets = new Insets(3, 8, 3, 8);
        g.fill = GridBagConstraints.HORIZONTAL;

        chkIpSpoofing = new JCheckBox("IP Spoofing (Headers)");
        chkPathSwapping = new JCheckBox("Path Swapping (X-Original-URL)");
        chkHopByHop = new JCheckBox("Hop-By-Hop Header Abuse");
        chkPathObf = new JCheckBox("Path Obfuscation");
        chkMethods = new JCheckBox("Method Tampering & Overrides");
        chkProtocolDowngrade = new JCheckBox("Protocol Downgrade");
        chkSuffixes = new JCheckBox("Suffix Attacks (.json, ?, ;)");
        chkCaseSwitch = new JCheckBox("Case Switching");
        chkUnicode = new JCheckBox("Unicode Normalization");
        chkBackslash = new JCheckBox("Backslash Bypass (IIS/Tomcat)");
        chkHeaderInjection = new JCheckBox("Header Injection (Proto/Port/Host)");

        chkHide404 = new JCheckBox("Hide 404 Responses");
        chkHide403 = new JCheckBox("Hide 403 Responses");

        // Layout: 2 columns
        JCheckBox[][] rows = {
                {chkIpSpoofing, chkPathObf},
                {chkPathSwapping, chkMethods},
                {chkHopByHop, chkProtocolDowngrade},
                {chkSuffixes, chkCaseSwitch},
                {chkUnicode, chkBackslash},
                {chkHeaderInjection, null},
        };

        for (int row = 0; row < rows.length; row++) {
            g.gridy = row;
            g.gridx = 0;
            panel.add(rows[row][0], g);
            if (rows[row][1] != null) {
                g.gridx = 1;
                panel.add(rows[row][1], g);
            }
        }

        // Separator before filter controls
        g.gridy = rows.length;
        g.gridx = 0;
        g.gridwidth = 2;
        panel.add(new JSeparator(), g);
        g.gridwidth = 1;

        g.gridy = rows.length + 1;
        g.gridx = 0;
        panel.add(chkHide404, g);
        g.gridx = 1;
        panel.add(chkHide403, g);

        return panel;
    }

    private JPanel buildScanSettingsPanel() {
        JPanel panel = new JPanel(new GridBagLayout());
        panel.setBorder(BorderFactory.createTitledBorder(
                BorderFactory.createLineBorder(new Color(180, 180, 180)),
                " Scan Settings ", TitledBorder.LEFT, TitledBorder.TOP, SECTION_TITLE));

        GridBagConstraints g = new GridBagConstraints();
        g.anchor = GridBagConstraints.WEST;
        g.insets = new Insets(4, 8, 4, 8);

        delayLabel = new JLabel("Request Delay (ms): " + DEFAULT_DELAY);
        delaySlider = new JSlider(0, 2000, DEFAULT_DELAY);
        delaySlider.setMajorTickSpacing(500);
        delaySlider.setMinorTickSpacing(50);
        delaySlider.setPaintTicks(true);
        delaySlider.setPaintLabels(true);
        delaySlider.addChangeListener(e ->
                delayLabel.setText("Request Delay (ms): " + delaySlider.getValue()));

        threadSpinner = new JSpinner(new SpinnerNumberModel(DEFAULT_THREADS, 1, 50, 1));
        JLabel threadLabel = new JLabel("Concurrency (Threads):");

        g.gridx = 0; g.gridy = 0; panel.add(delayLabel, g);
        g.gridx = 1; g.gridy = 0; g.fill = GridBagConstraints.HORIZONTAL; g.weightx = 1;
        panel.add(delaySlider, g);

        g.gridx = 0; g.gridy = 1; g.fill = GridBagConstraints.NONE; g.weightx = 0;
        panel.add(threadLabel, g);
        g.gridx = 1; g.gridy = 1;
        panel.add(threadSpinner, g);

        return panel;
    }

    private JPanel buildIPPanel() {
        JPanel panel = new JPanel(new BorderLayout());
        panel.setBorder(BorderFactory.createTitledBorder(
                BorderFactory.createLineBorder(new Color(180, 180, 180)),
                " IP Spoofing List (One per line) ", TitledBorder.LEFT, TitledBorder.TOP, SECTION_TITLE));
        ipConfigArea = new JTextArea(DEFAULT_IPS);
        ipConfigArea.setFont(new Font("Monospaced", Font.PLAIN, 12));
        panel.add(new JScrollPane(ipConfigArea), BorderLayout.CENTER);
        panel.setPreferredSize(new Dimension(400, 200));
        return panel;
    }

    private JPanel buildPathPanel() {
        JPanel panel = new JPanel(new BorderLayout());
        panel.setBorder(BorderFactory.createTitledBorder(
                BorderFactory.createLineBorder(new Color(180, 180, 180)),
                " Dictionary / Path List (One per line) ", TitledBorder.LEFT, TitledBorder.TOP, SECTION_TITLE));
        pathConfigArea = new JTextArea(DEFAULT_PATHS);
        pathConfigArea.setFont(new Font("Monospaced", Font.PLAIN, 12));
        panel.add(new JScrollPane(pathConfigArea), BorderLayout.CENTER);
        panel.setPreferredSize(new Dimension(400, 200));
        return panel;
    }

    // =========================================================================
    //  Actions
    // =========================================================================

    private void startAttack() {
        if (targetRequest == null) {
            JOptionPane.showMessageDialog(mainTabs,
                    "No target set.\nRight-click a request in Proxy HTTP History " +
                    "and choose \"Bypass 403 Forbidden\".",
                    "No Target", JOptionPane.WARNING_MESSAGE);
            return;
        }

        saveSettings();
        AttackConfig config = buildConfig();

        List<String> errors = config.validate();
        if (!errors.isEmpty()) {
            JOptionPane.showMessageDialog(mainTabs,
                    String.join("\n", errors),
                    "Validation Error", JOptionPane.WARNING_MESSAGE);
            return;
        }

        setAttackUIState(true);
        engine.startAttack(targetRequest, config);
    }

    private void togglePause() {
        engine.togglePause();
        SwingUtilities.invokeLater(() ->
                pauseBtn.setText(engine.isPaused() ? "Resume" : "Pause"));
    }

    private void stopAttack() {
        engine.stop();
        setAttackUIState(false);
        statusLabel.setText("Stopped");
    }

    private void clearResults() {
        tableModel.clear();
        requestViewer.setRequest(null);
        responseViewer.setResponse(null);
        progressBar.setValue(0);
        progressBar.setString("Ready");
        statusLabel.setText("Ready");
    }

    private void exportCSV() {
        if (tableModel.getRowCount() == 0) {
            JOptionPane.showMessageDialog(mainTabs, "No results to export.",
                    "Export", JOptionPane.INFORMATION_MESSAGE);
            return;
        }
        JFileChooser chooser = new JFileChooser();
        chooser.setSelectedFile(new File("403_buster_results.csv"));
        if (chooser.showSaveDialog(mainTabs) == JFileChooser.APPROVE_OPTION) {
            try (PrintWriter pw = new PrintWriter(new OutputStreamWriter(
                    new FileOutputStream(chooser.getSelectedFile()), StandardCharsets.UTF_8))) {
                // Header
                pw.println("ID,Method,URL,Technique,Category,Status,Length");
                // Rows
                for (int i = 0; i < tableModel.getRowCount(); i++) {
                    BypassResult r = tableModel.getResult(i);
                    pw.println(csvEscape(String.valueOf(r.getId())) + "," +
                            csvEscape(r.getMethod()) + "," +
                            csvEscape(r.getUrl()) + "," +
                            csvEscape(r.getTechnique()) + "," +
                            csvEscape(r.getCategory()) + "," +
                            r.getStatus() + "," +
                            r.getLength());
                }
                JOptionPane.showMessageDialog(mainTabs,
                        "Exported " + tableModel.getRowCount() + " results.",
                        "Export Complete", JOptionPane.INFORMATION_MESSAGE);
            } catch (IOException ex) {
                JOptionPane.showMessageDialog(mainTabs,
                        "Export failed: " + ex.getMessage(),
                        "Error", JOptionPane.ERROR_MESSAGE);
            }
        }
    }

    private String csvEscape(String s) {
        if (s == null) return "";
        if (s.contains(",") || s.contains("\"") || s.contains("\n")) {
            return "\"" + s.replace("\"", "\"\"") + "\"";
        }
        return s;
    }

    // =========================================================================
    //  AttackEngine.AttackListener Implementation
    // =========================================================================

    @Override
    public void onResult(BypassResult result) {
        SwingUtilities.invokeLater(() -> tableModel.addResult(result));
    }

    @Override
    public void onProgressUpdate(int completed, int total) {
        SwingUtilities.invokeLater(() -> {
            progressBar.setMaximum(total);
            progressBar.setValue(completed);
            int pct = total > 0 ? (int) ((completed * 100.0) / total) : 0;
            progressBar.setString(completed + " / " + total + " (" + pct + "%)");
            statusLabel.setText("Running... " + tableModel.getRowCount() + " findings");
        });
    }

    @Override
    public void onAttackStarted(int totalPayloads) {
        SwingUtilities.invokeLater(() -> {
            progressBar.setMaximum(totalPayloads);
            progressBar.setValue(0);
            progressBar.setString("0 / " + totalPayloads + " (0%)");
            statusLabel.setText("Attacking with " + totalPayloads + " payloads...");
        });
    }

    @Override
    public void onAttackComplete() {
        SwingUtilities.invokeLater(() -> {
            setAttackUIState(false);
            progressBar.setString("Complete — " + tableModel.getRowCount() + " findings");
            statusLabel.setText("Complete — " + tableModel.getRowCount() + " findings");
        });
    }

    @Override
    public void onError(String technique, String errorMessage) {
        api.logging().logToError("[403 Buster] " + technique + ": " + errorMessage);
    }

    // =========================================================================
    //  Internal Helpers
    // =========================================================================

    private AttackConfig buildConfig() {
        return new AttackConfig(
                chkIpSpoofing.isSelected(),
                chkPathSwapping.isSelected(),
                chkHopByHop.isSelected(),
                chkPathObf.isSelected(),
                chkMethods.isSelected(),
                chkProtocolDowngrade.isSelected(),
                chkSuffixes.isSelected(),
                chkHide404.isSelected(),
                chkHide403.isSelected(),
                chkCaseSwitch.isSelected(),
                chkUnicode.isSelected(),
                chkBackslash.isSelected(),
                chkHeaderInjection.isSelected(),
                delaySlider.getValue(),
                (Integer) threadSpinner.getValue(),
                ipConfigArea.getText(),
                pathConfigArea.getText()
        );
    }

    private void setAttackUIState(boolean active) {
        SwingUtilities.invokeLater(() -> {
            runBtn.setEnabled(!active);
            pauseBtn.setEnabled(active);
            stopBtn.setEnabled(active);
            if (!active) pauseBtn.setText("Pause");
        });
    }

    private void loadSettings() {
        String ips = preferences.getString(KEY_IPS);
        if (ips != null) ipConfigArea.setText(ips);
        String paths = preferences.getString(KEY_PATHS);
        if (paths != null) pathConfigArea.setText(paths);

        try {
            String d = preferences.getString(KEY_DELAY);
            if (d != null) { delaySlider.setValue(Integer.parseInt(d)); }
        } catch (NumberFormatException ignored) {}

        try {
            String t = preferences.getString(KEY_THREADS);
            if (t != null) { threadSpinner.setValue(Integer.parseInt(t)); }
        } catch (NumberFormatException ignored) {}

        loadToggle(chkIpSpoofing, "ipSpoofing", true);
        loadToggle(chkPathSwapping, "pathSwapping", true);
        loadToggle(chkHopByHop, "hopByHop", true);
        loadToggle(chkPathObf, "pathObf", true);
        loadToggle(chkMethods, "methods", true);
        loadToggle(chkProtocolDowngrade, "protocol", true);
        loadToggle(chkSuffixes, "suffixes", true);
        loadToggle(chkHide404, "hide404", false);
        loadToggle(chkHide403, "hide403", false);
        loadToggle(chkCaseSwitch, "caseSwitch", true);
        loadToggle(chkUnicode, "unicode", true);
        loadToggle(chkBackslash, "backslash", true);
        loadToggle(chkHeaderInjection, "headerInj", true);

        delayLabel.setText("Request Delay (ms): " + delaySlider.getValue());
    }

    private void loadToggle(JCheckBox check, String key, boolean defaultVal) {
        Boolean val = preferences.getBoolean(KEY_PREFIX + key);
        check.setSelected(val != null ? val : defaultVal);
    }

    // =========================================================================
    //  Table Model
    // =========================================================================

    static class ResultTableModel extends AbstractTableModel {
        private final CopyOnWriteArrayList<BypassResult> results = new CopyOnWriteArrayList<>();
        private final String[] columns = {"#", "Method", "URL", "Technique", "Category", "Status", "Length"};

        void addResult(BypassResult result) {
            results.add(result);
            fireTableRowsInserted(results.size() - 1, results.size() - 1);
        }

        void clear() {
            results.clear();
            fireTableDataChanged();
        }

        void removeRow(int index) {
            if (index >= 0 && index < results.size()) {
                results.remove(index);
                fireTableRowsDeleted(index, index);
            }
        }

        BypassResult getResult(int index) { return results.get(index); }

        @Override public int getRowCount() { return results.size(); }
        @Override public int getColumnCount() { return columns.length; }
        @Override public String getColumnName(int col) { return columns[col]; }

        @Override
        public Class<?> getColumnClass(int col) {
            if (col == 0 || col == 5 || col == 6) return Integer.class;
            return String.class;
        }

        @Override
        public Object getValueAt(int row, int col) {
            BypassResult r = results.get(row);
            switch (col) {
                case 0: return r.getId();
                case 1: return r.getMethod();
                case 2: return r.getUrl();
                case 3: return r.getTechnique();
                case 4: return r.getCategory();
                case 5: return r.getStatus();
                case 6: return r.getLength();
                default: return "";
            }
        }
    }

    // =========================================================================
    //  Color Renderer
    // =========================================================================

    class StatusColorRenderer extends DefaultTableCellRenderer {
        @Override
        public Component getTableCellRendererComponent(JTable table, Object value,
                boolean isSelected, boolean hasFocus, int row, int column) {
            Component c = super.getTableCellRendererComponent(table, value,
                    isSelected, hasFocus, row, column);

            if (!isSelected) {
                int modelRow = table.convertRowIndexToModel(row);
                BypassResult r = tableModel.getResult(modelRow);
                int status = r.getStatus();

                if (status >= 200 && status < 300) {
                    c.setBackground(BYPASS_GREEN);
                    if (r.isInteresting()) {
                        c.setForeground(new Color(27, 94, 32)); // dark green
                        c.setFont(c.getFont().deriveFont(Font.BOLD));
                    } else {
                        c.setForeground(Color.BLACK);
                    }
                } else if (status >= 300 && status < 400) {
                    c.setBackground(REDIRECT_ORANGE);
                    c.setForeground(Color.BLACK);
                } else if (status >= 500) {
                    c.setBackground(ERROR_RED);
                    c.setForeground(Color.BLACK);
                } else {
                    c.setBackground(Color.WHITE);
                    c.setForeground(Color.BLACK);
                }
            }
            return c;
        }
    }
}
