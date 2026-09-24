# -*- coding: utf-8 -*-
from double_agent_prelude import *
from double_agent_api import AgentAPIHandler
from double_agent_ui import *

class BurpExtenderChunk4Chunk2(object):
    def _do_open_settings(self):
        """Internal method to create and show settings dialog"""
        from javax.swing import JDialog, JTabbedPane, JTextField, JComboBox, JPasswordField, JTextArea, JFileChooser
        from javax.swing import SwingConstants, JCheckBox
        from java.awt import GridBagLayout, GridBagConstraints, Insets

        def _estimate_openai_context_window(model_name):
            model_l = str(model_name or "").lower()
            if "gpt-4o" in model_l or "gpt-4.1" in model_l or "gpt-5" in model_l:
                return 128000
            if model_l.startswith("gpt-4"):
                return 8192
            if "gpt-3.5" in model_l:
                return 16385
            return 0

        # Debug: Log that settings is opening
        self.stdout.println("\n[SETTINGS] Opening configuration dialog...")
        self.stdout.println("[SETTINGS] Current Provider: %s" % self.AI_PROVIDER)
        self.stdout.println("[SETTINGS] Current Model: %s" % self.MODEL)

        dialog = JDialog()
        dialog.setTitle("Double Agent Settings")
        dialog.setModal(True)
        dialog.setSize(750, 650)  # Wider to accommodate long model names, taller for Advanced tab
        dialog.setLocationRelativeTo(None)

        tabbedPane = JTabbedPane()
        tabbedPane.setTabLayoutPolicy(JTabbedPane.SCROLL_TAB_LAYOUT)

        # AI PROVIDER TAB
        aiPanel = JPanel(GridBagLayout())
        gbc = GridBagConstraints()
        gbc.insets = Insets(5, 5, 5, 5)
        gbc.anchor = GridBagConstraints.WEST
        gbc.fill = GridBagConstraints.HORIZONTAL

        row = 0

        gbc.gridx = 0
        gbc.gridy = row
        aiPanel.add(JLabel("AI Provider:"), gbc)
        gbc.gridx = 1
        gbc.gridwidth = 2
        providerCombo = JComboBox(["Ollama", "OpenAI", "Claude", "Gemini", "Bedrock", "DeepSeek"])
        providerCombo.setSelectedItem(self.AI_PROVIDER)

        # Auto-update API URL when provider changes
        from java.awt.event import ActionListener
        class ProviderChangeListener(ActionListener):
            def __init__(self, extender, urlField):
                self.extender = extender
                self.urlField = urlField

            def actionPerformed(self, e):
                provider = str(e.getSource().getSelectedItem())
                # Default URLs for each provider
                default_urls = {
                    "Ollama": "http://localhost:11434",
                    "OpenAI": "https://api.openai.com/v1",
                    "Claude": "https://api.anthropic.com/v1",
                    "Gemini": "https://generativelanguage.googleapis.com/v1",
                    "Bedrock": "https://bedrock-runtime.us-east-1.amazonaws.com",
                    "DeepSeek": "https://api.deepseek.com/v1"
                }
                if provider in default_urls:
                    self.urlField.setText(default_urls[provider])

        aiPanel.add(providerCombo, gbc)
        gbc.gridwidth = 1
        row += 1

        gbc.gridx = 0
        gbc.gridy = row
        apiUrlLabel = JLabel("API URL:")
        aiPanel.add(apiUrlLabel, gbc)
        gbc.gridx = 1
        gbc.gridwidth = 2
        apiUrlField = JTextField(self.API_URL, 30)

        # Add listener AFTER creating the field
        providerCombo.addActionListener(ProviderChangeListener(self, apiUrlField))

        aiPanel.add(apiUrlField, gbc)
        gbc.gridwidth = 1
        row += 1

        gbc.gridx = 0
        gbc.gridy = row
        apiKeyLabel = JLabel("API Key:")
        aiPanel.add(apiKeyLabel, gbc)
        gbc.gridx = 1
        gbc.gridwidth = 2
        apiKeyField = JPasswordField(self.API_KEYS_PER_PROVIDER.get(self.AI_PROVIDER, self.API_KEY), 30)
        aiPanel.add(apiKeyField, gbc)
        gbc.gridwidth = 1
        row += 1

        # Bedrock uses hardcoded us-east-1 region - no UI field needed

        gbc.gridx = 0
        gbc.gridy = row
        modelLabel = JLabel("Model:")
        if self.AI_PROVIDER == "Bedrock":
            modelLabel.setText("Model (serverless only):")
            modelLabel.setToolTipText("Bedrock list is limited to ON_DEMAND foundation models and SYSTEM_DEFINED inference profiles.")
        aiPanel.add(modelLabel, gbc)
        gbc.gridx = 1
        if self.AI_PROVIDER == "OpenAI":
            cached_eligible = [m for m in self.available_models if _estimate_openai_context_window(m) >= 120000]
            if len(cached_eligible) > 0:
                models_to_show = cached_eligible
            elif _estimate_openai_context_window(self.MODEL) >= 120000:
                models_to_show = [self.MODEL]
            else:
                models_to_show = []
        elif self.AI_PROVIDER == "Bedrock":
            models_to_show = self._bedrock_serverless_models()
        else:
            models_to_show = self.available_models if self.available_models else [self.MODEL]
        modelCombo = JComboBox(models_to_show)
        if self.MODEL in models_to_show:
            modelCombo.setSelectedItem(self.MODEL)
        elif len(models_to_show) > 0:
            modelCombo.setSelectedItem(models_to_show[0])
        aiPanel.add(modelCombo, gbc)

        def updateModelComboForProvider():
            provider = str(providerCombo.getSelectedItem())
            previous_model = str(modelCombo.getSelectedItem() or "")
            modelCombo.removeAllItems()

            if provider == "OpenAI":
                eligible_models = [m for m in self.available_models if _estimate_openai_context_window(m) >= 120000]
                models = eligible_models
            elif provider == "Bedrock":
                models = self._bedrock_serverless_models()
                modelLabel.setText("Model (serverless only):")
                modelLabel.setToolTipText("Bedrock list is limited to ON_DEMAND foundation models and SYSTEM_DEFINED inference profiles.")
            else:
                models = self.available_models if self.available_models else [self.MODEL]
                modelLabel.setText("Model:")
                modelLabel.setToolTipText(None)

            for model in models:
                modelCombo.addItem(model)

            if previous_model in models:
                modelCombo.setSelectedItem(previous_model)
            elif len(models) > 0:
                modelCombo.setSelectedIndex(0)

        gbc.gridx = 2
        refreshModelsBtn = JButton("Refresh")

        def refreshModels(e):
            refreshModelsBtn.setEnabled(False)
            refreshModelsBtn.setText("...")
            self.stdout.println("[SETTINGS] Fetching models...")
            def _do_refresh():
                # Temporarily apply dialog values so test_ai_connection uses them
                old_provider = self.AI_PROVIDER
                old_url = self.API_URL
                old_key = self.API_KEY
                self.AI_PROVIDER = str(providerCombo.getSelectedItem())
                self.API_URL = apiUrlField.getText().strip()
                self.API_KEY = "".join(apiKeyField.getPassword())
                try:
                    if self.test_ai_connection():
                        def _update_ui():
                            modelCombo.removeAllItems()
                            models = self._bedrock_serverless_models() if self.AI_PROVIDER == "Bedrock" else self.available_models
                            for model in models:
                                modelCombo.addItem(model)
                            if self.MODEL in models:
                                modelCombo.setSelectedItem(self.MODEL)
                            elif len(models) > 0:
                                modelCombo.setSelectedIndex(0)
                            self.stdout.println("[SETTINGS] Models refreshed")
                            refreshModelsBtn.setEnabled(True)
                            refreshModelsBtn.setText("Refresh")
                        SwingUtilities.invokeLater(lambda: _update_ui())
                    else:
                        # Restore previous values on failure
                        self.AI_PROVIDER = old_provider
                        self.API_URL = old_url
                        self.API_KEY = old_key
                        def _restore():
                            refreshModelsBtn.setEnabled(True)
                            refreshModelsBtn.setText("Refresh")
                        SwingUtilities.invokeLater(lambda: _restore())
                except:
                    self.AI_PROVIDER = old_provider
                    self.API_URL = old_url
                    self.API_KEY = old_key
                    def _restore():
                        refreshModelsBtn.setEnabled(True)
                        refreshModelsBtn.setText("Refresh")
                    SwingUtilities.invokeLater(lambda: _restore())
            t = threading.Thread(target=_do_refresh)
            t.setDaemon(True)
            t.start()

        refreshModelsBtn.addActionListener(refreshModels)
        aiPanel.add(refreshModelsBtn, gbc)

        def updateRefreshButtonState():
            is_bedrock = str(providerCombo.getSelectedItem()) == "Bedrock"
            refreshModelsBtn.setEnabled(True)
            if is_bedrock:
                refreshModelsBtn.setToolTipText("Refresh serverless Bedrock models only: ON_DEMAND foundation models and SYSTEM_DEFINED inference profiles")
            else:
                refreshModelsBtn.setToolTipText("Refresh available models")

        _prev_provider = [self.AI_PROVIDER]  # mutable container to track previous selection

        def updateProviderFieldState():
            provider = str(providerCombo.getSelectedItem())

            # Save the key currently in the field for the PREVIOUS provider before swapping
            current_key = "".join(apiKeyField.getPassword())
            if current_key and _prev_provider[0]:
                self.API_KEYS_PER_PROVIDER[_prev_provider[0]] = current_key
            _prev_provider[0] = provider

            is_bedrock = provider == "Bedrock"
            uses_api_key = provider in ("OpenAI", "Claude", "Gemini", "Bedrock", "DeepSeek")

            apiKeyLabel.setVisible(uses_api_key)

            if is_bedrock:
                apiUrlLabel.setVisible(False)
                apiUrlField.setVisible(False)
                apiKeyLabel.setText("Bedrock API Key:")
                apiUrlField.setText("https://bedrock-runtime.us-east-1.amazonaws.com")
            else:
                apiUrlLabel.setVisible(True)
                apiUrlField.setVisible(True)
                if provider == "OpenAI":
                    apiKeyLabel.setText("OpenAI API Key:")
                elif provider == "Claude":
                    apiKeyLabel.setText("Claude API Key:")
                elif provider == "Gemini":
                    apiKeyLabel.setText("Gemini API Key:")
                elif provider == "DeepSeek":
                    apiKeyLabel.setText("DeepSeek API Key:")
                else:
                    apiKeyLabel.setText("API Key:")

            # Swap API key field to show the stored key for this provider
            stored_key = self.API_KEYS_PER_PROVIDER.get(provider, "")
            apiKeyField.setText(stored_key)

            aiPanel.revalidate()
            aiPanel.repaint()

        providerCombo.addActionListener(lambda e: updateModelComboForProvider())
        providerCombo.addActionListener(lambda e: updateRefreshButtonState())
        providerCombo.addActionListener(lambda e: updateProviderFieldState())
        updateModelComboForProvider()
        updateRefreshButtonState()
        updateProviderFieldState()
        row += 1

        gbc.gridx = 0
        gbc.gridy = row
        aiPanel.add(JLabel("Max Tokens:"), gbc)
        gbc.gridx = 1
        gbc.gridwidth = 2
        maxTokensField = JTextField(str(self.MAX_TOKENS), 10)
        aiPanel.add(maxTokensField, gbc)
        gbc.gridwidth = 1
        row += 1

        gbc.gridx = 0
        gbc.gridy = row
        gbc.gridwidth = 3
        testBtn = JButton("Test Connection")

        def testConnection(e):
            testBtn.setEnabled(False)
            testBtn.setText("Testing...")
            old_provider = self.AI_PROVIDER
            old_url = self.API_URL
            old_key = self.API_KEY
            old_model = self.MODEL
            old_bedrock_region = self.BEDROCK_REGION

            selected_provider = str(providerCombo.getSelectedItem())
            self.AI_PROVIDER = selected_provider
            self.API_KEY = "".join(apiKeyField.getPassword())
            self.MODEL = str(modelCombo.getSelectedItem())
            self.BEDROCK_REGION = "us-east-1"  # Hardcoded
            self.API_URL = apiUrlField.getText().strip()
            if selected_provider == "Bedrock":
                self.API_URL = "https://bedrock-runtime.%s.amazonaws.com" % self.BEDROCK_REGION
            else:
                self.API_URL = apiUrlField.getText()

            def _do_test():
                error_msg = None
                success_msg = None
                try:
                    success = self.test_ai_connection()
                    if not success:
                        self.AI_PROVIDER = old_provider
                        self.API_URL = old_url
                        self.API_KEY = old_key
                        self.MODEL = old_model
                        self.BEDROCK_REGION = old_bedrock_region
                        error_msg = "Connection failed. Check the console for detailed error messages.\n\nCommon causes:\n- Wrong API URL or port\n- Missing or invalid API key\n- Network connectivity issues\n- AI service not running or blocked"
                    else:
                        if self.save_config():
                            self.stdout.println("[SETTINGS] Test connection succeeded; credentials saved locally")
                        success_msg = "Successfully connected to %s!\n\nModel: %s\nCredentials saved to local config." % (self.AI_PROVIDER, self.MODEL)
                except Exception as e:
                    error_msg = "Test connection error: %s" % str(e)
                    self.stderr.println("[SETTINGS ERROR] %s" % error_msg)
                finally:
                    def _restore():
                        testBtn.setEnabled(True)
                        testBtn.setText("Test Connection")
                        from javax.swing import JOptionPane
                        if error_msg:
                            JOptionPane.showMessageDialog(
                                dialog,
                                error_msg,
                                "Connection Failed",
                                JOptionPane.ERROR_MESSAGE
                            )
                        elif success_msg:
                            JOptionPane.showMessageDialog(
                                dialog,
                                success_msg,
                                "Connection Successful",
                                JOptionPane.INFORMATION_MESSAGE
                            )
                    SwingUtilities.invokeLater(lambda: _restore())
            t = threading.Thread(target=_do_test)
            t.setDaemon(True)
            t.start()

        testBtn.addActionListener(testConnection)
        aiPanel.add(testBtn, gbc)
        row += 1

        gbc.gridy = row
        helpText = JTextArea("")
        helpText.setEditable(False)
        helpText.setBackground(aiPanel.getBackground())
        aiPanel.add(helpText, gbc)

        def updateProviderHelpText():
            provider = str(providerCombo.getSelectedItem())
            if provider == "Ollama":
                text = (
                    "Provider: Ollama\n\n"
                    "URL: http://localhost:11434\n"
                    "Auth: No API key required."
                )
            elif provider == "OpenAI":
                text = (
                    "Provider: OpenAI\n\n"
                    "URL: https://api.openai.com/v1\n"
                    "Auth: API key required."
                )
            elif provider == "Claude":
                text = (
                    "Provider: Claude\n\n"
                    "URL: https://api.anthropic.com/v1\n"
                    "Auth: API key required."
                )
            elif provider == "Gemini":
                text = (
                    "Provider: Gemini\n\n"
                    "URL: https://generativelanguage.googleapis.com/v1\n"
                    "Auth: API key required."
                )
            elif provider == "Bedrock":
                text = (
                    "Provider: Bedrock\n\n"
                    "Runtime URL is auto-configured from Region.\n"
                    "Auth: Bedrock API key (Bearer token) required.\n"
                    "Models: serverless only. Lists ON_DEMAND foundation models and SYSTEM_DEFINED inference profiles.\n"
                    "Blocked: provisioned, custom, imported, marketplace, endpoint and application inference profile IDs."
                )
            elif provider == "DeepSeek":
                text = (
                    "Provider: DeepSeek\n\n"
                    "URL: https://api.deepseek.com/v1\n"
                    "Auth: API key required.\n"
                    "Models: deepseek-chat, deepseek-reasoner"
                )
            else:
                text = "Select a provider to see setup guidance."
            helpText.setText(text)

        providerCombo.addActionListener(lambda e: updateProviderHelpText())
        updateProviderHelpText()

        aiScroll = JScrollPane(aiPanel)
        aiScroll.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED)
        aiScroll.setHorizontalScrollBarPolicy(JScrollPane.HORIZONTAL_SCROLLBAR_NEVER)
        tabbedPane.addTab("AI Provider", aiScroll)

        reportingPinField = self._add_remote_reporting_settings_tab(tabbedPane)

        # ADVANCED TAB
        advancedPanel = JPanel(GridBagLayout())
        gbc = GridBagConstraints()
        gbc.insets = Insets(5, 5, 5, 5)
        gbc.anchor = GridBagConstraints.WEST
        gbc.fill = GridBagConstraints.HORIZONTAL

        row = 0

        # Help text for automatic Burp traffic analysis
        gbc.gridx = 0
        gbc.gridy = row
        gbc.gridwidth = 2
        passiveScanHelp = JTextArea(
            "Burp traffic analysis toggle has been moved to the main panel for easier access.\n"
            "When disabled, you can still manually analyze requests via right-click context menu.\n"
            "When enabled, completed in-scope responses from Proxy/browser, Extender/MCP, Repeater, and Scanner/crawl can be analyzed automatically."
        )
        passiveScanHelp.setEditable(False)
        passiveScanHelp.setBackground(advancedPanel.getBackground())
        passiveScanHelp.setFont(Font("Dialog", Font.ITALIC, 10))
        advancedPanel.add(passiveScanHelp, gbc)
        row += 1
        gbc.gridwidth = 1

        # Theme dropdown
        gbc.gridx = 0
        gbc.gridy = row
        advancedPanel.add(JLabel("Console Theme:"), gbc)
        gbc.gridx = 1
        themeCombo = JComboBox(["Auto", "Light", "Dark"])
        themeCombo.setSelectedItem(self.THEME)
        advancedPanel.add(themeCombo, gbc)
        row += 1

        gbc.gridx = 0
        gbc.gridy = row
        advancedPanel.add(JLabel("Verbose Logging:"), gbc)
        gbc.gridx = 1
        verboseCheck = JCheckBox("", self.VERBOSE)
        advancedPanel.add(verboseCheck, gbc)
        row += 1

        gbc.gridx = 0
        gbc.gridy = row
        gbc.gridwidth = 1
        advancedPanel.add(JLabel("Project Folder:"), gbc)
        gbc.gridx = 1
        workspaceDirField = JTextField(str(self.PROJECT_WORKSPACE_DIR or ""), 34)
        advancedPanel.add(workspaceDirField, gbc)
        gbc.gridx = 2
        browseWorkspaceBtn = JButton("Browse...")
        def browseWorkspaceDir(e):
            chooser = JFileChooser(workspaceDirField.getText().strip() or str(self.PROJECT_WORKSPACE_DIR or ""))
            chooser.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY)
            chooser.setAcceptAllFileFilterUsed(False)
            result = chooser.showOpenDialog(dialog)
            if result == JFileChooser.APPROVE_OPTION:
                selected = chooser.getSelectedFile()
                if selected is not None:
                    workspaceDirField.setText(selected.getAbsolutePath())
        browseWorkspaceBtn.addActionListener(browseWorkspaceDir)
        advancedPanel.add(browseWorkspaceBtn, gbc)
        row += 1

        gbc.gridx = 0
        gbc.gridy = row
        gbc.gridwidth = 3
        workspaceHelp = JTextArea(
            "Double Agent asks for this folder when the extension loads. It saves double-agent.json and may read findings.md from this project folder. Scope always comes from Burp Suite. Target notes live in View/Edit Test Context and /api/agent/knowledge."
        )
        workspaceHelp.setEditable(False)
        workspaceHelp.setBackground(advancedPanel.getBackground())
        workspaceHelp.setFont(Font("Dialog", Font.ITALIC, 10))
        advancedPanel.add(workspaceHelp, gbc)
        row += 1
        gbc.gridwidth = 1

        # AI Request Timeout setting
        gbc.gridx = 0
        gbc.gridy = row
        advancedPanel.add(JLabel("AI Request Timeout (seconds):"), gbc)
        gbc.gridx = 1
        timeoutField = JTextField(str(self.AI_REQUEST_TIMEOUT), 10)
        advancedPanel.add(timeoutField, gbc)
        row += 1

        # Help text for timeout
        gbc.gridx = 0
        gbc.gridy = row
        gbc.gridwidth = 2
        timeoutHelp = JTextArea(
            "Timeout for AI API requests (default: 60 seconds).\n"
            "Range: 10 to 99999 seconds (27.7 hours max).\n"
            "Increase if you get timeout errors.\n"
            "Recommended: 30-120s (fast models), 180-600s (large models)."
        )
        timeoutHelp.setEditable(False)
        timeoutHelp.setBackground(advancedPanel.getBackground())
        timeoutHelp.setFont(Font("Dialog", Font.ITALIC, 10))
        advancedPanel.add(timeoutHelp, gbc)
        row += 1
        gbc.gridwidth = 1

        # Analysis worker concurrency
        gbc.gridx = 0
        gbc.gridy = row
        advancedPanel.add(JLabel("Analysis Worker Threads:"), gbc)
        gbc.gridx = 1
        workerField = JTextField(str(self.ANALYSIS_WORKERS), 10)
        advancedPanel.add(workerField, gbc)
        row += 1

        gbc.gridx = 0
        gbc.gridy = row
        gbc.gridwidth = 2
        workerHelp = JTextArea(
            "Concurrent analysis workers (default: 1).\n"
            "Range: 1 to 10. Higher = more parallel scans, but more API/network load."
        )
        workerHelp.setEditable(False)
        workerHelp.setBackground(advancedPanel.getBackground())
        workerHelp.setFont(Font("Dialog", Font.ITALIC, 10))
        advancedPanel.add(workerHelp, gbc)
        row += 1
        gbc.gridwidth = 1

        gbc.gridx = 0
        gbc.gridy = row
        advancedPanel.add(JLabel("AI Request Concurrency:"), gbc)
        gbc.gridx = 1
        aiConcurrencyField = JTextField(str(self.AI_REQUEST_CONCURRENCY), 10)
        advancedPanel.add(aiConcurrencyField, gbc)
        row += 1

        gbc.gridx = 0
        gbc.gridy = row
        gbc.gridwidth = 2
        aiConcurrencyHelp = JTextArea(
            "Maximum simultaneous AI provider calls (default: 2).\n"
            "Keep this low for Bedrock to avoid timeout/no-response bursts."
        )
        aiConcurrencyHelp.setEditable(False)
        aiConcurrencyHelp.setBackground(advancedPanel.getBackground())
        aiConcurrencyHelp.setFont(Font("Dialog", Font.ITALIC, 10))
        advancedPanel.add(aiConcurrencyHelp, gbc)
        row += 1
        gbc.gridwidth = 1

        # Proxy auto-analysis backpressure settings
        gbc.gridx = 0
        gbc.gridy = row
        advancedPanel.add(JLabel("Proxy Auto-Analysis Backlog:"), gbc)
        gbc.gridx = 1
        proxyBacklogField = JTextField(str(self.MAX_PROXY_QUEUED_ANALYSES), 10)
        advancedPanel.add(proxyBacklogField, gbc)
        row += 1

        gbc.gridx = 0
        gbc.gridy = row
        advancedPanel.add(JLabel("Proxy Intake Interval (seconds):"), gbc)
        gbc.gridx = 1
        proxyIntervalField = JTextField(str(self.PROXY_ANALYSIS_MIN_INTERVAL_SECONDS), 10)
        advancedPanel.add(proxyIntervalField, gbc)
        row += 1

        gbc.gridx = 0
        gbc.gridy = row
        gbc.gridwidth = 2
        proxyPerfHelp = JTextArea(
            "Limits automatic Proxy traffic analysis so Burp stays responsive.\n"
            "Manual right-click analysis still uses the normal worker setting.\n"
            "Recommended: backlog 2-4, interval 0.5-2.0s."
        )
        proxyPerfHelp.setEditable(False)
        proxyPerfHelp.setBackground(advancedPanel.getBackground())
        proxyPerfHelp.setFont(Font("Dialog", Font.ITALIC, 10))
        advancedPanel.add(proxyPerfHelp, gbc)
        row += 1
        gbc.gridwidth = 1

        # Debug Tasks button
        gbc.gridx = 0
        gbc.gridy = row
        gbc.gridwidth = 2
        debugTasksBtn = JButton("Run Task Diagnostics", actionPerformed=self.debugTasks)
        advancedPanel.add(debugTasksBtn, gbc)
        row += 1

        # Help text for debug
        gbc.gridy = row
        debugHelp = JTextArea(
            "Click to generate detailed diagnostic report for stuck/queued tasks.\n"
            "Shows task counts, durations, threading status, and recommendations."
        )
        debugHelp.setEditable(False)
        debugHelp.setBackground(advancedPanel.getBackground())
        debugHelp.setFont(Font("Dialog", Font.ITALIC, 10))
        advancedPanel.add(debugHelp, gbc)
        row += 1

        gbc.gridwidth = 1

        gbc.gridx = 0
        gbc.gridy = row
        gbc.gridwidth = 2
        infoNotice = JTextArea(
            "Double Agent\n\n"
            "AI-powered passive security analysis + Agent agentic pair-testing for Burp Suite.\n\n"
            "Use the API docs endpoint for current agent workflow details."
        )
        infoNotice.setEditable(False)
        infoNotice.setBackground(advancedPanel.getBackground())
        infoNotice.setFont(Font("Dialog", Font.PLAIN, 11))
        advancedPanel.add(infoNotice, gbc)

        advancedScroll = JScrollPane(advancedPanel)
        advancedScroll.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED)
        advancedScroll.setHorizontalScrollBarPolicy(JScrollPane.HORIZONTAL_SCROLLBAR_NEVER)
        tabbedPane.addTab("Advanced", advancedScroll)

        # === SYSTEM PROMPT TAB ===
        promptPanel = JPanel(GridBagLayout())
        promptPanel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10))
        pgbc = GridBagConstraints()
        pgbc.insets = Insets(5, 5, 5, 5)
        pgbc.fill = GridBagConstraints.HORIZONTAL
        pgbc.anchor = GridBagConstraints.NORTHWEST

        # Scan prompt label
        pgbc.gridx = 0
        pgbc.gridy = 0
        pgbc.weightx = 1.0
        pgbc.weighty = 0.0
        scanPromptLabel = JLabel("Per-Request Scan Prompt:")
        scanPromptLabel.setFont(Font("Dialog", Font.BOLD, 12))
        promptPanel.add(scanPromptLabel, pgbc)

        # Scan prompt help
        pgbc.gridy = 1
        scanPromptHelp = JTextArea(
            "This prompt is sent to the AI for every request analysis. "
            "Edit to tune finding quality, suppress false positives, or change focus areas. "
            "The request data is appended automatically after this prompt."
        )
        scanPromptHelp.setLineWrap(True)
        scanPromptHelp.setWrapStyleWord(True)
        scanPromptHelp.setEditable(False)
        scanPromptHelp.setBackground(promptPanel.getBackground())
        scanPromptHelp.setFont(Font("Dialog", Font.PLAIN, 11))
        promptPanel.add(scanPromptHelp, pgbc)

        # Scan prompt text area - show current prompt (custom or default)
        pgbc.gridy = 2
        pgbc.fill = GridBagConstraints.BOTH
        pgbc.weighty = 1.0
        currentScanPrompt = self.CUSTOM_SCAN_PROMPT if self.CUSTOM_SCAN_PROMPT else self._default_scan_prompt()
        scanPromptArea = JTextArea(currentScanPrompt, 12, 60)
        scanPromptArea.setLineWrap(True)
        scanPromptArea.setWrapStyleWord(True)
        scanPromptArea.setFont(Font("Monospaced", Font.PLAIN, 12))
        scanPromptScroll = JScrollPane(scanPromptArea)
        promptPanel.add(scanPromptScroll, pgbc)

        # Reset scan prompt button
        pgbc.gridy = 3
        pgbc.fill = GridBagConstraints.NONE
        pgbc.weighty = 0.0
        pgbc.anchor = GridBagConstraints.WEST
        resetScanBtn = JButton("Reset to Default")
        resetScanBtn.addActionListener(lambda e: scanPromptArea.setText(self._default_scan_prompt()))
        promptPanel.add(resetScanBtn, pgbc)

        promptScroll = JScrollPane(promptPanel)
        promptScroll.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED)
        promptScroll.setHorizontalScrollBarPolicy(JScrollPane.HORIZONTAL_SCROLLBAR_NEVER)
        tabbedPane.addTab("System Prompt", promptScroll)

        # BUTTONS
        buttonPanel = JPanel()

        def saveSettings(e):
            def _estimate_openai_context_window(model_name):
                model_l = str(model_name or "").lower()
                if "gpt-4o" in model_l or "gpt-4.1" in model_l or "gpt-5" in model_l:
                    return 128000
                if model_l.startswith("gpt-4"):
                    return 8192
                if "gpt-3.5" in model_l:
                    return 16385
                return 0

            # Validate and store the reporting PIN before mutating other
            # settings. This does not call the remote API.
            try:
                self._save_remote_reporting_pin_field(reportingPinField)
            except ValueError as reporting_error:
                from javax.swing import JOptionPane
                JOptionPane.showMessageDialog(
                    dialog, str(reporting_error), "Remote reporting PIN",
                    JOptionPane.ERROR_MESSAGE)
                return

            # Save AI Provider settings
            self.AI_PROVIDER = str(providerCombo.getSelectedItem())
            self.API_URL = apiUrlField.getText()
            self.API_KEY = "".join(apiKeyField.getPassword())
            self.MODEL = str(modelCombo.getSelectedItem())
            self.BEDROCK_REGION = "us-east-1"  # Hardcoded

            # Store API key per-provider so switching doesn't lose keys
            self.API_KEYS_PER_PROVIDER[self.AI_PROVIDER] = self.API_KEY

            if self.AI_PROVIDER == "Bedrock":
                self.API_URL = "https://bedrock-runtime.%s.amazonaws.com" % self.BEDROCK_REGION

            if self.AI_PROVIDER == "OpenAI":
                model_ctx = _estimate_openai_context_window(self.MODEL)
                if model_ctx < 120000:
                    self.stderr.println("[!] Selected OpenAI model '%s' is blocked (context window < 120k)." % self.MODEL)
                    self.stderr.println("[!] Please choose an eligible model with >=120k context window.")
                    return
            elif self.AI_PROVIDER == "Bedrock":
                has_bearer_token = bool(str(self.API_KEY or "").strip())
                if not has_bearer_token:
                    self.stderr.println("[!] Bedrock requires API Key (Bearer token)")
                    return
                serverless_models = self._bedrock_serverless_models()
                if self.MODEL not in serverless_models:
                    self.stderr.println("[!] Bedrock model '%s' is blocked because it is not in the serverless allow-list." % self.MODEL)
                    self.stderr.println("[!] Click Refresh and choose an ON_DEMAND foundation model or SYSTEM_DEFINED inference profile.")
                    return

            try:
                self.MAX_TOKENS = int(maxTokensField.getText())
            except ValueError:
                self.MAX_TOKENS = 2048
                self.stderr.println("[!] Invalid Max Tokens value, using default: 2048")

            # Save Advanced settings
            self.PASSIVE_SCANNING_ENABLED = self.passiveScanCheck.isSelected()
            self.THEME = str(themeCombo.getSelectedItem())
            self.VERBOSE = verboseCheck.isSelected()

            # Save custom system prompts (empty = use default)
            scan_text = scanPromptArea.getText().strip()
            self.CUSTOM_SCAN_PROMPT = "" if scan_text == self._default_scan_prompt().strip() else scan_text

            # Apply theme immediately
            self.applyConsoleTheme()

            # Save timeout setting
            try:
                timeout = int(timeoutField.getText())
                if timeout < 10:
                    self.AI_REQUEST_TIMEOUT = 10
                    self.stderr.println("[!] Timeout too low, using minimum: 10 seconds")
                elif timeout > 99999:
                    self.AI_REQUEST_TIMEOUT = 99999
                    self.stderr.println("[!] Timeout too high, using maximum: 99999 seconds")
                else:
                    self.AI_REQUEST_TIMEOUT = timeout
            except ValueError:
                self.AI_REQUEST_TIMEOUT = 60
                self.stderr.println("[!] Invalid timeout value, using default: 60 seconds")

            # Save analysis worker setting
            try:
                worker_count = int(workerField.getText())
                if worker_count < 1:
                    self.ANALYSIS_WORKERS = 1
                    self.stderr.println("[!] Worker count too low, using minimum: 1")
                elif worker_count > 10:
                    self.ANALYSIS_WORKERS = 10
                    self.stderr.println("[!] Worker count too high, using maximum: 10")
                else:
                    self.ANALYSIS_WORKERS = worker_count
            except ValueError:
                self.ANALYSIS_WORKERS = 1
                self.stderr.println("[!] Invalid worker count, using default: 1")

            try:
                ai_concurrency = int(aiConcurrencyField.getText())
                if ai_concurrency < 1:
                    self.AI_REQUEST_CONCURRENCY = 1
                    self.stderr.println("[!] AI request concurrency too low, using minimum: 1")
                elif ai_concurrency > 5:
                    self.AI_REQUEST_CONCURRENCY = 5
                    self.stderr.println("[!] AI request concurrency too high, using maximum: 5")
                else:
                    self.AI_REQUEST_CONCURRENCY = ai_concurrency
            except ValueError:
                self.AI_REQUEST_CONCURRENCY = 2
                self.stderr.println("[!] Invalid AI request concurrency, using default: 2")

            if self.AI_PROVIDER == "Bedrock" and int(self.AI_REQUEST_TIMEOUT) < int(getattr(self, "MIN_BEDROCK_REQUEST_TIMEOUT", 120)):
                self.AI_REQUEST_TIMEOUT = int(getattr(self, "MIN_BEDROCK_REQUEST_TIMEOUT", 120))
                self.stderr.println("[!] Bedrock timeout too low, using minimum: %d seconds" % int(self.AI_REQUEST_TIMEOUT))

            # Rebuild semaphores with new concurrency
            self.semaphore = threading.Semaphore(max(1, int(self.ANALYSIS_WORKERS)))
            self._ai_request_semaphore = threading.Semaphore(max(1, int(self.AI_REQUEST_CONCURRENCY)))

            try:
                proxy_backlog = int(proxyBacklogField.getText())
                if proxy_backlog < 1:
                    self.MAX_PROXY_QUEUED_ANALYSES = 1
                    self.stderr.println("[!] Proxy backlog too low, using minimum: 1")
                elif proxy_backlog > 20:
                    self.MAX_PROXY_QUEUED_ANALYSES = 20
                    self.stderr.println("[!] Proxy backlog too high, using maximum: 20")
                else:
                    self.MAX_PROXY_QUEUED_ANALYSES = proxy_backlog
            except ValueError:
                self.MAX_PROXY_QUEUED_ANALYSES = 3
                self.stderr.println("[!] Invalid proxy backlog, using default: 3")

            try:
                proxy_interval = float(proxyIntervalField.getText())
                if proxy_interval < 0:
                    self.PROXY_ANALYSIS_MIN_INTERVAL_SECONDS = 0.0
                    self.stderr.println("[!] Proxy interval too low, using minimum: 0")
                elif proxy_interval > 10:
                    self.PROXY_ANALYSIS_MIN_INTERVAL_SECONDS = 10.0
                    self.stderr.println("[!] Proxy interval too high, using maximum: 10")
                else:
                    self.PROXY_ANALYSIS_MIN_INTERVAL_SECONDS = proxy_interval
            except ValueError:
                self.PROXY_ANALYSIS_MIN_INTERVAL_SECONDS = 1.0
                self.stderr.println("[!] Invalid proxy interval, using default: 1.0")

            try:
                workspace_dir = str(workspaceDirField.getText() or "").strip()
                if not workspace_dir:
                    self.stderr.println("[!] Project Folder is required")
                    return
                resolved_workspace_dir = self._normalize_project_workspace_dir(workspace_dir)
                if not resolved_workspace_dir:
                    self.stderr.println("[!] Could not resolve Project Folder")
                    return
                self.PROJECT_WORKSPACE_DIR = resolved_workspace_dir
                self._project_key_cache = None
            except Exception as e:
                self.stderr.println("[!] Invalid Project Folder: %s" % self._safe_ascii_text(e))
                return

            self._sync_jev_controls()

            # Log confirmation
            self.stdout.println("\n[SETTINGS] OK Configuration saved successfully")
            self.stdout.println("[SETTINGS] AI Provider: %s" % self.AI_PROVIDER)
            self.stdout.println("[SETTINGS] API URL: %s" % self.API_URL)
            self.stdout.println("[SETTINGS] Model: %s" % self.MODEL)
            self.stdout.println("[SETTINGS] Max Tokens: %d" % int(self.MAX_TOKENS))
            self.stdout.println("[SETTINGS] Request Timeout: %d seconds" % int(self.AI_REQUEST_TIMEOUT))
            self.stdout.println("[SETTINGS] Analysis Workers: %d" % int(self.ANALYSIS_WORKERS))
            self.stdout.println("[SETTINGS] AI Request Concurrency: %d" % int(self.AI_REQUEST_CONCURRENCY))
            self.stdout.println("[SETTINGS] Proxy Auto-Analysis Backlog: %d" % int(self.MAX_PROXY_QUEUED_ANALYSES))
            self.stdout.println("[SETTINGS] Proxy Intake Interval: %.1fs" % float(self.PROXY_ANALYSIS_MIN_INTERVAL_SECONDS))
            self.stdout.println("[SETTINGS] Console Theme: %s" % self.THEME)
            self.stdout.println("[SETTINGS] Verbose Logging: %s" % ("Enabled" if self.VERBOSE else "Disabled"))
            self.stdout.println("[SETTINGS] Burp traffic analysis: %s" % ("Enabled" if self.PASSIVE_SCANNING_ENABLED else "Disabled"))
            self.stdout.println("[SETTINGS] Project Folder: %s" % self._workspace_directory())
            self.stdout.println("[SETTINGS] Remote reporting PIN: %s" % (
                "Configured" if self.REMOTE_REPORTING_PIN else "Not configured"))

            # Save configuration to disk
            if self.save_config():
                self.stdout.println("[SETTINGS] OK Configuration persisted to disk")
            self.save_findings()
            self.stdout.println("[SETTINGS] Findings sidecar: %s" % self._safe_ascii_text(self._eternals_file_path(), 2000))

            # Refresh stats immediately so model and pricing fields reflect new settings
            self._ui_dirty = True
            self.refreshUI()

            dialog.dispose()

        saveBtn = JButton("Save")
        saveBtn.addActionListener(saveSettings)
        buttonPanel.add(saveBtn)

        cancelBtn = JButton("Cancel")
        cancelBtn.addActionListener(lambda e: dialog.dispose())
        buttonPanel.add(cancelBtn)

        # Assemble dialog
        dialog.add(tabbedPane, BorderLayout.CENTER)
        dialog.add(buttonPanel, BorderLayout.SOUTH)

        # Apply theme to dialog
        self._apply_dark_theme_to_container(dialog)

        # Show dialog
        dialog.setVisible(True)

    def log_to_console(self, message):
        with self.console_lock:
            timestamp = datetime.now().strftime("%H:%M:%S")
            message_str = str(message)

            if "http://" in message_str or "https://" in message_str:
                import re
                def truncate_url(match):
                    url = match.group(0)
                    if len(url) > 100:
                        return url[:97] + "..."
                    return url

                message_str = re.sub(r'https?://[^\s]+', truncate_url, message_str)

            if len(message_str) > 150:
                message_str = message_str[:147] + "..."

            formatted_msg = "[%s] %s" % (timestamp, message_str)
            self.console_messages.append(formatted_msg)

            if len(self.console_messages) > self.max_console_messages:
                self.console_messages = self.console_messages[-self.max_console_messages:]
        self._ui_dirty = True

    def _perf_ms_since(self, start):
        try:
            return int((time.time() - start) * 1000)
        except:
            return 0

    def _perf_debug(self, message, key="", min_interval=0.0, force=False):
        return

    def _perf_counts_snapshot(self):
        try:
            with self.tasks_lock:
                total_tasks = len(self.tasks)
                active_tasks = 0
                queued_tasks = 0
                proxy_tasks = 0
                for task in self.tasks[-1000:]:
                    status = str(task.get("status", ""))
                    if "Analyzing" in status or "Waiting" in status:
                        active_tasks += 1
                    elif "Queued" in status:
                        queued_tasks += 1
                    if str(task.get("type", "")) == "PROXY" and not self._is_terminal_status(status):
                        proxy_tasks += 1
            with self.findings_lock_ui:
                findings_count = len(self.findings_list)
            with self.console_lock:
                console_count = len(self.console_messages)
            with self.agent_queue_lock:
                agent_count = len(self.agent_queue)
            return "tasks=%d active_tasks=%d queued_tasks=%d proxy_tasks=%d findings=%d console=%d agent_queue=%d active_threads=%d refresh_pending=%s dirty=%s" % (
                total_tasks, active_tasks, queued_tasks, proxy_tasks, findings_count, console_count,
                agent_count, int(getattr(self, "_active_analysis_threads", 0)),
                str(getattr(self, "_refresh_pending", False)), str(getattr(self, "_ui_dirty", False)))
        except Exception as e:
            return "snapshot_error=%s" % self._safe_ascii_text(e, 200)

    def _navigate_to_url(self, url):
        """Navigate to a URL in Burp Suite by searching proxy history"""
        try:
            self.stdout.println("[FINDINGS] Navigating to: %s" % url[:80])

            # Search proxy history for matching URL
            history = self.callbacks.getProxyHistory()
            if not history:
                self.stdout.println("[FINDINGS] No proxy history available")
                return

            # Look for exact match first, then partial
            best_match = None
            for entry in reversed(history):  # Start from most recent
                try:
                    req = self.helpers.analyzeRequest(entry)
                    entry_url = str(req.getUrl())
                    if entry_url == url:
                        best_match = entry
                        break
                    # Partial match: URL contains our target
                    if url in entry_url or entry_url in url:
                        if not best_match:
                            best_match = entry
                except:
                    continue

            if best_match:
                # Send to Repeater
                http_service = best_match.getHttpService()
                request = best_match.getRequest()
                if http_service and request:
                    self.callbacks.sendToRepeater(
                        http_service.getHost(),
                        http_service.getPort(),
                        http_service.getProtocol() == "https",
                        request,
                        "Double Agent Finding"
                    )
                    self.stdout.println("[FINDINGS] Sent to Repeater: %s" % url[:60])
            else:
                self.stdout.println("[FINDINGS] Request not found in proxy history")
                # Try to open URL in browser as fallback
                try:
                    from java.awt import Desktop
                    from java.net import URI
                    if Desktop.isDesktopSupported():
                        Desktop.getDesktop().browse(URI(url))
                        self.stdout.println("[FINDINGS] Opened in browser")
                except:
                    pass

        except Exception as e:
            self.stderr.println("[FINDINGS] Navigation error: %s" % self._safe_ascii_text(e))

    def _normalize_finding_key(self, title):
        """Extract significant words from a finding title for fuzzy dedup."""
        title = str(title or "").lower()
        # Remove common filler words and punctuation
        noise = set(["in", "the", "a", "an", "of", "on", "for", "with", "and", "or",
                      "to", "is", "are", "be", "by", "as", "at", "from", "via", "into",
                      "not", "no", "its", "it", "this", "that", "has", "have", "been",
                      "may", "can", "could", "should", "will", "would", "does", "do",
                      "between", "through", "during", "before", "after", "using",
                      "request", "response", "endpoint", "header", "body", "found",
                      "detected", "identified", "observed", "exposed", "present",
                      "potential", "possible", "string", "value", "field", "data",
                      "api", "url", "path", "query", "parameter", "parameters"])
        # Strip punctuation
        clean = re.sub(r'[^a-z0-9\s]', ' ', title)
        words = set(w for w in clean.split() if w and len(w) > 2 and w not in noise)
        return frozenset(words)

    def _canonical_scanner_title(self, title):
        title_l = str(title or "").lower()
        title_l = title_l.replace("(burp scanner)", "")
        title_l = re.sub(r'[^a-z0-9\s]', ' ', title_l)
        title_l = re.sub(r'\s+', ' ', title_l).strip()
        # Burp emits variants such as "Cross-origin resource sharing
        # (reflected)"; these are one scanner issue class for reporting.
        if title_l.startswith("cross origin resource sharing"):
            return "cross origin resource sharing"
        return title_l

    def _canonical_finding_family(self, title, cwe="", detail="", evidence=""):
        text = " ".join([str(title or ""), str(cwe or ""), str(detail or ""), str(evidence or "")]).lower()
        text = text.replace("_", " ").replace("-", " ")
        cwe_l = str(cwe or "").lower()
        cwe_map = {
            "79": "xss",
            "89": "sql_injection",
            "22": "path_traversal",
            "352": "csrf",
            "918": "ssrf",
            "601": "open_redirect",
            "639": "idor",
            "862": "missing_authorization",
            "863": "incorrect_authorization",
            "200": "information_disclosure",
            "209": "verbose_error",
            "614": "cookie_secure_flag",
            "1004": "cookie_httponly_flag",
            "693": "security_header",
            "942": "cors",
        }
        m = re.search(r'cwe\D*(\d+)', cwe_l)
        if m and m.group(1) in cwe_map:
            return cwe_map[m.group(1)]

        rules = [
            ("jwt_expiration", ["jwt bearer token missing expiration", "jwt access token lacks expiration", "missing expiration claim", "lacks expiration claim", "expiration exp claim", "exp claim", "no exp claim", "missing exp"]),
            ("jwt_claim_ordering", ["nbf iat ordering", "not before issued at", "anomalous nbf", "anomalous iat"]),
            ("idor", ["idor", "object level authorization", "bola", "unauthorized object", "ownership check", "cross user", "other user"]),
            ("missing_authorization", ["missing authorization", "unauthorized access", "access control", "authorization bypass", "privilege escalation"]),
            ("xss", ["cross site scripting", "xss", "script injection", "javascript execution", "dom xss"]),
            ("sql_injection", ["sql injection", "sqli", "database error", "sql syntax"]),
            ("ssrf", ["server side request forgery", "ssrf", "external service request"]),
            ("csrf", ["cross site request forgery", "csrf", "anti csrf", "missing csrf"]),
            ("open_redirect", ["open redirect", "unvalidated redirect", "redirect parameter"]),
            ("path_traversal", ["path traversal", "directory traversal", "../", "file inclusion"]),
            ("cors", ["cross origin resource sharing", "cors", "access control allow origin"]),
            ("missing_csp", ["content security policy", "missing csp", "csp not enforced"]),
            ("missing_hsts", ["strict transport security", "hsts"]),
            ("x_frame_options", ["x frame options", "clickjacking", "frame options"]),
            ("x_content_type_options", ["x content type options", "nosniff"]),
            ("referrer_policy", ["referrer policy"]),
            ("permissions_policy", ["permissions policy", "feature policy"]),
            ("cookie_httponly_flag", ["httponly", "http only"]),
            ("cookie_secure_flag", ["cookie secure", "secure flag", "set cookie without secure"]),
            ("cookie_samesite_flag", ["samesite", "same site"]),
            ("token_in_url", ["token in url", "token in query", "credential in url", "api key in url", "password in url"]),
            ("secret_exposure", ["hardcoded secret", "api key", "secret key", "credential exposure", "password disclosure", "private key"]),
            ("verbose_error", ["verbose error", "stack trace", "debug error", "exception disclosure"]),
            ("information_disclosure", ["information disclosure", "sensitive data", "pii", "internal path", "server banner", "version disclosure"]),
            ("rate_limit", ["rate limit", "rate limiting", "brute force", "enumeration"]),
        ]
        for family, needles in rules:
            for needle in needles:
                if needle in text:
                    return family

        key = self._normalize_finding_key(title)
        if key:
            return "title_" + "_".join(sorted(list(key))[:4])
        return ""

    def _url_host(self, url):
        try:
            try:
                from urlparse import urlparse as _urlparse
            except ImportError:
                from urllib.parse import urlparse as _urlparse
            return (_urlparse(str(url or "")).hostname or "").lower()
        except:
            return ""
