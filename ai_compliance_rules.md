# Global AI Compliance Rules: Cyber Resilience Act (CRA)

This project must comply with the European Union's Cyber Resilience Act (CRA) and strictly adhere to "Security by Design" principles.

These rules apply to ALL AI Assistants (Claude Code, GitHub Copilot, Cursor, etc.) working in this repository.

## 1. General Security & Compliance Rules

- **No Hardcoding:** Never suggest or write code that contains hardcoded credentials, API tokens, passwords, or plain-text keys. Always suggest using `.env` or configuration files.

- **Secure Local Storage:** If local data persistence is required, never use plain-text storage (such as unencrypted SQLite or local files). Ensure proper encryption.

- **Dependency Transparency:** Every third-party library introduced must be tracked and validated.

## 2. Platform-Specific Agent Workflows

**🤖 If you are CLAUDE CODE (CLI):**
Whenever the user asks you to "Add a dependency", "Update a library", or runs the `/sbom` command, you must:

1. Run the appropriate installation command (e.g., `npm install` or `composer require`).

2. **Immediately and automatically** execute the Python script:
```python .cra-tools/sbom_generator.py```

3. Quickly parse the generated `sbom-*.json` output and report if there are any critical licensing or security issues.

4. If the user types `/sbom` or "generate SBOM", run the generator script directly without asking.

**💻 If you are GITHUB COPILOT / IDE Assistant:**

- **Dependency Alerts:** When suggesting code that introduces a new package, append this message to your response:

**⚠️ CRA Compliance:** Please update the SBOM! Run `python .cra-tools/sbom_generator.py` in your terminal.

- **Shortcut Command:** If the user types `/sbom` or "@workspace generate SBOM", reply exclusively with a markdown terminal code block containing:
  ```python .cra-tools/sbom_generator.py```


This allows the user to click the "Run in Terminal" button instantly.

## 3. Compliance Commands Reference

**Run Audit & Generate SBOM:** python `.cra-tools/sbom_generator.py`

**Output File Format:** CycloneDX 1.5 JSON (Machine-readable)

**Primary Publisher Contact:** [Your Company / Publisher Name]
