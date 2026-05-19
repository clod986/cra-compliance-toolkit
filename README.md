# **CRA Compliance Toolkit & SBOM Generator**

An automated, multi-language Software Bill of Materials (SBOM) generator designed to help software projects comply with the European **Cyber Resilience Act (CRA)**.

This toolkit automatically scans your project, generates a valid CycloneDX 1.5 JSON file, and performs a strict legal audit on cryptographic hashes, publisher attributions, and open-source licenses (Copyleft vs. Permissive).

## **Features**

* **Multi-Language Support:** Automatically detects and parses package-lock.json (Node/Vue/React), composer.lock (PHP/Laravel), and conan.lock (C/C++).  
* **CRA Security Audit:** Validates the presence of cryptographic hashes (SHA-1, SHA-512) for Supply Chain Integrity.  
* **Commercial License Scanner:** Flags restrictive Copyleft licenses (GPL, AGPL) that might pose a legal risk to closed-source commercial software.  
* **AI-Ready:** Includes a unified system prompt to integrate seamlessly with Claude Code, OpenAI Codex, Cursor, and GitHub Copilot.

## **🚀 Installation (For Existing Projects)**

The best way to integrate this toolkit into your existing projects while staying **DRY** (Don't Repeat Yourself) is by using a Git Submodule.

### **Step 1: Add the Submodule**

Run the following command in the root directory of your project:

```git submodule add https://github.com/clod986/cra-compliance-toolkit.git .cra-tools```

### **Step 2: Create the Configuration File**

Create a cra-config.json file in the root of your project to explicitly declare the software manufacturer (required by CRA):
```
{  
  "name": "my-project-name",  
  "publisher": "My Company Ltd.",  
  "authors": [  
    "Developer Name 1",  
    "Developer Name 2"  
  ]  
}
```

### **Step 3: Automate via Package Manager**

To ensure the SBOM is generated automatically every time dependencies change, add the script to your package manager's post-install hooks.

**For PHP (Composer):**

Add this to your `composer.json`:
```
"scripts": {  
    "post-install-cmd": [  
        "python .cra-tools/sbom_generator.py"  
    ],  
    "post-update-cmd": [  
        "python .cra-tools/sbom_generator.py"  
    ]  
}
```
**For Node.js (npm):**

Add this to your `package.json`:
```
"scripts": {  
    "postinstall": "python .cra-tools/sbom_generator.py"  
}
```
## **🤖 AI Agent Integration**

This toolkit is designed to turn your AI coding assistants into **Compliance Officers**. We use a single, unified ruleset (`ai_compliance_rules.md`) that works across all major AI assistants.

* **GitHub Copilot / VS Code:** Copy the file `ai_compliance_rules.md` from the `.cra-tools/` folder to `.github/copilot-instructions.md` in your project's root.  
* **Claude Code:** Copy the file `ai_compliance_rules.md` from the `.cra-tools/` folder to `CLAUDE.md` in your project's root.  
* **Cursor IDE:** Copy the content of `ai_compliance_rules.md` directly into your `.cursorrules` file in your project's root.

Once copied, simply type `/sbom` in your AI chat, or ask it to install a new library. The AI will automatically know how to run the compliance checks\!

## **🔄 Updating the Toolkit**

When new CRA regulations are introduced, simply pull the latest changes across all your projects by running:
```
git submodule update --remote  
```
