import json
import os
import uuid
import sys
import subprocess
import getpass
from datetime import datetime

# ==============================================================================
# MULTI-LANGUAGE SBOM GENERATOR WITH CRA COMPLIANCE & LICENSE AUDIT ENGINE
# Author: Claudio Petrarulo
# Intellectual Property: Maintained by the author, open for future developments
# Standard: CycloneDX 1.5 JSON (Machine-readable)
# ==============================================================================

# Codici colore ANSI per output a terminale
CLR_RESET = "\033[0m"
CLR_RED = "\033[91m"
CLR_GREEN = "\033[92m"
CLR_YELLOW = "\033[93m"
CLR_BLUE = "\033[94m"
CLR_CYAN = "\033[96m"
CLR_BOLD = "\033[1m"


class BaseParser:
    """Classe base per parser specifici per linguaggio."""
    def __init__(self, filepath):
        self.filepath = filepath
        self.components = []

    def can_parse(self):
        return os.path.exists(self.filepath)

    def parse(self):
        raise NotImplementedError("The parse() method must be implemented in the subclass.")

    def read_json(self):
        try:
            with open(self.filepath, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception as e:
            print(f"{CLR_RED}Error reading {self.filepath}: {e}{CLR_RESET}")
            return None


class NpmParser(BaseParser):
    """Parser per progetti Node.js, Vue.js, React (package-lock.json)"""
    def __init__(self):
        super().__init__('package-lock.json')

    def parse(self):
        print(f"{CLR_CYAN}🔍 Detected Node.js/Vue.js project. Analyzing package-lock.json...{CLR_RESET}")
        data = self.read_json()
        if not data: return []

        dependencies = data.get("packages", data.get("dependencies", {}))
        for pkg_path, pkg_info in dependencies.items():
            if not pkg_path or not isinstance(pkg_info, dict) or pkg_info.get("dev", False):
                continue
            
            pkg_name = pkg_path.split("node_modules/")[-1]
            version = pkg_info.get("version", "unknown")
            
            hashes = []
            integrity = pkg_info.get("integrity", "")
            if integrity.startswith("sha512-"):
                hashes.append({"alg": "SHA-512", "content": integrity.replace("sha512-", "")})
            elif integrity.startswith("sha1-"):
                hashes.append({"alg": "SHA-1", "content": integrity.replace("sha1-", "")})

            self.components.append({
                "type": "library",
                "name": pkg_name,
                "version": version,
                "purl": f"pkg:npm/{pkg_name}@{version}",
                "hashes": hashes
            })
        return self.components


class ComposerParser(BaseParser):
    """Parser per progetti PHP/Laravel (composer.lock)"""
    def __init__(self):
        super().__init__('composer.lock')

    def parse(self):
        print(f"{CLR_CYAN}🔍 Detected Laravel/PHP project. Analyzing composer.lock...{CLR_RESET}")
        data = self.read_json()
        if not data: return []

        for pkg in data.get("packages", []):
            name = pkg.get("name", "unknown")
            version = pkg.get("version", "unknown")
            
            hashes = []
            # Estrazione sicura hash da composer.lock
            shasum = pkg.get("dist", {}).get("shasum")
            reference = pkg.get("dist", {}).get("reference") or pkg.get("source", {}).get("reference")
            
            if shasum and shasum.strip() != "":
                hashes.append({"alg": "SHA-1", "content": shasum})
            elif reference and len(reference) == 40:
                hashes.append({"alg": "SHA-1", "content": reference})

            # Estrazione Licenze
            licenses = []
            for lic in pkg.get("license", []):
                licenses.append({"license": {"name": lic}})

            self.components.append({
                "type": "library",
                "name": name,
                "version": version,
                "purl": f"pkg:composer/{name}@{version}",
                "hashes": hashes,
                "licenses": licenses
            })
        return self.components


class ConanParser(BaseParser):
    """Parser per progetti Native/C++ (conan.lock)"""
    def __init__(self):
        super().__init__('conan.lock')

    def parse(self):
        print(f"{CLR_CYAN}🔍 Detected Native/C++ project. Analyzing conan.lock...{CLR_RESET}")
        data = self.read_json()
        if not data: return []
        
        graph = data.get("graph_lock", {}).get("nodes", {})
        for node_id, node_info in graph.items():
            ref = node_info.get("ref", "")
            if not ref or "/" not in ref:
                continue
            
            name, version_part = ref.split("/", 1)
            version = version_part.split("#")[0] if "#" in version_part else version_part

            self.components.append({
                "type": "library",
                "name": name,
                "version": version,
                "purl": f"pkg:conan/{name}@{version}",
                "hashes": []  
            })
        return self.components


class SbomGenerator:
    """Orchestratore che aggrega i risultati, genera file CycloneDX ed esegue audit."""
    def __init__(self):
        self.output_file = ""
        self.parsers = [NpmParser(), ComposerParser(), ConanParser()]
        self.all_components = []

    def get_project_metadata(self):
        metadata = {
            "name": os.path.basename(os.path.abspath(".")),
            "version": "",
            "publisher": "",
            "authors": [],
            "_source_name": "Root folder name",
            "_source_version": "Not found",
            "_source_publisher": "Not found",
            "_source_authors": "Not found"
        }
        
        # Carica dati grezzi dai manifesti se esistono
        pkg_data = {}
        comp_data = {}
        
        if os.path.exists("package.json"):
            try:
                with open("package.json", "r", encoding="utf-8") as f:
                    pkg_data = json.load(f)
            except Exception: pass
            
        if os.path.exists("composer.json"):
            try:
                with open("composer.json", "r", encoding="utf-8") as f:
                    comp_data = json.load(f)
            except Exception: pass

        invalid_names = ["backend", "frontend", "app", "root", "project", "server", "client", "laravel/laravel", "vue/cli", "react-app"]

        # --- ESTRAZIONE SVILUPPARATORI (Authors/Contributors) ---
        comp_authors_raw = comp_data.get("authors", [])
        pkg_author_raw = pkg_data.get("author", "")
        pkg_contrib_raw = pkg_data.get("contributors", [])
        
        authors_list = []
        if isinstance(comp_authors_raw, list):
            for a in comp_authors_raw:
                if isinstance(a, dict) and a.get("name"):
                    authors_list.append({"name": a.get("name")})
                elif isinstance(a, str):
                    authors_list.append({"name": a})
                    
        if pkg_author_raw:
            if isinstance(pkg_author_raw, dict) and pkg_author_raw.get("name"):
                authors_list.append({"name": pkg_author_raw.get("name")})
            elif isinstance(pkg_author_raw, str):
                authors_list.append({"name": pkg_author_raw})
                
        if isinstance(pkg_contrib_raw, list):
            for c in pkg_contrib_raw:
                if isinstance(c, dict) and c.get("name"):
                    authors_list.append({"name": c.get("name")})
                elif isinstance(c, str):
                    authors_list.append({"name": c})

        # Rimuove duplicati dagli sviluppatori
        seen = set()
        unique_authors = []
        for a in authors_list:
            if a["name"] not in seen:
                seen.add(a["name"])
                unique_authors.append(a)
                
        metadata["authors"] = unique_authors
        if unique_authors:
            metadata["_source_authors"] = "Manifest fields (authors/contributors)"

        # --- ESTRAZIONE AZIENDA/PUBLISHER ---
        # Priorità: Campo custom 'publisher' -> Primo sviluppatore in lista come fallback
        comp_publisher = comp_data.get("publisher", "")
        pkg_publisher = pkg_data.get("publisher", "")
        
        if comp_publisher:
            metadata["publisher"] = comp_publisher
            metadata["_source_publisher"] = "composer.json (custom 'publisher' field)"
        elif pkg_publisher:
            metadata["publisher"] = pkg_publisher
            metadata["_source_publisher"] = "package.json (custom 'publisher' field)"
        elif unique_authors:
            metadata["publisher"] = unique_authors[0]["name"]
            metadata["_source_publisher"] = "Fallback to first author in manifest"

        # --- ESTRAZIONE VERSIONE ---
        comp_version = comp_data.get("version", "")
        pkg_version = pkg_data.get("version", "")
        
        if comp_version:
            metadata["version"] = comp_version
            metadata["_source_version"] = "composer.json ('version' field)"
        elif pkg_version:
            metadata["version"] = pkg_version
            metadata["_source_version"] = "package.json ('version' field)"

        # --- ESTRAZIONE NOME ---
        comp_name = comp_data.get("name", "")
        pkg_name = pkg_data.get("name", "")
        
        if comp_name and comp_name.lower() not in invalid_names:
            metadata["name"] = comp_name
            metadata["_source_name"] = "composer.json ('name' field)"
        elif pkg_name and pkg_name.lower() not in invalid_names:
            metadata["name"] = pkg_name
            metadata["_source_name"] = "package.json ('name' field)"
        elif comp_name:
            metadata["name"] = comp_name
            metadata["_source_name"] = "composer.json ('name' field)"
        elif pkg_name:
            metadata["name"] = pkg_name
            metadata["_source_name"] = "package.json ('name' field)"

        # --- FALLBACK DINAMICI ---
        
        # 1. Fallback Publisher -> Git user.name
        if not metadata["publisher"]:
            try:
                git_name = subprocess.check_output(['git', 'config', 'user.name'], stderr=subprocess.DEVNULL).decode('utf-8').strip()
                if git_name:
                    metadata["publisher"] = git_name
                    metadata["_source_publisher"] = "Local Git (git config user.name)"
            except Exception:
                pass
                
        # 2. Fallback Publisher -> Variabili OS
        if not metadata["publisher"]:
            metadata["publisher"] = os.getenv("CRA_PUBLISHER", "")
            if metadata["publisher"]:
                metadata["_source_publisher"] = "Environment variable (CRA_PUBLISHER)"
            else:
                try:
                    metadata["publisher"] = getpass.getuser()
                    metadata["_source_publisher"] = "OS System User (getpass)"
                except Exception:
                    metadata["publisher"] = "Unknown-Author"
                    metadata["_source_publisher"] = "Hardcoded fallback (No source found)"
                    
        # 3. Fallback Versione -> Git tags / commit hash
        if not metadata["version"]:
            try:
                git_version = subprocess.check_output(['git', 'describe', '--tags', '--always'], stderr=subprocess.DEVNULL).decode('utf-8').strip()
                if git_version:
                    metadata["version"] = git_version
                    metadata["_source_version"] = "Local Git (git describe)"
            except Exception:
                pass
                
        # 4. Fallback Versione -> Variabili OS
        if not metadata["version"]:
            metadata["version"] = os.getenv("CRA_VERSION", "")
            if metadata["version"]:
                metadata["_source_version"] = "Environment variable (CRA_VERSION)"
            else:
                metadata["version"] = "0.0.0-unknown"
                metadata["_source_version"] = "Hardcoded fallback (No source found)"
                    
        # --- Auto-correzione Nomi Generici ---
        if metadata["name"].lower() in invalid_names and metadata["publisher"] not in ["", "Unknown-Author"]:
            safe_pub = metadata["publisher"].lower().replace(" ", "-").replace(".", "").replace(",", "")
            original_name = metadata["name"]
            metadata["name"] = f"{safe_pub}/{original_name}"
            metadata["_source_name"] += " (Auto-corrected dynamically with publisher prefix)"
                
        return metadata

    def run(self):
        print(f"\n{CLR_BOLD}=== STARTING SBOM GENERATOR ENGINE (CRA COMPLIANCE) ==={CLR_RESET}")
        
        for parser in self.parsers:
            if parser.can_parse():
                components = parser.parse()
                self.all_components.extend(components)

        if not self.all_components:
            print(f"{CLR_RED}❌ Error: No supported dependency manifest file (package-lock.json, composer.lock, conan.lock) found in the current directory.{CLR_RESET}")
            sys.exit(1)

        self.generate_cyclonedx()

    def generate_cyclonedx(self):
        project_meta = self.get_project_metadata()
        
        safe_proj_name = project_meta['name'].replace("/", "-").replace("\\", "-").replace(" ", "")
        self.output_file = f"sbom-{safe_proj_name}.json"
        
        # Estrae i nomi degli sviluppatori per mostrarli a terminale
        developer_names = [a["name"] for a in project_meta['authors']]
        dev_string = ", ".join(developer_names) if developer_names else "None mapped"

        print(f"\n{CLR_BOLD}=== METADATA SOURCES TRACKING ==={CLR_RESET}")
        print(f"📦 {CLR_BOLD}Project Name:{CLR_RESET} {project_meta['name']} {CLR_CYAN}(Source: {project_meta['_source_name']}){CLR_RESET}")
        print(f"🏷️  {CLR_BOLD}Version:{CLR_RESET} {project_meta['version']} {CLR_CYAN}(Source: {project_meta['_source_version']}){CLR_RESET}")
        print(f"🏢 {CLR_BOLD}Publisher (Company):{CLR_RESET} {project_meta['publisher']} {CLR_CYAN}(Source: {project_meta['_source_publisher']}){CLR_RESET}")
        print(f"👨‍💻 {CLR_BOLD}Authors (Developers):{CLR_RESET} {dev_string} {CLR_CYAN}(Source: {project_meta['_source_authors']}){CLR_RESET}")
        print(f"----------------------------------------------------------------------")
        
        # Nodo Componente Principale
        component_node = {
            "type": "application",
            "publisher": project_meta["publisher"],
            "name": project_meta["name"],
            "version": project_meta["version"]
        }
        
        # Inserisce l'array authors solo se esistono sviluppatori tracciati
        if project_meta["authors"]:
            component_node["authors"] = project_meta["authors"]
        
        sbom = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "serialNumber": f"urn:uuid:{uuid.uuid4()}",
            "version": 1,
            "metadata": {
                "timestamp": datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ'),
                "tools": {
                    "components": [{
                        "type": "application",
                        "author": "Claudio Petrarulo",
                        "name": "CRA Multi-Language SBOM Generator",
                        "version": "2.7"
                    }]
                },
                "component": component_node
            },
            "components": self.all_components
        }

        with open(self.output_file, 'w', encoding='utf-8') as f:
            json.dump(sbom, f, indent=4)
            
        print(f"\n{CLR_GREEN}✅ SBOM successfully generated: {self.output_file}{CLR_RESET}")
        print(f"📊 Total components tracked: {len(self.all_components)}")
        
        # Avvia Audit
        self.execute_cra_audit(sbom)
        self.execute_commercial_audit(sbom)

    def execute_cra_audit(self, sbom):
        """Analyzes the generated SBOM against CRA legal requirements."""
        print(f"\n{CLR_BOLD}======================================================================{CLR_RESET}")
        print(f"🛡️  {CLR_BOLD}{CLR_BLUE}CYBER RESILIENCE ACT (CRA) COMPLIANCE AUDIT - REPORT{CLR_RESET}")
        print(f"{CLR_BOLD}======================================================================{CLR_RESET}")
        
        errors = 0
        warnings = 0
        
        # 1. Publisher Check
        publisher = sbom["metadata"]["component"].get("publisher", "")
        if publisher in ["Unknown-Author", "Unknown", "", None]:
            print(f"[{CLR_RED}❌{CLR_RESET}] {CLR_BOLD}PUBLISHER IDENTIFICATION: FAILED{CLR_RESET}")
            print(f"    {CLR_RED}Reason: The author/publisher is set to '{publisher}'.{CLR_RESET}")
            print(f"    👉 {CLR_YELLOW}Fix: Add a custom 'publisher' field to your package.json or composer.json.{CLR_RESET}")
            errors += 1
        else:
            print(f"[{CLR_GREEN}✔️{CLR_RESET}] PUBLISHER IDENTIFICATION: PASSED ({publisher})")

        # 2. Project Name Check
        proj_name = sbom["metadata"]["component"]["name"]
        invalid_names = ["backend", "frontend", "app", "root", "project", "server", "client", "laravel/laravel", "vue/cli", "react-app"]
        if proj_name.lower() in invalid_names:
            print(f"[{CLR_RED}❌{CLR_RESET}] {CLR_BOLD}INVALID OR DEFAULT PROJECT NAME: FAILED{CLR_RESET}")
            print(f"    {CLR_RED}Reason: The name '{proj_name}' is a generic boilerplate name.{CLR_RESET}")
            print(f"    👉 {CLR_YELLOW}Fix: Change the 'name' field in your manifest to a unique identifier.{CLR_RESET}")
            errors += 1
        else:
            print(f"[{CLR_GREEN}✔️{CLR_RESET}] PROJECT NAME REQUIREMENT: PASSED ({proj_name})")

        # 3. Cryptographic Hashes Check
        total_components = len(sbom["components"])
        missing_hashes = 0
        for comp in sbom["components"]:
            if not comp.get("hashes") or len(comp["hashes"]) == 0:
                missing_hashes += 1

        if missing_hashes > 0:
            percentage = (missing_hashes / total_components) * 100
            print(f"[{CLR_RED}❌{CLR_RESET}] {CLR_BOLD}SUPPLY CHAIN INTEGRITY (HASHES): FAILED{CLR_RESET}")
            print(f"    {CLR_RED}Reason: {missing_hashes} dependencies out of {total_components} ({percentage:.1f}%) are missing cryptographic hashes.{CLR_RESET}")
            print(f"    👉 {CLR_YELLOW}Fix: Ensure your package-lock.json is valid or force recreate the composer.lock.{CLR_RESET}")
            errors += 1
        else:
            print(f"[{CLR_GREEN}✔️{CLR_RESET}] SUPPLY CHAIN INTEGRITY: PASSED (100% of components have verification hashes)")

        # 4. Licenses Check
        missing_licenses = 0
        for comp in sbom["components"]:
            if not comp.get("licenses") or len(comp["licenses"]) == 0:
                missing_licenses += 1
                
        if missing_licenses > 0:
            print(f"[{CLR_YELLOW}⚠️{CLR_RESET}] {CLR_BOLD}OPEN-SOURCE LICENSES MAPPING: INCOMPLETE{CLR_RESET}")
            print(f"    {CLR_YELLOW}Reason: {missing_licenses} dependencies do not declare a valid license.{CLR_RESET}")
            print(f"    👉 {CLR_YELLOW}Advice: CRA requires license analysis to prevent legal risks. Verify packages manually.{CLR_RESET}")
            warnings += 1
        else:
            print(f"[{CLR_GREEN}✔️{CLR_RESET}] LICENSES MAPPING: PASSED")

        # Final CRA Report
        print(f"----------------------------------------------------------------------")
        print(f"CRA COMPLIANCE AUDIT RESULT:")
        if errors > 0:
            print(f"🔴 {CLR_BOLD}{CLR_RED}NON-COMPLIANT (FAIL){CLR_RESET} - Found {errors} critical blocking errors and {warnings} warnings.")
            print(f"⚠️  {CLR_YELLOW}Note: An SBOM without digital signatures or legal attributions exposes the company to CRA sanctions.{CLR_RESET}")
        elif warnings > 0:
            print(f"🟡 {CLR_BOLD}{CLR_YELLOW}CONDITIONALLY COMPLIANT (WARNING){CLR_RESET} - Formal compliance achieved with {warnings} minor warnings.")
        else:
            print(f"🟢 {CLR_BOLD}{CLR_GREEN}COMPLIANT (PASS){CLR_RESET} - The SBOM meets all essential CRA audit criteria!")

    def execute_commercial_audit(self, sbom):
        """Analyzes licenses for commercial use viability and dual-licensing payments."""
        print(f"\n{CLR_BOLD}======================================================================{CLR_RESET}")
        print(f"💰  {CLR_BOLD}{CLR_BLUE}COMMERCIAL LICENSE & COPYLEFT AUDIT{CLR_RESET}")
        print(f"{CLR_BOLD}======================================================================{CLR_RESET}")
        
        strict_commercial_risk = ["GPL-1.0", "GPL-2.0", "GPL-3.0", "AGPL-3.0", "SSPL-1.0", "BUSL-1.1", "OSL-3.0"]
        permissive_licenses = ["MIT", "BSD", "APACHE", "ISC", "WTFPL", "ZLIB"]
        
        flagged_components = []
        unknown_components = []
        
        for comp in sbom.get("components", []):
            licenses = comp.get("licenses", [])
            if not licenses:
                unknown_components.append(comp["name"])
                continue
            
            has_strict_license = False
            has_permissive_alternative = False
            
            for lic in licenses:
                lic_name = lic.get("license", {}).get("name", "").upper()
                
                if any(strict.upper() in lic_name for strict in strict_commercial_risk):
                    has_strict_license = True
                
                if any(permissive in lic_name for permissive in permissive_licenses):
                    has_permissive_alternative = True
            
            if has_strict_license and not has_permissive_alternative:
                lic_names = [l.get("license", {}).get("name", "Unknown") for l in licenses]
                flagged_components.append((comp["name"], ", ".join(lic_names)))
        
        if not flagged_components and not unknown_components:
            print(f"[{CLR_GREEN}✔️{CLR_RESET}] {CLR_BOLD}{CLR_GREEN}ALL CLEAR! No commercial or copyleft restrictions detected.{CLR_RESET}")
            print(f"    All used libraries have permissive open-source licenses (like MIT/BSD) or safe dual-licenses.")
            print(f"    You are fully clear to use this software for proprietary commercial purposes without paying license fees.\n")
        else:
            if flagged_components:
                print(f"[{CLR_RED}❌{CLR_RESET}] {CLR_BOLD}COMMERCIAL LICENSE RISK DETECTED{CLR_RESET}")
                print(f"    {CLR_YELLOW}The following libraries use Strict Copyleft or Dual-licenses WITHOUT a permissive alternative.{CLR_RESET}")
                print(f"    {CLR_YELLOW}For proprietary commercial usage, you may need to PURCHASE A COMMERCIAL LICENSE or open-source your code:\n{CLR_RESET}")
                for name, lics in flagged_components:
                    print(f"    - {CLR_RED}{name}{CLR_RESET} (License: {lics})")
            
            if unknown_components:
                print(f"\n[{CLR_YELLOW}⚠️{CLR_RESET}] {CLR_BOLD}UNKNOWN LICENSES{CLR_RESET}")
                print(f"    Could not automatically determine the license for the following libraries. Manual check required:\n")
                for name in unknown_components:
                    print(f"    - {CLR_YELLOW}{name}{CLR_RESET}")
            print("\n")


if __name__ == "__main__":
    generator = SbomGenerator()
    generator.run()
