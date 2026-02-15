#!/usr/bin/env python3
"""
Threat Indicators Manager
Helper script to add, remove, and validate threat indicators in JSON configuration
"""

import json
import argparse
from pathlib import Path
from typing import List


class IndicatorManager:
    """Manages threat indicators JSON file"""
    
    def __init__(self, config_file: str = "threat_indicators.json"):
        self.config_file = Path(config_file)
        self.load_config()
    
    def load_config(self):
        """Load existing configuration"""
        if not self.config_file.exists():
            print(f"[!] Configuration file not found: {self.config_file}")
            print("[*] Creating new configuration file...")
            self.config = {}
            self.save_config()
        else:
            with open(self.config_file, 'r') as f:
                self.config = json.load(f)
            print(f"[+] Loaded configuration from {self.config_file}")
    
    def save_config(self):
        """Save configuration to file"""
        with open(self.config_file, 'w') as f:
            json.dump(self.config, f, indent=2)
        print(f"[+] Configuration saved to {self.config_file}")
    
    def list_categories(self):
        """List all available categories"""
        print("\n=== Available Categories ===")
        for i, category in enumerate(sorted(self.config.keys()), 1):
            print(f"{i}. {category}")
        print()
    
    def add_indicator(self, category: str, value: str, subcategory: str = None):
        """Add a new indicator to a category"""
        if category not in self.config:
            print(f"[!] Category '{category}' not found. Creating new category...")
            if subcategory:
                self.config[category] = {}
            else:
                self.config[category] = []
        
        if subcategory:
            # Nested structure like suspicious_processes
            if subcategory not in self.config[category]:
                self.config[category][subcategory] = []
            
            if value not in self.config[category][subcategory]:
                self.config[category][subcategory].append(value)
                print(f"[+] Added '{value}' to {category}/{subcategory}")
            else:
                print(f"[!] '{value}' already exists in {category}/{subcategory}")
        else:
            # Simple list structure
            if isinstance(self.config[category], list):
                if value not in self.config[category]:
                    self.config[category].append(value)
                    print(f"[+] Added '{value}' to {category}")
                else:
                    print(f"[!] '{value}' already exists in {category}")
            else:
                print(f"[!] Category '{category}' has nested structure. Use --subcategory")
        
        self.save_config()
    
    def remove_indicator(self, category: str, value: str, subcategory: str = None):
        """Remove an indicator from a category"""
        if category not in self.config:
            print(f"[!] Category '{category}' not found")
            return
        
        if subcategory:
            if subcategory in self.config[category]:
                if value in self.config[category][subcategory]:
                    self.config[category][subcategory].remove(value)
                    print(f"[+] Removed '{value}' from {category}/{subcategory}")
                    self.save_config()
                else:
                    print(f"[!] '{value}' not found in {category}/{subcategory}")
            else:
                print(f"[!] Subcategory '{subcategory}' not found in {category}")
        else:
            if isinstance(self.config[category], list):
                if value in self.config[category]:
                    self.config[category].remove(value)
                    print(f"[+] Removed '{value}' from {category}")
                    self.save_config()
                else:
                    print(f"[!] '{value}' not found in {category}")
            else:
                print(f"[!] Category '{category}' has nested structure. Use --subcategory")
    
    def search_indicator(self, search_term: str):
        """Search for an indicator across all categories"""
        print(f"\n=== Searching for '{search_term}' ===")
        found = False
        
        def search_dict(d, path=""):
            nonlocal found
            for key, value in d.items():
                current_path = f"{path}/{key}" if path else key
                
                if isinstance(value, dict):
                    search_dict(value, current_path)
                elif isinstance(value, list):
                    for item in value:
                        if search_term.lower() in str(item).lower():
                            print(f"  Found in {current_path}: {item}")
                            found = True
                elif search_term.lower() in str(value).lower():
                    print(f"  Found in {current_path}: {value}")
                    found = True
        
        search_dict(self.config)
        
        if not found:
            print(f"  No matches found for '{search_term}'")
        print()
    
    def list_indicators(self, category: str, subcategory: str = None):
        """List all indicators in a category"""
        if category not in self.config:
            print(f"[!] Category '{category}' not found")
            return
        
        print(f"\n=== {category} ===")
        
        if subcategory:
            if subcategory in self.config[category]:
                items = self.config[category][subcategory]
                for i, item in enumerate(items, 1):
                    print(f"{i}. {item}")
            else:
                print(f"[!] Subcategory '{subcategory}' not found")
        else:
            data = self.config[category]
            if isinstance(data, list):
                for i, item in enumerate(data, 1):
                    print(f"{i}. {item}")
            elif isinstance(data, dict):
                for subcat, items in data.items():
                    print(f"\n  {subcat}:")
                    for item in items:
                        print(f"    - {item}")
        print()
    
    def import_from_file(self, import_file: str, category: str, subcategory: str = None):
        """Import indicators from a text file (one per line)"""
        import_path = Path(import_file)
        if not import_path.exists():
            print(f"[!] Import file not found: {import_file}")
            return
        
        with open(import_path, 'r') as f:
            lines = [line.strip() for line in f if line.strip() and not line.startswith('#')]
        
        added = 0
        for line in lines:
            if subcategory:
                if category not in self.config:
                    self.config[category] = {}
                if subcategory not in self.config[category]:
                    self.config[category][subcategory] = []
                
                if line not in self.config[category][subcategory]:
                    self.config[category][subcategory].append(line)
                    added += 1
            else:
                if category not in self.config:
                    self.config[category] = []
                
                if line not in self.config[category]:
                    self.config[category].append(line)
                    added += 1
        
        print(f"[+] Imported {added} new indicators into {category}" + (f"/{subcategory}" if subcategory else ""))
        self.save_config()
    
    def validate_config(self):
        """Validate configuration structure"""
        print("\n=== Validating Configuration ===")
        errors = []
        warnings = []
        
        # Check for empty categories
        for category, value in self.config.items():
            if isinstance(value, list) and len(value) == 0:
                warnings.append(f"Empty category: {category}")
            elif isinstance(value, dict):
                for subcat, items in value.items():
                    if len(items) == 0:
                        warnings.append(f"Empty subcategory: {category}/{subcat}")
        
        # Check for duplicates
        for category, value in self.config.items():
            if isinstance(value, list):
                if len(value) != len(set(value)):
                    duplicates = [x for x in value if value.count(x) > 1]
                    errors.append(f"Duplicates in {category}: {set(duplicates)}")
            elif isinstance(value, dict):
                for subcat, items in value.items():
                    if len(items) != len(set(items)):
                        duplicates = [x for x in items if items.count(x) > 1]
                        errors.append(f"Duplicates in {category}/{subcat}: {set(duplicates)}")
        
        if errors:
            print("\nERRORS:")
            for error in errors:
                print(f"  [!] {error}")
        
        if warnings:
            print("\nWARNINGS:")
            for warning in warnings:
                print(f"  [*] {warning}")
        
        if not errors and not warnings:
            print("[+] Configuration is valid!")
        
        print()
        return len(errors) == 0
    
    def export_category(self, category: str, output_file: str):
        """Export a category to a text file"""
        if category not in self.config:
            print(f"[!] Category '{category}' not found")
            return
        
        with open(output_file, 'w') as f:
            data = self.config[category]
            if isinstance(data, list):
                for item in data:
                    f.write(f"{item}\n")
            elif isinstance(data, dict):
                for subcat, items in data.items():
                    f.write(f"# {subcat}\n")
                    for item in items:
                        f.write(f"{item}\n")
                    f.write("\n")
        
        print(f"[+] Exported {category} to {output_file}")


def main():
    parser = argparse.ArgumentParser(
        description="Manage threat indicators for DFIR investigation tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # List all categories
  python indicator_manager.py --list-categories

  # Add a ransomware extension
  python indicator_manager.py --add -c ransomware_extensions -v .newvariant

  # Add a credential theft tool
  python indicator_manager.py --add -c suspicious_processes -s credential_theft -v newtool.exe

  # Remove an indicator
  python indicator_manager.py --remove -c ransomware_extensions -v .oldvariant

  # Search for an indicator
  python indicator_manager.py --search mimikatz

  # List indicators in a category
  python indicator_manager.py --list -c ransomware_extensions

  # Import indicators from file
  python indicator_manager.py --import indicators.txt -c ransomware_extensions

  # Validate configuration
  python indicator_manager.py --validate

  # Export category to file
  python indicator_manager.py --export -c ransomware_extensions -o ransomware.txt
        """
    )
    
    parser.add_argument('-f', '--file', default='threat_indicators.json',
                       help='Path to threat indicators JSON file')
    parser.add_argument('--list-categories', action='store_true',
                       help='List all available categories')
    parser.add_argument('--add', action='store_true',
                       help='Add a new indicator')
    parser.add_argument('--remove', action='store_true',
                       help='Remove an indicator')
    parser.add_argument('--search', metavar='TERM',
                       help='Search for an indicator')
    parser.add_argument('--list', action='store_true',
                       help='List indicators in a category')
    parser.add_argument('--import', dest='import_file', metavar='FILE',
                       help='Import indicators from text file')
    parser.add_argument('--export', action='store_true',
                       help='Export category to text file')
    parser.add_argument('--validate', action='store_true',
                       help='Validate configuration')
    parser.add_argument('-c', '--category', help='Category name')
    parser.add_argument('-s', '--subcategory', help='Subcategory name (for nested structures)')
    parser.add_argument('-v', '--value', help='Indicator value')
    parser.add_argument('-o', '--output', help='Output file')
    
    args = parser.parse_args()
    
    manager = IndicatorManager(args.file)
    
    if args.list_categories:
        manager.list_categories()
    elif args.add:
        if not args.category or not args.value:
            print("[!] --add requires --category and --value")
        else:
            manager.add_indicator(args.category, args.value, args.subcategory)
    elif args.remove:
        if not args.category or not args.value:
            print("[!] --remove requires --category and --value")
        else:
            manager.remove_indicator(args.category, args.value, args.subcategory)
    elif args.search:
        manager.search_indicator(args.search)
    elif args.list:
        if not args.category:
            print("[!] --list requires --category")
        else:
            manager.list_indicators(args.category, args.subcategory)
    elif args.import_file:
        if not args.category:
            print("[!] --import requires --category")
        else:
            manager.import_from_file(args.import_file, args.category, args.subcategory)
    elif args.export:
        if not args.category or not args.output:
            print("[!] --export requires --category and --output")
        else:
            manager.export_category(args.category, args.output)
    elif args.validate:
        manager.validate_config()
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
