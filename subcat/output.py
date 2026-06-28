"""
Output module for SubCat.
Provides functionality for outputting results in various formats.
Supports both batch output and streaming (real-time) output.
"""
import os
import json
import csv
import time
import xml.etree.ElementTree as ET
from typing import List, Dict, Any, Optional, TextIO
from pathlib import Path


class OutputFormatter:
    """
    Handles batch formatting and writing of results in various formats.
    Use this for formatting complete result sets at once.
    """

    FORMATS = ['txt', 'json', 'csv', 'xml']

    @staticmethod
    def format_txt(domains: List[str]) -> str:
        """Format domains as plain text, one per line."""
        return '\n'.join(domains) + '\n' if domains else ''

    @staticmethod
    def format_json(data: Dict[str, Any]) -> str:
        """Format data as JSON with proper formatting."""
        return json.dumps(data, indent=2, ensure_ascii=False)

    @staticmethod
    def format_csv(domains: List[Dict[str, Any]], headers: List[str]) -> str:
        """Format domains as CSV with specified headers."""
        import io
        output = io.StringIO()
        writer = csv.DictWriter(output, fieldnames=headers, extrasaction='ignore')
        writer.writeheader()
        writer.writerows(domains)
        return output.getvalue()

    @staticmethod
    def format_xml(data: Dict[str, Any]) -> str:
        """Format data as XML."""
        root = ET.Element("subcat_results")

        # Add metadata
        if 'metadata' in data:
            meta = ET.SubElement(root, "metadata")
            for key, value in data['metadata'].items():
                elem = ET.SubElement(meta, key)
                elem.text = str(value)

        # Add domains
        domains_elem = ET.SubElement(root, "domains")
        for domain_data in data.get('domains', []):
            domain_elem = ET.SubElement(domains_elem, "domain")
            for key, value in domain_data.items():
                elem = ET.SubElement(domain_elem, key)
                if isinstance(value, list):
                    for item in value:
                        item_elem = ET.SubElement(elem, "item")
                        item_elem.text = str(item)
                else:
                    elem.text = str(value)

        # Add count
        count_elem = ET.SubElement(root, "count")
        count_elem.text = str(data.get('count', 0))

        return ET.tostring(root, encoding='unicode', method='xml')

    @classmethod
    def write(cls, data: Dict[str, Any], output_file: str, format_type: Optional[str] = None) -> bool:
        """
        Write data to a file in the specified format.

        :param data: Data dictionary containing domains and metadata
        :param output_file: Output file path
        :param format_type: Format type (if None, determined from file extension)
        :return: True if successful, False otherwise
        """
        try:
            # Determine format from file extension if not specified
            if not format_type:
                _, ext = os.path.splitext(output_file)
                format_type = ext[1:].lower() if ext else 'txt'

            format_type = format_type.lower()
            if format_type not in cls.FORMATS:
                format_type = 'txt'

            # Ensure parent directory exists
            Path(output_file).parent.mkdir(parents=True, exist_ok=True)

            # Format and write the data
            with open(output_file, 'w', encoding='utf-8') as f:
                if format_type == 'txt':
                    domains = [d.get('name', d) if isinstance(d, dict) else d
                              for d in data.get('domains', [])]
                    f.write(cls.format_txt(domains))
                elif format_type == 'json':
                    f.write(cls.format_json(data))
                elif format_type == 'csv':
                    domains = data.get('domains', [])
                    if domains:
                        # Determine headers from first domain
                        headers = list(domains[0].keys()) if isinstance(domains[0], dict) else ['domain']
                        f.write(cls.format_csv(domains, headers))
                elif format_type == 'xml':
                    f.write(cls.format_xml(data))

            return True
        except Exception:
            return False


class StreamingOutputWriter:
    """
    Handles streaming (real-time) output to files.
    Use this when you need to write results as they're discovered.
    """

    def __init__(
        self,
        output_file: str,
        format_type: str = 'txt',
        metadata: Optional[Dict[str, Any]] = None,
        include_fields: Optional[List[str]] = None
    ):
        """
        Initialize streaming output writer.

        :param output_file: Path to output file
        :param format_type: Output format (txt, json, csv, xml)
        :param metadata: Metadata to include in output
        :param include_fields: Fields to include in output (for csv/json)
        """
        self.output_file = output_file
        self.format_type = format_type.lower()
        self.metadata = metadata or {}
        self.include_fields = include_fields or ['name']
        self.file_handle: Optional[TextIO] = None
        self.is_initialized = False
        self.entry_count = 0
        self.start_time = time.time()

        if self.format_type not in OutputFormatter.FORMATS:
            raise ValueError(f"Unsupported format: {self.format_type}")

    def __enter__(self):
        """Context manager entry."""
        self.open()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.close()
        return False

    def open(self):
        """Open the output file and write headers."""
        if self.is_initialized:
            return

        try:
            # Ensure parent directory exists
            Path(self.output_file).parent.mkdir(parents=True, exist_ok=True)

            self.file_handle = open(self.output_file, 'w', encoding='utf-8')
            self._write_header()
            self.is_initialized = True
        except Exception as e:
            raise IOError(f"Failed to open output file: {e}")

    def _write_header(self):
        """Write format-specific header."""
        if not self.file_handle:
            return

        if self.format_type == 'json':
            self.file_handle.write('{\n')
            self.file_handle.write('  "metadata": ')
            self.file_handle.write(json.dumps(self.metadata, indent=4).replace('\n', '\n  '))
            self.file_handle.write(',\n')
            self.file_handle.write('  "domains": [\n')
        elif self.format_type == 'csv':
            writer = csv.DictWriter(self.file_handle, fieldnames=self.include_fields, extrasaction='ignore')
            writer.writeheader()
        elif self.format_type == 'xml':
            self.file_handle.write('<?xml version="1.0" encoding="UTF-8"?>\n')
            self.file_handle.write('<subcat_results>\n')
            self.file_handle.write('  <metadata>\n')
            for key, value in self.metadata.items():
                self.file_handle.write(f'    <{key}>{value}</{key}>\n')
            self.file_handle.write('  </metadata>\n')
            self.file_handle.write('  <domains>\n')

    def write_entry(self, data: Dict[str, Any]):
        """
        Write a single entry to the output file.

        :param data: Data dictionary for this entry
        """
        if not self.is_initialized or not self.file_handle:
            raise RuntimeError("Writer not initialized. Call open() first.")

        try:
            if self.format_type == 'txt':
                domain = data.get('name', str(data))
                self.file_handle.write(f"{domain}\n")
            elif self.format_type == 'json':
                if self.entry_count > 0:
                    self.file_handle.write(',\n')
                json_str = json.dumps(data, indent=4)
                self.file_handle.write('    ' + json_str.replace('\n', '\n    '))
            elif self.format_type == 'csv':
                writer = csv.DictWriter(self.file_handle, fieldnames=self.include_fields, extrasaction='ignore')
                writer.writerow(data)
            elif self.format_type == 'xml':
                self.file_handle.write('    <domain>\n')
                for key, value in data.items():
                    if isinstance(value, list):
                        self.file_handle.write(f'      <{key}>\n')
                        for item in value:
                            self.file_handle.write(f'        <item>{item}</item>\n')
                        self.file_handle.write(f'      </{key}>\n')
                    else:
                        # Escape XML special characters
                        escaped_value = str(value).replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')
                        self.file_handle.write(f'      <{key}>{escaped_value}</{key}>\n')
                self.file_handle.write('    </domain>\n')

            self.entry_count += 1
            self.file_handle.flush()
        except Exception as e:
            raise IOError(f"Failed to write entry: {e}")

    def close(self):
        """Close the output file and write footers."""
        if not self.is_initialized or not self.file_handle:
            return

        try:
            self._write_footer()
            self.file_handle.close()
            self.file_handle = None
            self.is_initialized = False
        except Exception:
            pass

    def _write_footer(self):
        """Write format-specific footer."""
        if not self.file_handle:
            return

        duration = time.time() - self.start_time

        if self.format_type == 'json':
            self.file_handle.write('\n  ],\n')
            self.file_handle.write(f'  "count": {self.entry_count},\n')
            self.file_handle.write(f'  "duration_seconds": {duration:.2f}\n')
            self.file_handle.write('}\n')
        elif self.format_type == 'xml':
            self.file_handle.write('  </domains>\n')
            self.file_handle.write(f'  <count>{self.entry_count}</count>\n')
            self.file_handle.write(f'  <duration_seconds>{duration:.2f}</duration_seconds>\n')
            self.file_handle.write('</subcat_results>\n')
