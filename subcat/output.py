"""
Output module for SubCat.
Provides functionality for outputting results in various formats.
"""
import os
import json
import csv
import xml.dom.minidom
from typing import List, Dict, Any, Optional, Union

class OutputFormatter:
    """
    Handles formatting and writing of results in various formats.
    """
    
    FORMATS = ['txt', 'json', 'csv', 'xml']
    
    @staticmethod
    def format_txt(domains: List[str]) -> str:
        """Format domains as plain text, one per line."""
        return '\n'.join(domains)
    
    @staticmethod
    def format_json(domains: List[str], metadata: Optional[Dict[str, Any]] = None) -> str:
        """Format domains as JSON."""
        data = {
            'domains': domains,
            'count': len(domains)
        }
        
        if metadata:
            data['metadata'] = metadata
        
        return json.dumps(data, indent=2)
    
    @staticmethod
    def format_csv(domains: List[str], metadata: Optional[Dict[str, Any]] = None) -> str:
        """Format domains as CSV."""
        import io
        output = io.StringIO()
        writer = csv.writer(output)
        
        # Write header
        writer.writerow(['domain'])
        
        # Write domains
        for domain in domains:
            writer.writerow([domain])
        
        return output.getvalue()
    
    @staticmethod
    def format_xml(domains: List[str], metadata: Optional[Dict[str, Any]] = None) -> str:
        """Format domains as XML."""
        doc = xml.dom.minidom.getDOMImplementation().createDocument(None, "subcat_results", None)
        root = doc.documentElement
        
        # Add metadata if provided
        if metadata:
            meta_elem = doc.createElement("metadata")
            root.appendChild(meta_elem)
            
            for key, value in metadata.items():
                elem = doc.createElement(key)
                text = doc.createTextNode(str(value))
                elem.appendChild(text)
                meta_elem.appendChild(elem)
        
        # Add domains
        domains_elem = doc.createElement("domains")
        root.appendChild(domains_elem)
        
        for domain in domains:
            domain_elem = doc.createElement("domain")
            text = doc.createTextNode(domain)
            domain_elem.appendChild(text)
            domains_elem.appendChild(domain_elem)
        
        # Add count
        count_elem = doc.createElement("count")
        text = doc.createTextNode(str(len(domains)))
        count_elem.appendChild(text)
        root.appendChild(count_elem)
        
        return doc.toprettyxml(indent="  ")
    
    @classmethod
    def format(cls, domains: List[str], format_type: str, metadata: Optional[Dict[str, Any]] = None) -> str:
        """
        Format domains in the specified format.
        
        :param domains: List of domains to format
        :param format_type: Format type (txt, json, csv, xml)
        :param metadata: Optional metadata to include
        :return: Formatted string
        """
        format_type = format_type.lower()
        
        if format_type not in cls.FORMATS:
            raise ValueError(f"Unsupported format: {format_type}. Supported formats: {', '.join(cls.FORMATS)}")
        
        if format_type == 'txt':
            return cls.format_txt(domains)
        elif format_type == 'json':
            return cls.format_json(domains, metadata)
        elif format_type == 'csv':
            return cls.format_csv(domains, metadata)
        elif format_type == 'xml':
            return cls.format_xml(domains, metadata)
    
    @classmethod
    def write(cls, domains: List[str], output_file: str, metadata: Optional[Dict[str, Any]] = None) -> bool:
        """
        Write domains to a file in the format determined by the file extension.
        
        :param domains: List of domains to write
        :param output_file: Output file path
        :param metadata: Optional metadata to include
        :return: True if successful, False otherwise
        """
        try:
            # Determine format from file extension
            _, ext = os.path.splitext(output_file)
            format_type = ext[1:].lower() if ext else 'txt'
            
            # Default to txt if format not supported
            if format_type not in cls.FORMATS:
                format_type = 'txt'
            
            # Format the data
            formatted_data = cls.format(domains, format_type, metadata)
            
            # Write to file
            with open(output_file, 'w') as f:
                f.write(formatted_data)
            
            return True
        except Exception:
            return False
