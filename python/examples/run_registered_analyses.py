#!/usr/bin/env python3
"""
Example script demonstrating how to register and run analyses using the Analysis registry.
"""

import os
import sys
from typing import Optional, Dict, Any

from ASN1nspect import ASN1AngrProject
from ASN1nspect.asn1c.Type import asn_type
from ASN1nspect.Analysis.Analysis import Analysis
from ASN1nspect.Analysis.NonEnforcedConstraintAnalysis import NonEnforcedConstraintAnalysis

# Import other analysis classes here if they exist
# from ASN1nspect.Analysis.SomeOtherAnalysis import SomeOtherAnalysis


# Example of creating a custom analysis and registering it
@Analysis.register
class CustomAnalysis(Analysis):
    """A simple example analysis that counts constraint properties."""
    
    def analyze(self):
        """Count and return the number of constraints in the type."""
        if self.is_differential and self.type2 is None:
            raise ValueError("Differential analysis requires two types, but type2 was None.")
            
        constraint_count = 0
        
        # Count constraints if they exist
        if hasattr(self.type1, 'encoding_constraints') and self.type1.encoding_constraints:
            if self.type1.encoding_constraints.general_constraints:
                constraint_count += 1
            if self.type1.encoding_constraints.size_constraints:
                constraint_count += len(self.type1.encoding_constraints.size_constraints)
            # Add more constraint types as needed
            
        return {
            "constraint_count": constraint_count,
            "name": self.type1.symbol.name if self.type1.symbol else "Unknown"
        }


def main():
    """Main function to demonstrate analysis registry functionality."""
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <path_to_binary>")
        sys.exit(1)
        
    binary_path = sys.argv[1]
    if not os.path.exists(binary_path):
        print(f"Error: Binary file '{binary_path}' not found.")
        sys.exit(1)
    
    print(f"Loading binary: {binary_path}")
    project = ASN1AngrProject(binary_path)
    
    # Get the first type for demonstration purposes
    if not project.types:
        print("No ASN.1 types found in the binary.")
        sys.exit(1)
        
    sample_type = next(iter(project.types.values()))
    
    # Display registered analyses
    print("\nRegistered Analyses:")
    for name in Analysis.get_registered_analyses().keys():
        print(f"- {name}")
    
    # Run all registered analyses
    print("\nRunning all analyses on type:", sample_type.symbol.name if sample_type.symbol else "Unknown")
    results = Analysis.run_all_analyses(sample_type)
    
    # Print results
    print("\nAnalysis Results:")
    for analysis_name, result in results.items():
        print(f"\n{analysis_name}:")
        if isinstance(result, dict):
            for key, value in result.items():
                print(f"  {key}: {value}")
        else:
            print(f"  {result}")


if __name__ == "__main__":
    main()