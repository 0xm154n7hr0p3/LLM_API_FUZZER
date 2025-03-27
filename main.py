#!/usr/bin/env python3
import argparse
import json
import logging
from typing import List, Type
import banner

#from src.vulnerabilities.prompt_injection import PromptInjectionFuzzer
#from src.base_fuzzer import BaseFuzzer
#from utils.request_handler import RequestHandler
#rom utils.result_analyzer import ResultAnalyzer

banner.banner()
banner.title()

# Configure logging
logging.basicConfig(
    level=logging.INFO, 
    format='%(asctime)s - %(levelname)s: %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)

# Mapping of vulnerability names to fuzzer classes
#VULNERABILITY_FUZZERS = {
#    'insecure_output_handling': InsecureOutputHandlingFuzzer,
#    'excessive_agency': ExcessiveAgencyFuzzer,
#    'system_prompt_leakage': SystemPromptLeakageFuzzer,
#    'vector_embedding_weaknesses': VectorEmbeddingWeaknessesFuzzer,
#    'misinformation': MisinformationFuzzer,
#    'unbounded_consumption': UnboundedConsumptionFuzzer,
#    'prompt_injection': PromptInjectionFuzzer,
#    'sensitive_information_disclosure': SensitiveInformationDisclosureFuzzer
#}
def create_argument_parser() -> argparse.ArgumentParser:
    """
    Create and configure argument parser for the LLM fuzzer.
    
    :return: Configured ArgumentParser object
    """
    parser = argparse.ArgumentParser(
        description='LLM API Vulnerability Fuzzer - Test LLM security with OWASP TOP 10',
        epilog='Example: python main.py -e https://api.example.com/generate -v prompt_injection'
    )
    
    parser.add_argument(
        '-e', '--endpoint', 
        type=str, 
        required=True, 
        help='LLM API endpoint URL'
    )
    
    parser.add_argument(
        '-v', '--vulnerability', 
        type=str, 
        #choices=list(VULNERABILITY_FUZZERS.keys()),
        required=True, 
        help='Specific vulnerability to test'
    )
    
    parser.add_argument(
        '-o', '--output', 
        type=str, 
        default='fuzzer_results.json', 
        help='Output file for fuzzing results (default: fuzzer_results.json)'
    )
    
    parser.add_argument(
        '-l', '--log-file', 
        type=str, 
        default='fuzzer_logs.log', 
        help='Log file path (default: fuzzer_logs.log)'
    )
    
    parser.add_argument(
        '--log-level', 
        type=str, 
        choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'],
        default='INFO', 
        help='Set the logging level (default: INFO)'
    )
    
    parser.add_argument(
        '--max-payloads', 
        type=int, 
        default=None, 
        help='Limit the number of payloads to test (optional)'
    )
    
    parser.add_argument(
        '-H', '--headers', 
        type=str, 
        default=None, 
        help='Add headers to the request as JSON, e.g. \'{"Cookie": "yk=value"}\''
    )
    
    parser.add_argument(
        '--raw-request', 
        action='store_true', 
        help='Perform raw request without additional processing'
    )
    
    return parser

def run_fuzzer(
    endpoint: str, 
    vulnerability: str, 
    output_file: str, 
    max_payloads: int = None
) -> dict:
    """
    Run the specified vulnerability fuzzer.
    
    :param endpoint: LLM API endpoint
    :param vulnerability: Vulnerability type to test
    :param output_file: File to save results
    :param max_payloads: Optional limit on number of payloads
    :return: Fuzzing results
    """
    # Initialize components
    request_handler = RequestHandler()
    result_analyzer = ResultAnalyzer()

    # Get the appropriate fuzzer class
    fuzzer_class = VULNERABILITY_FUZZERS[vulnerability]
    
    # Create fuzzer instance
    fuzzer = fuzzer_class(
        model_endpoint=endpoint,
        request_handler=request_handler,
        result_analyzer=result_analyzer
    )

    # Potentially limit payloads
    if max_payloads is not None:
        fuzzer.payloads = fuzzer.payloads[:max_payloads]

    # Run fuzzing
    logger.info(f"Starting fuzzing for {vulnerability} vulnerability")
    results = fuzzer.fuzz()

    # Save results to file
    try:
        with open(output_file, 'w') as f:
            json.dump(results, f, indent=2)
        logger.info(f"Results saved to {output_file}")
    except IOError as e:
        logger.error(f"Failed to write results: {e}")

    return results

def main():
    """
    Main entry point for the LLM Fuzzer application.
    Parses arguments and orchestrates fuzzing process.
    """
    # Parse command-line arguments
    parser = create_argument_parser()
    args = parser.parse_args()

    # Set logging level
    logging.getLogger().setLevel(args.log_level)

    try:
        # Run the fuzzer
        results = run_fuzzer(
            endpoint=args.endpoint,
            vulnerability=args.vulnerability,
            output_file=args.output,
            max_payloads=args.max_payloads
        )

        # Print summary to console
        print(json.dumps({
            'total_payloads': results.get('total_payloads', 0),
            'successful_exploits': len(results.get('successful_exploits', [])),
            'failed_attempts': len(results.get('failed_attempts', []))
        }, indent=2))

    except Exception as e:
        logger.error(f"Fuzzing failed: {e}")
        raise

if __name__ == "__main__":
    main()