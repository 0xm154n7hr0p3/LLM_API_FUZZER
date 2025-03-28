#!/usr/bin/env python3
#main.py
import argparse
import json
import logging
import os
import banner
from colorama import Fore, Back, Style, init
init()
#from src.vulnerabilities.prompt_injection import PromptInjectionFuzzer
from src.vulnerabilities.system_prompt_leakage.system_prompt_leakage import SystemPromptLeakageFuzzer
#from src.base_fuzzer import BaseFuzzer
from utils.request_handler import RequestHandler
from utils.result_analyzer import ResultAnalyzer

# Update the vulnerability fuzzers dictionary
VULNERABILITY_FUZZERS = {
#    'insecure_output_handling': InsecureOutputHandlingFuzzer,
#    'excessive_agency': ExcessiveAgencyFuzzer,
    'system_prompt_leakage': SystemPromptLeakageFuzzer,
#    'vector_embedding_weaknesses': VectorEmbeddingWeaknessesFuzzer,
#    'misinformation': MisinformationFuzzer,
#    'unbounded_consumption': UnboundedConsumptionFuzzer,
#    'prompt_injection': PromptInjectionFuzzer,
#    'sensitive_information_disclosure': SensitiveInformationDisclosureFuzzer
}

def setup_logging(log_file: str, log_level: str) -> logging.Logger:
    """
    Configure and setup logging for the application.
    
    :param log_file: Path to the log file
    :param log_level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
    :return: Configured logger object
    """
    # Create logger
    logger = logging.getLogger('LLMFuzzer')
    
    # Convert log level string to logging constant
    log_level_map = {
        'DEBUG': logging.DEBUG,
        'INFO': logging.INFO,
        'WARNING': logging.WARNING,
        'ERROR': logging.ERROR,
        'CRITICAL': logging.CRITICAL
    }
    numeric_level = log_level_map.get(log_level.upper(), logging.INFO)
    
    # Set logger's log level
    logger.setLevel(numeric_level)
    
    # Create formatter
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    
    # Create file handler
    try:
        file_handler = logging.FileHandler(log_file)
        file_handler.setFormatter(formatter)
        file_handler.setLevel(numeric_level)
        logger.addHandler(file_handler)
    except IOError as e:
        print(f"Error creating log file: {e}")
        # Fallback to console logging if file handler fails
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(formatter)
        console_handler.setLevel(numeric_level)
        logger.addHandler(console_handler)
    
    # Create console handler
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    console_handler.setLevel(numeric_level)
    logger.addHandler(console_handler)
    
    return logger

def create_argument_parser() -> argparse.ArgumentParser:
    """
    Create and configure argument parser for the LLM fuzzer.
    
    :return: Configured ArgumentParser object
    """
    parser = argparse.ArgumentParser(
        description='LLM API Vulnerability Fuzzer - Test LLM security with OWASP TOP 10',
        epilog='Example: python main.py -e https://api.example.com/generate -v prompt_injection -R req.txt '
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
        choices=list(VULNERABILITY_FUZZERS.keys()),
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
        '-R', '--raw-request', 
        type=str,
        required=True,
        help='Path to file containing raw HTTP request'
    )
    
    # Optional arguments for custom payload and indicator files
    parser.add_argument(
        '--payload-file', 
        type=str, 
        help='Custom payload file for the selected vulnerability'
    )
    
    parser.add_argument(
        '--success-indicators', 
        type=str, 
        help='Custom success indicators file'
    )
    
    parser.add_argument(
        '--failure-indicators', 
        type=str, 
        help='Custom failure indicators file'
    )
    
    return parser

def run_fuzzer(
    endpoint: str, 
    vulnerability: str, 
    output_file: str, 
    max_payloads: int = None,
    raw_request_file: str = None,
    payload_file: str = None,
    success_indicators_file: str = None,
    failure_indicators_file: str = None
) -> dict:
    """
    Run the specified vulnerability fuzzer.
    
    :param endpoint: LLM API endpoint
    :param vulnerability: Vulnerability type to test
    :param output_file: File to save results
    :param max_payloads: Optional limit on number of payloads
    :param raw_request_file: Optional raw HTTP request template file
    :param payload_file: Optional custom payload file
    :param success_indicators_file: Optional success indicators file
    :param failure_indicators_file: Optional failure indicators file
    :return: Fuzzing results
    """
    # Initialize components
    request_handler = RequestHandler(raw_request_file=raw_request_file)
    result_analyzer = ResultAnalyzer()

    # Get the appropriate fuzzer class
    fuzzer_class = VULNERABILITY_FUZZERS[vulnerability]
    
    # Create fuzzer instance with additional parameters
    fuzzer_kwargs = {
        'model_endpoint': endpoint,
        'request_handler': request_handler,
        'result_analyzer': result_analyzer
    }
    
    # Add optional parameters if provided
    if payload_file:
        fuzzer_kwargs['payload_file'] = payload_file
    if success_indicators_file:
        fuzzer_kwargs['success_indicators_file'] = success_indicators_file
    if failure_indicators_file:
        fuzzer_kwargs['failure_indicators_file'] = failure_indicators_file
    
    # Create fuzzer instance
    fuzzer = fuzzer_class(**fuzzer_kwargs)

    # Potentially limit payloads
    if max_payloads is not None:
        fuzzer.payloads = fuzzer.payloads[:max_payloads]

    # Run fuzzing
    global logger  # Use the global logger
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


def highlight_indicators(response: str, indicators: list[str]) -> str:
    """Highlight indicators found in the response"""
    highlighted = response
    for indicator in indicators:
        if indicator.lower() in highlighted.lower():
            # Find all case-insensitive matches
            start_idx = 0
            while True:
                match_idx = highlighted.lower().find(indicator.lower(), start_idx)
                if match_idx == -1:
                    break
                # Replace the matched portion with colored version
                original_text = highlighted[match_idx:match_idx+len(indicator)]
                highlighted = (
                    highlighted[:match_idx] + 
                    f"{Back.RED}{Fore.WHITE}{original_text}{Style.RESET_ALL}" + 
                    highlighted[match_idx+len(indicator):]
                )
                start_idx = match_idx + len(indicator) + len(Back.RED + Fore.WHITE + Style.RESET_ALL)
    return highlighted
def main():
    """
    Main entry point for the LLM Fuzzer application.
    Parses arguments and orchestrates fuzzing process.
    """
    # Parse command-line arguments
    banner.banner()
    banner.title()

    parser = create_argument_parser()
    args = parser.parse_args()

    # Setup global logger
    global logger
    logger = setup_logging(args.log_file, args.log_level)

    try:
        # Run the fuzzer
        results = run_fuzzer(
            endpoint=args.endpoint,
            vulnerability=args.vulnerability,
            output_file=args.output,
            max_payloads=args.max_payloads,
            raw_request_file=args.raw_request,
            payload_file=args.payload_file,
            success_indicators_file=args.success_indicators,
            failure_indicators_file=args.failure_indicators
        )

        # Print colored summary to console
        print(f"\n{Fore.YELLOW}=== Fuzzing Summary ==={Style.RESET_ALL}")
        print(f"Total payloads tested: {Fore.CYAN}{results.get('total_payloads', 0)}{Style.RESET_ALL}")
        print(f"Successful exploits: {Fore.GREEN}{len(results.get('successful_exploits', []))}{Style.RESET_ALL}")
        print(f"Blocked attempts: {Fore.RED}{len(results.get('blocked_attempts', []))}{Style.RESET_ALL}")
        print(f"Failed attempts: {len(results.get('failed_attempts', []))}\n")

        # Print detailed successful exploits with highlighting
        if results.get('successful_exploits'):
            print(f"{Fore.YELLOW}=== Successful Exploits ==={Style.RESET_ALL}")
            for i, exploit in enumerate(results['successful_exploits'], 1):
                print(f"\n{Fore.GREEN}Exploit #{i}{Style.RESET_ALL}")
                print(f"{Fore.CYAN}Payload:{Style.RESET_ALL}\n{exploit['payload']}")
                
                # Get indicators from the exploit results if available
                indicators = []
                if 'matched_indicators' in exploit:
                    indicators = exploit['matched_indicators']
                elif 'custom_indicators' in results:
                    indicators = results['custom_indicators']
                
                highlighted_response = highlight_indicators(
                    exploit['response'],
                    indicators
                )
                print(f"\n{Fore.CYAN}Response:{Style.RESET_ALL}\n{highlighted_response}")

    except Exception as e:
        logger.error(f"Fuzzing failed: {e}")
        raise
if __name__ == "__main__":
    main()