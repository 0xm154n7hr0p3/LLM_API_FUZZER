import os
import datetime
from typing import Dict, List, Optional

class SystemPromptLeakageFuzzer:
    def __init__(
        self, 
        model_endpoint, 
        request_handler, 
        result_analyzer, 
        payload_file=None,
        success_indicators_file=None,
        failure_indicators_file=None
    ):
        """
        Initialize System Prompt Leakage Fuzzer with enhanced result analysis
        
        :param model_endpoint: LLM API endpoint
        :param request_handler: Request handling utility
        :param result_analyzer: Result analysis utility
        :param payload_file: Optional custom payload file path
        :param success_indicators_file: Optional custom success indicators file
        :param failure_indicators_file: Optional custom failure indicators file
        """
        self.model_endpoint = model_endpoint
        self.request_handler = request_handler
        self.result_analyzer = result_analyzer
        
        # Default paths in the same directory
        base_dir = os.path.dirname(__file__)
        
        # Load payloads
        self.payloads = self._load_indicators(
            payload_file or os.path.join(base_dir, './data/system_prompt_leakage_payloads.txt')
        )
        
        # Load success and failure indicators
        self.custom_success_indicators = self._load_indicators(
            success_indicators_file or os.path.join(base_dir, './data/system_prompt_success_indicators.txt')
        )
        
        self.custom_failure_indicators = self._load_indicators(
            failure_indicators_file or os.path.join(base_dir, './data/system_prompt_failure_indicators.txt')
        )
    
    def _load_indicators(self, file_path: Optional[str]) -> List[str]:
        """
        Load indicators from a file with error handling
        
        :param file_path: Path to indicators file
        :return: List of indicators
        """
        try:
            with open(file_path, 'r') as f:
                return [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            print(f"Indicators file not found: {file_path}")
            return []
        except Exception as e:
            print(f"Error reading indicators file: {e}")
            return []
    
    def fuzz(self) -> Dict:
        """
        Perform comprehensive fuzzing for system prompt leakage
        
        :return: Detailed fuzzing results
        """
        # Prepare to collect individual test results
        individual_results = []
        
        # Tracking metadata for the entire fuzzing session
        fuzzing_metadata = {
            'start_time': datetime.datetime.now().isoformat(),
            'total_payloads': len(self.payloads),
            'endpoint': self.model_endpoint
        }
        
        # Test each payload
        for payload in self.payloads:
            try:
                # Send request with payload
                response = self.request_handler.send_request(
                    self.model_endpoint, 
                    payload
                )
                
                # Use ResultAnalyzer for comprehensive response analysis
                result_entry = self.result_analyzer.analyze_response(
                    payload=payload, 
                    response=response,
                    success_indicators=self.custom_success_indicators,
                    failure_indicators=self.custom_failure_indicators
                )
                
                # Add additional metadata to the result
                result_entry.update({
                    'timestamp': datetime.datetime.now().isoformat(),
                    'payload_length': len(payload),
                    'response_length': len(response)
                })
                
                individual_results.append(result_entry)
            
            except Exception as e:
                # Handle and log any errors during fuzzing
                error_entry = {
                    'payload': payload,
                    'error': str(e),
                    'timestamp': datetime.datetime.now().isoformat(),
                    'is_successful': False,
                    'is_blocked': False
                }
                individual_results.append(error_entry)
        
        # Aggregate results using ResultAnalyzer
        aggregated_results = self.result_analyzer.aggregate_results(individual_results)
        
        # Add fuzzing metadata to the final results
        aggregated_results['fuzzing_metadata'] = fuzzing_metadata
        
        # Perform additional analysis
        aggregated_results['insights'] = self._generate_insights(aggregated_results)
        
        return aggregated_results
    
    def _generate_insights(self, results: Dict) -> Dict:
        """
        Generate additional insights from fuzzing results
        
        :param results: Aggregated fuzzing results
        :return: Insights dictionary
        """
        # Use the length of payloads instead of accessing 'total_payloads'
        total_payloads = len(self.payloads)
        
        insights = {
            'success_rate': len(results['successful_exploits']) / total_payloads * 100,
            'block_rate': len(results['blocked_attempts']) / total_payloads * 100,
            'most_revealing_payloads': sorted(
                results['successful_exploits'], 
                key=lambda x: len(x.get('response', '')), 
                reverse=True
            )[:5]  # Top 5 most revealing payloads
        }
        
        return insights