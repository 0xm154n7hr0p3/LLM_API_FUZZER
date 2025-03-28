#/utils/result_analyzer.py
import json
from typing import List, Dict, Union, Optional

class ResultAnalyzer:
    """
    Comprehensive result analyzer for LLM vulnerability fuzzing.
    Provides detailed analysis of LLM responses across different vulnerability tests.
    """
    def __init__(
        self, 
        success_indicators_file: Optional[str] = None, 
        failure_indicators_file: Optional[str] = None
    ):
        """
        Initialize the ResultAnalyzer with optional indicator files.
        
        :param success_indicators_file: Path to file with success indicators
        :param failure_indicators_file: Path to file with failure indicators
        """
        self.success_indicators = self._load_indicators(success_indicators_file)
        self.failure_indicators = self._load_indicators(failure_indicators_file)

    def _load_indicators(self, file_path: Optional[str]) -> List[str]:
        """
        Load indicators from a JSON file.
        
        :param file_path: Path to the indicators file
        :return: List of indicators, or empty list if file not provided
        """
        if not file_path:
            return []
        
        try:
            with open(file_path, 'r') as f:
                return json.load(f)
        except (FileNotFoundError, json.JSONDecodeError) as e:
            print(f"Error loading indicators file: {e}")
            return []

    def check_success(
        self, 
        response: str, 
        custom_indicators: Optional[List[str]] = None
    ) -> bool:
        """
        Check if response contains any success indicators.
        
        :param response: LLM response text
        :param custom_indicators: Optional list of custom success indicators
        :return: Whether vulnerability was successfully triggered
        """
        # Combine default and custom indicators
        indicators = self.success_indicators + (custom_indicators or [])
        
        # Case-insensitive search for indicators
        response_lower = response.lower()
        return any(
            indicator.lower() in response_lower 
            for indicator in indicators
        )

    def check_failure(
        self, 
        response: str, 
        custom_indicators: Optional[List[str]] = None
    ) -> bool:
        """
        Check if response contains any failure indicators.
        
        :param response: LLM response text
        :param custom_indicators: Optional list of custom failure indicators
        :return: Whether the attempt was blocked or failed
        """
        # Combine default and custom indicators
        indicators = self.failure_indicators + (custom_indicators or [])
        
        # Case-insensitive search for indicators
        response_lower = response.lower()
        return any(
            indicator.lower() in response_lower 
            for indicator in indicators
        )

    def analyze_response(
        self, 
        payload: str, 
        response: str, 
        success_indicators: Optional[List[str]] = None,
        failure_indicators: Optional[List[str]] = None
    ) -> Dict[str, Union[str, bool]]:
        """
        Comprehensive analysis of a single fuzzing response.
        
        :param payload: Payload used in the test
        :param response: LLM response to analyze
        :param success_indicators: Optional custom success indicators
        :param failure_indicators: Optional custom failure indicators
        :return: Detailed analysis of the response
        """
        analysis = {
            'payload': payload,
            'response': response,
            'is_successful': self.check_success(
                response, 
                custom_indicators=success_indicators
            ),
            'is_blocked': self.check_failure(
                response, 
                custom_indicators=failure_indicators
            )
        }
        
        return analysis

    def aggregate_results(
        self, 
        individual_results: List[Dict[str, Union[str, bool]]]
    ) -> Dict[str, List[Dict[str, Union[str, bool]]]]:
        """
        Aggregate results from multiple fuzzing attempts.
        
        :param individual_results: List of individual test results
        :return: Categorized results
        """
        aggregated_results = {
            'total_payloads': len(individual_results),
            'successful_exploits': [
                result for result in individual_results 
                if result['is_successful']
            ],
            'blocked_attempts': [
                result for result in individual_results 
                if result['is_blocked']
            ],
            'failed_attempts': [
                result for result in individual_results 
                if not result['is_successful'] and not result['is_blocked']
            ]
        }
        
        return aggregated_results