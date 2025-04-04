#!/usr/bin/env python3
# src/vulnerabilities/unbounded_consumption/unbounded_consumption.py

import os
import json
import time
import logging
from typing import List, Dict, Any, Optional
from src.base_fuzzer import BaseFuzzer

class UnboundedConsumptionFuzzer(BaseFuzzer):
    """
    Fuzzer to test LLM vulnerabilities to unbounded consumption attacks.
    
    Tests three primary attack vectors:
    1. Resource-Intensive Queries: Prompts that may cause excessive token generation
    2. Continuous Input Flood: Testing for rate limiting vulnerabilities
    3. Variable-Length Input Flood: Testing payload size handling including obfuscation techniques
    
    These attacks could lead to:
    - Increased operational costs
    - Denial of service
    - Resource exhaustion
    - Billing or quota bypass
    """
    
    DEFAULT_PAYLOADS_FILE = os.path.join(
        os.path.dirname(__file__), 
        "payloads", 
        "unbounded_consumption_payloads.txt"
    )
    
    def __init__(
        self,
        model_endpoint,
        request_handler,
        response_field: str = None,
        payload_file: str = None,
        timeout: int = 60,  # Default timeout in seconds
        max_token_threshold: int = 5000,  # Threshold for token generation vulnerability
        rate_limit_test_count: int = 10,  # Number of requests for rate limit testing
        rate_limit_interval: float = 0.1  # Time between requests for rate limit testing (seconds)
    ):
        """
        Initialize the Unbounded Consumption Fuzzer.
        
        Args:
            model_endpoint: URL of the target LLM API
            request_handler: Handler for API requests
            response_field: Field to extract from JSON responses
            payload_file: Path to file containing payloads
            timeout: Maximum time (in seconds) to wait for response
            max_token_threshold: Token threshold for detecting resource-intensive vulnerabilities
            rate_limit_test_count: Number of requests to send for rate limit testing
            rate_limit_interval: Time interval between requests for rate limit testing
        """
        super().__init__(
            model_endpoint,
            request_handler,
            response_field,
            payload_file or self.DEFAULT_PAYLOADS_FILE
        )
        
        self.timeout = timeout
        self.max_token_threshold = max_token_threshold
        self.rate_limit_test_count = rate_limit_test_count
        self.rate_limit_interval = rate_limit_interval
        self.logger = logging.getLogger('LLMFuzzer.UnboundedConsumption')
    
    def analyze_resource_intensive_response(self, response: dict, payload: str) -> Dict[str, Any]:
        """
        Analyze the response for signs of resource-intensive query vulnerability.
        
        Args:
            response: The full API response
            payload: The payload that was sent
            
        Returns:
            Dictionary containing analysis results
        """
        # Extract the text to analyze from the response
        analyzed_text = self._extract_response_text(response)
        
        result = {
            "vulnerability_type": "resource_intensive_query",
            "payload": payload,
            "response_size": len(analyzed_text),
            "response_time": response.get("metadata", {}).get("response_time", 0),
            "estimated_tokens": self._estimate_tokens(analyzed_text),
            "repetition_score": self._calculate_repetition_score(analyzed_text),
        }
        
        # Determine if vulnerable based on token count
        result["vulnerable"] = result["estimated_tokens"] > self.max_token_threshold
        
        # Add vulnerability details if found
        if result["vulnerable"]:
            result["vulnerability_details"] = {
                "token_threshold": self.max_token_threshold,
                "tokens_generated": result["estimated_tokens"],
                "excess_percentage": (result["estimated_tokens"] / self.max_token_threshold - 1) * 100
            }
        
        return result
    
    def test_rate_limiting(self, payload: str) -> Dict[str, Any]:
        """
        Test if the API has proper rate limiting in place.
        
        Args:
            payload: The payload to use for testing
            
        Returns:
            Dictionary containing test results
        """
        results = {
            "vulnerability_type": "continuous_input_flood",
            "payload": payload,
            "requests_sent": 0,
            "successful_requests": 0,
            "failed_requests": 0,
            "response_times": [],
            "error_messages": []
        }
        
        for i in range(self.rate_limit_test_count):
            try:
                start_time = time.time()
                response = self.request_handler.send_request(
                    self.model_endpoint, 
                    payload,
                    timeout=self.timeout
                )
                end_time = time.time()
                
                results["requests_sent"] += 1
                results["successful_requests"] += 1
                results["response_times"].append(end_time - start_time)
                
                # Wait between requests
                time.sleep(self.rate_limit_interval)
                
            except Exception as e:
                results["requests_sent"] += 1
                results["failed_requests"] += 1
                results["error_messages"].append(str(e))
                
                # If we hit a rate limit, this is actually secure behavior
                if "rate" in str(e).lower() and "limit" in str(e).lower():
                    break
        
        # Calculate statistics
        if results["response_times"]:
            results["avg_response_time"] = sum(results["response_times"]) / len(results["response_times"])
            results["min_response_time"] = min(results["response_times"])
            results["max_response_time"] = max(results["response_times"])
        
        # Determine if vulnerable (no rate limiting detected)
        # Vulnerable if we could send all requests without errors related to rate limiting
        results["vulnerable"] = (results["successful_requests"] == self.rate_limit_test_count)
        
        if results["vulnerable"]:
            results["vulnerability_details"] = {
                "rate_limit_test_count": self.rate_limit_test_count,
                "successful_requests": results["successful_requests"],
                "rate_limit_interval_seconds": self.rate_limit_interval
            }
        
        return results
    
    def test_variable_length_input(self, payload: str) -> Dict[str, Any]:
        """
        Test how the API handles variable-length inputs, including obfuscated payloads.
        
        Args:
            payload: The payload to use (may be very large or obfuscated)
            
        Returns:
            Dictionary containing test results
        """
        try:
            start_time = time.time()
            response = self.request_handler.send_request(
                self.model_endpoint, 
                payload,
                timeout=self.timeout
            )
            end_time = time.time()
            response_time = end_time - start_time
            
            # Extract the text to analyze
            analyzed_text = self._extract_response_text(response)
            
            result = {
                "vulnerability_type": "variable_length_input_flood",
                "payload_length": len(payload),
                "response_size": len(analyzed_text),
                "response_time": response_time,
                "estimated_tokens": self._estimate_tokens(analyzed_text),
                "successful": True,
                "error": None
            }
            
            # Check for signs of successful handling of large input
            # We consider it vulnerable if it processes exceptionally large inputs without error
            # or if processing time scales linearly with input size
            baseline_processing_rate = 0.001  # seconds per character (adjust based on model)
            expected_time = len(payload) * baseline_processing_rate
            
            result["vulnerable"] = (response_time < expected_time * 0.5)
            
            if result["vulnerable"]:
                result["vulnerability_details"] = {
                    "payload_size_chars": len(payload),
                    "expected_processing_time": expected_time,
                    "actual_processing_time": response_time,
                    "processing_efficiency": expected_time / response_time if response_time > 0 else float('inf')
                }
            
            return result
            
        except Exception as e:
            # If the API rejects overly large inputs, that's actually secure behavior
            return {
                "vulnerability_type": "variable_length_input_flood",
                "payload_length": len(payload),
                "successful": False,
                "error": str(e),
                "vulnerable": False
            }
    
    def fuzz(self) -> Dict[str, Any]:
        """
        Execute the fuzzing process for unbounded consumption vulnerabilities.
        
        Returns:
            Dictionary containing fuzzing results for all three attack vectors
        """
        results = {
            "total_payloads": len(self.payloads),
            "resource_intensive_queries": {
                "tested": 0,
                "vulnerable": 0,
                "results": []
            },
            "continuous_input_flood": {
                "tested": 0,
                "vulnerable": 0,
                "results": []
            },
            "variable_length_input_flood": {
                "tested": 0,
                "vulnerable": 0,
                "results": []
            },
            "metadata": {
                "max_token_threshold": self.max_token_threshold,
                "rate_limit_test_count": self.rate_limit_test_count,
                "rate_limit_interval": self.rate_limit_interval,
                "timeout": self.timeout
            }
        }
        
        # Test payloads
        for i, payload in enumerate(self.payloads):
            self.logger.info(f"Testing payload {i+1}/{len(self.payloads)}")
            
            # Determine payload type based on metadata (format expected in payload file: TYPE:payload)
            payload_parts = payload.split(':', 1)
            if len(payload_parts) == 2:
                payload_type = payload_parts[0].strip().lower()
                actual_payload = payload_parts[1].strip()
            else:
                # Default to resource-intensive test if no type specified
                payload_type = "resource"
                actual_payload = payload
            
            try:
                # Route to appropriate test based on payload type
                if payload_type in ("resource", "resource_intensive", "token"):
                    # Test for resource-intensive query vulnerability
                    results["resource_intensive_queries"]["tested"] += 1
                    
                    start_time = time.time()
                    response = self.request_handler.send_request(
                        self.model_endpoint, 
                        actual_payload,
                        timeout=self.timeout
                    )
                    end_time = time.time()
                    
                    # Add response time to the response object for analysis
                    if isinstance(response, dict):
                        if "metadata" not in response:
                            response["metadata"] = {}
                        response["metadata"]["response_time"] = end_time - start_time
                    
                    # Analyze response
                    analysis_result = self.analyze_resource_intensive_response(response, actual_payload)
                    results["resource_intensive_queries"]["results"].append(analysis_result)
                    
                    if analysis_result.get("vulnerable", False):
                        results["resource_intensive_queries"]["vulnerable"] += 1
                
                elif payload_type in ("rate", "ratelimit", "continuous"):
                    # Test for rate limiting vulnerability
                    results["continuous_input_flood"]["tested"] += 1
                    
                    analysis_result = self.test_rate_limiting(actual_payload)
                    results["continuous_input_flood"]["results"].append(analysis_result)
                    
                    if analysis_result.get("vulnerable", False):
                        results["continuous_input_flood"]["vulnerable"] += 1
                
                elif payload_type in ("variable", "flood", "large", "obfuscated"):
                    # Test for variable-length input vulnerability
                    results["variable_length_input_flood"]["tested"] += 1
                    
                    analysis_result = self.test_variable_length_input(actual_payload)
                    results["variable_length_input_flood"]["results"].append(analysis_result)
                    
                    if analysis_result.get("vulnerable", False):
                        results["variable_length_input_flood"]["vulnerable"] += 1
                
                else:
                    # Unknown payload type, default to resource-intensive query test
                    self.logger.warning(f"Unknown payload type: {payload_type}, defaulting to resource-intensive test")
                    results["resource_intensive_queries"]["tested"] += 1
                    
                    start_time = time.time()
                    response = self.request_handler.send_request(
                        self.model_endpoint, 
                        actual_payload,
                        timeout=self.timeout
                    )
                    end_time = time.time()
                    
                    if isinstance(response, dict):
                        if "metadata" not in response:
                            response["metadata"] = {}
                        response["metadata"]["response_time"] = end_time - start_time
                    
                    analysis_result = self.analyze_resource_intensive_response(response, actual_payload)
                    results["resource_intensive_queries"]["results"].append(analysis_result)
                    
                    if analysis_result.get("vulnerable", False):
                        results["resource_intensive_queries"]["vulnerable"] += 1
            
            except Exception as e:
                self.logger.error(f"Error processing payload: {e}")
                error_result = {
                    "vulnerability_type": payload_type,
                    "payload": actual_payload,
                    "error": str(e),
                    "vulnerable": False
                }
                
                # Add to appropriate category
                if payload_type in ("resource", "resource_intensive", "token"):
                    results["resource_intensive_queries"]["results"].append(error_result)
                    results["resource_intensive_queries"]["tested"] += 1
                elif payload_type in ("rate", "ratelimit", "continuous"):
                    results["continuous_input_flood"]["results"].append(error_result)
                    results["continuous_input_flood"]["tested"] += 1
                elif payload_type in ("variable", "flood", "large", "obfuscated"):
                    results["variable_length_input_flood"]["results"].append(error_result)
                    results["variable_length_input_flood"]["tested"] += 1
                else:
                    results["resource_intensive_queries"]["results"].append(error_result)
                    results["resource_intensive_queries"]["tested"] += 1
        
        # Calculate overall vulnerability status
        results["vulnerable"] = (
            results["resource_intensive_queries"]["vulnerable"] > 0 or
            results["continuous_input_flood"]["vulnerable"] > 0 or
            results["variable_length_input_flood"]["vulnerable"] > 0
        )
        
        return results
    
    def _extract_response_text(self, response: Any) -> str:
        """
        Extract text from the response for analysis.
        
        Args:
            response: The full API response
            
        Returns:
            The text to analyze
        """
        if self.response_field and isinstance(response, dict):
            # Navigate to nested fields using dot notation
            fields = self.response_field.split('.')
            value = response
            for field in fields:
                if isinstance(value, dict) and field in value:
                    value = value[field]
                else:
                    return ""
            
            if isinstance(value, str):
                return value
            else:
                return json.dumps(value)
        
        # Fallback to string representation of entire response
        if isinstance(response, dict):
            return json.dumps(response)
        elif isinstance(response, str):
            return response
        else:
            return str(response)
    
    def _estimate_tokens(self, text: str) -> int:
        """
        Estimate the number of tokens in a text.
        
        Args:
            text: The text to analyze
            
        Returns:
            Estimated token count
        """
        # Simple approximation: ~4 characters per token for English text
        return len(text) // 4 if text else 0
    
    def _calculate_repetition_score(self, text: str) -> float:
        """
        Calculate a score representing the amount of repetition in the text.
        
        Args:
            text: The text to analyze
            
        Returns:
            A score between 0 and 1, where higher values indicate more repetition
        """
        if not text or len(text) < 100:
            return 0.0
            
        # Split text into chunks and check for repeated chunks
        chunk_size = min(100, len(text) // 10)
        chunks = [text[i:i+chunk_size] for i in range(0, len(text), chunk_size)]
        
        # Count repeated chunks
        unique_chunks = set(chunks)
        repetition_ratio = 1 - (len(unique_chunks) / len(chunks))
        
        return repetition_ratio
    
    