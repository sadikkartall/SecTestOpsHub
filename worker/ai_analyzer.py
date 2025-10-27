import os
import logging
from typing import Optional
import openai
from models import Finding

logger = logging.getLogger(__name__)


class AIAnalyzer:
    """AI-powered finding analyzer using LLM"""
    
    def __init__(self):
        self.api_key = os.getenv("OPENAI_API_KEY")
        self.model = os.getenv("LLM_MODEL", "gpt-3.5-turbo")
        self.enabled = bool(self.api_key)
        
        if self.enabled:
            openai.api_key = self.api_key
            logger.info("AI Analyzer initialized with OpenAI")
        else:
            logger.warning("AI Analyzer disabled - no API key provided")
    
    def analyze_finding(self, finding: Finding, db_session) -> None:
        """
        Analyze a finding using AI and update it with:
        - AI summary (2-3 sentences)
        - AI recommendation
        - Probable false positive flag
        """
        if not self.enabled:
            return
        
        try:
            # Build prompt
            prompt = self._build_prompt(finding)
            
            # Call OpenAI API
            response = openai.ChatCompletion.create(
                model=self.model,
                messages=[
                    {
                        "role": "system",
                        "content": "You are a cybersecurity expert analyzing vulnerability findings. Provide concise, actionable insights."
                    },
                    {
                        "role": "user",
                        "content": prompt
                    }
                ],
                max_tokens=500,
                temperature=0.3
            )
            
            # Parse response
            ai_response = response.choices[0].message.content
            
            # Split response into sections
            sections = self._parse_ai_response(ai_response)
            
            # Update finding
            finding.ai_summary = sections.get("summary", "")
            finding.ai_recommendation = sections.get("recommendation", "")
            finding.probable_fp = sections.get("false_positive", False)
            
            db_session.commit()
            logger.info(f"AI analysis completed for finding {finding.id}")
            
        except Exception as e:
            logger.error(f"AI analysis failed for finding {finding.id}: {str(e)}")
    
    def _build_prompt(self, finding: Finding) -> str:
        """Build prompt for AI analysis"""
        prompt = f"""Analyze this security finding:

Tool: {finding.tool}
Title: {finding.title}
Severity: {finding.severity}
Endpoint: {finding.endpoint or 'N/A'}
Description: {finding.description or 'N/A'}

Provide:
1. SUMMARY: A 2-3 sentence summary of the finding and its impact
2. RECOMMENDATION: Specific, actionable steps to remediate (2-3 sentences)
3. FALSE_POSITIVE: Assess if this is likely a false positive (YES/NO)

Format your response exactly as:
SUMMARY: [your summary]
RECOMMENDATION: [your recommendation]
FALSE_POSITIVE: [YES or NO]
"""
        return prompt
    
    def _parse_ai_response(self, response: str) -> dict:
        """Parse structured AI response"""
        sections = {
            "summary": "",
            "recommendation": "",
            "false_positive": False
        }
        
        try:
            lines = response.strip().split('\n')
            
            for line in lines:
                if line.startswith("SUMMARY:"):
                    sections["summary"] = line.replace("SUMMARY:", "").strip()
                elif line.startswith("RECOMMENDATION:"):
                    sections["recommendation"] = line.replace("RECOMMENDATION:", "").strip()
                elif line.startswith("FALSE_POSITIVE:"):
                    fp_value = line.replace("FALSE_POSITIVE:", "").strip().upper()
                    sections["false_positive"] = fp_value == "YES"
            
        except Exception as e:
            logger.error(f"Error parsing AI response: {str(e)}")
        
        return sections

