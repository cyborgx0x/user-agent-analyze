import user_agents
import re
import logging
from typing import Dict, Any, Optional, List
from dataclasses import dataclass
from enum import Enum

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class ThreatLevel(Enum):
    """Threat level classification"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

@dataclass
class UserAgentAnalysis:
    """Structure to hold user agent analysis results"""
    is_valid: bool
    is_bot: bool
    is_mobile: bool
    is_pc: bool
    os_family: str
    os_version: str
    browser_family: str
    browser_version: str
    threat_level: ThreatLevel
    security_flags: List[str]
    blocked: bool
    reason: Optional[str] = None

class SecureUserAgentAnalyzer:
    """Enhanced user agent analyzer with security protections"""
    
    def __init__(self):
        # Maximum length to prevent DoS attacks
        self.MAX_UA_LENGTH = 2048
        
        # Known malicious patterns (regex patterns)
        self.MALICIOUS_PATTERNS = [
            r'<script.*?>.*?</script>',  # XSS attempts
            r'javascript:',              # JavaScript injection
            r'vbscript:',               # VBScript injection
            r'data:text/html',          # Data URI attacks
            r'[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]',  # Control characters
            r'(?:union|select|insert|delete|update|drop|create|alter|exec|execute)',  # SQL injection patterns
            r'\.\./',                   # Path traversal
            r'%2e%2e%2f',              # URL encoded path traversal
            r'cmd\.exe|powershell|bash|sh|wget|curl',  # Command injection
        ]
        
        # Suspicious bot patterns (more aggressive than normal bots)
        self.SUSPICIOUS_BOT_PATTERNS = [
            r'scanner|scraper|crawler|spider|bot|harvester',
            r'nikto|nmap|sqlmap|gobuster|dirb|wfuzz',
            r'vulnerability|exploit|hack|attack',
            r'python-requests|curl|wget|libwww',
            r'masscan|zmap|shodan',
        ]
        
        # Rate limiting patterns (detect automated tools)
        self.AUTOMATION_PATTERNS = [
            r'HeadlessChrome',
            r'PhantomJS',
            r'Selenium',
            r'WebDriver',
            r'automation',
            r'headless',
        ]
        
        # Legitimate bot whitelist
        self.LEGITIMATE_BOTS = {
            'googlebot', 'bingbot', 'slurp', 'duckduckbot', 'baiduspider',
            'yandexbot', 'facebookexternalhit', 'twitterbot', 'linkedinbot',
            'pinterest', 'whatsapp', 'telegrambot', 'slackbot', 'discordbot'
        }
        
        # Compile regex patterns for performance
        self.compiled_malicious = [re.compile(pattern, re.IGNORECASE) for pattern in self.MALICIOUS_PATTERNS]
        self.compiled_suspicious = [re.compile(pattern, re.IGNORECASE) for pattern in self.SUSPICIOUS_BOT_PATTERNS]
        self.compiled_automation = [re.compile(pattern, re.IGNORECASE) for pattern in self.AUTOMATION_PATTERNS]

    def _validate_input(self, user_agent_string: str) -> tuple[bool, Optional[str]]:
        """Validate user agent string for basic security issues"""
        if not user_agent_string:
            return False, "Empty user agent"
        
        if len(user_agent_string) > self.MAX_UA_LENGTH:
            return False, f"User agent too long (>{self.MAX_UA_LENGTH} chars)"
        
        # Check for malicious patterns
        for pattern in self.compiled_malicious:
            if pattern.search(user_agent_string):
                return False, f"Malicious pattern detected: {pattern.pattern}"
        
        # Check for non-printable characters (except common ones)
        if re.search(r'[\x00-\x08\x0B\x0C\x0E-\x1F\x7F-\x9F]', user_agent_string):
            return False, "Invalid characters detected"
        
        return True, None

    def _analyze_security_threats(self, user_agent_string: str, ua_parsed) -> tuple[ThreatLevel, List[str]]:
        """Analyze potential security threats"""
        security_flags = []
        threat_level = ThreatLevel.LOW
        
        # Check for suspicious bot patterns
        for pattern in self.compiled_suspicious:
            if pattern.search(user_agent_string):
                security_flags.append(f"Suspicious bot pattern: {pattern.pattern}")
                threat_level = ThreatLevel.HIGH
        
        # Check for automation tools
        for pattern in self.compiled_automation:
            if pattern.search(user_agent_string):
                security_flags.append(f"Automation tool detected: {pattern.pattern}")
                threat_level = max(threat_level, ThreatLevel.MEDIUM)
        
        # Check for unusual bot behavior
        if ua_parsed.is_bot:
            bot_family = ua_parsed.browser.family.lower()
            if not any(legitimate in bot_family for legitimate in self.LEGITIMATE_BOTS):
                security_flags.append("Unknown/suspicious bot")
                threat_level = max(threat_level, ThreatLevel.MEDIUM)
        
        # Check for version spoofing (very old or very new versions)
        if ua_parsed.browser.version_string:
            try:
                major_version = int(ua_parsed.browser.version[0]) if ua_parsed.browser.version else 0
                if major_version < 50 and ua_parsed.browser.family in ['Chrome', 'Firefox']:
                    security_flags.append("Potentially outdated browser version")
                    threat_level = max(threat_level, ThreatLevel.MEDIUM)
            except (ValueError, IndexError, TypeError):
                security_flags.append("Invalid browser version format")
        
        # Check for empty or minimal user agents
        if len(user_agent_string.strip()) < 20:
            security_flags.append("Suspiciously short user agent")
            threat_level = max(threat_level, ThreatLevel.MEDIUM)
        
        # Check for unusual character patterns
        if re.search(r'[{}|\\^~\[\]`]', user_agent_string):
            security_flags.append("Unusual characters detected")
            threat_level = max(threat_level, ThreatLevel.MEDIUM)
        
        # Check for excessive repetition (potential fuzzing)
        words = user_agent_string.split()
        if len(words) != len(set(words)) and len(words) > 10:
            security_flags.append("Excessive word repetition")
            threat_level = max(threat_level, ThreatLevel.MEDIUM)
        
        return threat_level, security_flags

    def _should_block(self, threat_level: ThreatLevel, security_flags: List[str]) -> tuple[bool, Optional[str]]:
        """Determine if the request should be blocked"""
        if threat_level == ThreatLevel.CRITICAL:
            return True, "Critical threat detected"
        
        if threat_level == ThreatLevel.HIGH:
            return True, "High threat level - blocking request"
        
        # Block if multiple medium-level flags
        if threat_level == ThreatLevel.MEDIUM and len(security_flags) >= 2:
            return True, "Multiple security concerns detected"
        
        return False, None

    def analyze_user_agent(self, user_agent_string: str) -> UserAgentAnalysis:
        """
        Comprehensive user agent analysis with security checks
        
        Args:
            user_agent_string: The user agent string to analyze
            
        Returns:
            UserAgentAnalysis: Detailed analysis results
        """
        try:
            # Input validation
            is_valid, validation_error = self._validate_input(user_agent_string)
            if not is_valid:
                logger.warning(f"Invalid user agent rejected: {validation_error}")
                return UserAgentAnalysis(
                    is_valid=False,
                    is_bot=False,
                    is_mobile=False,
                    is_pc=False,
                    os_family="Unknown",
                    os_version="Unknown",
                    browser_family="Unknown",
                    browser_version="Unknown",
                    threat_level=ThreatLevel.CRITICAL,
                    security_flags=[validation_error],
                    blocked=True,
                    reason=validation_error
                )
            
            # Parse user agent
            ua_parsed = user_agents.parse(user_agent_string)
            
            # Security threat analysis
            threat_level, security_flags = self._analyze_security_threats(user_agent_string, ua_parsed)
            
            # Determine if should block
            should_block, block_reason = self._should_block(threat_level, security_flags)
            
            # Log security events
            if threat_level in [ThreatLevel.HIGH, ThreatLevel.CRITICAL] or should_block:
                logger.warning(f"Security concern detected - UA: {user_agent_string[:100]}... "
                             f"Threat: {threat_level.value}, Flags: {security_flags}")
            
            return UserAgentAnalysis(
                is_valid=True,
                is_bot=ua_parsed.is_bot,
                is_mobile=ua_parsed.is_mobile,
                is_pc=ua_parsed.is_pc,
                os_family=ua_parsed.os.family or "Unknown",
                os_version=str(ua_parsed.os.version_string) if ua_parsed.os.version_string else "Unknown",
                browser_family=ua_parsed.browser.family or "Unknown",
                browser_version=str(ua_parsed.browser.version_string) if ua_parsed.browser.version_string else "Unknown",
                threat_level=threat_level,
                security_flags=security_flags,
                blocked=should_block,
                reason=block_reason
            )
            
        except Exception as e:
            logger.error(f"Error analyzing user agent: {e}")
            return UserAgentAnalysis(
                is_valid=False,
                is_bot=False,
                is_mobile=False,
                is_pc=False,
                os_family="Error",
                os_version="Error",
                browser_family="Error",
                browser_version="Error",
                threat_level=ThreatLevel.CRITICAL,
                security_flags=[f"Analysis error: {str(e)}"],
                blocked=True,
                reason="Internal analysis error"
            )

    def print_analysis(self, analysis: UserAgentAnalysis, user_agent_string: str = ""):
        """Print formatted analysis results"""
        print(f"Analyzing: {user_agent_string[:80]}{'...' if len(user_agent_string) > 80 else ''}")
        print(f"Valid: {analysis.is_valid}")
        print(f"Is a bot? {analysis.is_bot}")
        print(f"Is mobile? {analysis.is_mobile}")
        print(f"Is PC? {analysis.is_pc}")
        print(f"OS Family: {analysis.os_family}")
        print(f"OS Version: {analysis.os_version}")
        print(f"Browser Family: {analysis.browser_family}")
        print(f"Browser Version: {analysis.browser_version}")
        print(f"Threat Level: {analysis.threat_level.value.upper()}")
        
        if analysis.security_flags:
            print("Security Flags:")
            for flag in analysis.security_flags:
                print(f"  - {flag}")
        
        if analysis.blocked:
            print(f"🚫 BLOCKED: {analysis.reason}")
        else:
            print("✅ ALLOWED")
        
        print("-" * 50)


def main():
    """Test function with various user agent examples"""
    analyzer = SecureUserAgentAnalyzer()
    
    test_user_agents = [
        # Legitimate browsers
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.5938.132 Safari/537.36",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 16_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 Mobile/15E148 Safari/605.1.15",
        
        # Legitimate bots
        "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
        "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bot.html)",
        
        # Suspicious/malicious examples
        "Mozilla/5.0<script>alert('xss')</script>",
        "curl/7.68.0",
        "python-requests/2.25.1",
        "Nikto/2.1.6",
        "Mozilla/5.0 (compatible; vulnerability-scanner/1.0)",
        "HeadlessChrome/91.0.4472.114",
        "",  # Empty user agent
        "A" * 3000,  # Too long user agent
        "Mozilla/5.0 \x00\x01\x02",  # Control characters
    ]
    
    for ua_string in test_user_agents:
        analysis = analyzer.analyze_user_agent(ua_string)
        analyzer.print_analysis(analysis, ua_string)


if __name__ == "__main__":
    main()