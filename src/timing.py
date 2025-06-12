"""
Timing utilities for network scanning
"""
import time
import random
from functools import wraps


# Timing templates definition
TIMING_TEMPLATES = {
    "paranoid": {"delay": 5.0, "timeout": 10, "retries": 1, "max_threads": 1},
    "sneaky": {"delay": 2.0, "timeout": 5, "retries": 1, "max_threads": 1}, 
    "polite": {"delay": 1.0, "timeout": 3, "retries": 1, "max_threads": 2},
    "normal": {"delay": 0.5, "timeout": 2, "retries": 1, "max_threads": 5},
    "aggressive": {"delay": 0.1, "timeout": 1, "retries": 1, "max_threads": 10},
    "insane": {"delay": 0.01, "timeout": 0.5, "retries": 1, "max_threads": 20}
}


class TimingConfig:
    """Timing configuration class for scans"""
    
    def __init__(self, template_name="normal", **overrides):
        if isinstance(template_name, dict):
            # Direct config passed
            self.config = template_name.copy()
        else:
            # Template name passed
            self.config = TIMING_TEMPLATES.get(template_name, TIMING_TEMPLATES["normal"]).copy()
        
        # Apply any overrides
        self.config.update(overrides)
    
    @property
    def delay(self):
        return self.config.get("delay", 0.5)
    
    @property
    def timeout(self):
        return self.config.get("timeout", 2)
    
    @property
    def retries(self):
        return self.config.get("retries", 1)
    
    @property
    def max_threads(self):
        return self.config.get("max_threads", 5)
    
    def apply_delay(self, jitter=True):
        """Apply timing delay with optional jitter"""
        if self.delay > 0:
            delay_time = self.delay
            if jitter and self.delay > 0.1:
                # Add ±20% jitter to avoid detection patterns
                jitter_range = self.delay * 0.2
                delay_time += random.uniform(-jitter_range, jitter_range)
                delay_time = max(0, delay_time)  # Ensure non-negative
            
            time.sleep(delay_time)
    
    def __str__(self):
        return f"TimingConfig(delay={self.delay}s, timeout={self.timeout}s, retries={self.retries}, threads={self.max_threads})"


def with_timing(func):
    """Decorator to add timing support to scan functions"""
    @wraps(func)
    def wrapper(*args, **kwargs):
        # Extract timing-related parameters
        timing = kwargs.pop('timing', 'normal')
        delay = kwargs.pop('delay', None)
        retries = kwargs.pop('retries', None)
        apply_delay = kwargs.pop('apply_delay', True)
        
        # Create timing config
        if isinstance(timing, TimingConfig):
            timing_config = timing
        else:
            overrides = {}
            if delay is not None:
                overrides['delay'] = delay
            if retries is not None:
                overrides['retries'] = retries
            timing_config = TimingConfig(timing, **overrides)
        
        # Apply pre-scan delay if requested
        if apply_delay:
            timing_config.apply_delay()
        
        # Update timeout in kwargs if not already set
        if 'timeout' not in kwargs:
            kwargs['timeout'] = timing_config.timeout
        
        # Execute with retries
        last_exception = None
        for attempt in range(timing_config.retries + 1):
            try:
                result = func(*args, **kwargs)
                if result is not None:
                    return result
            except Exception as e:
                last_exception = e
                if attempt < timing_config.retries:
                    # Brief delay before retry
                    time.sleep(0.1)
                    continue
                else:
                    break
        
        # If we got here, all retries failed
        if last_exception:
            raise last_exception
        return None
    
    return wrapper


def adaptive_delay(success_rate, base_delay=0.5, min_delay=0.1, max_delay=5.0):
    """
    Calculate adaptive delay based on success rate
    Higher success rate = shorter delay
    Lower success rate = longer delay to avoid detection
    """
    if success_rate >= 0.8:
        return min_delay
    elif success_rate >= 0.6:
        return base_delay
    elif success_rate >= 0.4:
        return base_delay * 2
    elif success_rate >= 0.2:
        return base_delay * 3
    else:
        return min(max_delay, base_delay * 5)


def get_timing_template(name):
    """Get timing template by name"""
    return TIMING_TEMPLATES.get(name, TIMING_TEMPLATES["normal"])


def create_timing_config(template_name="normal", **overrides):
    """Create a timing configuration"""
    return TimingConfig(template_name, **overrides)


class AdaptiveTiming:
    """Adaptive timing that adjusts based on scan results"""
    
    def __init__(self, initial_template="normal"):
        self.config = TimingConfig(initial_template)
        self.scan_count = 0
        self.success_count = 0
        self.last_adjustment = 0
        self.adjustment_interval = 10  # Adjust every 10 scans
    
    def record_result(self, success):
        """Record scan result for adaptive adjustment"""
        self.scan_count += 1
        if success:
            self.success_count += 1
        
        # Adjust timing every N scans
        if self.scan_count - self.last_adjustment >= self.adjustment_interval:
            self._adjust_timing()
            self.last_adjustment = self.scan_count
    
    def _adjust_timing(self):
        """Adjust timing based on success rate"""
        if self.scan_count == 0:
            return
        
        success_rate = self.success_count / self.scan_count
        new_delay = adaptive_delay(success_rate, self.config.delay)
        
        self.config.config['delay'] = new_delay
        
        # Also adjust timeout based on success rate
        if success_rate < 0.3:
            # Increase timeout if many failures
            self.config.config['timeout'] = min(10, self.config.timeout * 1.5)
        elif success_rate > 0.9:
            # Decrease timeout if very successful
            self.config.config['timeout'] = max(0.5, self.config.timeout * 0.8)
    
    def get_config(self):
        """Get current timing configuration"""
        return self.config
    
    def apply_delay(self):
        """Apply current timing delay"""
        self.config.apply_delay()


# Rate limiting utilities
class RateLimiter:
    """Simple rate limiter for scan operations"""
    
    def __init__(self, max_rate=10):  # max operations per second
        self.max_rate = max_rate
        self.min_interval = 1.0 / max_rate if max_rate > 0 else 0
        self.last_call = 0
    
    def wait(self):
        """Wait if necessary to maintain rate limit"""
        if self.min_interval <= 0:
            return
        
        now = time.time()
        elapsed = now - self.last_call
        
        if elapsed < self.min_interval:
            time.sleep(self.min_interval - elapsed)
        
        self.last_call = time.time()


def timing_aware_scan(scan_func, targets, timing_config, rate_limit=None, progress_callback=None):
    """
    Execute scans with timing awareness
    
    Args:
        scan_func: Function to call for each target
        targets: List of targets (ports, IPs, etc.)
        timing_config: TimingConfig instance
        rate_limit: Optional RateLimiter instance
        progress_callback: Optional callback function for progress updates
    """
    results = {}
    
    for i, target in enumerate(targets):
        # Apply rate limiting
        if rate_limit:
            rate_limit.wait()
        
        # Apply timing delay
        timing_config.apply_delay()
        
        # Execute scan
        try:
            result = scan_func(target, timeout=timing_config.timeout)
            results[target] = result
        except Exception as e:
            results[target] = {"status": "error", "error": str(e)}
        
        # Progress callback
        if progress_callback:
            progress_callback(i + 1, len(targets))
    
    return results
