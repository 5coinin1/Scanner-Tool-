import time
import random
from functools import wraps

TIMING_TEMPLATES = {
    "paranoid": {"delay": 5.0, "timeout": 10, "retries": 1, "max_threads": 1},
    "sneaky": {"delay": 2.0, "timeout": 5, "retries": 1, "max_threads": 1}, 
    "polite": {"delay": 1.0, "timeout": 3, "retries": 1, "max_threads": 2},
    "normal": {"delay": 0.5, "timeout": 2, "retries": 1, "max_threads": 5},
    "aggressive": {"delay": 0.1, "timeout": 1, "retries": 1, "max_threads": 10},
    "insane": {"delay": 0.01, "timeout": 0.5, "retries": 1, "max_threads": 20}
}

class TimingConfig:
    def __init__(self, template_name="normal", **overrides):
        if isinstance(template_name, dict):
            self.config = template_name.copy()
        else:
            self.config = TIMING_TEMPLATES.get(template_name, TIMING_TEMPLATES["normal"]).copy()
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
        if self.delay > 0:
            delay_time = self.delay
            if jitter and self.delay > 0.1:
                jitter_range = self.delay * 0.2
                delay_time += random.uniform(-jitter_range, jitter_range)
                delay_time = max(0, delay_time)
            time.sleep(delay_time)
    
    def __str__(self):
        return f"TimingConfig(delay={self.delay}s, timeout={self.timeout}s, retries={self.retries}, threads={self.max_threads})"

def with_timing(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        timing = kwargs.pop('timing', 'normal')
        delay = kwargs.pop('delay', None)
        retries = kwargs.pop('retries', None)
        apply_delay = kwargs.pop('apply_delay', True)
        
        if isinstance(timing, TimingConfig):
            timing_config = timing
        else:
            overrides = {}
            if delay is not None:
                overrides['delay'] = delay
            if retries is not None:
                overrides['retries'] = retries
            timing_config = TimingConfig(timing, **overrides)
        
        if apply_delay:
            timing_config.apply_delay()
        
        if 'timeout' not in kwargs:
            kwargs['timeout'] = timing_config.timeout
        
        last_exception = None
        for attempt in range(timing_config.retries + 1):
            try:
                result = func(*args, **kwargs)
                if result is not None:
                    return result
            except Exception as e:
                last_exception = e
                if attempt < timing_config.retries:
                    time.sleep(0.1)
                    continue
                else:
                    break
        
        if last_exception:
            raise last_exception
        return None
    
    return wrapper

def adaptive_delay(success_rate, base_delay=0.5, min_delay=0.1, max_delay=5.0):
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

class AdaptiveTiming:
    def __init__(self, initial_template="normal"):
        self.config = TimingConfig(initial_template)
        self.scan_count = 0
        self.success_count = 0
        self.last_adjustment = 0
        self.adjustment_interval = 10
    
    def record_result(self, success):
        self.scan_count += 1
        if success:
            self.success_count += 1
        
        if self.scan_count - self.last_adjustment >= self.adjustment_interval:
            self._adjust_timing()
            self.last_adjustment = self.scan_count
    
    def _adjust_timing(self):
        if self.scan_count == 0:
            return
        
        success_rate = self.success_count / self.scan_count
        new_delay = adaptive_delay(success_rate, self.config.delay)
        self.config.config['delay'] = new_delay
        
        if success_rate < 0.3:
            self.config.config['timeout'] = min(10, self.config.timeout * 1.5)
        elif success_rate > 0.9:
            self.config.config['timeout'] = max(0.5, self.config.timeout * 0.8)
    
    def get_config(self):
        return self.config
    
    def apply_delay(self):
        self.config.apply_delay()

class RateLimiter:
    def __init__(self, max_rate=10):
        self.max_rate = max_rate
        self.min_interval = 1.0 / max_rate if max_rate > 0 else 0
        self.last_call = 0
    
    def wait(self):
        if self.min_interval <= 0:
            return
        
        now = time.time()
        elapsed = now - self.last_call
        
        if elapsed < self.min_interval:
            time.sleep(self.min_interval - elapsed)
        
        self.last_call = time.time()
