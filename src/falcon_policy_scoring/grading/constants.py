"""
Constants for grading policy settings.
"""

# ML Slider values mapped to numeric levels for comparison
MLSLIDER_LEVELS = {
    'DISABLED': 0,
    'CAUTIOUS': 1,
    'MODERATE': 2,
    'AGGRESSIVE': 3,
    'EXTRA_AGGRESSIVE': 4
}

# Toggle values mapped to numeric levels
# Duplicate keys are intentional for mapping to a common value
# pylint: disable=duplicate-key
TOGGLE_LEVELS = {
    False: 0,
    True: 1,
    'false': 0,
    'true': 1,
    0: 0,
    1: 1
}
# pylint: enable=duplicate-key

# N-level sensor update values mapped to numeric levels
N_LEVELS = {
    'disabled': -1,
    'other': 0,
    'pinned': 1,
    'n-2': 2,
    'n-1': 3,
    'n': 4
}
