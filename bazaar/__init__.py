__version__ = "0.1.0"
__version_info__ = tuple(
    [
        int(num) if num.isdigit() else num
        for num in __version__.replace("-", ".", 1).split(".")
    ]
)

from bazaar.core.init_es import init_es, init_fuzzy_match_es

init_es()
init_fuzzy_match_es()

