from rich.console import Console
from rich.theme import Theme

# Theme for console text
console_theme = Theme({
    "banner": "bold magenta",
    "header": "bold magenta",
    "error": "bold red",
    "prompt": "bold",
    "default": ""
})

# Configuration for Console
console = Console(theme=console_theme)