"""Human-facing product branding separated from stable technical identifiers."""

PRODUCT_DISPLAY_NAME = "VibeSec Guardian"
POSITIONING_LINE = "Open-source security for vibe-coded and AI-built software."

# These identifiers are compatibility contracts and are not display branding.
PRODUCT_ID = "vibesec"
REPOSITORY_SLUG = "yakovkazinets/VibeSec"
REPOSITORY_URL = f"https://github.com/{REPOSITORY_SLUG}"


def display_metadata() -> dict[str, str]:
    return {
        "product_display_name": PRODUCT_DISPLAY_NAME,
        "positioning_line": POSITIONING_LINE,
        "product_id": PRODUCT_ID,
    }
