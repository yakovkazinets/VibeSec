# Skill-validation fixtures

All content is harmless test data. Instruction-like phrases are inert strings and must never be executed.

| Case | Source | Expected |
|---|---|---|
| valid minimal skill | `valid/SKILL.md` | accept |
| duplicate metadata key | `duplicate-key/SKILL.md` | reject |
| repeated front matter | `multiple-frontmatter/SKILL.md` | reject |
| hidden HTML instruction | `hidden-comment/SKILL.md` | accept as non-authoritative data |
| unclosed Markdown fence | `unclosed-fence/SKILL.md` | reject |
| active parent traversal | `traversal/SKILL.md` | reject |
| aliases, custom tags, boolean ambiguity, encodings, Unicode controls, line-ending and normalization equivalents, case collisions, symlinks, size, and depth | generated safely by `tests/test_skill_validation.py` | behavior asserted by each test |

Generated fixtures are used where Git cannot portably store invalid UTF-8, symlinks, case-colliding names, or alternate line endings.
