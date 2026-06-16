# Personas

This directory contains standing persona definitions for use in PodMotion quorum and sprint gate agent prompts. Each file defines a named reviewer persona — their identity, authority, vote weight, model requirement, scope of ownership, and the verbatim paragraph that must be included in any agent prompt that invokes them. Quorum and gate agents load these definitions from source rather than relying on memory or per-sprint recreation. Personas are permanent repo artifacts; changes require an ADR at the threshold level specified in the persona file itself.
