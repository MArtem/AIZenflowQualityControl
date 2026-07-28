# Adapters

This directory will contain typed integrations for explicitly supported project and toolchain
surfaces.

Adapters must receive project facts through validated profiles. They must not infer or hardcode
application-specific defaults, and unsupported inputs must remain distinguishable from successful
execution.
