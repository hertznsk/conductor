**ACA execution profiles**: configure the pool and session scope under an
environment profile's `aca` block, independently of the agent's model
provider. The legacy `provider: aca` form remains available with a
deprecation notice. The obsolete `conductor.providers.aca_protocol` import
has been removed; import wire models from `conductor.runner.protocol`.
