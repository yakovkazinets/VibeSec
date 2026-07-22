# Eligible passive DAST target

An authorized non-production service already exists as a digest-pinned image, declares a non-root user, needs no secrets or custom startup command, and listens on a known internal HTTP port. Recommend the separate DAST Baseline add-on on a disposable trusted runner, keep `observe` first, and state that application code will execute inside the isolated target container.
