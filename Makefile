GO ?= go

.PHONY: hero hero-svg
hero: ## Play the README animation in an 80x20 terminal
	env GOWORK=off $(GO) -C examples/hero run .

hero-svg: ## Regenerate the self-contained README SVG
	env GOWORK=off $(GO) -C examples/hero run . -svg ../../docs/hero.svg

.PHONY: hero-check
hero-check: ## Check real fixtures and generated hero freshness
	env GOWORK=off $(GO) -C examples/hero test ./...
