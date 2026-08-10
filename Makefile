CS_VERSION = release-v5.2.2
CS_COMMIT = 321bc5bc53601b9690b54c023c0cbfac0f0230f2
CS_MAVEN_IMAGE = maven:3.9.16-eclipse-temurin-21@sha256:c07f7ccfb8ca6c9fa29ee523f00afa7d2ca6132c92f8652c4aebb5ee3491f502
GOLANGCI_LINT_VERSION = v2.12.2
PKGSITE_VERSION = v0.3.0

setup-dev:
	@make setup-cs
	@go install golang.org/x/pkgsite/cmd/pkgsite@$(PKGSITE_VERSION)

setup-cs:
	@./scripts/verify-conformance-pin.sh
	@set -eu; \
	if [ ! -e "conformance-suite" ]; then \
	  echo "Fetching conformance suite $(CS_VERSION) ($(CS_COMMIT))..."; \
	  git init --quiet conformance-suite; \
	  git -C conformance-suite remote add origin https://gitlab.com/openid/conformance-suite.git; \
	  git -C conformance-suite fetch --quiet --depth=1 origin "$(CS_COMMIT)"; \
	  git -C conformance-suite checkout --quiet --detach "$(CS_COMMIT)"; \
	fi; \
	if ! actual_commit="$$(git -C conformance-suite rev-parse HEAD 2>/dev/null)"; then \
	  echo "conformance-suite is not a valid Git checkout" >&2; \
	  exit 1; \
	fi; \
	if [ "$$actual_commit" != "$(CS_COMMIT)" ]; then \
	  echo "Expected conformance suite $(CS_VERSION) ($(CS_COMMIT)), got $$actual_commit" >&2; \
	  echo "Recreate conformance-suite before running setup-cs" >&2; \
	  exit 1; \
	fi
	@./scripts/prepare-conformance-suite.sh conformance-suite

	@set -eu; \
	if [ ! -f "conformance-suite/target/fapi-test-suite.jar" ]; then \
	  docker run --rm \
	    --mount "type=bind,src=$${PWD}/conformance-suite,dst=/usr/src/mymaven" \
	    --workdir /usr/src/mymaven \
	    "$(CS_MAVEN_IMAGE)" \
	    mvn -B clean package -DskipTests=true; \
	fi

test-coverage:
	@go test -coverprofile=coverage.out $$(go list ./pkg/... ./internal/... | grep -v /internal/oidctest)
	@go tool cover -html="coverage.out" -o coverage.html
	@total_coverage="$$(go tool cover -func=coverage.out | awk '$$1 == "total:" {print $$3}')"; \
	  echo "Total Coverage: $$total_coverage"

install-lint:
	@go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION)

lint:
	@golangci-lint run ./pkg/... ./internal/... ./examples/...

test-benchmark:
	@go test -bench=. -benchmem ./pkg/... ./internal/...

keys:
	@openssl req -x509 -newkey rsa:2048 -keyout examples/keys/server.key -out examples/keys/server.crt -days 365 -nodes \
		-subj "/CN=op"
	@openssl req -x509 -newkey rsa:2048 -keyout examples/keys/client_one.key -out examples/keys/client_one.crt -days 365 -nodes \
		-subj "/CN=client_one"
	@openssl req -x509 -newkey rsa:2048 -keyout examples/keys/client_two.key -out examples/keys/client_two.crt -days 365 -nodes \
		-subj "/CN=client_two"

run-cs:
	@docker compose up

cs-oidc-tests:
	@conformance-suite/venv/bin/python3 conformance-suite/scripts/run-test-plan.py \
		oidcc-basic-certification-test-plan[server_metadata=discovery][client_registration=dynamic_client] ./examples/oidc/config.json \
		oidcc-dynamic-certification-test-plan[response_type=code] ./examples/oidc/config.json \
		oidcc-dynamic-certification-test-plan[response_type=id_token] ./examples/oidc/config.json \
		oidcc-dynamic-certification-test-plan[response_type=id_token\ token] ./examples/oidc/config.json \
		oidcc-dynamic-certification-test-plan[response_type=code\ id_token] ./examples/oidc/config.json \
		oidcc-dynamic-certification-test-plan[response_type=code\ token] ./examples/oidc/config.json \
		oidcc-dynamic-certification-test-plan[response_type=code\ id_token\ token] ./examples/oidc/config.json \
		oidcc-formpost-basic-certification-test-plan[server_metadata=discovery][client_registration=dynamic_client] ./examples/oidc/config.json \
		oidcc-formpost-hybrid-certification-test-plan[server_metadata=discovery][client_registration=dynamic_client] ./examples/oidc/config.json \
		oidcc-formpost-implicit-certification-test-plan[server_metadata=discovery][client_registration=dynamic_client] ./examples/oidc/config.json \
		oidcc-rp-initiated-logout-certification-test-plan[response_type=code\ id_token][client_registration=dynamic_client] ./examples/oidc/config.json \
		--expected-failures-file ./examples/oidc/failures.json \
		--export-dir ./examples/oidc \
		--verbose

cs-fapi1-op-mtls-tests:
	@conformance-suite/venv/bin/python3 conformance-suite/scripts/run-test-plan.py \
		fapi1-advanced-final-test-plan[client_auth_type=mtls][fapi_auth_request_method=by_value][fapi_profile=plain_fapi][fapi_response_mode=plain_response] ./examples/fapi1_op_mtls/config.json \
		--export-dir ./examples/fapi1_op_mtls \
		--verbose

cs-fapi1-op-mtls-par-tests:
	@conformance-suite/venv/bin/python3 conformance-suite/scripts/run-test-plan.py \
		fapi1-advanced-final-test-plan[client_auth_type=mtls][fapi_auth_request_method=pushed][fapi_profile=plain_fapi][fapi_response_mode=plain_response] ./examples/fapi1_op_mtls_par/config.json \
		--export-dir ./examples/fapi1_op_mtls_par \
		--verbose

cs-fapi1-op-private-key-tests:
	@conformance-suite/venv/bin/python3 conformance-suite/scripts/run-test-plan.py \
		fapi1-advanced-final-test-plan[client_auth_type=private_key_jwt][fapi_auth_request_method=by_value][fapi_profile=plain_fapi][fapi_response_mode=plain_response] ./examples/fapi1_op_private_key/config.json \
		--export-dir ./examples/fapi1_op_private_key \
		--verbose

cs-fapi1-op-private-key-par-tests:
	@conformance-suite/venv/bin/python3 conformance-suite/scripts/run-test-plan.py \
		fapi1-advanced-final-test-plan[client_auth_type=private_key_jwt][fapi_auth_request_method=pushed][fapi_profile=plain_fapi][fapi_response_mode=plain_response] ./examples/fapi1_op_private_key_par/config.json \
		--export-dir ./examples/fapi1_op_private_key_par \
		--verbose

cs-fapi1-op-mtls-jarm-tests:
	@conformance-suite/venv/bin/python3 conformance-suite/scripts/run-test-plan.py \
		fapi1-advanced-final-test-plan[client_auth_type=mtls][fapi_auth_request_method=by_value][fapi_profile=plain_fapi][fapi_response_mode=jarm] ./examples/fapi1_op_mtls_jarm/config.json \
		--export-dir ./examples/fapi1_op_mtls_jarm \
		--verbose

cs-fapi1-op-mtls-par-jarm-tests:
	@conformance-suite/venv/bin/python3 conformance-suite/scripts/run-test-plan.py \
		fapi1-advanced-final-test-plan[client_auth_type=mtls][fapi_auth_request_method=pushed][fapi_profile=plain_fapi][fapi_response_mode=jarm] ./examples/fapi1_op_mtls_par_jarm/config.json \
		--export-dir ./examples/fapi1_op_mtls_par_jarm \
		--verbose

cs-fapi1-op-private-key-jarm-tests:
	@conformance-suite/venv/bin/python3 conformance-suite/scripts/run-test-plan.py \
		fapi1-advanced-final-test-plan[client_auth_type=private_key_jwt][fapi_auth_request_method=by_value][fapi_profile=plain_fapi][fapi_response_mode=jarm] ./examples/fapi1_op_private_key_jarm/config.json \
		--export-dir ./examples/fapi1_op_private_key_jarm \
		--verbose

cs-fapi1-op-private-key-par-jarm-tests:
	@conformance-suite/venv/bin/python3 conformance-suite/scripts/run-test-plan.py \
		fapi1-advanced-final-test-plan[client_auth_type=private_key_jwt][fapi_auth_request_method=pushed][fapi_profile=plain_fapi][fapi_response_mode=jarm] ./examples/fapi1_op_private_key_par_jarm/config.json \
		--export-dir ./examples/fapi1_op_private_key_par_jarm \
		--verbose

cs-fapi2-sp-op-mtls-mtls-tests:
	@conformance-suite/venv/bin/python3 conformance-suite/scripts/run-test-plan.py \
		fapi2-security-profile-final-test-plan[client_auth_type=mtls][sender_constrain=mtls][openid=openid_connect][fapi_profile=plain_fapi] ./examples/fapi2_sp_op_mtls_mtls/config.json \
		--export-dir ./examples/fapi2_sp_op_mtls_mtls \
		--verbose

cs-fapi2-sp-op-mtls-dpop-tests:
	@conformance-suite/venv/bin/python3 conformance-suite/scripts/run-test-plan.py \
		fapi2-security-profile-final-test-plan[client_auth_type=mtls][sender_constrain=dpop][openid=openid_connect][fapi_profile=plain_fapi] ./examples/fapi2_sp_op_mtls_dpop/config.json \
		--export-dir ./examples/fapi2_sp_op_mtls_dpop \
		--verbose

cs-fapi2-sp-op-private-key-mtls-tests:
	@conformance-suite/venv/bin/python3 conformance-suite/scripts/run-test-plan.py \
		fapi2-security-profile-final-test-plan[client_auth_type=private_key_jwt][sender_constrain=mtls][openid=openid_connect][fapi_profile=plain_fapi] ./examples/fapi2_sp_op_private_key_mtls/config.json \
		--export-dir ./examples/fapi2_sp_op_private_key_mtls \
		--verbose

cs-fapi2-sp-op-private-key-dpop-tests:
	@conformance-suite/venv/bin/python3 conformance-suite/scripts/run-test-plan.py \
		fapi2-security-profile-final-test-plan[client_auth_type=private_key_jwt][sender_constrain=dpop][openid=openid_connect][fapi_profile=plain_fapi] ./examples/fapi2_sp_op_private_key_dpop/config.json \
		--export-dir ./examples/fapi2_sp_op_private_key_dpop \
		--verbose

cs-fapi2-ms-op-jar-tests:
	@conformance-suite/venv/bin/python3 conformance-suite/scripts/run-test-plan.py \
		fapi2-message-signing-final-test-plan[client_auth_type=private_key_jwt][sender_constrain=mtls][authorization_request_type=simple][openid=openid_connect][fapi_request_method=signed_non_repudiation][fapi_profile=plain_fapi][fapi_response_mode=plain_response] ./examples/fapi2_ms_op_jar/config.json \
		--export-dir ./examples/fapi2_ms_op_jar \
		--verbose

cs-fapi2-ms-op-jarm-tests:
	@conformance-suite/venv/bin/python3 conformance-suite/scripts/run-test-plan.py \
			fapi2-message-signing-final-test-plan[client_auth_type=private_key_jwt][sender_constrain=mtls][authorization_request_type=simple][openid=openid_connect][fapi_request_method=unsigned][fapi_profile=plain_fapi][fapi_response_mode=jarm] ./examples/fapi2_ms_op_jarm/config.json \
		--export-dir ./examples/fapi2_ms_op_jarm \
		--verbose

cs-fapi1-tests:
	@conformance-suite/venv/bin/python3 conformance-suite/scripts/run-test-plan.py \
		fapi1-advanced-final-test-plan[client_auth_type=private_key_jwt][fapi_auth_request_method=by_value][fapi_profile=plain_fapi][fapi_response_mode=jarm] ./examples/fapi1/config.json \
		fapi1-advanced-final-test-plan[client_auth_type=mtls][fapi_auth_request_method=by_value][fapi_profile=plain_fapi][fapi_response_mode=jarm] ./examples/fapi1/mtls_config.json \
		fapi1-advanced-final-test-plan[client_auth_type=private_key_jwt][fapi_auth_request_method=pushed][fapi_profile=plain_fapi][fapi_response_mode=jarm] ./examples/fapi1/config.json \
		fapi1-advanced-final-test-plan[client_auth_type=private_key_jwt][fapi_auth_request_method=by_value][fapi_profile=plain_fapi][fapi_response_mode=plain_response] ./examples/fapi1/config.json \
		--export-dir ./examples/fapi1 \
		--verbose

cs-fapiciba-tests:
	@conformance-suite/venv/bin/python3 conformance-suite/scripts/run-test-plan.py \
		fapi-ciba-id1-test-plan[client_auth_type=private_key_jwt][ciba_mode=poll][fapi_ciba_profile=plain_fapi][client_registration=dynamic_client] ./examples/fapiciba/config.json \
		fapi-ciba-id1-test-plan[client_auth_type=private_key_jwt][ciba_mode=ping][fapi_ciba_profile=plain_fapi][client_registration=dynamic_client] ./examples/fapiciba/config.json \
		--export-dir ./examples/fapiciba \
		--verbose

cs-federation-tests:
	@conformance-suite/venv/bin/python3 conformance-suite/scripts/run-test-plan.py \
		openid-federation-entity-joined-to-test-federation-op-test-plan[server_metadata=discovery][client_registration=automatic] ./examples/federation/config.json \
		--export-dir ./examples/federation \
		--verbose
